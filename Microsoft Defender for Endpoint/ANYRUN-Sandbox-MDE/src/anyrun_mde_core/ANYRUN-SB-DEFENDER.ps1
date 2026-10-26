param (
    [Parameter(Mandatory = $true)]
    [string]$payload
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function ConvertFrom-Base64Url {
    param (
        [Parameter(Mandatory = $true)]
        [string]$value
    )

    $base64 = $value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        0 { }
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        default { throw 'Invalid Base64URL value.' }
    }

    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
}

function Restore-FromQuarantine {
    param (
        [string]$file,
        [string]$restorePath
    )

    Write-Host "Checking quarantine for file: $file"
    & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Restore -FilePath $file -Path $restorePath
    Start-Sleep -Seconds 5
    $restoredFilePath = Join-Path -Path $restorePath -ChildPath (Split-Path $file -Leaf)
    return Test-Path -LiteralPath $restoredFilePath -PathType Leaf
}

function Upload-ToBlob {
    param (
        [string]$file,
        [string]$blobName,
        [string]$sas,
        [string]$storageAccountName,
        [string]$containerName
    )

    if (-not $sas.StartsWith('?')) {
        $sas = '?' + $sas
    }
    $blobUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName$sas"
    $fileContent = [System.IO.File]::ReadAllBytes($file)
    $headers = @{
        'x-ms-blob-type' = 'BlockBlob'
        'x-ms-version' = '2021-04-10'
        'Content-Type' = 'application/octet-stream'
        'Content-Length' = $fileContent.Length
    }
    Invoke-RestMethod -Uri $blobUrl -Method Put -Headers $headers -Body $fileContent | Out-Null
    Write-Host "File uploaded to Blob Storage successfully: $blobName"
}

$payloadParts = $payload.Split('.')
if (
    $payloadParts.Count -lt 6 -or
    $payloadParts[0] -ne 'v2' -or
    (($payloadParts.Count - 3) % 3) -ne 0
) {
    throw 'Invalid or unsupported Live Response payload.'
}

$storageAccountName = ConvertFrom-Base64Url -value $payloadParts[1]
$containerName = ConvertFrom-Base64Url -value $payloadParts[2]
$targets = @()
for ($index = 3; $index -lt $payloadParts.Count; $index += 3) {
    $targets += [pscustomobject]@{
        FilePath = ConvertFrom-Base64Url -value $payloadParts[$index]
        BlobName = ConvertFrom-Base64Url -value $payloadParts[$index + 1]
        SasToken = ConvertFrom-Base64Url -value $payloadParts[$index + 2]
    }
}

$date = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$tempFolder = Join-Path -Path $env:TEMP -ChildPath ('ANYRUN_' + [Guid]::NewGuid().ToString('N'))
$exclusionAdded = $false
$uploadedCount = 0

try {
    New-Item -Path $tempFolder -ItemType Directory -ErrorAction Stop | Out-Null

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentUser, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
    ))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
    ))
    Set-Acl -Path $tempFolder -AclObject $acl

    Add-MpPreference -ExclusionPath $tempFolder
    $exclusionAdded = $true

    foreach ($target in $targets) {
        $tempFilePath = Join-Path -Path $tempFolder -ChildPath (Split-Path $target.FilePath -Leaf)
        try {
            if (Test-Path -LiteralPath $target.FilePath -PathType Leaf) {
                Copy-Item -LiteralPath $target.FilePath -Destination $tempFilePath -Force
            } elseif (-not (Restore-FromQuarantine -file $target.FilePath -restorePath $tempFolder)) {
                throw "File was not found at the source path or in quarantine: $($target.FilePath)"
            }

            Upload-ToBlob `
                -file $tempFilePath `
                -blobName $target.BlobName `
                -sas $target.SasToken `
                -storageAccountName $storageAccountName `
                -containerName $containerName
            $uploadedCount++
        } catch {
            Write-Error "Failed to collect an evidence file: $($_.Exception.Message)" -ErrorAction Continue
        } finally {
            if (Test-Path -LiteralPath $tempFilePath) {
                Remove-Item -LiteralPath $tempFilePath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if ($uploadedCount -eq 0) {
        throw 'No evidence files could be collected or uploaded.'
    }
    if ($uploadedCount -lt $targets.Count) {
        Write-Warning "Uploaded $uploadedCount of $($targets.Count) evidence files."
    }
    Write-Host "Script completed successfully at $date"
} finally {
    if ($exclusionAdded) {
        Remove-MpPreference -ExclusionPath $tempFolder -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $tempFolder) {
        Remove-Item -LiteralPath $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}
