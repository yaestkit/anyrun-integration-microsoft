param (
    [Parameter(Mandatory = $true)]
    [string]$payload
)

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
        default { throw "Invalid Base64URL value." }
    }

    $bytes = [Convert]::FromBase64String($base64)
    return [Text.Encoding]::UTF8.GetString($bytes)
}

$payloadParts = $payload.Split('.')
if ($payloadParts.Count -lt 5 -or $payloadParts[0] -ne 'v1') {
    throw "Invalid or unsupported Live Response payload."
}

$SAStoken = ConvertFrom-Base64Url -value $payloadParts[1]
$storageAccountName = ConvertFrom-Base64Url -value $payloadParts[2]
$containerName = ConvertFrom-Base64Url -value $payloadParts[3]
$filePath = @()
for ($index = 4; $index -lt $payloadParts.Count; $index++) {
    $filePath += ConvertFrom-Base64Url -value $payloadParts[$index]
}

# Get current date for logging
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Define temp folder
$tempFolder = Join-Path -Path $env:TEMP -ChildPath "ANYRUN_Temp"

# Function to check if file is in quarantine and restore it to specified path
function Restore-FromQuarantine {
    param (
        [string]$file,
        [string]$restorePath
    )
    Write-Host "Checking quarantine for file: $file"
    & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Restore -FilePath $file -Path $restorePath
    Start-Sleep -Seconds 5
    $restoredFilePath = Join-Path -Path $restorePath -ChildPath (Split-Path $file -Leaf)
    if (Test-Path $restoredFilePath) {
        Write-Host "File restored from quarantine successfully to: $restoredFilePath"
        return $true
    } else {
        Write-Host "File not found in quarantine."
        return $false
    }
}

# Function to upload file to Blob Storage
function Upload-ToBlob {
    param (
        [string]$file,
        [string]$sas
    )
    $blobName = Split-Path $file -Leaf
    # Ensure SAS starts with '?'
    if (-not $sas.StartsWith("?")) {
        $sas = "?" + $sas
    }
    $blobUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName$sas"
    Write-Host "Uploading file to Blob Storage: $blobName"
    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
        "x-ms-version" = "2021-04-10"
        "Content-Type" = "application/octet-stream"
    }
    $fileSize = (Get-Item $file).Length
    $headers["Content-Length"] = $fileSize
    $fileContent = [System.IO.File]::ReadAllBytes($file)
    try {
        Invoke-RestMethod -Uri $blobUrl -Method Put -Headers $headers -Body $fileContent
        Write-Host "File uploaded to Blob Storage successfully: $blobName"
        return $true
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode) {
            Write-Host "Error uploading file to Blob Storage. HTTP status: $statusCode"
        } else {
            Write-Host "Error uploading file to Blob Storage."
        }
        return $false
    }
}

# Main logic
Write-Host "Starting script at $date for files: $($filePath -join ', ')"

# Create temp folder if not exists
if (-not (Test-Path $tempFolder)) {
    New-Item -Path $tempFolder -ItemType Directory | Out-Null
    Write-Host "Temp folder created: $tempFolder"
} else {
    Write-Host "Temp folder already exists: $tempFolder"
}

# Set permissions on temp folder to only current user and SYSTEM
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($userRule)
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($systemRule)
Set-Acl -Path $tempFolder -AclObject $acl
Write-Host "Permissions set on temp folder: accessible only to current user and SYSTEM"

# Add temp folder to MDE exclusions
Add-MpPreference -ExclusionPath $tempFolder
Write-Host "Temp folder added to MDE exclusions"

# Track overall success
$allSuccess = $true

# Process each file path
foreach ($path in $filePath) {
    $tempFilePath = Join-Path -Path $tempFolder -ChildPath (Split-Path $path -Leaf)

    # Check if file exists at original path
    if (Test-Path $path) {
        # Move to temp folder if exists
        Copy-Item -Path $path -Destination $tempFilePath -Force
        Write-Host "File moved to temp folder: $tempFilePath"
    } else {
        # Try to restore from quarantine directly to temp folder
        if (Restore-FromQuarantine -file $path -restorePath $tempFolder) {
            Write-Host "File restored directly to temp folder: $tempFilePath"
        } else {
            Write-Host "File not found at $path or in quarantine. Skipping this file."
            $allSuccess = $false
            continue
        }
    }

    # Upload to Blob
    $uploadSuccess = Upload-ToBlob -file $tempFilePath -sas $SAStoken
    if (-not $uploadSuccess) {
        $allSuccess = $false
    }

    # Clean up this file
    Remove-Item -Path $tempFilePath -Force
    Write-Host "File removed from temp folder: $tempFilePath"
}

# Final clean up
Remove-MpPreference -ExclusionPath $tempFolder
Write-Host "Temp folder removed from MDE exclusions"

# Delete temp folder with try-catch for error handling
try {
    Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction Stop
    Write-Host "Temp folder deleted successfully; associated ACL rules removed automatically."
} catch {
    Write-Host "Error deleting temp folder: $_. ACL rules may persist if folder remains."
    $allSuccess = $false
}

if ($allSuccess) {
    Write-Host "Script completed successfully at $date"
} else {
    Write-Host "Script completed with some failures at $date"
}
