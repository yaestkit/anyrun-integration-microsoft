param (
    [string]$filePath = "",
    [string]$SAStoken = "",
    [string]$storageAccountName = "",
    [string]$containerName = ""
)

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
    $quarantineCmd = "& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Restore -FilePath '$file' -Path '$restorePath'"
    Invoke-Expression $quarantineCmd
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
    Write-Host "Uploading to URL: $blobUrl"  # Debug: Print URL
    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
        "x-ms-version" = "2021-04-10"
        "Content-Type" = "application/octet-stream"
    }
    $fileSize = (Get-Item $file).Length
    $headers["Content-Length"] = $fileSize
    $fileContent = [System.IO.File]::ReadAllBytes($file)
    try {
        Invoke-RestMethod -Uri $blobUrl -Method Put -Headers $headers -Body $fileContent -Verbose
        Write-Host "File uploaded to Blob Storage successfully: $blobName"
        return $true
    } catch {
        Write-Host "Error uploading file: $_"
        Write-Host "Response: $($_.Exception.Response)"
        return $false
    }
}

# Main logic
Write-Host "Starting script at $date for file: $filePath"

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

# Process the file path
$tempFilePath = Join-Path -Path $tempFolder -ChildPath (Split-Path $filePath -Leaf)

# Check if file exists at original path
if (Test-Path $filePath) {
    # Move to temp folder if exists
    Copy-Item -Path $filePath -Destination $tempFilePath -Force
    Write-Host "File copied to temp folder: $tempFilePath"
} else {
    # Try to restore from quarantine directly to temp folder
    if (Restore-FromQuarantine -file $filePath -restorePath $tempFolder) {
        Write-Host "File restored directly to temp folder: $tempFilePath"
    } else {
        Write-Host "File not found at $filePath or in quarantine. Exiting script."
        $allSuccess = $false
    }
}

# Upload to Blob if processing succeeded
if ($allSuccess) {
    $uploadSuccess = Upload-ToBlob -file $tempFilePath -sas $SAStoken
    if (-not $uploadSuccess) {
        $allSuccess = $false
    }
}

# Clean up this file
Remove-Item -Path $tempFilePath -Force
Write-Host "File removed from temp folder: $tempFilePath"

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
    Write-Host "Script failed at $date"
}