#Requires -Version 7.0

<#
.SYNOPSIS
  Deploys an ANY.RUN Sandbox or TI Feeds connector for Microsoft Defender
  for Endpoint.

.DESCRIPTION
  Interactive installer intended for Azure Cloud Shell (PowerShell). It creates
  or reuses Entra app registrations, configures WindowsDefenderATP application
  permissions, attempts to grant admin consent, prepares Azure resources, and
  deploys the connector ARM templates.

  The script is safe to re-run. Existing resource groups, dedicated connector
  app registrations, workspaces, and storage accounts are reused. An App
  Registration with permissions for another API is rejected as shared.

.PARAMETER Connector
  Sandbox analyzes Defender alerts with ANY.RUN Sandbox. Feeds imports TI
  indicators into Defender on a schedule.
  There is no default; omitting this parameter opens an interactive menu. Required in -NonInteractive mode.

.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1

.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Sandbox

.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Feeds

.NOTES
  The Sandbox connector still requires the operator to enable Defender Live
  Response settings and to review the Defender Antivirus quarantine policy.
#>

[CmdletBinding()]
param(
  [Parameter(HelpMessage = "Choose Sandbox or Feeds. Omit this parameter for the interactive menu.")]
  [ValidateSet("Sandbox", "Feeds")]
  [string]$Connector,

  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
  [string]$TenantId,
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
  [string]$SubscriptionId,
  [ValidatePattern('^[^<>%&:\\?/#]{1,90}(?<!\.)$')]
  [string]$ResourceGroup,
  [ValidatePattern('^[a-z0-9]{0,12}$', Options = 'None')]
  [string]$InstanceName,
  [string]$Region = "eastus",
  [string]$LogAnalyticsWorkspaceName,
  [switch]$ForceGraphDeviceCode,

  [string]$SandboxAppDisplayName = "ANYRUN-Sandbox-MDE-Connector",
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
  [string]$SandboxAppId,
  [SecureString]$SandboxClientSecret,
  [SecureString]$SandboxApiKey,
  [string]$SandboxFunctionName,
  [ValidatePattern('^[A-Za-z0-9._()-]{1,80}$')]
  [string]$SandboxLogicAppName,
  [string]$SandboxStorageAccountName,
  [string]$SandboxBlobContainerName = "anyrun-quarantine",
  [ValidateSet("bylink", "owner")]
  [string]$SandboxAnalysisPrivacyType = "bylink",

  [string]$FeedsAppDisplayName = "ANYRUN-Feeds-MDE-Connector",
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
  [string]$FeedsAppId,
  [SecureString]$FeedsClientSecret,
  [SecureString]$FeedsApiKey,
  [string]$FeedsFunctionName,
  [ValidatePattern('^[A-Za-z0-9._()-]{1,80}$')]
  [string]$FeedsLogicAppName,
  [string]$FeedsStorageAccountName,
  [ValidateRange(1, 168)]
  [int]$FeedsIntervalHours = 2,
  [ValidateRange(1, 365)]
  [int]$FeedsFetchDepthDays = 30,
  [ValidateRange(1, 100)]
  [int]$FeedsMinimumConfidence = 50,
  [ValidateSet("Audit", "Block", "Disabled")]
  [string]$DefenderIndicatorAction = "Audit",

  [ValidateRange(1, 24)]
  [int]$SecretLifetimeMonths = 6,

  [switch]$SkipFunctionApp,
  [switch]$SkipLogicApp,
  [switch]$TestFeedsInvocation,
  [switch]$NonInteractive,
  [switch]$ConfirmDedicatedAppRegistration,
  [switch]$ApproveDefenderPermissions,
  [switch]$DeferConsent,
  [switch]$RotateClientSecret
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version 3.0

# Reviewed release artifacts. The branch is resolved to a commit at run time and
# every downloaded file must match these SHA-256 values. Update them together
# with the checked-in templates and Function packages.
$Repository = "yaestkit/anyrun-integration-microsoft"
$RepositoryRef = "refs/heads/asyncv2"
$script:Artifacts = @{
  Sandbox = @{
    Path = "ANYRUN-Sandbox-MDE"; FunctionDirectory = "ANYRUN-Sandbox-MDE-FA"
    FunctionTemplate = "ANYRUN-Sandbox-MDE-FA.json"; FunctionTemplateSha256 = "f19bf0d6d6be2fd46fdf95b42c38dd7ff689b2cb57ff240fef363f738c423dbf"
    Package = "ANYRUN-Sandbox-MDE-FA.zip"; PackageSha256 = "96bb5ff6a54d5c9cfb245445aa21ace760264c93a4424e75ce892ea7c20aa0dd"
    LogicTemplate = "ANYRUN-Sandbox-MDE-LA.json"; LogicTemplateSha256 = "1c1d080bb98cc8afa84cfb9e86e9f141175254e91fa34d6abd66c0e6eb186113"
  }
  Feeds = @{
    Path = "ANYRUN-TI-Feeds-MDE"; FunctionDirectory = "ANYRUN-Feeds-MDE-FA"
    FunctionTemplate = "ANYRUN-Feeds-MDE-FA.json"; FunctionTemplateSha256 = "355c0109232ba3fc537a35a68459594b6dabcf8b2d9d7190b9888f1212c9ef83"
    Package = "ANYRUN-Feeds-MDE-FA.zip"; PackageSha256 = "38256d0fbfebc09037ebb9ddf6eea40f272edd7c350747496a5ba5838244f843"
    LogicTemplate = "ANYRUN-Feeds-MDE-LA.json"; LogicTemplateSha256 = "e219f7f13a09646b940fefb659cedf5cb35cd196ede67d6aa48c88f6b1f397ec"
  }
}

$script:WindowsDefenderAtpAppId = "fc780465-2017-40d4-a0c5-307022471b92"
$script:StorageBlobDataContributorRoleId = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
# Granted by earlier template versions; removed during upgrade.
$script:LegacyStorageBlobDataOwnerRoleId = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
$script:InstallerTagPrefix = "anyrun-mde-installer:v1"
$script:GraphSessionOwned = $false
$script:TemporaryFiles = [System.Collections.Generic.List[string]]::new()
$script:DeferredConsentUrls = [System.Collections.Generic.List[string]]::new()
$script:DeferredConnectorLabels = [System.Collections.Generic.List[string]]::new()
$sandboxStorageNameWasPassed = $PSBoundParameters.ContainsKey("SandboxStorageAccountName")
$feedsStorageNameWasPassed = $PSBoundParameters.ContainsKey("FeedsStorageAccountName")
$instanceNameWasPassed = $PSBoundParameters.ContainsKey("InstanceName")
$sandboxDisplayNameWasPassed = $PSBoundParameters.ContainsKey("SandboxAppDisplayName")
$feedsDisplayNameWasPassed = $PSBoundParameters.ContainsKey("FeedsAppDisplayName")
$regionWasPassed = $PSBoundParameters.ContainsKey("Region")
$sandboxAppIdWasPassed = $PSBoundParameters.ContainsKey("SandboxAppId")
$feedsAppIdWasPassed = $PSBoundParameters.ContainsKey("FeedsAppId")
$indicatorActionWasPassed = $PSBoundParameters.ContainsKey("DefenderIndicatorAction")

$sandboxRoles = @(
  "Alert.ReadWrite.All",
  "Machine.LiveResponse",
  "Machine.ReadWrite.All",
  "Ti.ReadWrite",
  "Library.Manage"
)

$feedsRoles = @(
  "Ti.ReadWrite"
)

function Write-Banner {
  param([Parameter(Mandatory = $true)][string]$Text)
  Write-Host ""
  Write-Host "========================================================================" -ForegroundColor Magenta
  Write-Host "  $Text" -ForegroundColor Magenta
  Write-Host "========================================================================" -ForegroundColor Magenta
}

function Write-Phase {
  param([string]$Number, [string]$Text)
  Write-Host ""
  Write-Host "[$Number] $Text" -ForegroundColor Cyan
  Write-Host ("-" * 72) -ForegroundColor DarkGray
}

function Write-Step {
  param([string]$Text)
  Write-Host "  -> $Text" -ForegroundColor Gray
}

function Read-Text {
  param(
    [Parameter(Mandatory = $true)][string]$Prompt,
    [string]$Default,
    [string]$ValidationPattern,
    [string]$ValidationMessage = "Invalid value.",
    [string]$HelpText
  )

  if (-not $NonInteractive) {
    if ($HelpText) { Write-Host "  $HelpText" -ForegroundColor Gray }
    $inputHint = if ([string]::IsNullOrWhiteSpace($Default)) { "A value is required; there is no default." } else { "Press Enter to use the value in brackets." }
    Write-Host "  $inputHint" -ForegroundColor DarkGray
  }
  while ($true) {
    $suffix = if ([string]::IsNullOrWhiteSpace($Default)) { "" } else { " [$Default]" }
    if ($NonInteractive) {
      if ([string]::IsNullOrWhiteSpace($Default)) { throw "Non-interactive deployment requires a value for: $Prompt" }
      return $Default
    }
    $value = Read-Host "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($value)) { $value = $Default }
    if ([string]::IsNullOrWhiteSpace($value)) {
      Write-Host "    A value is required." -ForegroundColor Red
      continue
    }
    $value = $value.Trim()
    if ($ValidationPattern -and $value -notmatch $ValidationPattern) {
      Write-Host "    $ValidationMessage" -ForegroundColor Red
      continue
    }
    return $value.Trim()
  }
}

function Read-Choice {
  param(
    [Parameter(Mandatory = $true)][string]$Prompt,
    [Parameter(Mandatory = $true)][string[]]$Options,
    [int]$Default = 1,
    [string[]]$Values,
    [string]$HelpText
  )

  if ($Default -lt 0 -or $Default -gt $Options.Count) { throw "Choice default is outside the options list." }
  if ($Values -and $Values.Count -ne $Options.Count) { throw "Choice values must match the options list." }
  if ($NonInteractive) { throw "Non-interactive deployment cannot answer prompt: $Prompt" }
  Write-Host ""
  Write-Host "  $Prompt" -ForegroundColor White
  if ($HelpText) { Write-Host "  $HelpText" -ForegroundColor Gray }
  for ($i = 0; $i -lt $Options.Count; $i++) {
    $marker = if (($i + 1) -eq $Default) { " (default)" } else { "" }
    Write-Host "    [$($i + 1)] $($Options[$i])$marker"
  }

  $choiceHint = "Enter a number from 1 to $($Options.Count)"
  if ($Values) { $choiceHint += " or a name ($($Values -join ", "))" }
  $choiceHint += if ($Default -gt 0) { "; Enter selects $Default." } else { "; no default. Empty input will ask again." }
  Write-Host "  $choiceHint" -ForegroundColor DarkGray
  while ($true) {
    $raw = (Read-Host "  Choice").Trim()
    if ([string]::IsNullOrWhiteSpace($raw) -and $Default -gt 0) { return $Default }
    if ($Values) {
      for ($i = 0; $i -lt $Values.Count; $i++) {
        if ($raw -eq $Values[$i]) { return ($i + 1) }
      }
    }
    $selected = 0
    if ([int]::TryParse($raw, [ref]$selected) -and $selected -ge 1 -and $selected -le $Options.Count) {
      return $selected
    }
    Write-Host "    $choiceHint" -ForegroundColor Red
  }
}

function Select-Connector {
  param([string]$RequestedConnector)
  if ($RequestedConnector) { return $RequestedConnector }
  if ($NonInteractive) { throw "Supply -Connector Sandbox or Feeds when using -NonInteractive." }
  $values = @("Sandbox", "Feeds")
  $selected = Read-Choice -Prompt "Choose the connector to install" -Default 0 -Values $values -Options @(
    "Sandbox - analyze Defender alerts with ANY.RUN Sandbox",
    "Feeds - import ANY.RUN TI indicators into Defender on a schedule"
  )
  if ($selected -eq 2) { return "Feeds" }
  return "Sandbox"
}

function Select-IndicatorAction {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("Sandbox", "Feeds")][string]$ConnectorType,
    [Parameter(Mandatory = $true)][string]$Requested,
    [bool]$WasPassed = $false,
    [AllowEmptyString()][string]$ExistingValue = ""
  )

  # An explicit parameter wins. Otherwise keep the value of an existing
  # installation, so an update does not silently reset the operator's choice.
  if ($WasPassed) { return $Requested }
  $allowed = if ($ConnectorType -eq "Sandbox") { @("Audit", "Block", "Disabled") } else { @("Audit", "Block") }
  $current = @($allowed | Where-Object { $_ -eq $ExistingValue }) | Select-Object -First 1
  if (-not $current) { $current = $Requested }
  if ($NonInteractive -or $ConnectorType -ne "Sandbox") { return $current }

  $selected = Read-Choice -Prompt "Indicator action for IOCs found by ANY.RUN" `
    -Default ([Array]::IndexOf($allowed, $current) + 1) -Values $allowed `
    -HelpText "Audit and Block create Microsoft Defender indicators that raise an alert on match. Option 3 keeps IOCs only in the alert comments and the ANY.RUN report." `
    -Options @(
      "Audit - import IOCs; Defender raises an alert on match",
      "Block - import IOCs and block them",
      "Do not import IOCs - keep them only in alert comments"
    )
  return $allowed[$selected - 1]
}

function Confirm-Action {
  param([Parameter(Mandatory = $true)][string]$Prompt, [bool]$Default = $true)
  if ($NonInteractive) { return $Default }
  $hint = if ($Default) { "Y/n" } else { "y/N" }
  $defaultAnswer = if ($Default) { "Yes" } else { "No" }
  Write-Host "  Enter Y (yes) or N (no); Enter selects $defaultAnswer." -ForegroundColor DarkGray
  while ($true) {
    $answer = (Read-Host "$Prompt [$hint]").Trim().ToLowerInvariant()
    if (-not $answer) { return $Default }
    if ($answer -in @("y", "yes")) { return $true }
    if ($answer -in @("n", "no")) { return $false }
    Write-Host "    Enter Y (yes) or N (no)." -ForegroundColor Red
  }
}

function Assert-GuidValue {
  param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][string]$Name)
  $parsed = [Guid]::Empty
  if (-not [Guid]::TryParseExact($Value, "D", [ref]$parsed)) {
    throw "$Name must be a canonical GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
  }
  return $parsed.ToString("D")
}

function Resolve-RepositoryCommit {
  param([Parameter(Mandatory = $true)][string]$RepositoryName, [Parameter(Mandatory = $true)][string]$Ref)

  if ($Ref -match '^[0-9a-fA-F]{40}$') { return $Ref.ToLowerInvariant() }
  if ($Ref.Contains('..') -or $Ref.StartsWith('/') -or $Ref.EndsWith('/')) {
    throw "RepositoryRef '$Ref' is not a safe Git reference."
  }

  $encodedRef = [Uri]::EscapeDataString($Ref)
  Write-Step "Resolving repository ref '$Ref' to an immutable commit..."
  try {
    $commit = Invoke-RestMethod -Method GET -Uri "https://api.github.com/repos/$RepositoryName/commits/$encodedRef" `
      -Headers @{ Accept = "application/vnd.github+json"; "User-Agent" = "ANYRUN-MDE-Installer" }
  } catch {
    throw "Could not resolve repository ref '$Ref' in '$RepositoryName': $($_.Exception.Message)"
  }
  $sha = "$($commit.sha)"
  if ($sha -notmatch '^[0-9a-fA-F]{40}$') { throw "GitHub returned an invalid commit SHA for '$Ref'." }
  Write-Host "  Resolved artifact commit: $sha" -ForegroundColor Green
  return $sha.ToLowerInvariant()
}

function Get-VerifiedRemoteFile {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $parsedUri = [Uri]$Uri
  if ($parsedUri.Scheme -ne 'https' -or $parsedUri.Host -ne 'raw.githubusercontent.com') {
    throw "$Label URI must use https://raw.githubusercontent.com. Received '$Uri'."
  }
  Invoke-WebRequest -Uri $Uri -OutFile $Destination
  $actualHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne $ExpectedSha256.ToLowerInvariant()) {
    throw "$Label SHA-256 mismatch. Expected $ExpectedSha256 but downloaded $actualHash."
  }
  Write-Host "  Verified $Label SHA-256 ($actualHash)." -ForegroundColor Green
}

function Show-ResourceGroupWriteAccess {
  param([Parameter(Mandatory = $true)][string]$Scope)
  Write-Step "Reviewing privileged write access to the connector resource group..."
  $assignments = @(Get-AzRoleAssignment -Scope $Scope -ErrorAction SilentlyContinue | Where-Object {
    $_.RoleDefinitionName -in @('Owner', 'Contributor', 'Website Contributor', 'User Access Administrator')
  })
  if ($assignments.Count -eq 0) {
    Write-Host "  No built-in broad write assignments were returned. Custom roles and group membership still require review." -ForegroundColor Yellow
    return
  }
  Write-Host "  Treat this resource group as privileged: Function settings contain Defender workload credentials." -ForegroundColor Yellow
}

function Read-RequiredSecret {
  param([Parameter(Mandatory = $true)][string]$Prompt, [string]$HelpText)
  if ($NonInteractive) { throw "Non-interactive deployment requires the secret parameter for: $Prompt" }
  if ($HelpText) { Write-Host "  $HelpText" -ForegroundColor Gray }
  Write-Host "  Paste the value only. Input is masked; a non-empty value is required." -ForegroundColor DarkGray
  while ($true) {
    $secret = Read-Host $Prompt -AsSecureString
    if ($secret -and $secret.Length -gt 0) { return $secret }
    Write-Host "    A non-empty value is required." -ForegroundColor Red
  }
}

function ConvertTo-SecureValue {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
  $secureValue = [SecureString]::new()
  foreach ($character in $Value.ToCharArray()) { $secureValue.AppendChar($character) }
  $secureValue.MakeReadOnly()
  return $secureValue
}

function ConvertFrom-SecureValue {
  param([Parameter(Mandatory = $true)][SecureString]$Value)
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
  }
}

function ConvertTo-PowerShellLiteral {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
  $escapedValue = $Value.Replace("'", "''")
  return "'$escapedValue'"
}

function Get-ModuleInstallationRoot {
  param([Parameter(Mandatory = $true)]$ModuleInfo)
  return (Split-Path -Parent (Split-Path -Parent $ModuleInfo.ModuleBase))
}

function Assert-ModuleCommands {
  param(
    [Parameter(Mandatory = $true)][string]$ModuleName,
    [string[]]$RequiredCommands = @()
  )
  $missingCommands = @($RequiredCommands | Where-Object {
    -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
  })
  if ($missingCommands.Count -gt 0) {
    throw "PowerShell module '$ModuleName' is loaded but does not provide required commands: $($missingCommands -join ', '). Open a fresh Cloud Shell session after updating its module bundle."
  }
}

function Ensure-Module {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][Version]$MinimumVersion,
    [string[]]$RequiredCommands = @()
  )

  # Azure Cloud Shell preloads a mutually compatible Az module bundle. Importing
  # a newer CurrentUser submodule into that process can load a second private
  # assembly (for example Az.Authorization.private) and fail. Once a module
  # family is loaded, always select siblings from the same installation root.
  $anchorName = if ($Name -like "Az.*") {
    "Az.Accounts"
  } elseif ($Name -like "Microsoft.Graph.*") {
    "Microsoft.Graph.Authentication"
  } else {
    $null
  }
  $anchor = if ($anchorName) {
    Get-Module -Name $anchorName | Sort-Object Version -Descending | Select-Object -First 1
  } else {
    $null
  }
  $anchorRoot = if ($anchor) { Get-ModuleInstallationRoot -ModuleInfo $anchor } else { $null }

  $loaded = Get-Module -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
  if ($loaded) {
    if ($anchorRoot -and (Get-ModuleInstallationRoot -ModuleInfo $loaded) -ne $anchorRoot) {
      # Cloud Shell can preload a CurrentUser submodule alongside its system
      # Az.Accounts module. If PowerShell has already loaded both successfully,
      # do not attempt to replace either one in-process. Validate the cmdlets
      # below and continue with the established session instead.
      Write-Host "  WARNING: $Name $($loaded.Version) is already loaded from a different module bundle; retaining the loaded module and validating required commands." -ForegroundColor Yellow
    }
    if ($loaded.Version -lt $MinimumVersion) {
      Write-Host "  Using Cloud Shell's bundled $Name $($loaded.Version) (validated by required-command checks; tested version is $MinimumVersion)." -ForegroundColor Yellow
    }
    Assert-ModuleCommands -ModuleName $Name -RequiredCommands $RequiredCommands
    return
  }

  $available = @(Get-Module -ListAvailable -Name $Name)
  $selected = if ($anchorRoot) {
    $available | Where-Object {
      (Get-ModuleInstallationRoot -ModuleInfo $_) -eq $anchorRoot
    } | Sort-Object Version -Descending | Select-Object -First 1
  } else {
    $available | Where-Object Version -ge $MinimumVersion |
      Sort-Object Version -Descending | Select-Object -First 1
  }

  if (-not $selected -and $anchorRoot -and $Name -like "Microsoft.Graph.*") {
    Write-Host "  Installing PowerShell module '$Name' $($anchor.Version) to match the loaded Graph module bundle..." -ForegroundColor Yellow
    Install-Module -Name $Name -RequiredVersion $anchor.Version -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    $selected = Get-Module -ListAvailable -Name $Name | Where-Object {
      (Get-ModuleInstallationRoot -ModuleInfo $_) -eq $anchorRoot -and $_.Version -eq $anchor.Version
    } | Select-Object -First 1
  }
  if (-not $selected -and $anchorRoot) {
    throw "PowerShell module '$Name' is not present in the currently loaded '$anchorName' bundle. Restart Cloud Shell before changing Az/Graph module versions; mixing module bundles in one process is unsafe."
  }
  if (-not $selected) {
    Write-Host "  Installing PowerShell module '$Name' (minimum $MinimumVersion) for the current user..." -ForegroundColor Yellow
    Install-Module -Name $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    $selected = Get-Module -ListAvailable -Name $Name |
      Where-Object Version -ge $MinimumVersion |
      Sort-Object Version -Descending |
      Select-Object -First 1
  }
  if (-not $selected) { throw "PowerShell module '$Name' could not be located after installation." }
  if ($selected.Version -lt $MinimumVersion) {
    Write-Host "  Using Cloud Shell's bundled $Name $($selected.Version) (validated by required-command checks; tested version is $MinimumVersion)." -ForegroundColor Yellow
  }
  Import-Module -FullyQualifiedName @{ ModuleName = $Name; RequiredVersion = $selected.Version } -ErrorAction Stop
  Assert-ModuleCommands -ModuleName $Name -RequiredCommands $RequiredCommands
}

function ConvertFrom-AzRestContent {
  param([Parameter(Mandatory = $true)]$Response)
  if ([string]::IsNullOrWhiteSpace($Response.Content)) { return $null }
  return $Response.Content | ConvertFrom-Json
}

function Invoke-AzRestJson {
  param(
    [Parameter(Mandatory = $true)][string]$Method,
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Payload,
    [int[]]$AllowedStatusCodes = @()
  )

  # Invoke-AzRestMethod does not throw on HTTP errors. Report the real status
  # instead of a later StrictMode "property cannot be found" error.
  $arguments = @{ Method = $Method; Path = $Path }
  if ($PSBoundParameters.ContainsKey("Payload")) { $arguments.Payload = $Payload }
  $response = Invoke-AzRestMethod @arguments
  $status = [int]$response.StatusCode
  if ($AllowedStatusCodes -contains $status) { return $null }
  if ($status -lt 200 -or $status -ge 300) {
    $detail = "$($response.Content)"
    if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
    throw "Azure request $Method $($Path.Split('?')[0]) returned HTTP $status. $detail"
  }
  return ConvertFrom-AzRestContent -Response $response
}

function Get-ObjectPropertyValue {
  param([Parameter(Mandatory = $true)]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
  $property = $InputObject.PSObject.Properties[$Name]
  if ($property) { return $property.Value }
  return $null
}

function Ensure-ResourceProvider {
  param([Parameter(Mandatory = $true)][string]$ProviderNamespace)

  $provider = Get-AzResourceProvider -ProviderNamespace $ProviderNamespace -ErrorAction SilentlyContinue
  if ($provider -and $provider.RegistrationState -eq "Registered") {
    Write-Host "  = $ProviderNamespace is registered." -ForegroundColor DarkGray
    return
  }

  Write-Step "Registering Azure resource provider '$ProviderNamespace'..."
  Register-AzResourceProvider -ProviderNamespace $ProviderNamespace | Out-Null
  for ($attempt = 1; $attempt -le 30; $attempt++) {
    $provider = Get-AzResourceProvider -ProviderNamespace $ProviderNamespace -ErrorAction SilentlyContinue
    if ($provider -and $provider.RegistrationState -eq "Registered") { return }
    if ($attempt -lt 30) { Start-Sleep -Seconds 10 }
  }
  throw "Azure resource provider '$ProviderNamespace' did not reach Registered state within five minutes."
}

function Test-EffectiveRoleAssignmentPermission {
  param([Parameter(Mandatory = $true)][string]$Scope)

  $path = "$Scope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
  $response = Invoke-AzRestJson -Method GET -Path $path
  $target = "Microsoft.Authorization/roleAssignments/write"
  foreach ($permission in @($response.value)) {
    $allowed = @($permission.actions | Where-Object { $target -like $_ }).Count -gt 0
    $denied = @($permission.notActions | Where-Object { $target -like $_ }).Count -gt 0
    if ($allowed -and -not $denied) { return $true }
  }
  return $false
}

function Assert-FlexConsumptionRegion {
  param([Parameter(Mandatory = $true)][string]$Location)

  Ensure-Module "Az.Functions" -MinimumVersion "5.0.1" -RequiredCommands @("Get-AzFunctionAppAvailableLocation")
  $locations = @(Get-AzFunctionAppAvailableLocation -PlanType FlexConsumption -SubscriptionId $SubscriptionId)
  $requested = $Location.Replace(" ", "").ToLowerInvariant()
  $match = $locations | Where-Object {
    $_.Name.Replace(" ", "").ToLowerInvariant() -eq $requested
  } | Select-Object -First 1
  if (-not $match) {
    throw "Azure Functions Flex Consumption is not available in region '$Location'. Choose a supported region returned by Get-AzFunctionAppAvailableLocation -PlanType FlexConsumption."
  }
  Write-Host "  Flex Consumption is available in '$Location'." -ForegroundColor Green
}

function Assert-FunctionAppNameAvailable {
  param([Parameter(Mandatory = $true)][string]$Name)

  $existing = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Web/sites" -Name $Name -ErrorAction SilentlyContinue
  if ($existing) { return }

  $body = @{ name = $Name; type = "Microsoft.Web/sites"; isFqdn = $false } | ConvertTo-Json -Compress
  $path = "/subscriptions/$SubscriptionId/providers/Microsoft.Web/checknameavailability?api-version=2024-04-01"
  $result = Invoke-AzRestJson -Method POST -Path $path -Payload $body
  if (-not (Get-ObjectPropertyValue -InputObject $result -Name "nameAvailable")) {
    throw "Function App name '$Name' is unavailable: $($result.message)"
  }
}

function Assert-StorageAccountUsable {
  param([Parameter(Mandatory = $true)][string]$Name)

  if ($Name -notmatch '^[a-z0-9]{3,24}$') {
    throw "Storage account name '$Name' must contain 3-24 lowercase letters or numbers."
  }
  $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $Name -ErrorAction SilentlyContinue
  if ($account) {
    $allowSharedKeyAccess = Get-ObjectPropertyValue -InputObject $account -Name "AllowSharedKeyAccess"
    if ($allowSharedKeyAccess -eq $false) {
      throw "Storage account '$Name' has AllowSharedKeyAccess=false. The current connector runtime uses account keys and cannot use this account."
    }
    return
  }
  $availability = Get-AzStorageAccountNameAvailability -Name $Name
  if (-not $availability.NameAvailable) {
    throw "Storage account name '$Name' is unavailable: $($availability.Message)"
  }
}

function Get-ExistingFunctionConfiguration {
  param([Parameter(Mandatory = $true)][string]$FunctionAppName)

  $site = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Web/sites" -Name $FunctionAppName -ErrorAction SilentlyContinue
  if (-not $site) { return $null }
  $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$FunctionAppName/config/appsettings/list?api-version=2024-04-01"
  return Invoke-AzRestJson -Method POST -Path $path -Payload "{}"
}

function Connect-AzureSmart {
  param([string]$RequestedTenantId, [string]$RequestedSubscriptionId)

  $context = Get-AzContext -ErrorAction SilentlyContinue
  $needsLogin = -not $context
  if ($context -and $RequestedTenantId -and $context.Tenant.Id -ne $RequestedTenantId) { $needsLogin = $true }

  if ($needsLogin) {
    Write-Step "Signing in to Azure..."
    Write-Host "  Follow the Azure sign-in instructions with the account and directory for this deployment." -ForegroundColor Gray
    if ($RequestedTenantId) { Connect-AzAccount -Tenant $RequestedTenantId | Out-Null }
    else                    { Connect-AzAccount | Out-Null }
  }

  $context = Get-AzContext
  $effectiveTenantId = if ($RequestedTenantId) { $RequestedTenantId } else { $context.Tenant.Id }

  if ($RequestedSubscriptionId) {
    Set-AzContext -TenantId $effectiveTenantId -SubscriptionId $RequestedSubscriptionId | Out-Null
    return Get-AzContext
  }

  $subscriptions = @(Get-AzSubscription -TenantId $effectiveTenantId | Where-Object State -eq "Enabled" | Sort-Object Name)
  if ($subscriptions.Count -eq 0) { throw "No enabled Azure subscriptions are available in tenant '$effectiveTenantId'." }

  if ($subscriptions.Count -eq 1) {
    Set-AzContext -TenantId $effectiveTenantId -SubscriptionId $subscriptions[0].Id | Out-Null
    return Get-AzContext
  }

  $current = Get-AzContext
  $currentSubscriptionId = if ($current -and $current.Subscription) { $current.Subscription.Id } else { $null }
  if ($NonInteractive) {
    throw "Multiple enabled subscriptions are available. Supply -SubscriptionId for a non-interactive deployment."
  }
  Write-Host ""
  Write-Host "  Available subscriptions:" -ForegroundColor White
  Write-Host "  Choose where to deploy the Azure resources. Enter a list number; there is no default." -ForegroundColor Gray
  for ($i = 0; $i -lt $subscriptions.Count; $i++) {
    $currentMarker = if ($currentSubscriptionId -and $subscriptions[$i].Id -eq $currentSubscriptionId) { " (current)" } else { "" }
    Write-Host "    [$($i + 1)] $($subscriptions[$i].Name) ($($subscriptions[$i].Id))$currentMarker"
  }
  while ($true) {
    $raw = Read-Host "  Subscription number"
    $selected = 0
    if ([int]::TryParse($raw, [ref]$selected) -and $selected -ge 1 -and $selected -le $subscriptions.Count) { break }
    Write-Host "    Enter a number from 1 to $($subscriptions.Count)." -ForegroundColor Red
  }
  Set-AzContext -TenantId $effectiveTenantId -SubscriptionId $subscriptions[$selected - 1].Id | Out-Null
  return Get-AzContext
}

function Connect-GraphSmart {
  param([Parameter(Mandatory = $true)][string]$RequestedTenantId)

  $requiredScopes = @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All")
  $context = Get-MgContext -ErrorAction SilentlyContinue
  $reuse = $false
  if ($context -and $context.TenantId -eq $RequestedTenantId) {
    # Access-token contexts do not always expose Scopes. In that case validate
    # the session with a real Graph request, as the VMRay installer does.
    $contextScopes = @($context.Scopes)
    $missingScopes = if ($contextScopes.Count -gt 0) {
      @($requiredScopes | Where-Object { $contextScopes -notcontains $_ })
    } else {
      @()
    }
    if ($missingScopes.Count -eq 0 -and -not $ForceGraphDeviceCode) {
      try {
        Get-MgApplication -Top 1 -ErrorAction Stop | Out-Null
        $reuse = $true
      } catch { $reuse = $false }
    }
  }

  if ($reuse) {
    Write-Host "  Reusing Microsoft Graph session." -ForegroundColor Green
    return
  }

  if ($context) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }

  if (-not $ForceGraphDeviceCode) {
    $azureContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($azureContext -and $azureContext.Tenant.Id -eq $RequestedTenantId) {
      try {
        Write-Step "Reusing the Azure session for Microsoft Graph..."
        $tokenResult = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        $graphToken = if ($tokenResult.Token -is [SecureString]) {
          $tokenResult.Token
        } else {
          ConvertTo-SecureValue -Value $tokenResult.Token
        }
        Connect-MgGraph -AccessToken $graphToken -NoWelcome -ErrorAction Stop | Out-Null
        $script:GraphSessionOwned = $true
        Get-MgApplication -Top 1 -ErrorAction Stop | Out-Null
        Write-Host "  Connected to Microsoft Graph through the existing Azure session." -ForegroundColor Green
        return
      } catch {
        Write-Host "  Azure-session Graph authentication was unavailable: $($_.Exception.Message)" -ForegroundColor Yellow
      }
    }
  }

  Write-Step "Signing in to Microsoft Graph with application-management scopes..."
  Write-Host "  Open https://microsoft.com/devicelogin and enter the device code shown below." -ForegroundColor Yellow
  # Browser-based Connect-MgGraph can wait indefinitely in Azure Cloud Shell.
  # Device code is the reliable fallback when the Azure token cannot be reused.
  Connect-MgGraph -TenantId $RequestedTenantId -Scopes $requiredScopes -UseDeviceCode -NoWelcome | Out-Null
  $script:GraphSessionOwned = $true
}

function Get-StableSuffix {
  param([Parameter(Mandatory = $true)][string]$InputText, [int]$Length = 8)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
    $hex = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
    return $hex.Substring(0, $Length)
  } finally {
    $sha.Dispose()
  }
}

function Get-AzureAppNameHash {
  param(
    [Parameter(Mandatory = $true)][string]$ResourceGroupName,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9]{1,12}$', Options = 'None')][string]$InstanceName
  )

  # Evaluate the same ARM expression as Azure App 1.1.3. This incremental
  # deployment contains no resources and never handles connector credentials.
  $template = @{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters = @{ instanceName = @{ type = 'string' } }
    resources = @()
    outputs = @{ nameHash = @{ type = 'string'; value = "[take(uniqueString(resourceGroup().id, parameters('instanceName')), 6)]" } }
  }
  $maxAttempts = 3
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
      Write-Step "Evaluating Azure resource names (attempt $attempt/$maxAttempts)..."
      $deployment = New-AzResourceGroupDeployment -Name "ANYRUN-MDE-Names-$InstanceName" `
        -ResourceGroupName $ResourceGroupName -Mode Incremental -TemplateObject $template `
        -TemplateParameterObject @{ instanceName = $InstanceName } -ErrorAction Stop
      break
    } catch {
      $details = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
      $message = "$($_.Exception.Message) $details"
      $retryable = $message -match '(?i)HttpClient\.Timeout|timed out|timeout|DeploymentActive'
      if (-not $retryable) { throw }
      if ($attempt -eq $maxAttempts) {
        throw "Azure resource-name evaluation did not complete after $maxAttempts attempts. Re-run with the same resource group and instance name. No connector identity or Function/Logic App has been created by this step. Azure error: $message"
      }
      Write-Host "  Azure resource-name evaluation timed out or is still active; retrying the same empty deployment in 10 seconds. Resource names stay unchanged." -ForegroundColor Yellow
      Start-Sleep -Seconds 10
    }
  }
  if ($deployment.ProvisioningState -ne 'Succeeded') {
    throw "Resource naming evaluation failed: $($deployment.ProvisioningState)."
  }
  $hash = [string]$deployment.Outputs['nameHash'].Value
  if ($hash -cnotmatch '^[a-z2-7]{6}$') { throw 'ARM returned an invalid resource-name hash.' }
  return $hash
}

function Get-ConnectorDefaultNames {
  param(
    [Parameter(Mandatory = $true)][ValidateSet('Sandbox', 'Feeds')][string]$ConnectorType,
    [AllowEmptyString()][ValidatePattern('^[a-z0-9]{0,12}$', Options = 'None')][string]$InstanceName,
    [string]$NameHash,
    [string]$LegacySuffix
  )

  if ([string]::IsNullOrEmpty($InstanceName)) {
    if ($LegacySuffix -cnotmatch '^[a-f0-9]{8}$') { throw 'Legacy naming requires the original installer suffix.' }
    return @{
      SandboxFunctionName = "anyrun-sandbox-mde-$LegacySuffix"
      SandboxLogicAppName = "ANYRUN-Sandbox-MDE-LA-$LegacySuffix"
      SandboxStorageAccountName = "arsb$LegacySuffix"
      FeedsFunctionName = "anyrun-feeds-mde-$LegacySuffix"
      FeedsLogicAppName = "ANYRUN-Feeds-MDE-LA-$LegacySuffix"
      FeedsStorageAccountName = "arfd$LegacySuffix"
      LogAnalyticsWorkspaceName = "anyrun-mde-law-$LegacySuffix"
    }
  }
  if ($NameHash -cnotmatch '^[a-z2-7]{6}$') { throw 'Instance naming requires the six-character ARM hash.' }
  $sandboxBase = "ANYRUN-Sandbox-MDE-$InstanceName"
  $feedsBase = "ANYRUN-Feeds-MDE-$InstanceName"
  $workspaceBase = switch ($ConnectorType) {
    Sandbox { $sandboxBase }
    Feeds { $feedsBase }
  }
  $sandboxStorage = "anyrunsb$NameHash$InstanceName"
  $feedsStorage = "anyrunfeeds$NameHash$InstanceName"
  return @{
    SandboxFunctionName = "$sandboxBase-$NameHash-FA"
    SandboxLogicAppName = "$sandboxBase-LA"
    SandboxStorageAccountName = $sandboxStorage.Substring(0, [Math]::Min(24, $sandboxStorage.Length))
    FeedsFunctionName = "$feedsBase-$NameHash-FA"
    FeedsLogicAppName = "$feedsBase-LA"
    FeedsStorageAccountName = $feedsStorage.Substring(0, [Math]::Min(24, $feedsStorage.Length))
    LogAnalyticsWorkspaceName = "$workspaceBase-LAW"
  }
}

function Select-ExistingResourceName {
  param(
    [Parameter(Mandatory = $true)][string]$PreferredName,
    [Parameter(Mandatory = $true)][string]$ResourceType,
    [string[]]$PreviousNames = @(),
    [object[]]$Resources = @()
  )

  if (-not $Resources) { return $PreferredName }
  foreach ($candidate in (@($PreferredName) + $PreviousNames)) {
    $existing = @($Resources | Where-Object { $_.ResourceType -eq $ResourceType -and $_.Name -eq $candidate })
    if ($existing.Count -gt 0) { return [string]$existing[0].Name }
  }
  return $PreferredName
}

function Get-ArmGuid {
  param([Parameter(Mandatory = $true)][string[]]$Values)

  # ARM guid() is RFC 4122 v5 with this fixed namespace and '-' joined arguments.
  $namespace = [Guid]"11fb06fb-712d-4ddd-98c7-e71bbd588830"
  $namespaceBytes = $namespace.ToByteArray()
  [Array]::Reverse($namespaceBytes, 0, 4)
  [Array]::Reverse($namespaceBytes, 4, 2)
  [Array]::Reverse($namespaceBytes, 6, 2)
  $nameBytes = [Text.Encoding]::UTF8.GetBytes(($Values -join '-'))
  $inputBytes = [byte[]]::new($namespaceBytes.Length + $nameBytes.Length)
  [Array]::Copy($namespaceBytes, 0, $inputBytes, 0, $namespaceBytes.Length)
  [Array]::Copy($nameBytes, 0, $inputBytes, $namespaceBytes.Length, $nameBytes.Length)
  $sha1 = [Security.Cryptography.SHA1]::Create()
  try { $hash = $sha1.ComputeHash($inputBytes) } finally { $sha1.Dispose() }
  $guidBytes = [byte[]]$hash[0..15]
  $guidBytes[6] = [byte](($guidBytes[6] -band 0x0f) -bor 0x50)
  $guidBytes[8] = [byte](($guidBytes[8] -band 0x3f) -bor 0x80)
  [Array]::Reverse($guidBytes, 0, 4)
  [Array]::Reverse($guidBytes, 4, 2)
  [Array]::Reverse($guidBytes, 6, 2)
  return ([Guid]::new($guidBytes)).ToString('D')
}

function Get-ResourceServicePrincipal {
  param([Parameter(Mandatory = $true)][string]$ResourceAppId, [string]$FriendlyName)
  $sp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -Property Id,AppId,DisplayName,AppRoles | Select-Object -First 1
  if (-not $sp) {
    Write-Host "  Creating the '$FriendlyName' service principal in this tenant..." -ForegroundColor Yellow
    $sp = New-MgServicePrincipal -AppId $ResourceAppId
    $sp = Get-MgServicePrincipal -ServicePrincipalId $sp.Id -Property Id,AppId,DisplayName,AppRoles
  }
  return $sp
}

function Get-OrCreateClientServicePrincipal {
  param([Parameter(Mandatory = $true)][string]$ApplicationId)

  for ($attempt = 1; $attempt -le 6; $attempt++) {
    $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$ApplicationId'" -Property Id,AppId -ErrorAction SilentlyContinue |
      Select-Object -First 1
    if ($servicePrincipal) { return $servicePrincipal }

    try {
      return New-MgServicePrincipal -AppId $ApplicationId
    } catch {
      if ($attempt -eq 6) { throw }
      Write-Host "  App Registration is still replicating; retrying service-principal creation in 5 seconds..." -ForegroundColor DarkGray
      Start-Sleep -Seconds 5
    }
  }
}

function Resolve-AppRoles {
  param(
    [Parameter(Mandatory = $true)]$ResourceServicePrincipal,
    [Parameter(Mandatory = $true)][string[]]$RoleValues
  )

  $resolved = @()
  foreach ($value in $RoleValues) {
    $role = $ResourceServicePrincipal.AppRoles |
      Where-Object { $_.Value -eq $value -and $_.IsEnabled } |
      Select-Object -First 1
    if (-not $role) { throw "WindowsDefenderATP application permission '$value' was not found in this tenant." }
    $resolved += [pscustomobject]@{ Value = $value; Id = $role.Id }
  }
  return $resolved
}

function Merge-RequiredResourceAccess {
  param(
    [Parameter(Mandatory = $true)]$Application,
    [Parameter(Mandatory = $true)]$ResolvedRoles
  )

  $merged = @()
  foreach ($entry in @($Application.RequiredResourceAccess)) {
    if ($entry.ResourceAppId -eq $script:WindowsDefenderAtpAppId) {
      continue
    }

    $preservedAccess = @($entry.ResourceAccess | ForEach-Object { @{ Id = $_.Id; Type = $_.Type } })
    $merged += @{ ResourceAppId = $entry.ResourceAppId; ResourceAccess = $preservedAccess }
  }

  $merged += @{
    ResourceAppId = $script:WindowsDefenderAtpAppId
    ResourceAccess = @($ResolvedRoles | ForEach-Object { @{ Id = $_.Id; Type = "Role" } })
  }
  return $merged
}

function Test-AppRoleConsent {
  param([string]$ClientServicePrincipalId, $RequiredRoles)
  $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipalId -All -ErrorAction SilentlyContinue)
  $granted = @($assignments | ForEach-Object { $_.AppRoleId.ToString() })
  foreach ($role in $RequiredRoles) {
    if ($granted -notcontains $role.Id.ToString()) { return $false }
  }
  return $true
}

function Grant-AppRoleConsent {
  param(
    [string]$ClientServicePrincipalId,
    [string]$ResourceServicePrincipalId,
    $RequiredRoles
  )

  $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipalId -All -ErrorAction SilentlyContinue)
  $granted = @($assignments | ForEach-Object { $_.AppRoleId.ToString() })
  $allSucceeded = $true

  foreach ($role in $RequiredRoles) {
    if ($granted -contains $role.Id.ToString()) {
      Write-Host "    = $($role.Value) (already granted)" -ForegroundColor DarkGray
      continue
    }
    try {
      $body = @{
        principalId = $ClientServicePrincipalId
        resourceId  = $ResourceServicePrincipalId
        appRoleId   = $role.Id
      }
      New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipalId -BodyParameter $body | Out-Null
      Write-Host "    + $($role.Value)" -ForegroundColor Green
    } catch {
      Write-Host "    ! $($role.Value): $($_.Exception.Message)" -ForegroundColor Yellow
      $allSucceeded = $false
      if ("$($_.Exception.Message)" -match '403|Authorization_RequestDenied|Insufficient privileges') {
        Write-Host "    Remaining permissions were not attempted because this account cannot grant admin consent." -ForegroundColor Yellow
        break
      }
    }
  }
  return $allSucceeded
}

function Remove-ExcessDefenderConsent {
  param(
    [Parameter(Mandatory = $true)][string]$ClientServicePrincipalId,
    [Parameter(Mandatory = $true)][string]$ResourceServicePrincipalId,
    [Parameter(Mandatory = $true)]$RequiredRoles
  )

  $requiredIds = @($RequiredRoles | ForEach-Object { $_.Id.ToString() })
  $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipalId -All)
  foreach ($assignment in $assignments) {
    if ($assignment.ResourceId.ToString() -ne $ResourceServicePrincipalId) { continue }
    if ($requiredIds -contains $assignment.AppRoleId.ToString()) { continue }
    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipalId `
      -AppRoleAssignmentId $assignment.Id -Confirm:$false
    Write-Host "    - Removed unused WindowsDefenderATP permission assignment $($assignment.AppRoleId)." -ForegroundColor DarkGray
  }
}

function Wait-ForConsent {
  param([string]$ClientServicePrincipalId, $RequiredRoles, [int]$Attempts = 6)
  for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    if (Test-AppRoleConsent -ClientServicePrincipalId $ClientServicePrincipalId -RequiredRoles $RequiredRoles) { return $true }
    if ($attempt -lt $Attempts) {
      Write-Host "  Consent is still propagating ($attempt/$Attempts); waiting 15 seconds..." -ForegroundColor DarkGray
      Start-Sleep -Seconds 15
    }
  }
  return $false
}

function New-ConnectorSecret {
  param([Parameter(Mandatory = $true)]$Application, [string]$Label)
  $passwordCredential = @{
    DisplayName = "ANY.RUN $Label deployment secret $(Get-Date -Format 'yyyy-MM-dd')"
    EndDateTime = (Get-Date).AddMonths($SecretLifetimeMonths)
  }
  $result = Add-MgApplicationPassword -ApplicationId $Application.Id -BodyParameter @{ PasswordCredential = $passwordCredential }
  Write-Host "  Created a client secret expiring $($result.EndDateTime.ToString('yyyy-MM-dd'))." -ForegroundColor Green
  return [pscustomobject]@{
    Secret = ConvertTo-SecureValue -Value $result.SecretText
    KeyId  = $result.KeyId
  }
}

function Test-DefenderCredential {
  param(
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][SecureString]$ClientSecret,
    [Parameter(Mandatory = $true)][string[]]$RequiredRoleValues,
    [Parameter(Mandatory = $true)][string]$Label
  )

  Write-Step "Validating the $Label client secret and effective Defender permissions..."
  $plainSecret = ConvertFrom-SecureValue -Value $ClientSecret
  $lastFailure = $null
  try {
    for ($attempt = 1; $attempt -le 5; $attempt++) {
      $token = $null
      try {
        $token = Invoke-RestMethod -Method POST `
          -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            client_id     = $ClientId
            client_secret = $plainSecret
            grant_type    = "client_credentials"
            scope         = "https://api.securitycenter.microsoft.com/.default"
          }
      } catch {
        $lastFailure = "$($_.Exception.Message)"
      }

      if ($token) {
        $payloadPart = $token.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($payloadPart.Length % 4) {
          2 { $payloadPart += "==" }
          3 { $payloadPart += "=" }
        }
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadPart)) | ConvertFrom-Json
        $tokenRoles = @(Get-ObjectPropertyValue -InputObject $claims -Name "roles")
        $missingRoles = @($RequiredRoleValues | Where-Object { $tokenRoles -notcontains $_ })
        if ($missingRoles.Count -eq 0) {
          Write-Host "  $Label credentials and Defender roles are valid." -ForegroundColor Green
          return
        }
        $lastFailure = "token is missing required Defender roles: $($missingRoles -join ', ')"
      }

      if ($attempt -lt 5) {
        $delaySeconds = 10 * $attempt
        Write-Host "  Defender credential or roles are still propagating ($attempt/5); waiting $delaySeconds seconds..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $delaySeconds
      }
    }
  } finally {
    $plainSecret = $null
  }
  throw "$Label credential validation failed after five attempts: $lastFailure. If the stored secret is expired, re-run with -RotateClientSecret."
}

function Remove-OldConnectorSecrets {
  param(
    [Parameter(Mandatory = $true)][string]$ApplicationObjectId,
    [Parameter(Mandatory = $true)][Guid]$CurrentKeyId,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $application = Get-MgApplication -ApplicationId $ApplicationObjectId -Property PasswordCredentials
  $prefix = "ANY.RUN $Label deployment secret "
  foreach ($credential in @($application.PasswordCredentials)) {
    if ($credential.KeyId -eq $CurrentKeyId -or [string]::IsNullOrWhiteSpace($credential.DisplayName) -or -not $credential.DisplayName.StartsWith($prefix)) { continue }
    Remove-MgApplicationPassword -ApplicationId $ApplicationObjectId -KeyId $credential.KeyId -Confirm:$false
    Write-Host "  Removed superseded deployment secret '$($credential.DisplayName)'." -ForegroundColor DarkGray
  }
}

function Assert-DedicatedConnectorApplication {
  param(
    [Parameter(Mandatory = $true)]$Application,
    [Parameter(Mandatory = $true)]$ClientServicePrincipal,
    [Parameter(Mandatory = $true)]$DefenderServicePrincipal,
    [Parameter(Mandatory = $true)][string]$Label
  )

  Write-Host "  Existing App Registration: $($Application.DisplayName) ($($Application.AppId))" -ForegroundColor White
  $foreignRequiredAccess = @($Application.RequiredResourceAccess | Where-Object {
    $_.ResourceAppId -ne $script:WindowsDefenderAtpAppId -and @($_.ResourceAccess).Count -gt 0
  })
  if ($foreignRequiredAccess.Count -gt 0) {
    $resourceIds = @($foreignRequiredAccess | ForEach-Object ResourceAppId) -join ', '
    throw "The selected $Label App Registration declares permissions to other APIs ($resourceIds). Refusing to create or expose a client secret for a shared/privileged application."
  }

  $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipal.Id -All)
  $foreignAssignments = @($assignments | Where-Object {
    $_.ResourceId.ToString() -ne $DefenderServicePrincipal.Id.ToString()
  })
  if ($foreignAssignments.Count -gt 0) {
    $resourceIds = @($foreignAssignments | ForEach-Object { $_.ResourceId.ToString() } | Sort-Object -Unique) -join ', '
    throw "The selected $Label service principal has app-role assignments outside WindowsDefenderATP ($resourceIds). Use a dedicated App Registration."
  }

  $defenderRoleNames = @($assignments | Where-Object {
    $_.ResourceId.ToString() -eq $DefenderServicePrincipal.Id.ToString()
  } | ForEach-Object {
    $assignmentId = $_.AppRoleId.ToString()
    $role = $DefenderServicePrincipal.AppRoles | Where-Object { $_.Id.ToString() -eq $assignmentId } | Select-Object -First 1
    if ($role) { $role.Value } else { $assignmentId }
  })
  $displayRoles = if ($defenderRoleNames.Count) { $defenderRoleNames -join ', ' } else { '(none)' }
  Write-Host "  Current WindowsDefenderATP roles: $displayRoles" -ForegroundColor DarkGray
}

function Confirm-DefenderPermissionGrant {
  param([Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)]$Roles)

  Write-Host "  The installer is about to request tenant-wide application permissions for ${Label}:" -ForegroundColor Yellow
  foreach ($role in $Roles) { Write-Host "    - $($role.Value)" -ForegroundColor Yellow }
  if ($Label -eq 'Sandbox') {
    Write-Host "  Machine.LiveResponse and Library.Manage can execute connector scripts on managed endpoints." -ForegroundColor Yellow
  } else {
    Write-Host "  Ti.ReadWrite lets the dedicated Feeds application manage indicators it creates." -ForegroundColor Yellow
  }

  if ($ApproveDefenderPermissions) { return }
  if ($NonInteractive) {
    throw "Non-interactive consent requires -ApproveDefenderPermissions after reviewing the requested roles."
  }
  if (-not (Confirm-Action "  Grant these Defender application permissions?" $true)) {
    throw "Defender application-permission grant was not approved."
  }
}

function Ensure-ConnectorIdentity {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$DisplayName,
    [string]$ExistingAppId,
    [SecureString]$ExistingClientSecret,
    [Parameter(Mandatory = $true)][string[]]$RequiredRoleValues,
    [bool]$TrustedExistingFunctionBinding = $false,
    [switch]$RotateSecret
  )

  Write-Host ""
  Write-Host "  Configuring Entra identity for $Label..." -ForegroundColor White

  $wdatpSp = Get-ResourceServicePrincipal -ResourceAppId $script:WindowsDefenderAtpAppId -FriendlyName "WindowsDefenderATP"
  $roles = Resolve-AppRoles -ResourceServicePrincipal $wdatpSp -RoleValues $RequiredRoleValues

  $connectorKey = if ($Label -eq 'Sandbox') { 'sandbox' } else { 'feeds' }
  $installerTag = "$($script:InstallerTagPrefix):$connectorKey"
  $application = $null
  $created = $false
  $newCredentialKeyId = $null
  if ($ExistingAppId) {
    $ExistingAppId = Assert-GuidValue -Value $ExistingAppId -Name "$Label AppId"
    $application = Get-MgApplication -Filter "appId eq '$ExistingAppId'" -Property Id,AppId,DisplayName,RequiredResourceAccess,Tags | Select-Object -First 1
    if (-not $application) { throw "No App Registration with client ID '$ExistingAppId' was found." }
    if ($TrustedExistingFunctionBinding) {
      if (@($application.Tags) -notcontains $installerTag) {
        throw "The existing $Label Function App references unmarked App Registration '$($application.DisplayName)' ($ExistingAppId). Refusing to trust an identity controlled through Function settings. Re-run with the explicit AppId, client secret, and -ConfirmDedicatedAppRegistration after reviewing the application."
      }
      Write-Host "  Reusing the App Registration already bound to the existing $Label Function App." -ForegroundColor Green
    } else {
      Write-Host "  The supplied App Registration must be dedicated to the $Label connector; its WindowsDefenderATP permissions will be normalized." -ForegroundColor Yellow
      $dedicatedConfirmed = $ConfirmDedicatedAppRegistration -or (Confirm-Action "  Confirm that '$($application.DisplayName)' is dedicated to this connector" $false)
      if (-not $dedicatedConfirmed) {
        throw "A dedicated App Registration is required. Shared identities can cause TI Feeds to delete indicators created by other workloads."
      }
    }
  } else {
    $escapedName = $DisplayName.Replace("'", "''")
    $appMatches = @(Get-MgApplication -Filter "displayName eq '$escapedName'" -Property Id,AppId,DisplayName,RequiredResourceAccess,Tags)
    if ($appMatches.Count -gt 1) {
      throw "Multiple App Registrations named '$DisplayName' exist. Re-run with the appropriate AppId parameter."
    }
    if ($appMatches.Count -eq 1) {
      Write-Host "  Found existing App Registration '$DisplayName' ($($appMatches[0].AppId))." -ForegroundColor Yellow
      if ($NonInteractive -and -not $ConfirmDedicatedAppRegistration) {
        throw "Non-interactive reuse of an App Registration found by display name requires -ConfirmDedicatedAppRegistration or an explicit connector AppId."
      }
      if (Confirm-Action "  Reuse this App Registration for this connector?" $true) {
        $application = $appMatches[0]
        Write-Host "  Reuse is safe only when this App Registration is dedicated to the $Label connector." -ForegroundColor Yellow
        $dedicatedConfirmed = $ConfirmDedicatedAppRegistration -or (Confirm-Action "  Confirm this App Registration is used only by this connector" $false)
        if (-not $dedicatedConfirmed) {
          throw "A dedicated App Registration is required."
        }
      } else {
        $DisplayName = Read-Text -Prompt "New App Registration display name" -Default "$DisplayName-$(Get-Date -Format 'yyyyMMdd')" `
          -HelpText "Enter a new Entra App Registration display name, for example ANYRUN-Feeds-MDE-test-Connector."
      }
    }
  }

  if (-not $application) {
    Write-Step "Creating App Registration '$DisplayName'..."
    $application = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg" -Tags @($installerTag)
    $application = Get-MgApplication -ApplicationId $application.Id -Property Id,AppId,DisplayName,RequiredResourceAccess,Tags
    $created = $true
    Write-Host "  Created App Registration with client ID $($application.AppId)." -ForegroundColor Green
  }

  $appSp = Get-OrCreateClientServicePrincipal -ApplicationId $application.AppId

  if (-not $created) {
    Assert-DedicatedConnectorApplication -Application $application -ClientServicePrincipal $appSp `
      -DefenderServicePrincipal $wdatpSp -Label $Label
    if (@($application.Tags) -notcontains $installerTag) {
      if ($TrustedExistingFunctionBinding) { throw "Unmarked Function binding cannot be adopted implicitly." }
      $updatedTags = @(@($application.Tags) + @($installerTag)) | Sort-Object -Unique
      Update-MgApplication -ApplicationId $application.Id -Tags $updatedTags
      Write-Host "  Added installer ownership marker '$installerTag'." -ForegroundColor Green
    }
  }

  Write-Step "Ensuring WindowsDefenderATP application permissions..."
  $requiredResourceAccess = Merge-RequiredResourceAccess -Application $application -ResolvedRoles $roles
  Update-MgApplication -ApplicationId $application.Id -RequiredResourceAccess $requiredResourceAccess

  Write-Step "Granting tenant-wide admin consent when permitted..."
  $consentDeferred = $false
  if (Test-AppRoleConsent -ClientServicePrincipalId $appSp.Id -RequiredRoles $roles) {
    Write-Host "  All required application permissions are already granted." -ForegroundColor Green
  } else {
    Confirm-DefenderPermissionGrant -Label $Label -Roles $roles
    $granted = Grant-AppRoleConsent -ClientServicePrincipalId $appSp.Id -ResourceServicePrincipalId $wdatpSp.Id -RequiredRoles $roles
    $consentVisible = if ($granted) {
      Wait-ForConsent -ClientServicePrincipalId $appSp.Id -RequiredRoles $roles -Attempts 2
    } else {
      $false
    }
    if (-not $consentVisible) {
      $consentUrl = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$($application.AppId)"
      Write-Host ""
      Write-Host "  An Application Administrator, Cloud Application Administrator, Privileged Role Administrator, or Global Administrator must grant consent:" -ForegroundColor Yellow
      Write-Host "  $consentUrl" -ForegroundColor Cyan
      if ($DeferConsent) {
        $choice = 2
      } elseif ($NonInteractive) {
        throw "Admin consent is not visible yet. Grant consent and re-run, or add -DeferConsent to deploy only the Function App now."
      } else {
        $choice = Read-Choice -Prompt "Admin consent" `
          -HelpText "Open the URL above and have an administrator grant consent before choosing 1. Option 2 leaves the connector incomplete: the Logic App will not be deployed." -Options @(
          "Consent was granted; verify now",
          "Continue with Function App only and grant consent later"
        ) -Default 1
      }
      if ($choice -eq 1) {
        if (-not (Wait-ForConsent -ClientServicePrincipalId $appSp.Id -RequiredRoles $roles)) {
          Write-Host "  Consent could not be verified yet. The URL will be repeated in the summary." -ForegroundColor Yellow
          $consentDeferred = $true
        }
      } else {
        $consentDeferred = $true
      }
      if ($consentDeferred) {
        $script:DeferredConsentUrls.Add($consentUrl)
        $script:DeferredConnectorLabels.Add($Label)
      }
    }
  }

  if (-not $consentDeferred) {
    Remove-ExcessDefenderConsent -ClientServicePrincipalId $appSp.Id `
      -ResourceServicePrincipalId $wdatpSp.Id -RequiredRoles $roles
  }

  $clientSecret = if ($RotateSecret) { $null } else { $ExistingClientSecret }
  if ($RotateSecret) {
    $newCredential = New-ConnectorSecret -Application $application -Label $Label
    $clientSecret = $newCredential.Secret
    $newCredentialKeyId = $newCredential.KeyId
  } elseif (-not $clientSecret) {
    if ($created) {
      $newCredential = New-ConnectorSecret -Application $application -Label $Label
      $clientSecret = $newCredential.Secret
      $newCredentialKeyId = $newCredential.KeyId
    } else {
      $secretChoice = Read-Choice -Prompt "Client secret for '$($application.DisplayName)'" `
        -HelpText "Choose 1 if you have a valid secret value for this registration. Choose 2 to create a new secret and configure the Function App with it." -Options @(
        "Paste an existing secret",
        "Generate a new secret"
      ) -Default 1
      if ($secretChoice -eq 1) {
        $clientSecret = Read-RequiredSecret "  Client secret" `
          -HelpText "Use the client secret VALUE saved when it was created in Entra ID > App registrations > this app > Certificates & secrets. Do not enter its secret ID, app ID or the ANY.RUN API key."
      } else {
        $newCredential = New-ConnectorSecret -Application $application -Label $Label
        $clientSecret = $newCredential.Secret
        $newCredentialKeyId = $newCredential.KeyId
      }
    }
  }

  if (-not $consentDeferred) {
    Test-DefenderCredential -ClientId $application.AppId -ClientSecret $clientSecret `
      -RequiredRoleValues $RequiredRoleValues -Label $Label
  }

  return [pscustomobject]@{
    ApplicationObjectId = $application.Id
    ClientId           = $application.AppId
    ClientSecret       = $clientSecret
    ConsentDeferred    = $consentDeferred
    DisplayName        = $application.DisplayName
    NewCredentialKeyId = $newCredentialKeyId
  }
}

function Ensure-ResourceGroup {
  param([string]$Name, [string]$Location)
  $existing = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
  if ($existing) {
    if ($existing.Location -ne $Location) {
      Write-Host "  Resource group already exists in '$($existing.Location)'; using that location." -ForegroundColor Yellow
    }
    return $existing
  }
  Write-Step "Creating resource group '$Name' in '$Location'..."
  return New-AzResourceGroup -Name $Name -Location $Location
}

function Ensure-LogAnalyticsWorkspace {
  param([string]$ResourceGroupName, [string]$Name, [string]$Location)
  $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
  if ($workspace) {
    Write-Host "  Reusing Log Analytics workspace '$Name'." -ForegroundColor Green
    return $workspace
  }
  Write-Step "Creating Log Analytics workspace '$Name'..."
  return New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $Name -Location $Location -Sku PerGB2018
}

function Ensure-StorageAccount {
  param([string]$ResourceGroupName, [string]$Name, [string]$Location)

  if ($Name -notmatch '^[a-z0-9]{3,24}$') {
    throw "Storage account name '$Name' must contain 3-24 lowercase letters or numbers."
  }

  $created = $false
  $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
  if ($account) {
    Write-Host "  Reusing storage account '$Name'." -ForegroundColor Green
    $propertyNames = @($account.PSObject.Properties.Name)
    if ($propertyNames -contains "AllowSharedKeyAccess" -and $account.AllowSharedKeyAccess -eq $false) {
      throw "Storage account '$Name' has AllowSharedKeyAccess=false. The current connector runtime uses account keys and cannot use this account."
    }
  } else {
    $availability = Get-AzStorageAccountNameAvailability -Name $Name
    if (-not $availability.NameAvailable) {
      throw "Storage account name '$Name' is unavailable: $($availability.Message)"
    }
    Write-Step "Creating storage account '$Name'..."
    $account = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $Name -Location $Location `
      -SkuName Standard_LRS -Kind StorageV2 -EnableHttpsTrafficOnly $true -MinimumTlsVersion TLS1_2 `
      -AllowBlobPublicAccess $false
    $created = $true
  }

  # Re-read the effective state because an Azure Policy with Modify can change
  # AllowSharedKeyAccess during creation.
  $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $Name
  $allowSharedKeyAccess = Get-ObjectPropertyValue -InputObject $account -Name "AllowSharedKeyAccess"
  if ($allowSharedKeyAccess -eq $false) {
    throw "Storage account '$Name' has AllowSharedKeyAccess=false after policy evaluation. The current connector runtime requires account keys."
  }

  $keys = @(Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $Name)
  if ($keys.Count -eq 0) { throw "No access key was returned for storage account '$Name'." }
  $storageSuffix = (Get-AzContext).Environment.StorageEndpointSuffix
  if ([string]::IsNullOrWhiteSpace($storageSuffix)) { $storageSuffix = "core.windows.net" }
  $connectionString = "DefaultEndpointsProtocol=https;AccountName=$Name;AccountKey=$($keys[0].Value);EndpointSuffix=$storageSuffix"

  return [pscustomobject]@{
    Name                   = $Name
    Key                    = ConvertTo-SecureValue -Value $keys[0].Value
    ConnectionString       = ConvertTo-SecureValue -Value $connectionString
    Created                = $created
  }
}

function Remove-ConnectorDeploymentArtifacts {
  param(
    [Parameter(Mandatory = $true)][string]$StorageAccountName,
    [Parameter(Mandatory = $true)][bool]$AllowRoleCleanup
  )

  if (-not $AllowRoleCleanup) {
    Write-Host "  Custom storage name supplied; automatic stale role-assignment cleanup is disabled." -ForegroundColor DarkGray
    return
  }

  $storage = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -ErrorAction SilentlyContinue
  if (-not $storage) { return }

  # The templates use a deterministic role-assignment name that omits principalId.
  # If a Function App was deleted and recreated, the old assignment can block ARM
  # with RoleAssignmentUpdateNotPermitted. On connector-owned storage, remove only
  # assignments whose principal has already been deleted. Azure can report
  # ObjectType=Unknown merely because the operator cannot resolve directory
  # objects, so absence is confirmed through the authenticated Graph session.
  $assignments = @(Get-AzRoleAssignment -Scope $storage.Id -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Scope -eq $storage.Id -and
      ($_.RoleDefinitionId -like "*$($script:StorageBlobDataContributorRoleId)" -or
       $_.RoleDefinitionId -like "*$($script:LegacyStorageBlobDataOwnerRoleId)")
    })
  if (@($assignments | Where-Object ObjectType -eq "Unknown").Count -gt 0 -and -not $ForceGraphDeviceCode) {
    Connect-GraphSmart -RequestedTenantId $TenantId
  }
  foreach ($assignment in $assignments) {
    if ($assignment.ObjectType -ne "Unknown") { continue }
    $confirmedDeleted = $false
    try {
      Get-MgServicePrincipal -ServicePrincipalId $assignment.ObjectId -Property Id -ErrorAction Stop | Out-Null
    } catch {
      $graphMessage = "$($_.Exception.Message)"
      if ($graphMessage -match '404|Request_ResourceNotFound|does not exist|not found') {
        $confirmedDeleted = $true
      } else {
        Write-Host "  Could not verify stale principal '$($assignment.ObjectId)'; preserving its role assignment." -ForegroundColor Yellow
      }
    }
    if (-not $confirmedDeleted) { continue }
    Write-Host "  Removing stale Storage Blob Data role assignment '$($assignment.RoleAssignmentName)' of a deleted Function App identity..." -ForegroundColor Yellow
    Remove-AzRoleAssignment -InputObject $assignment | Out-Null
  }
}

function Remove-LegacyStorageRoleAssignment {
  param(
    [Parameter(Mandatory = $true)][string]$StorageAccountName,
    [Parameter(Mandatory = $true)][string]$FunctionAppName,
    [Parameter(Mandatory = $true)][ValidateSet('Sandbox', 'Feeds')][string]$ConnectorType,
    [switch]$SupersededOwner
  )

  $storage = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName -ErrorAction SilentlyContinue
  if (-not $storage) { return }
  $sitePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$($FunctionAppName)?api-version=2024-11-01"
  try {
    $site = Invoke-AzRestJson -Method GET -Path $sitePath -AllowedStatusCodes @(404)
  } catch { return }
  if (-not $site) { return }
  $identity = Get-ObjectPropertyValue -InputObject $site -Name "identity"
  if (-not $identity) { return }
  $principalId = "$(Get-ObjectPropertyValue -InputObject $identity -Name 'principalId')"
  if ($principalId -notmatch '^[0-9a-fA-F-]{36}$') { return }

  $ownerAssignments = @(Get-AzRoleAssignment -Scope $storage.Id -ErrorAction SilentlyContinue | Where-Object {
    $_.Scope -eq $storage.Id -and
    $_.ObjectId.ToString() -eq $principalId -and
    $_.RoleDefinitionId -like "*$($script:LegacyStorageBlobDataOwnerRoleId)"
  })
  if ($SupersededOwner) {
    # After deployment the Function App identity holds Storage Blob Data
    # Contributor, which is what Flex Consumption deployment storage needs.
    foreach ($assignment in $ownerAssignments) {
      Write-Host "  Removing superseded Storage Blob Data Owner assignment '$($assignment.RoleAssignmentName)'; the Function App now uses Storage Blob Data Contributor." -ForegroundColor Yellow
      Remove-AzRoleAssignment -InputObject $assignment | Out-Null
    }
    return
  }

  # The oldest templates used a role-assignment name without the principal ID.
  # Remove it before deployment so ARM can create the current assignment.
  $legacyNames = [System.Collections.Generic.List[string]]::new()
  $legacyNames.Add((Get-ArmGuid -Values @($storage.Id, $script:LegacyStorageBlobDataOwnerRoleId)))
  if ($ConnectorType -eq 'Feeds') {
    $legacyNames.Add((Get-ArmGuid -Values @($storage.Id, $script:LegacyStorageBlobDataOwnerRoleId, 'feeds')))
  }
  foreach ($assignment in @($ownerAssignments | Where-Object { $legacyNames -contains $_.RoleAssignmentName })) {
    Write-Host "  Removing legacy Storage Blob Data Owner assignment '$($assignment.RoleAssignmentName)' before idempotent migration..." -ForegroundColor Yellow
    Remove-AzRoleAssignment -InputObject $assignment | Out-Null
  }
}

function Get-ConnectorArtifacts {
  param([Parameter(Mandatory = $true)][ValidateSet("Sandbox", "Feeds")][string]$ConnectorType)

  # Templates are deployed exactly as reviewed; only parameters differ per
  # installation. The package URI is pinned to the resolved commit, so ARM
  # downloads the same ZIP whose SHA-256 is verified here.
  $artifact = $script:Artifacts[$ConnectorType]
  $root = "https://raw.githubusercontent.com/$Repository/$($script:ResolvedRepositoryRef)/Microsoft%20Defender%20for%20Endpoint/$($artifact.Path)"
  $result = [ordered]@{ PackageUri = "$root/Function%20App/$($artifact.Package)" }
  $downloads = @(
    @{ Key = "FunctionTemplate"; Uri = "$root/Function%20App/$($artifact.FunctionTemplate)"; Sha256 = $artifact.FunctionTemplateSha256; Label = "$ConnectorType Function template" },
    @{ Key = "Package"; Uri = $result.PackageUri; Sha256 = $artifact.PackageSha256; Label = "$ConnectorType Function package" },
    @{ Key = "LogicTemplate"; Uri = "$root/Logic%20App/$($artifact.LogicTemplate)"; Sha256 = $artifact.LogicTemplateSha256; Label = "$ConnectorType Logic template" }
  )
  foreach ($download in $downloads) {
    $extension = if ($download.Key -eq "Package") { "zip" } else { "json" }
    $path = Join-Path ([IO.Path]::GetTempPath()) "anyrun-$($ConnectorType.ToLowerInvariant())-$($download.Key.ToLowerInvariant())-$([Guid]::NewGuid().ToString('N')).$extension"
    $script:TemporaryFiles.Add($path)
    Get-VerifiedRemoteFile -Uri $download.Uri -Destination $path -ExpectedSha256 $download.Sha256 -Label $download.Label
    $result[$download.Key] = $path
  }

  $archive = $null
  try {
    $archive = [IO.Compression.ZipFile]::OpenRead($result.Package)
    $entryNames = @($archive.Entries | ForEach-Object FullName)
    $requiredEntries = @("host.json", "requirements.txt", "$($artifact.FunctionDirectory)/function.json")
    $missingEntries = @($requiredEntries | Where-Object { $entryNames -notcontains $_ })
    if ($missingEntries.Count -gt 0) {
      throw "missing required ZIP entries: $($missingEntries -join ', ')."
    }
  } catch {
    throw "$ConnectorType package at '$($result.PackageUri)' is not a valid Function deployment ZIP: $($_.Exception.Message)"
  } finally {
    if ($archive) { $archive.Dispose() }
  }
  Write-Host "  Function packageUri is pinned to commit '$($script:ResolvedRepositoryRef)'." -ForegroundColor DarkGray
  return [pscustomobject]$result
}

function Get-FunctionTemplateParameters {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Names,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][SecureString]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$StorageAccountName,
    [Parameter(Mandatory = $true)][SecureString]$StorageKey,
    [Parameter(Mandatory = $true)][SecureString]$StorageConnectionString,
    [Parameter(Mandatory = $true)][SecureString]$ApiKey,
    [bool]$ConfigureLifecyclePolicy = $false
  )

  $parameters = @{
    functionAppName              = $Names.FunctionApp
    hostingPlanName              = $Names.HostingPlan
    appInsightsName              = $Names.AppInsights
    packageUri                   = $Names.PackageUri
    AzureTenantID                = $TenantId
    AzureClientID                = $ClientId
    AzureClientSecret            = $ClientSecret
    AzureStorageAccountName      = $StorageAccountName
    AzureStorageConnectionString = $StorageConnectionString
    LogAnalyticsWorkspaceName    = $LogAnalyticsWorkspaceName
    DefenderIndicatorAction      = $DefenderIndicatorAction
  }
  if ($Connector -eq "Sandbox") {
    $parameters.AzureStorageAccountKey = $StorageKey
    $parameters.AzureBlobContainerName = $SandboxBlobContainerName
    $parameters.ANYRUN_API_KEY = $ApiKey
    $parameters.ConfigureEvidenceLifecyclePolicy = $ConfigureLifecyclePolicy
  } else {
    $parameters.anyrunApiKey = $ApiKey
  }
  return $parameters
}

function Get-LogicTemplateParameters {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Names,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][SecureString]$ClientSecret
  )

  if ($Connector -eq "Sandbox") {
    return @{
      logicAppName        = $Names.LogicApp
      azureTenantId       = $TenantId
      azureClientId       = $ClientId
      azureClientSecret   = $ClientSecret
      functionAppName     = $Names.FunctionApp
      analysisPrivacyType = $SandboxAnalysisPrivacyType
    }
  }
  return @{
    logicAppName                 = $Names.LogicApp
    intervalRecurrence           = $FeedsIntervalHours
    feedFetchDepth               = $FeedsFetchDepthDays
    minimum_confidence_threshold = $FeedsMinimumConfidence
    functionAppName              = $Names.FunctionApp
  }
}

function Test-ArmDeployment {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$TemplateFile,
    [Parameter(Mandatory = $true)][hashtable]$TemplateParameters
  )

  $splat = @{
    ResourceGroupName       = $ResourceGroup
    TemplateFile            = $TemplateFile
    TemplateParameterObject = $TemplateParameters
    ErrorAction             = "Stop"
    WarningVariable         = "armValidationWarnings"
  }

  Write-Step "Validating $Label against Azure Policy and ARM..."
  $armValidationWarnings = @()
  $validationErrors = @(Test-AzResourceGroupDeployment @splat)
  if ($validationErrors.Count -gt 0) {
    $messages = @($validationErrors | ForEach-Object { $_.Message }) -join "`n"
    throw "$Label pre-flight validation failed:`n$messages"
  }
  if (@($armValidationWarnings).Count -gt 0) {
    $diagnostics = ($armValidationWarnings | ForEach-Object { $_.ToString() }) -join "`n"
    if ($diagnostics -match 'NestedDeploymentShortCircuited' -and $diagnostics -match 'AssignFunctionStorageRole') {
      Write-Host "  Azure could not prevalidate the storage role assignment because the Function App identity is resolved during deployment. Azure will evaluate this part when deploying; this warning alone does not mean deployment failed." -ForegroundColor Yellow
    }
    Write-Host "  $Label ARM validation completed with diagnostics; some checks may be deferred until deployment." -ForegroundColor Yellow
  } else {
    Write-Host "  $Label ARM validation succeeded." -ForegroundColor Green
  }
}

function Get-DeploymentOperationDiagnostic {
  param([Parameter(Mandatory = $true)]$Operation)

  $target = Get-ObjectPropertyValue -InputObject $Operation -Name "TargetResource"
  $resourceName = $null
  if ($target -is [string]) {
    $resourceName = $target
  } elseif ($target) {
    $resourceName = Get-ObjectPropertyValue -InputObject $target -Name "ResourceName"
    if (-not $resourceName) { $resourceName = Get-ObjectPropertyValue -InputObject $target -Name "Id" }
    if (-not $resourceName) { $resourceName = Get-ObjectPropertyValue -InputObject $target -Name "ResourceType" }
  }
  if (-not $resourceName) {
    $resourceName = Get-ObjectPropertyValue -InputObject $Operation -Name "OperationId"
  }
  if (-not $resourceName) { $resourceName = "unknown resource" }

  $statusMessage = Get-ObjectPropertyValue -InputObject $Operation -Name "StatusMessage"
  if (-not $statusMessage) {
    $statusMessage = Get-ObjectPropertyValue -InputObject $Operation -Name "ProvisioningState"
  }
  if ($statusMessage -and $statusMessage -isnot [string]) {
    $statusMessage = $statusMessage | ConvertTo-Json -Depth 20 -Compress
  }
  if (-not $statusMessage) { $statusMessage = "No status message was returned by Azure." }

  return [pscustomobject]@{
    Resource = "$resourceName"
    Message  = "$statusMessage"
  }
}

function Invoke-ArmDeployment {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$TemplateFile,
    [Parameter(Mandatory = $true)][hashtable]$TemplateParameters
  )

  if (-not (Test-Path -LiteralPath $TemplateFile -PathType Leaf)) { throw "Template file '$TemplateFile' does not exist." }

  $baseName = ("anyrun-{0}-{1}" -f ($Label -replace '[^a-zA-Z0-9-]', '-').ToLowerInvariant(), (Get-Date -Format 'yyyyMMddHHmmss'))
  $maxAttempts = 5
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    $deploymentName = "$baseName-$attempt"
    $splat = @{
      Name                    = $deploymentName
      ResourceGroupName       = $ResourceGroup
      TemplateFile            = $TemplateFile
      TemplateParameterObject = $TemplateParameters
      Mode                    = "Incremental"
    }

    try {
      Write-Step "Deploying $Label (attempt $attempt/$maxAttempts)..."
      $deployment = New-AzResourceGroupDeployment @splat
      if ($deployment.ProvisioningState -ne "Succeeded") {
        throw "$Label deployment completed with state '$($deployment.ProvisioningState)'."
      }
      Write-Host "  $Label deployment succeeded." -ForegroundColor Green
      return $deployment
    } catch {
      $errorDetails = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
      $message = "$($_.Exception.Message) $errorDetails"
      $failedOperations = @(Get-AzResourceGroupDeploymentOperation -ResourceGroupName $ResourceGroup `
        -DeploymentName $deploymentName -ErrorAction SilentlyContinue |
        Where-Object { (Get-ObjectPropertyValue -InputObject $_ -Name "ProvisioningState") -eq "Failed" })
      $operationDiagnostics = @($failedOperations | ForEach-Object {
        Get-DeploymentOperationDiagnostic -Operation $_
      })
      $operationMessages = @($operationDiagnostics | ForEach-Object { $_.Message }) -join " `n"
      $message = "$message $operationMessages"

      $identityNotReady = $message -match 'PrincipalNotFound|replication delay|does not exist in the directory'
      $onedeployFailed = @($operationDiagnostics | Where-Object {
        $_.Resource -match '(?i)(?:/|\\)extensions(?:/|\\)onedeploy$|sites/extensions.*onedeploy'
      }).Count -gt 0
      $packageRbacNotReady = $message -match 'AuthorizationPermissionMismatch' -or (
        $message -match '(?i)(?:status\s*code|http)?\s*403|Forbidden' -and
        $message -match '(?i)onedeploy|sites/extensions|package|blob|storage'
      )
      $transientOneDeployFailure = $onedeployFailed -and $message -match '(?i)No status message|Code:\s*\)|timeout|temporar|InternalServerError|ServiceUnavailable'
      if ($attempt -lt $maxAttempts -and ($identityNotReady -or $packageRbacNotReady -or $transientOneDeployFailure)) {
        $waitSeconds = if ($packageRbacNotReady) { 45 } else { 30 }
        $reason = if ($packageRbacNotReady) {
          "onedeploy failed while package access or Storage RBAC may still be propagating"
        } elseif ($transientOneDeployFailure) {
          "onedeploy returned an explicitly transient or empty diagnostic"
        } else {
          "Managed identity has not replicated"
        }
        Write-Host "  $reason; waiting $waitSeconds seconds before retry." -ForegroundColor Yellow
        Start-Sleep -Seconds $waitSeconds
        continue
      }
      Write-Host "  Failed deployment operations:" -ForegroundColor Yellow
      if ($operationDiagnostics.Count -eq 0) {
        Write-Host "    $message" -ForegroundColor Yellow
      } else {
        $operationDiagnostics | ForEach-Object {
          Write-Host "    $($_.Resource): $($_.Message)" -ForegroundColor Yellow
        }
      }
      throw
    }
  }
}

function Assert-FunctionName {
  param([string]$Name)
  if ($Name -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,58}[A-Za-z0-9])$') {
    throw "Function App name '$Name' must contain 2-60 letters, numbers, or internal hyphens, and must start and end with a letter or number."
  }
}

function Assert-LogicAppName {
  param([Parameter(Mandatory = $true)][string]$Name)
  if ($Name -notmatch '^[A-Za-z0-9._()-]{1,80}$') {
    throw "Logic App name '$Name' must be 1-80 characters and contain only letters, digits, period, underscore, parentheses, or hyphen."
  }
}

function Wait-FunctionRegistration {
  param(
    [Parameter(Mandatory = $true)][string]$FunctionAppName,
    [Parameter(Mandatory = $true)][string]$FunctionName,
    [int]$Attempts = 36
  )

  $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$FunctionAppName/functions?api-version=2022-03-01"
  for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    try {
      $result = Invoke-AzRestJson -Method GET -Path $path
      $match = @($result.value | Where-Object { $_.name.Split('/')[-1] -eq $FunctionName })
      if ($match.Count -gt 0) {
        Write-Host "  Function '$FunctionName' is registered in '$FunctionAppName'." -ForegroundColor Green
        return
      }
    } catch {
      if ($attempt -eq $Attempts) { throw }
    }
    if ($attempt -lt $Attempts) {
      Write-Host "  Waiting for function registration ($attempt/$Attempts)..." -ForegroundColor DarkGray
      Start-Sleep -Seconds 10
    }
  }
  throw "Function '$FunctionName' did not appear in '$FunctionAppName' within six minutes. Logic App deployment was not attempted."
}

function Get-ResourceProvisioningState {
  param([string]$ResourceType, [string]$Name)
  if ($ResourceType -eq 'Microsoft.Logic/workflows') {
    # Query the workflow provider in the selected subscription directly rather
    # than inferring success from deployment status or the current Az context.
    $expectedId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$Name"
    $response = Invoke-AzRestMethod -Method GET -Path "${expectedId}?api-version=2016-06-01" -ErrorAction Stop
    if ($response.StatusCode -eq 404) { return 'NOT FOUND' }
    if ($response.StatusCode -ne 200) { throw "Logic App verification for '$expectedId' returned HTTP $($response.StatusCode)." }
    $workflow = ConvertFrom-AzRestContent -Response $response
    if (-not $workflow -or
        (Get-ObjectPropertyValue -InputObject $workflow -Name 'id') -ne $expectedId -or
        (Get-ObjectPropertyValue -InputObject $workflow -Name 'type') -ne 'Microsoft.Logic/workflows' -or
        (Get-ObjectPropertyValue -InputObject $workflow -Name 'name') -ne $Name) {
      throw "Azure returned an unexpected resource while verifying Logic App '$expectedId'."
    }
    $properties = Get-ObjectPropertyValue -InputObject $workflow -Name 'properties'
    if (-not $properties) { throw "Logic App '$expectedId' has no readable properties." }
    $state = Get-ObjectPropertyValue -InputObject $properties -Name 'state'
    $provisioningState = Get-ObjectPropertyValue -InputObject $properties -Name 'provisioningState'
    Write-Host "  Confirmed Logic App ID : $expectedId" -ForegroundColor White
    Write-Host "  Logic App state        : $state" -ForegroundColor White
    Write-Host "  Open Logic App         : https://portal.azure.com/#resource$expectedId/overview" -ForegroundColor Cyan
    if ($state -ne 'Enabled') { throw "Logic App '$Name' is '$state'; expected Enabled." }
    if (-not $provisioningState) { return 'UNKNOWN' }
    return $provisioningState
  }
  $resource = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType $ResourceType -Name $Name -ExpandProperties -ErrorAction SilentlyContinue
  if (-not $resource) { return "NOT FOUND" }
  $propertyNames = @($resource.Properties.PSObject.Properties.Name)
  if ($propertyNames -contains "provisioningState") { return $resource.Properties.provisioningState }
  if ($propertyNames -contains "state") { return $resource.Properties.state }
  return "Present"
}

function Get-ApiConnectionStatus {
  param([Parameter(Mandatory = $true)][string]$Name)
  $resource = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Web/connections" -Name $Name -ExpandProperties -ErrorAction SilentlyContinue
  if (-not $resource) { return "NOT FOUND" }
  $propertyNames = @($resource.Properties.PSObject.Properties.Name)
  if ($propertyNames -contains "overallStatus") { return $resource.Properties.overallStatus }
  $statuses = if ($propertyNames -contains "statuses") { @($resource.Properties.statuses) } else { @() }
  if ($statuses.Count -gt 0) { return ($statuses | ForEach-Object status) -join ", " }
  return "UNKNOWN"
}

function Invoke-FeedsSmokeTest {
  param([Parameter(Mandatory = $true)][string]$LogicAppName)
  $triggeredAfter = (Get-Date).ToUniversalTime().AddSeconds(-5)
  $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$LogicAppName/triggers/Recurrence/run?api-version=2016-06-01"
  $response = Invoke-AzRestMethod -Method POST -Path $path -Payload "{}"
  if ([int]$response.StatusCode -notin @(200, 202)) {
    throw "Feeds Logic App smoke test returned HTTP $($response.StatusCode)."
  }
  Write-Host "  Feeds Logic App test run was accepted (HTTP $($response.StatusCode)); waiting for completion..." -ForegroundColor DarkGray

  $runsPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$LogicAppName/runs?api-version=2016-06-01&`$top=10"
  for ($attempt = 1; $attempt -le 36; $attempt++) {
    $runs = Invoke-AzRestJson -Method GET -Path $runsPath
    $run = @($runs.value | Where-Object {
      [DateTime]$_.properties.startTime -ge $triggeredAfter
    } | Sort-Object { [DateTime]$_.properties.startTime } -Descending) | Select-Object -First 1

    if ($run) {
      $status = "$($run.properties.status)"
      if ($status -eq "Succeeded") {
        Write-Host "  Feeds Logic App test run '$($run.name)' succeeded." -ForegroundColor Green
        return
      }
      if ($status -in @("Failed", "Cancelled", "TimedOut", "Aborted", "Skipped")) {
        $errorText = if ($run.properties.error) { $run.properties.error | ConvertTo-Json -Depth 10 -Compress } else { "no error details returned" }
        throw "Feeds Logic App test run '$($run.name)' finished with status '$status': $errorText"
      }
    }

    if ($attempt -lt 36) {
      Write-Host "  Feeds test run is still pending ($attempt/36)..." -ForegroundColor DarkGray
      Start-Sleep -Seconds 10
    }
  }
  throw "Feeds Logic App test run did not finish within six minutes."
}

try {
Write-Banner "ANY.RUN Microsoft Defender for Endpoint connector deployment"

$Connector = Select-Connector -RequestedConnector $Connector
if (-not $NonInteractive) {
  Write-Host "  Prompts explain the expected input; brackets show defaults. API keys and client secrets use masked input." -ForegroundColor Gray
  Write-Host "  Azure uses your signed-in directory. To select another directory/subscription, rerun with -TenantId / -SubscriptionId (GUIDs from Azure portal)." -ForegroundColor Gray
}

$deploySandbox = $Connector -eq "Sandbox"
$deployFeeds = $Connector -eq "Feeds"
if ($deployFeeds -and $DefenderIndicatorAction -eq "Disabled") {
  throw "-DefenderIndicatorAction Disabled applies only to Sandbox. TI Feeds exists to import indicators; use Audit or Block."
}
if ($RotateClientSecret -and $SkipFunctionApp) {
  throw "-RotateClientSecret cannot be combined with -SkipFunctionApp because the Function App must receive the new secret."
}

Write-Phase "0" "Pre-flight"
Write-Step "Loading required PowerShell modules..."
Ensure-Module "Az.Accounts" -MinimumVersion "5.5.3" -RequiredCommands @(
  "Connect-AzAccount", "Get-AzAccessToken", "Get-AzContext", "Get-AzSubscription", "Invoke-AzRestMethod", "Set-AzContext"
)
Ensure-Module "Az.Resources" -MinimumVersion "10.2.1" -RequiredCommands @(
  "Get-AzResource", "Get-AzResourceGroup", "Get-AzResourceGroupDeploymentOperation", "Get-AzResourceProvider",
  "Get-AzRoleAssignment", "New-AzResourceGroup", "New-AzResourceGroupDeployment", "Register-AzResourceProvider",
  "Remove-AzResource", "Remove-AzRoleAssignment", "Test-AzResourceGroupDeployment"
)
Ensure-Module "Az.Storage" -MinimumVersion "9.7.2" -RequiredCommands @(
  "Get-AzStorageAccount", "Get-AzStorageAccountKey", "Get-AzStorageAccountNameAvailability", "New-AzStorageAccount"
)
Ensure-Module "Az.OperationalInsights" -MinimumVersion "3.4.1" -RequiredCommands @(
  "Get-AzOperationalInsightsWorkspace", "New-AzOperationalInsightsWorkspace"
)
Ensure-Module "Microsoft.Graph.Authentication" -MinimumVersion "2.40.0" -RequiredCommands @(
  "Connect-MgGraph", "Disconnect-MgGraph", "Get-MgContext"
)
Ensure-Module "Microsoft.Graph.Applications" -MinimumVersion "2.40.0" -RequiredCommands @(
  "Add-MgApplicationPassword", "Get-MgApplication", "Get-MgServicePrincipal", "Get-MgServicePrincipalAppRoleAssignment",
  "New-MgApplication", "New-MgServicePrincipal", "New-MgServicePrincipalAppRoleAssignment", "Remove-MgApplicationPassword",
  "Remove-MgServicePrincipalAppRoleAssignment", "Update-MgApplication"
)

$script:ResolvedRepositoryRef = Resolve-RepositoryCommit -RepositoryName $Repository -Ref $RepositoryRef

$azureContext = Connect-AzureSmart -RequestedTenantId $TenantId -RequestedSubscriptionId $SubscriptionId
$TenantId = $azureContext.Tenant.Id
$SubscriptionId = $azureContext.Subscription.Id
Connect-GraphSmart -RequestedTenantId $TenantId

Write-Host ""
Write-Host "  Tenant       : $TenantId" -ForegroundColor White
Write-Host "  Subscription : $($azureContext.Subscription.Name) ($SubscriptionId)" -ForegroundColor White
Write-Host "  Connector    : $Connector" -ForegroundColor White
if (-not (Confirm-Action "  Continue with this tenant and subscription?" $true)) { throw "Deployment cancelled." }

if (-not $ResourceGroup) {
  $defaultResourceGroup = "ANYRUN-MDE-RG"
  # Keep the original default group on upgrades when it already exists.
  if (Get-AzResourceGroup -Name "rg-anyrun-mde" -ErrorAction SilentlyContinue) {
    $defaultResourceGroup = "rg-anyrun-mde"
  }
  $ResourceGroup = Read-Text -Prompt "Resource group name" -Default $defaultResourceGroup `
    -HelpText "Enter an existing group name to reuse it (Sandbox and Feeds may share a group), or a new name to create it. Example: ANYRUN-MDE-RG. Existing groups keep their region." `
    -ValidationPattern '^[^<>%&:\\?/#]{1,90}(?<!\.)$' -ValidationMessage "Use 1 to 90 characters, no < > % & : backslash ? / #, and no trailing period."
}
if ($ResourceGroup -notmatch '^[^<>%&:\\?/#]{1,90}(?<!\.)$') {
  throw "Resource group name '$ResourceGroup' contains invalid characters or ends with a period."
}
$existingResourceGroup = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
if ($existingResourceGroup) {
  $Region = $existingResourceGroup.Location
  Write-Host "  Using existing resource group '$ResourceGroup' in '$Region'." -ForegroundColor Green
} elseif (-not $regionWasPassed) {
  if ($NonInteractive) {
    throw "A new resource group requires an explicit -Region in non-interactive mode."
  }
  $Region = Read-Text -Prompt "Azure region" -Default $Region `
    -HelpText "Enter an Azure region code for the new group, for example eastus or westeurope. Flex Consumption support will be checked before deployment."
}
Write-Step "Checking Azure providers and Flex Consumption support before creating the resource group..."
foreach ($providerNamespace in @("Microsoft.Web", "Microsoft.Storage", "Microsoft.Insights", "Microsoft.OperationalInsights", "Microsoft.Logic")) {
  Ensure-ResourceProvider -ProviderNamespace $providerNamespace
}
Assert-FlexConsumptionRegion -Location $Region
$resourceGroupObject = Ensure-ResourceGroup -Name $ResourceGroup -Location $Region
$Region = $resourceGroupObject.Location

$stableSuffix = Get-StableSuffix -InputText "$TenantId|$SubscriptionId|$ResourceGroup" -Length 8
$existingResources = @()
if ($existingResourceGroup) {
  $existingResources = @(Get-AzResource -ResourceGroupName $ResourceGroup -ErrorAction Stop)
}
$legacyNames = Get-ConnectorDefaultNames -ConnectorType $Connector -InstanceName '' -LegacySuffix $stableSuffix
$resourceNameTypes = @{
  SandboxFunctionName = 'Microsoft.Web/sites'; FeedsFunctionName = 'Microsoft.Web/sites'
  SandboxLogicAppName = 'Microsoft.Logic/workflows'; FeedsLogicAppName = 'Microsoft.Logic/workflows'
  SandboxStorageAccountName = 'Microsoft.Storage/storageAccounts'; FeedsStorageAccountName = 'Microsoft.Storage/storageAccounts'
  LogAnalyticsWorkspaceName = 'Microsoft.OperationalInsights/workspaces'
}
$hasLegacyResources = $false
foreach ($key in $resourceNameTypes.Keys) {
  if (@($existingResources | Where-Object {
    $_.ResourceType -eq $resourceNameTypes[$key] -and $_.Name -eq $legacyNames[$key]
  }).Count -gt 0) { $hasLegacyResources = $true; break }
}
$useLegacyNames = [string]::IsNullOrEmpty($InstanceName) -and ($instanceNameWasPassed -or $hasLegacyResources)
if ($useLegacyNames) {
  $defaultNames = $legacyNames
  Write-Step "Reusing the original installer resource names..."
} else {
  if (-not $InstanceName) {
    # Unlike the portal's random suggestion, keep the installer default stable
    # for this tenant/subscription/group so an unattended re-run is an update.
    $defaultInstance = Get-StableSuffix -InputText ("$TenantId|$SubscriptionId|$ResourceGroup".ToLowerInvariant()) -Length 6
    $InstanceName = Read-Text -Prompt "Instance name (reuse the same value for updates)" `
      -Default $defaultInstance -ValidationPattern '^[a-z0-9]{1,12}$' `
      -ValidationMessage 'Use 1 to 12 lowercase letters or digits.' `
      -HelpText 'Use 1 to 12 lowercase letters or digits, for example prod01. Keep the same value to update an installation; a different value creates a separate instance.'
    $InstanceName = $InstanceName.ToLowerInvariant()
  }
  Write-Step "Resolving Azure App resource names for instance '$InstanceName'..."
  $nameHash = Get-AzureAppNameHash -ResourceGroupName $ResourceGroup -InstanceName $InstanceName
  $defaultNames = Get-ConnectorDefaultNames -ConnectorType $Connector -InstanceName $InstanceName -NameHash $nameHash
  if (-not $sandboxDisplayNameWasPassed) { $SandboxAppDisplayName = "ANYRUN-Sandbox-MDE-$InstanceName-$nameHash-Connector" }
  if (-not $feedsDisplayNameWasPassed) { $FeedsAppDisplayName = "ANYRUN-Feeds-MDE-$InstanceName-$nameHash-Connector" }
}

# Explicit names always win. Case-insensitive matching preserves the casing
# returned by Azure and keeps existing resources instead of creating duplicates.
foreach ($key in $resourceNameTypes.Keys) {
  if ((-not $deploySandbox -and $key.StartsWith('Sandbox')) -or
      (-not $deployFeeds -and $key.StartsWith('Feeds'))) { continue }
  if (-not (Get-Variable -Name $key -ValueOnly)) {
    $previousNames = @()
    if (-not $useLegacyNames -and $key.EndsWith('FunctionName')) {
      # Azure App 1.1.3 originally used a lowercase name without the FA suffix.
      $previousNames = @($defaultNames[$key].Substring(0, $defaultNames[$key].Length - 3).ToLowerInvariant())
    }
    $resolvedName = Select-ExistingResourceName -PreferredName $defaultNames[$key] `
      -ResourceType $resourceNameTypes[$key] -PreviousNames $previousNames -Resources $existingResources
    Set-Variable -Name $key -Value $resolvedName
  }
}
if ($deploySandbox) {
  Assert-FunctionName -Name $SandboxFunctionName
  Assert-LogicAppName -Name $SandboxLogicAppName
}
if ($deployFeeds) {
  Assert-FunctionName -Name $FeedsFunctionName
  Assert-LogicAppName -Name $FeedsLogicAppName
}

Write-Step "Checking permissions and global names before changing Entra ID..."
$resourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
if (-not (Test-EffectiveRoleAssignmentPermission -Scope $resourceGroupScope)) {
  throw "The signed-in account does not have Microsoft.Authorization/roleAssignments/write at '$resourceGroupScope'. Use Owner or User Access Administrator plus Contributor."
}
Show-ResourceGroupWriteAccess -Scope $resourceGroupScope
if ($deploySandbox) { Assert-FunctionAppNameAvailable -Name $SandboxFunctionName }
if ($deployFeeds)   { Assert-FunctionAppNameAvailable -Name $FeedsFunctionName }
if ($deploySandbox) { Assert-StorageAccountUsable -Name $SandboxStorageAccountName.ToLowerInvariant() }
if ($deployFeeds)   { Assert-StorageAccountUsable -Name $FeedsStorageAccountName.ToLowerInvariant() }

Write-Phase "1" "Azure resources and ARM validation"
$workspace = Ensure-LogAnalyticsWorkspace -ResourceGroupName $ResourceGroup -Name $LogAnalyticsWorkspaceName -Location $Region
Write-Host "  Workspace: $($workspace.Name)" -ForegroundColor Green

# One connector is installed per run. Collect its connector-specific values once
# so every later phase uses the same names, credentials and labels.
$isSandbox = $Connector -eq "Sandbox"
$label = if ($isSandbox) { "Sandbox" } else { "TI Feeds" }
$functionName = Get-Variable -Name "$($Connector)FunctionName" -ValueOnly
$logicAppName = Get-Variable -Name "$($Connector)LogicAppName" -ValueOnly
$storageAccountName = Get-Variable -Name "$($Connector)StorageAccountName" -ValueOnly
$storageNameWasPassed = if ($isSandbox) { $sandboxStorageNameWasPassed } else { $feedsStorageNameWasPassed }
$appId = Get-Variable -Name "$($Connector)AppId" -ValueOnly
$appIdWasPassed = if ($isSandbox) { $sandboxAppIdWasPassed } else { $feedsAppIdWasPassed }
$clientSecret = Get-Variable -Name "$($Connector)ClientSecret" -ValueOnly
$apiKey = Get-Variable -Name "$($Connector)ApiKey" -ValueOnly
$appDisplayName = Get-Variable -Name "$($Connector)AppDisplayName" -ValueOnly
$requiredRoles = if ($isSandbox) { $sandboxRoles } else { $feedsRoles }
$functionEntryPoint = $script:Artifacts[$Connector].FunctionDirectory
$apiKeySetting = if ($isSandbox) { "ANYRUN_API_KEY" } else { "ANYRUN_api_key" }

# On re-runs, recover the existing runtime configuration instead of forcing the
# operator to retain secrets or creating another credential every time.
$identityRecoveredFromFunction = $false
$existingConfiguration = Get-ExistingFunctionConfiguration -FunctionAppName $functionName
if ($SkipFunctionApp -and -not $existingConfiguration) {
  throw "-SkipFunctionApp was specified, but Function App '$functionName' does not exist."
}
if ($existingConfiguration) {
  $settings = $existingConfiguration.properties
  $existingClientId = Get-ObjectPropertyValue -InputObject $settings -Name "AzureClientID"
  $existingClientSecret = Get-ObjectPropertyValue -InputObject $settings -Name "AzureClientSecret"
  $existingApiKey = Get-ObjectPropertyValue -InputObject $settings -Name $apiKeySetting
  if ($existingClientId) { $existingClientId = Assert-GuidValue -Value "$existingClientId" -Name "$label Function App AzureClientID" }
  if (-not $appId) { $appId = $existingClientId }
  elseif ($existingClientId -and $existingClientId -ne $appId) {
    throw "$($Connector)AppId '$appId' does not match the existing Function App configuration."
  }
  if ($existingClientId -and -not $appIdWasPassed) { $identityRecoveredFromFunction = $true }
  if (-not $RotateClientSecret -and -not $clientSecret -and $existingClientSecret) {
    $clientSecret = ConvertTo-SecureValue -Value $existingClientSecret
  }
  if (-not $apiKey -and $existingApiKey) {
    # The Sandbox template stores the key with the API-KEY prefix.
    $apiKey = ConvertTo-SecureValue -Value ("$existingApiKey" -replace '^API-KEY\s+', '')
  }
  Write-Host "  Recovered $label credentials from the existing Function App settings." -ForegroundColor Green
}
if (-not $SkipFunctionApp) {
  $existingIndicatorAction = if ($existingConfiguration) {
    "$(Get-ObjectPropertyValue -InputObject $existingConfiguration.properties -Name 'DefenderIndicatorAction')"
  } else { "" }
  $DefenderIndicatorAction = Select-IndicatorAction -ConnectorType $Connector -Requested $DefenderIndicatorAction `
    -WasPassed $indicatorActionWasPassed -ExistingValue $existingIndicatorAction
  Write-Host "  Indicator action: $DefenderIndicatorAction" -ForegroundColor Green
}

$artifacts = Get-ConnectorArtifacts -ConnectorType $Connector

# Installer and Azure App instances share names. Original installer instances
# keep the template default: plan and Application Insights named after the app.
$hostingPlanName = $functionName
$appInsightsName = $functionName
if (-not $useLegacyNames) {
  $baseName = "ANYRUN-$Connector-MDE-$InstanceName"
  $hostingPlanName = Select-ExistingResourceName -PreferredName "$baseName-Plan" `
    -ResourceType 'Microsoft.Web/serverfarms' -PreviousNames @($functionName) -Resources $existingResources
  $appInsightsName = Select-ExistingResourceName -PreferredName "$baseName-AI" `
    -ResourceType 'Microsoft.Insights/components' -PreviousNames @($functionName) -Resources $existingResources
}
$names = @{
  FunctionApp = $functionName; HostingPlan = $hostingPlanName; AppInsights = $appInsightsName
  LogicApp = $logicAppName; PackageUri = $artifacts.PackageUri
}

$placeholderSecret = ConvertTo-SecureValue -Value "preflight-placeholder"
$placeholderClientId = "00000000-0000-0000-0000-000000000000"
if (-not $SkipFunctionApp) {
  Test-ArmDeployment -Label "$label Function App" -TemplateFile $artifacts.FunctionTemplate `
    -TemplateParameters (Get-FunctionTemplateParameters -Names $names -ClientId $placeholderClientId `
      -ClientSecret $placeholderSecret -StorageAccountName $storageAccountName -StorageKey $placeholderSecret `
      -StorageConnectionString $placeholderSecret -ApiKey $placeholderSecret -ConfigureLifecyclePolicy $false)
}
if (-not $SkipLogicApp) {
  Test-ArmDeployment -Label "$label Logic App" -TemplateFile $artifacts.LogicTemplate `
    -TemplateParameters (Get-LogicTemplateParameters -Names $names -ClientId $placeholderClientId -ClientSecret $placeholderSecret)
}

$storage = Ensure-StorageAccount -ResourceGroupName $ResourceGroup -Name $storageAccountName.ToLowerInvariant() -Location $Region
if (-not $apiKey) {
  $apiKey = if ($isSandbox) {
    Read-RequiredSecret "  ANY.RUN Sandbox API key (without the 'API-KEY ' prefix)" -HelpText "Use the Sandbox API key from your ANY.RUN account API settings. It is separate from the TI Feeds key; omit the API-KEY prefix."
  } else {
    Read-RequiredSecret "  ANY.RUN TI Feeds API key (without a prefix)" -HelpText "Use the TI Feeds API key issued for your ANY.RUN Threat Intelligence subscription. Enter the raw key without an Authorization header or authentication prefix."
  }
}

Write-Phase "2" "App Registration and API permissions"
$identity = Ensure-ConnectorIdentity -Label $label -DisplayName $appDisplayName `
  -ExistingAppId $appId -ExistingClientSecret $clientSecret -RequiredRoleValues $requiredRoles `
  -TrustedExistingFunctionBinding $identityRecoveredFromFunction -RotateSecret:$RotateClientSecret

Write-Phase "3" "Function App"
$functionDeployed = $false
if (-not $SkipFunctionApp) {
  Remove-LegacyStorageRoleAssignment -StorageAccountName $storage.Name -FunctionAppName $functionName -ConnectorType $Connector
  Remove-ConnectorDeploymentArtifacts -StorageAccountName $storage.Name -AllowRoleCleanup (-not $storageNameWasPassed)
  $functionParameters = Get-FunctionTemplateParameters -Names $names -ClientId $identity.ClientId `
    -ClientSecret $identity.ClientSecret -StorageAccountName $storage.Name -StorageKey $storage.Key `
    -StorageConnectionString $storage.ConnectionString -ApiKey $apiKey -ConfigureLifecyclePolicy ([bool]$storage.Created)
  Invoke-ArmDeployment -Label "$label Function App" -TemplateFile $artifacts.FunctionTemplate `
    -TemplateParameters $functionParameters | Out-Null
  $functionDeployed = $true
  # The template now grants Storage Blob Data Contributor. Remove the Owner
  # grant created by earlier template versions only after the new role exists.
  Remove-LegacyStorageRoleAssignment -StorageAccountName $storage.Name -FunctionAppName $functionName `
    -ConnectorType $Connector -SupersededOwner
  Remove-ConnectorDeploymentArtifacts -StorageAccountName $storage.Name -AllowRoleCleanup (-not $storageNameWasPassed)
} else {
  Write-Host "  Function App deployment skipped; the existing app will be verified before Logic App deployment." -ForegroundColor Yellow
}

Write-Phase "4" "Logic App"
$logicDeployed = $false
if (-not $SkipLogicApp -and -not $identity.ConsentDeferred) {
  Wait-FunctionRegistration -FunctionAppName $functionName -FunctionName $functionEntryPoint
  Invoke-ArmDeployment -Label "$label Logic App" -TemplateFile $artifacts.LogicTemplate `
    -TemplateParameters (Get-LogicTemplateParameters -Names $names -ClientId $identity.ClientId -ClientSecret $identity.ClientSecret) | Out-Null
  $logicDeployed = $true
} elseif ($identity.ConsentDeferred) {
  Write-Host "  $label Logic App skipped because Defender admin consent is not complete." -ForegroundColor Yellow
}
if ($SkipLogicApp) {
  Write-Host "  Logic App deployment was skipped by -SkipLogicApp." -ForegroundColor Yellow
}

Write-Phase "5" "Verification"
$verificationFailures = [System.Collections.Generic.List[string]]::new()
$logicState = if ($SkipLogicApp) { "SKIPPED (-SkipLogicApp)" } else { "NOT DEPLOYED (Defender admin consent pending)" }
try { Wait-FunctionRegistration -FunctionAppName $functionName -FunctionName $functionEntryPoint -Attempts 1 }
catch { $verificationFailures.Add($_.Exception.Message) }
$functionState = Get-ResourceProvisioningState -ResourceType "Microsoft.Web/sites" -Name $functionName
Write-Host ("  {0,-20} : {1}" -f "$Connector Function App", $functionState) -ForegroundColor White
if ($functionState -notin @("Running", "Succeeded")) { $verificationFailures.Add("$Connector Function App state is '$functionState'.") }
if ($logicDeployed -or (-not $SkipLogicApp -and -not $identity.ConsentDeferred)) {
  $logicState = Get-ResourceProvisioningState -ResourceType "Microsoft.Logic/workflows" -Name $logicAppName
  Write-Host ("  {0,-20} : {1}" -f "$Connector Logic App", $logicState) -ForegroundColor White
  if ($logicState -ne "Succeeded") { $verificationFailures.Add("$Connector Logic App state is '$logicState'.") }
  if ($isSandbox) {
    $connectionState = Get-ApiConnectionStatus -Name "wdatp--anyrun-app"
    Write-Host ("  {0,-20} : {1}" -f "WDATP connection", $connectionState) -ForegroundColor White
    if ($connectionState -ne "Connected") { $verificationFailures.Add("WDATP API connection state is '$connectionState'.") }
  } elseif ($TestFeedsInvocation -and $logicState -eq "Succeeded") {
    try { Invoke-FeedsSmokeTest -LogicAppName $logicAppName }
    catch { $verificationFailures.Add("Feeds Logic App smoke test failed: $($_.Exception.Message)") }
  }
}

# Old installer-created secrets are removed only after both consumers (Function
# App settings and the Logic App connection) received the new one.
if ($verificationFailures.Count -eq 0 -and $functionDeployed -and $logicDeployed -and
    -not $identity.ConsentDeferred -and $identity.NewCredentialKeyId) {
  if (-not $ForceGraphDeviceCode) { Connect-GraphSmart -RequestedTenantId $TenantId }
  Remove-OldConnectorSecrets -ApplicationObjectId $identity.ApplicationObjectId `
    -CurrentKeyId $identity.NewCredentialKeyId -Label $label
}

$logicAppsIncomplete = $SkipLogicApp -or $identity.ConsentDeferred
if ($verificationFailures.Count -gt 0 -or $logicAppsIncomplete) {
  Write-Banner "Deployment summary - INCOMPLETE"
} else {
  Write-Banner "Deployment summary"
}
Write-Host "  Resource group : $ResourceGroup" -ForegroundColor White
Write-Host "  Region         : $Region" -ForegroundColor White
Write-Host "  Instance       : $(if ($useLegacyNames) { 'legacy' } else { $InstanceName })" -ForegroundColor White
Write-Host "  Log Analytics  : $LogAnalyticsWorkspaceName" -ForegroundColor White
Write-Host ""
Write-Host ("  {0,-24} : {1} ({2})" -f "$Connector App Registration", $identity.DisplayName, $identity.ClientId) -ForegroundColor White
Write-Host ("  {0,-24} : {1}" -f "$Connector Function App", $functionName) -ForegroundColor White
Write-Host ("  {0,-24} : {1} [{2}]" -f "$Connector Logic App", $logicAppName, $logicState) -ForegroundColor $(if ($logicState -eq 'Succeeded') { 'White' } else { 'Yellow' })
Write-Host ("  {0,-24} : {1}" -f "$Connector Storage", $storage.Name) -ForegroundColor White

if ($script:DeferredConsentUrls.Count -gt 0) {
  Write-Host ""
  Write-Host "  ACTION REQUIRED - grant admin consent:" -ForegroundColor Yellow
  $script:DeferredConsentUrls | Sort-Object -Unique | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
  Write-Host "  After consent is granted, resume without redeploying the Function App:" -ForegroundColor Yellow
  $continuationArguments = [System.Collections.Generic.List[string]]::new()
  $continuationValues = [ordered]@{
    Connector = $Connector; TenantId = $TenantId; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup
    InstanceName = $InstanceName; Region = $Region; LogAnalyticsWorkspaceName = $LogAnalyticsWorkspaceName
    "$($Connector)FunctionName" = $functionName; "$($Connector)LogicAppName" = $logicAppName
    "$($Connector)StorageAccountName" = $storageAccountName
  }
  foreach ($argument in $continuationValues.GetEnumerator()) {
    $continuationArguments.Add("-$($argument.Key) $(ConvertTo-PowerShellLiteral "$($argument.Value)")")
  }
  if ($isSandbox) {
    $continuationArguments.Add("-SandboxAnalysisPrivacyType $(ConvertTo-PowerShellLiteral $SandboxAnalysisPrivacyType)")
  }
  $continuationArguments.Add("-SkipFunctionApp")
  Write-Host "    ./Deploy-ANYRUNMDEConnector.ps1 $($continuationArguments -join ' ')" -ForegroundColor Cyan
}

if ($isSandbox) {
  Write-Host ""
  Write-Host "  ACTION REQUIRED - Defender for Endpoint settings:" -ForegroundColor Yellow
  Write-Host "    1. Open https://security.microsoft.com" -ForegroundColor White
  Write-Host "    2. Go to Settings > Endpoints > Advanced features." -ForegroundColor White
  Write-Host "    3. Enable Live Response and Live Response for Servers." -ForegroundColor White
  Write-Host "    4. Enable Live Response unsigned script execution after reviewing the risk." -ForegroundColor White
  Write-Host "    5. Review the Defender Antivirus quarantine policy. The installer does not change it." -ForegroundColor White
}

Write-Host ""
Write-Host "  CREDENTIAL ROTATION REQUIRED:" -ForegroundColor Yellow
Write-Host "    Client secrets expire after $SecretLifetimeMonths month(s). Configure an Entra expiry alert" -ForegroundColor White
Write-Host "    and rerun this installer with -RotateClientSecret before expiration." -ForegroundColor White

Write-Host ""
if ($verificationFailures.Count -gt 0) {
  Write-Host "Deployment verification failed:" -ForegroundColor Red
  $verificationFailures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
  throw "Deployment completed with verification failures. Review the messages above before using the connector."
}
if ($logicAppsIncomplete) {
  Write-Host "PARTIAL DEPLOYMENT: connector activation is incomplete; Logic App deployment was skipped or Defender admin consent is pending." -ForegroundColor Yellow
  if ($SkipLogicApp) {
    Write-Host "Resume with the same connector, resource group and instance name, without -SkipLogicApp. Use -SkipFunctionApp to reuse the verified Function App." -ForegroundColor Yellow
  }
  if ($identity.ConsentDeferred) {
    Write-Host "Grant Defender admin consent, then run the continuation command shown above to deploy the Logic App." -ForegroundColor Yellow
  }
} else {
  Write-Host "Deployment finished. API keys and client secrets were not printed." -ForegroundColor Green
}
} finally {
  foreach ($temporaryFile in $script:TemporaryFiles) {
    Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
  }
  if ($script:GraphSessionOwned) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    $script:GraphSessionOwned = $false
  }
}
