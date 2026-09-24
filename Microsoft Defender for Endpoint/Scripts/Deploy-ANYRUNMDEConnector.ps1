#Requires -Version 7.0

<#
.SYNOPSIS
  Deploys the ANY.RUN Sandbox and/or TI Feeds connectors for Microsoft Defender
  for Endpoint.

.DESCRIPTION
  Interactive installer intended for Azure Cloud Shell (PowerShell). It creates
  or reuses Entra app registrations, configures WindowsDefenderATP application
  permissions, attempts to grant admin consent, prepares Azure resources, and
  deploys the connector ARM templates.

  The script is safe to re-run. Existing resource groups, app registrations,
  workspaces, and storage accounts are reused. Existing app permissions that are
  unrelated to ANY.RUN are preserved.

.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Sandbox

.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Feeds

.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Both

.NOTES
  The Sandbox connector still requires the operator to enable Defender Live
  Response settings and to review the Defender Antivirus quarantine policy.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Sandbox", "Feeds", "Both")]
  [string]$Connector,

  [string]$TenantId,
  [string]$SubscriptionId,
  [string]$ResourceGroup,
  [string]$Region = "eastus",
  [string]$LogAnalyticsWorkspaceName,
  [switch]$ForceGraphDeviceCode,

  [string]$SandboxAppDisplayName = "ANYRUN-Sandbox-MDE-Connector",
  [string]$SandboxAppId,
  [SecureString]$SandboxClientSecret,
  [SecureString]$SandboxApiKey,
  [string]$SandboxFunctionName,
  [string]$SandboxLogicAppName,
  [string]$SandboxStorageAccountName,
  [string]$SandboxBlobContainerName = "anyrun-quarantine",

  [string]$FeedsAppDisplayName = "ANYRUN-Feeds-MDE-Connector",
  [string]$FeedsAppId,
  [SecureString]$FeedsClientSecret,
  [SecureString]$FeedsApiKey,
  [string]$FeedsFunctionName,
  [string]$FeedsLogicAppName,
  [string]$FeedsStorageAccountName,
  [ValidateRange(1, 168)]
  [int]$FeedsIntervalHours = 2,
  [ValidateRange(1, 365)]
  [int]$FeedsFetchDepthDays = 30,
  [ValidateRange(1, 100)]
  [int]$FeedsMinimumConfidence = 50,
  [ValidateSet("Allowed", "Audit", "Block")]
  [string]$DefenderIndicatorAction = "Audit",

  [ValidateRange(1, 24)]
  [int]$SecretLifetimeMonths = 12,

  [switch]$SkipFunctionApp,
  [switch]$SkipLogicApp,
  [switch]$TestFeedsInvocation,
  [switch]$NonInteractive,
  [switch]$ConfirmDedicatedAppRegistration,
  [switch]$DeferConsent,
  [switch]$RotateClientSecret,

  [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
  [string]$Repository = "yaestkit/anyrun-integration-microsoft",
  [string]$RepositoryRef = "refs/heads/feat/add-install-script",
  [string]$SandboxFunctionTemplateUri,
  [string]$SandboxLogicTemplateUri,
  [string]$FeedsFunctionTemplateUri,
  [string]$FeedsLogicTemplateUri,
  [ValidatePattern('^[0-9a-fA-F]{64}$')]
  [string]$SandboxPackageSha256,
  [ValidatePattern('^[0-9a-fA-F]{64}$')]
  [string]$FeedsPackageSha256,
  [string]$SandboxFunctionTemplateFile,
  [string]$SandboxLogicTemplateFile,
  [string]$FeedsFunctionTemplateFile,
  [string]$FeedsLogicTemplateFile
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version 3.0

$script:WindowsDefenderAtpAppId = "fc780465-2017-40d4-a0c5-307022471b92"
$script:StorageBlobDataOwnerRoleId = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
$script:DeferredConsentUrls = [System.Collections.Generic.List[string]]::new()
$script:DeferredConnectorLabels = [System.Collections.Generic.List[string]]::new()
$sandboxStorageNameWasPassed = $PSBoundParameters.ContainsKey("SandboxStorageAccountName")
$feedsStorageNameWasPassed = $PSBoundParameters.ContainsKey("FeedsStorageAccountName")
$regionWasPassed = $PSBoundParameters.ContainsKey("Region")

$sandboxRoles = @(
  "Alert.ReadWrite.All",
  "Machine.LiveResponse",
  "Machine.Read.All",
  "Ti.ReadWrite",
  "Library.Manage"
)

$feedsRoles = @(
  "Ti.ReadWrite"
)

$encodedRoot = "https://raw.githubusercontent.com/$Repository/$RepositoryRef/Microsoft%20Defender%20for%20Endpoint"
if (-not $SandboxFunctionTemplateUri) { $SandboxFunctionTemplateUri = "$encodedRoot/ANYRUN-Sandbox-MDE/Function%20App/ANYRUN-Sandbox-MDE-FA.json" }
if (-not $SandboxLogicTemplateUri)    { $SandboxLogicTemplateUri    = "$encodedRoot/ANYRUN-Sandbox-MDE/Logic%20App/ANYRUN-Sandbox-MDE-LA.json" }
if (-not $FeedsFunctionTemplateUri)   { $FeedsFunctionTemplateUri   = "$encodedRoot/ANYRUN-TI-Feeds-MDE/Function%20App/ANYRUN-Feeds-MDE-FA.json" }
if (-not $FeedsLogicTemplateUri)      { $FeedsLogicTemplateUri      = "$encodedRoot/ANYRUN-TI-Feeds-MDE/Logic%20App/ANYRUN-Feeds-MDE-LA.json" }

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
    [string]$ValidationMessage = "Invalid value."
  )

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
    [int]$Default = 1
  )

  if ($NonInteractive) { throw "Non-interactive deployment cannot answer prompt: $Prompt" }
  Write-Host ""
  Write-Host "  $Prompt" -ForegroundColor White
  for ($i = 0; $i -lt $Options.Count; $i++) {
    $marker = if (($i + 1) -eq $Default) { " (default)" } else { "" }
    Write-Host "    [$($i + 1)] $($Options[$i])$marker"
  }

  while ($true) {
    $raw = Read-Host "  Choice"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    $selected = 0
    if ([int]::TryParse($raw, [ref]$selected) -and $selected -ge 1 -and $selected -le $Options.Count) {
      return $selected
    }
    Write-Host "    Enter a number from 1 to $($Options.Count)." -ForegroundColor Red
  }
}

function Confirm-Action {
  param([Parameter(Mandatory = $true)][string]$Prompt, [bool]$Default = $true)
  if ($NonInteractive) { return $Default }
  $hint = if ($Default) { "Y/n" } else { "y/N" }
  while ($true) {
    $answer = (Read-Host "$Prompt [$hint]").Trim().ToLowerInvariant()
    if (-not $answer) { return $Default }
    if ($answer -in @("y", "yes")) { return $true }
    if ($answer -in @("n", "no")) { return $false }
  }
}

function Read-RequiredSecret {
  param([Parameter(Mandatory = $true)][string]$Prompt)
  if ($NonInteractive) { throw "Non-interactive deployment requires the secret parameter for: $Prompt" }
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

function Ensure-Module {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][Version]$MinimumVersion
  )
  $compatible = Get-Module -ListAvailable -Name $Name |
    Where-Object Version -ge $MinimumVersion |
    Sort-Object Version -Descending |
    Select-Object -First 1
  if (-not $compatible) {
    Write-Host "  Installing PowerShell module '$Name' (minimum $MinimumVersion) for the current user..." -ForegroundColor Yellow
    Install-Module -Name $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
  }
  Import-Module -Name $Name -MinimumVersion $MinimumVersion -ErrorAction Stop
}

function ConvertFrom-AzRestContent {
  param([Parameter(Mandatory = $true)]$Response)
  if ([string]::IsNullOrWhiteSpace($Response.Content)) { return $null }
  return $Response.Content | ConvertFrom-Json
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
  $response = ConvertFrom-AzRestContent -Response (Invoke-AzRestMethod -Method GET -Path $path)
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

  Ensure-Module "Az.Functions" -MinimumVersion "5.0.1"
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
  $result = ConvertFrom-AzRestContent -Response (Invoke-AzRestMethod -Method POST -Path $path -Payload $body)
  if (-not $result.nameAvailable) {
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
  return ConvertFrom-AzRestContent -Response (Invoke-AzRestMethod -Method POST -Path $path -Payload "{}")
}

function Connect-AzureSmart {
  param([string]$RequestedTenantId, [string]$RequestedSubscriptionId)

  $context = Get-AzContext -ErrorAction SilentlyContinue
  $needsLogin = -not $context
  if ($context -and $RequestedTenantId -and $context.Tenant.Id -ne $RequestedTenantId) { $needsLogin = $true }

  if ($needsLogin) {
    Write-Step "Signing in to Azure..."
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

  $application = $null
  $created = $false
  $newCredentialKeyId = $null
  if ($ExistingAppId) {
    $application = Get-MgApplication -Filter "appId eq '$ExistingAppId'" -Property Id,AppId,DisplayName,RequiredResourceAccess | Select-Object -First 1
    if (-not $application) { throw "No App Registration with client ID '$ExistingAppId' was found." }
    if ($TrustedExistingFunctionBinding) {
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
    $appMatches = @(Get-MgApplication -Filter "displayName eq '$escapedName'" -Property Id,AppId,DisplayName,RequiredResourceAccess)
    if ($appMatches.Count -gt 1) {
      throw "Multiple App Registrations named '$DisplayName' exist. Re-run with the appropriate AppId parameter."
    }
    if ($appMatches.Count -eq 1) {
      Write-Host "  Found existing App Registration '$DisplayName' ($($appMatches[0].AppId))." -ForegroundColor Yellow
      if (Confirm-Action "  Reuse it?" $true) {
        $application = $appMatches[0]
        Write-Host "  Reuse is safe only when this App Registration is dedicated to the $Label connector." -ForegroundColor Yellow
        $dedicatedConfirmed = $ConfirmDedicatedAppRegistration -or (Confirm-Action "  Confirm dedicated use" $false)
        if (-not $dedicatedConfirmed) {
          throw "A dedicated App Registration is required."
        }
      } else {
        $DisplayName = Read-Text -Prompt "New App Registration display name" -Default "$DisplayName-$(Get-Date -Format 'yyyyMMdd')"
      }
    }
  }

  if (-not $application) {
    Write-Step "Creating App Registration '$DisplayName'..."
    $application = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg"
    $application = Get-MgApplication -ApplicationId $application.Id -Property Id,AppId,DisplayName,RequiredResourceAccess
    $created = $true
    Write-Host "  Created App Registration with client ID $($application.AppId)." -ForegroundColor Green
  }

  $appSp = Get-OrCreateClientServicePrincipal -ApplicationId $application.AppId

  if ($Label -eq "TI Feeds" -and -not $created) {
    $existingAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appSp.Id -All)
    $nonFeedsAssignments = @($existingAssignments | Where-Object {
      if ($_.ResourceId.ToString() -ne $wdatpSp.Id.ToString()) { return $false }
      $assignedRoleId = $_.AppRoleId.ToString()
      $assignedRole = $wdatpSp.AppRoles | Where-Object { $_.Id.ToString() -eq $assignedRoleId } | Select-Object -First 1
      return $assignedRole -and $assignedRole.Value -notin @("Ti.Read.All", "Ti.ReadWrite", "Ti.ReadWrite.All")
    })
    if ($nonFeedsAssignments.Count -gt 0) {
      throw "The selected TI Feeds App Registration has non-TI Defender permissions and appears to be shared with another workload. Create a dedicated Feeds App Registration instead."
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
        $choice = Read-Choice -Prompt "Admin consent" -Options @(
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
      $secretChoice = Read-Choice -Prompt "Client secret for '$($application.DisplayName)'" -Options @(
        "Paste an existing secret",
        "Generate a new secret"
      ) -Default 1
      if ($secretChoice -eq 1) {
        $clientSecret = Read-RequiredSecret "  Client secret"
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
  }
}

function Remove-ConnectorDeploymentArtifacts {
  param(
    [Parameter(Mandatory = $true)][string]$StorageAccountName,
    [Parameter(Mandatory = $true)][bool]$AllowRoleCleanup
  )

  # Both official Flex templates use this transient deployment-script name. A
  # failed/cancelled deployment can leave it behind and block the next attempt.
  $waitScript = Get-AzResource -ResourceGroupName $ResourceGroup `
    -ResourceType "Microsoft.Resources/deploymentScripts" -Name "WaitSection" `
    -ErrorAction SilentlyContinue
  if ($waitScript) {
    Write-Host "  Removing leftover transient deployment script 'WaitSection'..." -ForegroundColor Yellow
    Remove-AzResource -ResourceId $waitScript.ResourceId -Force | Out-Null
  }

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
      $_.RoleDefinitionId -like "*$($script:StorageBlobDataOwnerRoleId)"
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
    Write-Host "  Removing stale Storage Blob Data Owner assignment '$($assignment.RoleAssignmentName)'..." -ForegroundColor Yellow
    Remove-AzRoleAssignment -InputObject $assignment | Out-Null
  }
}

function New-PreparedFunctionTemplate {
  param(
    [Parameter(Mandatory = $true)][string]$TemplateUri,
    [Parameter(Mandatory = $true)][ValidateSet("Sandbox", "Feeds")][string]$ConnectorType
  )

  $temporaryPath = Join-Path ([IO.Path]::GetTempPath()) "anyrun-$($ConnectorType.ToLowerInvariant())-$([Guid]::NewGuid().ToString('N')).json"
  Invoke-WebRequest -Uri $TemplateUri -OutFile $temporaryPath
  $template = Get-Content -LiteralPath $temporaryPath -Raw | ConvertFrom-Json
  $extension = @($template.resources | Where-Object type -eq "Microsoft.Web/sites/extensions") | Select-Object -First 1
  if (-not $extension) { throw "Function template '$TemplateUri' does not contain a Microsoft.Web/sites/extensions resource." }

  $packageUri = "$($extension.properties.packageUri)"
  if ([string]::IsNullOrWhiteSpace($packageUri)) {
    throw "$ConnectorType Function template does not define properties.packageUri."
  }

  $expectedPackageHash = if ($ConnectorType -eq "Sandbox") { $SandboxPackageSha256 } else { $FeedsPackageSha256 }
  if ($expectedPackageHash) {
    $packagePath = Join-Path ([IO.Path]::GetTempPath()) "anyrun-package-$([Guid]::NewGuid().ToString('N')).zip"
    try {
      Invoke-WebRequest -Uri $packageUri -OutFile $packagePath
      $actualPackageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
      if ($actualPackageHash -ne $expectedPackageHash) {
        throw "$ConnectorType package SHA-256 mismatch. Expected $expectedPackageHash but downloaded $actualPackageHash."
      }
      Write-Host "  Verified $ConnectorType Function package SHA-256." -ForegroundColor Green
    } finally {
      Remove-Item -LiteralPath $packagePath -Force -ErrorAction SilentlyContinue
    }
  } else {
    Write-Host "  WARNING: no package SHA-256 was supplied; the package URI declared by the template will be used without content-hash verification." -ForegroundColor Yellow
  }

  # The upstream templates use a fixed 30-second deploymentScript. Besides
  # requiring Microsoft.ContainerInstance, it does not guarantee that the role
  # assignment is ready. Depend on the actual assignment resource instead.
  $template.resources = @($template.resources | Where-Object {
    -not ($_.type -eq "Microsoft.Resources/deploymentScripts" -and $_.name -eq "WaitSection")
  })
  $roleAssignment = @($template.resources | Where-Object type -eq "Microsoft.Authorization/roleAssignments") | Select-Object -First 1
  if ($roleAssignment) {
    if (-not $roleAssignment.scope -or "$($roleAssignment.scope)" -notmatch 'Microsoft\.Storage/storageAccounts') {
      throw "$ConnectorType Function template storage role assignment is not scoped to the connector storage account."
    }
    $roleAssignment.properties | Add-Member -NotePropertyName principalType -NotePropertyValue "ServicePrincipal" -Force

    # A role assignment with scope=storageAccount is an ARM extension resource.
    # Its dependency ID must include that scope; resourceId(roleAssignments, ...)
    # would point at a different resource at resource-group scope.
    $roleAssignmentNameExpression = "$($roleAssignment.name)".Trim()
    if ($roleAssignmentNameExpression.StartsWith('[') -and $roleAssignmentNameExpression.EndsWith(']')) {
      $roleAssignmentNameExpression = $roleAssignmentNameExpression.Substring(1, $roleAssignmentNameExpression.Length - 2)
    }
    $extension.dependsOn = @("[extensionResourceId(resourceId('Microsoft.Storage/storageAccounts', parameters('AzureStorageAccountName')), 'Microsoft.Authorization/roleAssignments', $roleAssignmentNameExpression)]")
  } else {
    # A template that has already received the scoped-RBAC fix keeps the role
    # assignment inside a nested deployment. Preserve it and make onedeploy
    # depend on that deployment instead of trying to transform it again.
    $roleDeployment = @($template.resources | Where-Object {
      $_.type -eq "Microsoft.Resources/deployments" -and
      $_.properties.template -and
      @($_.properties.template.resources | Where-Object type -eq "Microsoft.Authorization/roleAssignments").Count -gt 0
    }) | Select-Object -First 1
    if (-not $roleDeployment) { throw "$ConnectorType Function template does not contain its storage role assignment." }

    $nestedRoleAssignment = @($roleDeployment.properties.template.resources | Where-Object type -eq "Microsoft.Authorization/roleAssignments") | Select-Object -First 1
    if (-not $nestedRoleAssignment.scope -or "$($nestedRoleAssignment.scope)" -notmatch 'Microsoft\.Storage/storageAccounts') {
      throw "$ConnectorType Function template storage role assignment is not scoped to the connector storage account."
    }
    $nestedRoleAssignment.properties | Add-Member -NotePropertyName principalType -NotePropertyValue "ServicePrincipal" -Force

    $roleDeploymentNameExpression = "$($roleDeployment.name)".Trim()
    if ($roleDeploymentNameExpression.StartsWith('[') -and $roleDeploymentNameExpression.EndsWith(']')) {
      $roleDeploymentNameExpression = $roleDeploymentNameExpression.Substring(1, $roleDeploymentNameExpression.Length - 2)
    } else {
      $escapedRoleDeploymentName = $roleDeploymentNameExpression.Replace("'", "''")
      $roleDeploymentNameExpression = "'$escapedRoleDeploymentName'"
    }
    $extension.dependsOn = @("[resourceId('Microsoft.Resources/deployments', $roleDeploymentNameExpression)]")
  }
  $template | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $temporaryPath -Encoding utf8NoBOM
  Write-Host "  Prepared $ConnectorType Function template without rewriting packageUri ('$packageUri')." -ForegroundColor DarkGray
  return $temporaryPath
}

function New-RegionalLogicTemplate {
  param(
    [Parameter(Mandatory = $true)][string]$TemplateUri,
    [Parameter(Mandatory = $true)][ValidateSet("Sandbox", "Feeds")][string]$ConnectorType
  )

  $temporaryPath = Join-Path ([IO.Path]::GetTempPath()) "anyrun-$($ConnectorType.ToLowerInvariant())-logic-$([Guid]::NewGuid().ToString('N')).json"
  Invoke-WebRequest -Uri $TemplateUri -OutFile $temporaryPath
  $template = Get-Content -LiteralPath $temporaryPath -Raw | ConvertFrom-Json
  $workflow = @($template.resources | Where-Object type -eq "Microsoft.Logic/workflows") | Select-Object -First 1
  if (-not $workflow) { throw "$ConnectorType Logic App template does not contain a Microsoft.Logic/workflows resource." }
  $workflow.location = "[resourceGroup().location]"
  $template | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $temporaryPath -Encoding utf8NoBOM
  return $temporaryPath
}

function Test-ArmDeployment {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [string]$TemplateUri,
    [string]$TemplateFile,
    [Parameter(Mandatory = $true)][hashtable]$TemplateParameters
  )

  $splat = @{
    ResourceGroupName       = $ResourceGroup
    TemplateParameterObject = $TemplateParameters
    ErrorAction             = "Stop"
  }
  if ($TemplateFile) { $splat.TemplateFile = $TemplateFile }
  else               { $splat.TemplateUri = $TemplateUri }

  Write-Step "Validating $Label against Azure Policy and ARM..."
  $validationErrors = @(Test-AzResourceGroupDeployment @splat)
  if ($validationErrors.Count -gt 0) {
    $messages = @($validationErrors | ForEach-Object { $_.Message }) -join "`n"
    throw "$Label pre-flight validation failed:`n$messages"
  }
  Write-Host "  $Label ARM validation succeeded." -ForegroundColor Green
}

function Invoke-ArmDeployment {
  param(
    [string]$Label,
    [string]$TemplateUri,
    [string]$TemplateFile,
    [hashtable]$TemplateParameters
  )

  if ($TemplateFile) {
    if (-not (Test-Path -LiteralPath $TemplateFile -PathType Leaf)) { throw "Template file '$TemplateFile' does not exist." }
  } elseif (-not $TemplateUri) {
    throw "No template URI or file was supplied for '$Label'."
  }

  $baseName = ("anyrun-{0}-{1}" -f ($Label -replace '[^a-zA-Z0-9-]', '-').ToLowerInvariant(), (Get-Date -Format 'yyyyMMddHHmmss'))
  $maxAttempts = 5
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    $deploymentName = "$baseName-$attempt"
    $splat = @{
      Name                    = $deploymentName
      ResourceGroupName       = $ResourceGroup
      TemplateParameterObject = $TemplateParameters
      Mode                    = "Incremental"
    }
    if ($TemplateFile) { $splat.TemplateFile = $TemplateFile }
    else               { $splat.TemplateUri = $TemplateUri }

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
        Where-Object ProvisioningState -eq "Failed")
      $operationMessages = @($failedOperations | ForEach-Object {
        if ($_.StatusMessage) { "$($_.StatusMessage)" } else { "$($_.ProvisioningState)" }
      }) -join " `n"
      $message = "$message $operationMessages"

      $identityNotReady = $message -match 'PrincipalNotFound|replication delay|does not exist in the directory'
      $packageRbacNotReady = $message -match 'AuthorizationPermissionMismatch' -or (
        $message -match '(?i)(?:status\s*code|http)?\s*403|Forbidden' -and
        $message -match '(?i)onedeploy|sites/extensions|package|blob|storage'
      )
      if ($attempt -lt $maxAttempts -and ($identityNotReady -or $packageRbacNotReady)) {
        $waitSeconds = if ($packageRbacNotReady) { 45 } else { 30 }
        $reason = if ($packageRbacNotReady) { "Storage data-plane RBAC has not propagated to onedeploy" } else { "Managed identity has not replicated" }
        Write-Host "  $reason; waiting $waitSeconds seconds before retry." -ForegroundColor Yellow
        Start-Sleep -Seconds $waitSeconds
        continue
      }
      Write-Host "  Failed deployment operations:" -ForegroundColor Yellow
      $failedOperations | ForEach-Object {
          $statusMessage = if ($_.StatusMessage) { $_.StatusMessage } else { $_.ProvisioningState }
          Write-Host "    $($_.TargetResource.ResourceName): $statusMessage" -ForegroundColor Yellow
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

function Wait-FunctionRegistration {
  param(
    [Parameter(Mandatory = $true)][string]$FunctionAppName,
    [Parameter(Mandatory = $true)][string]$FunctionName,
    [int]$Attempts = 36
  )

  $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$FunctionAppName/functions?api-version=2022-03-01"
  for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    try {
      $result = ConvertFrom-AzRestContent -Response (Invoke-AzRestMethod -Method GET -Path $path)
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
    $runs = ConvertFrom-AzRestContent -Response (Invoke-AzRestMethod -Method GET -Path $runsPath)
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

Write-Banner "ANY.RUN Microsoft Defender for Endpoint connector deployment"

$deploySandbox = $Connector -in @("Sandbox", "Both")
$deployFeeds = $Connector -in @("Feeds", "Both")
if ($RotateClientSecret -and $SkipFunctionApp) {
  throw "-RotateClientSecret cannot be combined with -SkipFunctionApp because the Function App must receive the new secret."
}

Write-Phase "0" "Pre-flight"
Write-Step "Loading required PowerShell modules..."
Ensure-Module "Az.Accounts" -MinimumVersion "5.5.3"
Ensure-Module "Az.Resources" -MinimumVersion "10.2.1"
Ensure-Module "Az.Storage" -MinimumVersion "9.7.2"
Ensure-Module "Az.OperationalInsights" -MinimumVersion "3.4.1"
Ensure-Module "Microsoft.Graph.Authentication" -MinimumVersion "2.40.0"
Ensure-Module "Microsoft.Graph.Applications" -MinimumVersion "2.40.0"

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
  $ResourceGroup = Read-Text -Prompt "Resource group name" -Default "rg-anyrun-mde"
}
$existingResourceGroup = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
if ($existingResourceGroup) {
  $Region = $existingResourceGroup.Location
} elseif (-not $regionWasPassed) {
  if ($NonInteractive) {
    throw "A new resource group requires an explicit -Region in non-interactive mode."
  }
  $Region = Read-Text -Prompt "Azure region" -Default $Region
}
Write-Step "Checking Azure providers and Flex Consumption support before creating the resource group..."
foreach ($providerNamespace in @("Microsoft.Web", "Microsoft.Storage", "Microsoft.Insights", "Microsoft.OperationalInsights", "Microsoft.Logic")) {
  Ensure-ResourceProvider -ProviderNamespace $providerNamespace
}
Assert-FlexConsumptionRegion -Location $Region
$resourceGroupObject = Ensure-ResourceGroup -Name $ResourceGroup -Location $Region
$Region = $resourceGroupObject.Location

$stableSuffix = Get-StableSuffix -InputText "$TenantId|$SubscriptionId|$ResourceGroup" -Length 8
if (-not $LogAnalyticsWorkspaceName) { $LogAnalyticsWorkspaceName = "anyrun-mde-law-$stableSuffix" }
if ($deploySandbox) {
  if (-not $SandboxFunctionName)       { $SandboxFunctionName = "anyrun-sandbox-mde-$stableSuffix" }
  if (-not $SandboxLogicAppName)       { $SandboxLogicAppName = "ANYRUN-Sandbox-MDE-LA-$stableSuffix" }
  if (-not $SandboxStorageAccountName) { $SandboxStorageAccountName = "arsb$stableSuffix" }
  Assert-FunctionName -Name $SandboxFunctionName
}
if ($deployFeeds) {
  if (-not $FeedsFunctionName)       { $FeedsFunctionName = "anyrun-feeds-mde-$stableSuffix" }
  if (-not $FeedsLogicAppName)       { $FeedsLogicAppName = "ANYRUN-Feeds-MDE-LA-$stableSuffix" }
  if (-not $FeedsStorageAccountName) { $FeedsStorageAccountName = "arfd$stableSuffix" }
  Assert-FunctionName -Name $FeedsFunctionName
}

Write-Step "Checking permissions and global names before changing Entra ID..."
$resourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
if (-not (Test-EffectiveRoleAssignmentPermission -Scope $resourceGroupScope)) {
  throw "The signed-in account does not have Microsoft.Authorization/roleAssignments/write at '$resourceGroupScope'. Use Owner or User Access Administrator plus Contributor."
}
if ($deploySandbox) { Assert-FunctionAppNameAvailable -Name $SandboxFunctionName }
if ($deployFeeds)   { Assert-FunctionAppNameAvailable -Name $FeedsFunctionName }
if ($deploySandbox) { Assert-StorageAccountUsable -Name $SandboxStorageAccountName.ToLowerInvariant() }
if ($deployFeeds)   { Assert-StorageAccountUsable -Name $FeedsStorageAccountName.ToLowerInvariant() }

Write-Phase "1" "Azure resources and ARM validation"
$workspace = Ensure-LogAnalyticsWorkspace -ResourceGroupName $ResourceGroup -Name $LogAnalyticsWorkspaceName -Location $Region
Write-Host "  Workspace: $($workspace.Name)" -ForegroundColor Green

# On re-runs, recover the existing runtime configuration instead of forcing the
# operator to retain secrets or creating another credential every time.
$sandboxIdentityRecoveredFromFunction = $false
$feedsIdentityRecoveredFromFunction = $false
if ($deploySandbox) {
  $sandboxExistingConfiguration = Get-ExistingFunctionConfiguration -FunctionAppName $SandboxFunctionName
  if ($SkipFunctionApp -and -not $sandboxExistingConfiguration) {
    throw "-SkipFunctionApp was specified, but Function App '$SandboxFunctionName' does not exist."
  }
  if ($sandboxExistingConfiguration) {
    $settings = $sandboxExistingConfiguration.properties
    $existingClientId = Get-ObjectPropertyValue -InputObject $settings -Name "AzureClientID"
    $existingClientSecret = Get-ObjectPropertyValue -InputObject $settings -Name "AzureClientSecret"
    $existingApiKey = Get-ObjectPropertyValue -InputObject $settings -Name "ANYRUN_API_KEY"
    if (-not $SandboxAppId) { $SandboxAppId = $existingClientId }
    elseif ($existingClientId -and $existingClientId -ne $SandboxAppId) {
      throw "SandboxAppId '$SandboxAppId' does not match the existing Function App configuration."
    }
    if ($existingClientId) { $sandboxIdentityRecoveredFromFunction = $true }
    if (-not $RotateClientSecret -and -not $SandboxClientSecret -and $existingClientSecret) {
      $SandboxClientSecret = ConvertTo-SecureValue -Value $existingClientSecret
    }
    if (-not $SandboxApiKey -and $existingApiKey) {
      $sandboxKey = "$existingApiKey" -replace '^API-KEY\s+', ''
      $SandboxApiKey = ConvertTo-SecureValue -Value $sandboxKey
    }
    Write-Host "  Recovered Sandbox credentials from the existing Function App settings." -ForegroundColor Green
  }
}
if ($deployFeeds) {
  $feedsExistingConfiguration = Get-ExistingFunctionConfiguration -FunctionAppName $FeedsFunctionName
  if ($SkipFunctionApp -and -not $feedsExistingConfiguration) {
    throw "-SkipFunctionApp was specified, but Function App '$FeedsFunctionName' does not exist."
  }
  if ($feedsExistingConfiguration) {
    $settings = $feedsExistingConfiguration.properties
    $existingClientId = Get-ObjectPropertyValue -InputObject $settings -Name "AzureClientID"
    $existingClientSecret = Get-ObjectPropertyValue -InputObject $settings -Name "AzureClientSecret"
    $existingApiKey = Get-ObjectPropertyValue -InputObject $settings -Name "ANYRUN_api_key"
    if (-not $FeedsAppId) { $FeedsAppId = $existingClientId }
    elseif ($existingClientId -and $existingClientId -ne $FeedsAppId) {
      throw "FeedsAppId '$FeedsAppId' does not match the existing Function App configuration."
    }
    if ($existingClientId) { $feedsIdentityRecoveredFromFunction = $true }
    if (-not $RotateClientSecret -and -not $FeedsClientSecret -and $existingClientSecret) {
      $FeedsClientSecret = ConvertTo-SecureValue -Value $existingClientSecret
    }
    if (-not $FeedsApiKey -and $existingApiKey) {
      $FeedsApiKey = ConvertTo-SecureValue -Value $existingApiKey
    }
    Write-Host "  Recovered TI Feeds credentials from the existing Function App settings." -ForegroundColor Green
  }
}

$effectiveSandboxFunctionTemplate = $SandboxFunctionTemplateFile
$removeSandboxTemplate = $false
$effectiveFeedsFunctionTemplate = $FeedsFunctionTemplateFile
$removeFeedsTemplate = $false
if (-not $SkipFunctionApp) {
  $placeholderSecret = ConvertTo-SecureValue -Value "preflight-placeholder"
  if ($deploySandbox) {
    if (-not $effectiveSandboxFunctionTemplate) {
      $effectiveSandboxFunctionTemplate = New-PreparedFunctionTemplate -TemplateUri $SandboxFunctionTemplateUri -ConnectorType Sandbox
      $removeSandboxTemplate = $true
    }
    Test-ArmDeployment -Label "Sandbox Function App" -TemplateUri $SandboxFunctionTemplateUri `
      -TemplateFile $effectiveSandboxFunctionTemplate -TemplateParameters @{
        functionAppName = $SandboxFunctionName; AzureTenantID = $TenantId
        AzureClientID = "00000000-0000-0000-0000-000000000000"; AzureClientSecret = $placeholderSecret
        AzureStorageAccountName = $SandboxStorageAccountName; AzureStorageAccountKey = $placeholderSecret
        AzureStorageConnectionString = $placeholderSecret; AzureBlobContainerName = $SandboxBlobContainerName
        ANYRUN_API_KEY = $placeholderSecret; LogAnalyticsWorkspaceName = $LogAnalyticsWorkspaceName
      }
  }
  if ($deployFeeds) {
    if (-not $effectiveFeedsFunctionTemplate) {
      $effectiveFeedsFunctionTemplate = New-PreparedFunctionTemplate -TemplateUri $FeedsFunctionTemplateUri -ConnectorType Feeds
      $removeFeedsTemplate = $true
    }
    Test-ArmDeployment -Label "TI Feeds Function App" -TemplateUri $FeedsFunctionTemplateUri `
      -TemplateFile $effectiveFeedsFunctionTemplate -TemplateParameters @{
        functionAppName = $FeedsFunctionName; anyrunApiKey = $placeholderSecret
        AzureClientID = "00000000-0000-0000-0000-000000000000"; AzureClientSecret = $placeholderSecret
        AzureTenantID = $TenantId; AzureStorageAccountName = $FeedsStorageAccountName
        AzureStorageConnectionString = $placeholderSecret; LogAnalyticsWorkspaceName = $LogAnalyticsWorkspaceName
        DefenderIndicatorAction = $DefenderIndicatorAction
      }
  }
}

$sandboxStorage = $null
$feedsStorage = $null
if ($deploySandbox) {
  $sandboxStorage = Ensure-StorageAccount -ResourceGroupName $ResourceGroup -Name $SandboxStorageAccountName.ToLowerInvariant() -Location $Region
  if (-not $SandboxApiKey) { $SandboxApiKey = Read-RequiredSecret "  ANY.RUN Sandbox API key (without the 'API-KEY ' prefix)" }
}
if ($deployFeeds) {
  $feedsStorage = Ensure-StorageAccount -ResourceGroupName $ResourceGroup -Name $FeedsStorageAccountName.ToLowerInvariant() -Location $Region
  if (-not $FeedsApiKey) { $FeedsApiKey = Read-RequiredSecret "  ANY.RUN TI Feeds API key (without a prefix)" }
}

Write-Phase "2" "App Registration and API permissions"
$sandboxIdentity = $null
$feedsIdentity = $null

if ($deploySandbox) {
  $sandboxIdentity = Ensure-ConnectorIdentity -Label "Sandbox" -DisplayName $SandboxAppDisplayName `
    -ExistingAppId $SandboxAppId -ExistingClientSecret $SandboxClientSecret -RequiredRoleValues $sandboxRoles `
    -TrustedExistingFunctionBinding $sandboxIdentityRecoveredFromFunction -RotateSecret:$RotateClientSecret
}
if ($deployFeeds) {
  $feedsIdentity = Ensure-ConnectorIdentity -Label "TI Feeds" -DisplayName $FeedsAppDisplayName `
    -ExistingAppId $FeedsAppId -ExistingClientSecret $FeedsClientSecret -RequiredRoleValues $feedsRoles `
    -TrustedExistingFunctionBinding $feedsIdentityRecoveredFromFunction -RotateSecret:$RotateClientSecret
}

Write-Phase "3" "Function Apps"
$sandboxFunctionDeployed = $false
$feedsFunctionDeployed = $false
if ($deploySandbox -and -not $SkipFunctionApp) {
  Remove-ConnectorDeploymentArtifacts -StorageAccountName $sandboxStorage.Name `
    -AllowRoleCleanup (-not $sandboxStorageNameWasPassed)
  $sandboxFunctionParameters = @{
    functionAppName              = $SandboxFunctionName
    AzureTenantID                = $TenantId
    AzureClientID                = $sandboxIdentity.ClientId
    AzureClientSecret            = $sandboxIdentity.ClientSecret
    AzureStorageAccountName      = $sandboxStorage.Name
    AzureStorageAccountKey       = $sandboxStorage.Key
    AzureStorageConnectionString = $sandboxStorage.ConnectionString
    AzureBlobContainerName       = $SandboxBlobContainerName
    ANYRUN_API_KEY               = $SandboxApiKey
    LogAnalyticsWorkspaceName    = $LogAnalyticsWorkspaceName
  }
  try {
    Invoke-ArmDeployment -Label "Sandbox Function App" -TemplateUri $SandboxFunctionTemplateUri `
      -TemplateFile $effectiveSandboxFunctionTemplate -TemplateParameters $sandboxFunctionParameters | Out-Null
    $sandboxFunctionDeployed = $true
  } finally {
    if ($removeSandboxTemplate) { Remove-Item -LiteralPath $effectiveSandboxFunctionTemplate -Force -ErrorAction SilentlyContinue }
  }
  Remove-ConnectorDeploymentArtifacts -StorageAccountName $sandboxStorage.Name `
    -AllowRoleCleanup (-not $sandboxStorageNameWasPassed)
}

if ($deployFeeds -and -not $SkipFunctionApp) {
  Remove-ConnectorDeploymentArtifacts -StorageAccountName $feedsStorage.Name `
    -AllowRoleCleanup (-not $feedsStorageNameWasPassed)
  $feedsFunctionParameters = @{
    functionAppName              = $FeedsFunctionName
    anyrunApiKey                 = $FeedsApiKey
    AzureClientID                = $feedsIdentity.ClientId
    AzureClientSecret            = $feedsIdentity.ClientSecret
    AzureTenantID                = $TenantId
    AzureStorageAccountName      = $feedsStorage.Name
    AzureStorageConnectionString = $feedsStorage.ConnectionString
    LogAnalyticsWorkspaceName    = $LogAnalyticsWorkspaceName
    DefenderIndicatorAction      = $DefenderIndicatorAction
  }
  try {
    Invoke-ArmDeployment -Label "TI Feeds Function App" -TemplateUri $FeedsFunctionTemplateUri `
      -TemplateFile $effectiveFeedsFunctionTemplate -TemplateParameters $feedsFunctionParameters | Out-Null
    $feedsFunctionDeployed = $true
  } finally {
    if ($removeFeedsTemplate) { Remove-Item -LiteralPath $effectiveFeedsFunctionTemplate -Force -ErrorAction SilentlyContinue }
  }
  Remove-ConnectorDeploymentArtifacts -StorageAccountName $feedsStorage.Name `
    -AllowRoleCleanup (-not $feedsStorageNameWasPassed)
}
if ($SkipFunctionApp) {
  Write-Host "  Function App deployment skipped; existing apps will be verified before Logic App deployment." -ForegroundColor Yellow
}

Write-Phase "4" "Logic Apps"
$sandboxLogicDeployed = $false
$feedsLogicDeployed = $false
if ($deploySandbox -and -not $SkipLogicApp -and -not $sandboxIdentity.ConsentDeferred) {
  Wait-FunctionRegistration -FunctionAppName $SandboxFunctionName -FunctionName "ANYRUN-Sandbox-MDE-FA"
  $sandboxLogicParameters = @{
    logicAppName      = $SandboxLogicAppName
    azureTenantId     = $TenantId
    azureClientId     = $sandboxIdentity.ClientId
    azureClientSecret = $sandboxIdentity.ClientSecret
    functionAppName   = $SandboxFunctionName
  }
  Invoke-ArmDeployment -Label "Sandbox Logic App" -TemplateUri $SandboxLogicTemplateUri `
    -TemplateFile $SandboxLogicTemplateFile -TemplateParameters $sandboxLogicParameters | Out-Null
  $sandboxLogicDeployed = $true
} elseif ($deploySandbox -and $sandboxIdentity.ConsentDeferred) {
  Write-Host "  Sandbox Logic App skipped because Defender admin consent is not complete." -ForegroundColor Yellow
}

if ($deployFeeds -and -not $SkipLogicApp -and -not $feedsIdentity.ConsentDeferred) {
  Wait-FunctionRegistration -FunctionAppName $FeedsFunctionName -FunctionName "ANYRUN-Feeds-MDE-FA"
  $feedsLogicParameters = @{
    logicAppName               = $FeedsLogicAppName
    intervalRecurrence         = $FeedsIntervalHours
    feedFetchDepth             = $FeedsFetchDepthDays
    minimum_confidence_threshold = $FeedsMinimumConfidence
    functionAppName            = $FeedsFunctionName
  }
  $effectiveFeedsLogicTemplate = $FeedsLogicTemplateFile
  $removeFeedsLogicTemplate = $false
  if (-not $effectiveFeedsLogicTemplate) {
    $effectiveFeedsLogicTemplate = New-RegionalLogicTemplate -TemplateUri $FeedsLogicTemplateUri -ConnectorType Feeds
    $removeFeedsLogicTemplate = $true
  }
  try {
    Invoke-ArmDeployment -Label "TI Feeds Logic App" -TemplateUri $FeedsLogicTemplateUri `
      -TemplateFile $effectiveFeedsLogicTemplate -TemplateParameters $feedsLogicParameters | Out-Null
    $feedsLogicDeployed = $true
  } finally {
    if ($removeFeedsLogicTemplate) { Remove-Item -LiteralPath $effectiveFeedsLogicTemplate -Force -ErrorAction SilentlyContinue }
  }
} elseif ($deployFeeds -and $feedsIdentity.ConsentDeferred) {
  Write-Host "  TI Feeds Logic App skipped because Defender admin consent is not complete." -ForegroundColor Yellow
}
if ($SkipLogicApp) {
  Write-Host "  Logic App deployment was skipped by -SkipLogicApp." -ForegroundColor Yellow
}

Write-Phase "5" "Verification"
$verificationFailures = [System.Collections.Generic.List[string]]::new()
if ($deploySandbox) {
  try { Wait-FunctionRegistration -FunctionAppName $SandboxFunctionName -FunctionName "ANYRUN-Sandbox-MDE-FA" -Attempts 1 }
  catch { $verificationFailures.Add($_.Exception.Message) }
  $sandboxFunctionState = Get-ResourceProvisioningState -ResourceType "Microsoft.Web/sites" -Name $SandboxFunctionName
  Write-Host "  Sandbox Function App : $sandboxFunctionState" -ForegroundColor White
  if ($sandboxFunctionState -notin @("Running", "Succeeded")) { $verificationFailures.Add("Sandbox Function App state is '$sandboxFunctionState'.") }
  if ($sandboxLogicDeployed -or (-not $SkipLogicApp -and -not $sandboxIdentity.ConsentDeferred)) {
    $sandboxLogicState = Get-ResourceProvisioningState -ResourceType "Microsoft.Logic/workflows" -Name $SandboxLogicAppName
    $sandboxConnectionState = Get-ApiConnectionStatus -Name "wdatp--anyrun-app"
    Write-Host "  Sandbox Logic App    : $sandboxLogicState" -ForegroundColor White
    Write-Host "  WDATP connection     : $sandboxConnectionState" -ForegroundColor White
    if ($sandboxLogicState -ne "Succeeded") { $verificationFailures.Add("Sandbox Logic App state is '$sandboxLogicState'.") }
    if ($sandboxConnectionState -ne "Connected") { $verificationFailures.Add("WDATP API connection state is '$sandboxConnectionState'.") }
  }
}
if ($deployFeeds) {
  try { Wait-FunctionRegistration -FunctionAppName $FeedsFunctionName -FunctionName "ANYRUN-Feeds-MDE-FA" -Attempts 1 }
  catch { $verificationFailures.Add($_.Exception.Message) }
  $feedsFunctionState = Get-ResourceProvisioningState -ResourceType "Microsoft.Web/sites" -Name $FeedsFunctionName
  Write-Host "  Feeds Function App   : $feedsFunctionState" -ForegroundColor White
  if ($feedsFunctionState -notin @("Running", "Succeeded")) { $verificationFailures.Add("Feeds Function App state is '$feedsFunctionState'.") }
  if ($feedsLogicDeployed -or (-not $SkipLogicApp -and -not $feedsIdentity.ConsentDeferred)) {
    $feedsLogicState = Get-ResourceProvisioningState -ResourceType "Microsoft.Logic/workflows" -Name $FeedsLogicAppName
    Write-Host "  Feeds Logic App      : $feedsLogicState" -ForegroundColor White
    if ($feedsLogicState -ne "Succeeded") { $verificationFailures.Add("Feeds Logic App state is '$feedsLogicState'.") }
    if ($TestFeedsInvocation -and $feedsLogicState -eq "Succeeded") {
      try { Invoke-FeedsSmokeTest -LogicAppName $FeedsLogicAppName }
      catch { $verificationFailures.Add("Feeds Logic App smoke test failed: $($_.Exception.Message)") }
    }
  }
}

if ($verificationFailures.Count -eq 0) {
  if (-not $ForceGraphDeviceCode -and (($deploySandbox -and $sandboxIdentity.NewCredentialKeyId) -or ($deployFeeds -and $feedsIdentity.NewCredentialKeyId))) {
    Connect-GraphSmart -RequestedTenantId $TenantId
  }
  if ($deploySandbox -and $sandboxFunctionDeployed -and $sandboxLogicDeployed -and -not $sandboxIdentity.ConsentDeferred -and $sandboxIdentity.NewCredentialKeyId) {
    Remove-OldConnectorSecrets -ApplicationObjectId $sandboxIdentity.ApplicationObjectId `
      -CurrentKeyId $sandboxIdentity.NewCredentialKeyId -Label "Sandbox"
  }
  if ($deployFeeds -and $feedsFunctionDeployed -and $feedsLogicDeployed -and -not $feedsIdentity.ConsentDeferred -and $feedsIdentity.NewCredentialKeyId) {
    Remove-OldConnectorSecrets -ApplicationObjectId $feedsIdentity.ApplicationObjectId `
      -CurrentKeyId $feedsIdentity.NewCredentialKeyId -Label "TI Feeds"
  }
}

Write-Banner "Deployment summary"
Write-Host "  Resource group : $ResourceGroup" -ForegroundColor White
Write-Host "  Region         : $Region" -ForegroundColor White
Write-Host "  Log Analytics  : $LogAnalyticsWorkspaceName" -ForegroundColor White
if ($deploySandbox) {
  Write-Host ""
  Write-Host "  Sandbox App Registration : $($sandboxIdentity.DisplayName) ($($sandboxIdentity.ClientId))" -ForegroundColor White
  Write-Host "  Sandbox Function App     : $SandboxFunctionName" -ForegroundColor White
  Write-Host "  Sandbox Logic App        : $SandboxLogicAppName" -ForegroundColor White
  Write-Host "  Sandbox Storage          : $($sandboxStorage.Name)" -ForegroundColor White
}
if ($deployFeeds) {
  Write-Host ""
  Write-Host "  Feeds App Registration   : $($feedsIdentity.DisplayName) ($($feedsIdentity.ClientId))" -ForegroundColor White
  Write-Host "  Feeds Function App       : $FeedsFunctionName" -ForegroundColor White
  Write-Host "  Feeds Logic App          : $FeedsLogicAppName" -ForegroundColor White
  Write-Host "  Feeds Storage            : $($feedsStorage.Name)" -ForegroundColor White
}

if ($script:DeferredConsentUrls.Count -gt 0) {
  Write-Host ""
  Write-Host "  ACTION REQUIRED - grant admin consent:" -ForegroundColor Yellow
  $script:DeferredConsentUrls | Sort-Object -Unique | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
  Write-Host "  After consent is granted, resume without redeploying the Function App:" -ForegroundColor Yellow
  $continuationArguments = [System.Collections.Generic.List[string]]::new()
  $continuationArguments.Add("-Connector $(ConvertTo-PowerShellLiteral $Connector)")
  $continuationArguments.Add("-TenantId $(ConvertTo-PowerShellLiteral $TenantId)")
  $continuationArguments.Add("-SubscriptionId $(ConvertTo-PowerShellLiteral $SubscriptionId)")
  $continuationArguments.Add("-ResourceGroup $(ConvertTo-PowerShellLiteral $ResourceGroup)")
  $continuationArguments.Add("-Region $(ConvertTo-PowerShellLiteral $Region)")
  $continuationArguments.Add("-LogAnalyticsWorkspaceName $(ConvertTo-PowerShellLiteral $LogAnalyticsWorkspaceName)")
  $continuationArguments.Add("-Repository $(ConvertTo-PowerShellLiteral $Repository)")
  $continuationArguments.Add("-RepositoryRef $(ConvertTo-PowerShellLiteral $RepositoryRef)")
  if ($deploySandbox) {
    $continuationArguments.Add("-SandboxFunctionName $(ConvertTo-PowerShellLiteral $SandboxFunctionName)")
    $continuationArguments.Add("-SandboxLogicAppName $(ConvertTo-PowerShellLiteral $SandboxLogicAppName)")
    $continuationArguments.Add("-SandboxStorageAccountName $(ConvertTo-PowerShellLiteral $SandboxStorageAccountName)")
  }
  if ($deployFeeds) {
    $continuationArguments.Add("-FeedsFunctionName $(ConvertTo-PowerShellLiteral $FeedsFunctionName)")
    $continuationArguments.Add("-FeedsLogicAppName $(ConvertTo-PowerShellLiteral $FeedsLogicAppName)")
    $continuationArguments.Add("-FeedsStorageAccountName $(ConvertTo-PowerShellLiteral $FeedsStorageAccountName)")
  }
  $continuationArguments.Add("-SkipFunctionApp")
  Write-Host "    ./Deploy-ANYRUNMDEConnector.ps1 $($continuationArguments -join ' ')" -ForegroundColor Cyan
}

if ($deploySandbox) {
  Write-Host ""
  Write-Host "  ACTION REQUIRED - Defender for Endpoint settings:" -ForegroundColor Yellow
  Write-Host "    1. Open https://security.microsoft.com" -ForegroundColor White
  Write-Host "    2. Go to Settings > Endpoints > Advanced features." -ForegroundColor White
  Write-Host "    3. Enable Live Response and Live Response for Servers." -ForegroundColor White
  Write-Host "    4. Enable Live Response unsigned script execution after reviewing the risk." -ForegroundColor White
  Write-Host "    5. Review the Defender Antivirus quarantine policy. The installer does not change it." -ForegroundColor White
}

Write-Host ""
if ($verificationFailures.Count -gt 0) {
  Write-Host "Deployment verification failed:" -ForegroundColor Red
  $verificationFailures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
  throw "Deployment completed with verification failures. Review the messages above before using the connector."
}
if ($script:DeferredConsentUrls.Count -gt 0) {
  Write-Host "Function deployment finished, but connector activation is incomplete until admin consent and the Logic App continuation run succeed." -ForegroundColor Yellow
} else {
  Write-Host "Deployment finished. API keys and client secrets were not printed." -ForegroundColor Green
}
