#Requires -Version 7.4
<#
.SYNOPSIS
  Installs ANY.RUN Sandbox, TI Feeds, or both in a new or explicitly approved Azure resource group.
.DESCRIPTION
  A single readable script downloads pinned, hash-verified release files. Run serially in PowerShell 7.4+, preferably
  Azure Cloud Shell. Re-run the same command to finish an interrupted installation.
  Existing integrations from other installers are never imported. See README.md.
.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Both -ResourceGroup rg-anyrun-mde
.EXAMPLE
  ./Deploy-ANYRUNMDEConnector.ps1 -Connector Feeds -PlanOnly
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('Sandbox', 'Feeds', 'Both')][string]$Connector,
  [ValidatePattern('^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')][string]$TenantId,
  [ValidatePattern('^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')][string]$SubscriptionId,
  [ValidatePattern('^[a-zA-Z0-9._()-]{1,80}$')][string]$ResourceGroup = 'rg-anyrun-mde',
  [string]$Region = 'eastus',
  [switch]$UseExistingResourceGroup,
  [ValidateNotNull()][hashtable]$Tags = @{},
  [SecureString]$SandboxApiKey,
  [SecureString]$FeedsApiKey,
  [switch]$RotateSecret,
  [ValidateSet('AzureToken', 'Interactive')][string]$GraphAuthMode = 'AzureToken',
  [switch]$InstallMissingModules,
  [switch]$ApproveDefenderPermissions,
  [switch]$NonInteractive,
  [switch]$PlanOnly,
  [ValidateSet('Audit', 'Block')][string]$IndicatorAction = 'Audit',
  [ValidateSet('owner', 'bylink')][string]$SandboxPrivacy = 'owner',
  [ValidateRange(1, 168)][int]$FeedsIntervalHours = 2,
  [ValidateRange(1, 365)][int]$FeedsFetchDepthDays = 30,
  [ValidateRange(1, 100)][int]$FeedsMinimumConfidence = 50
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 3.0

function Get-Field($Object, [string]$Name) {
  if ($null -eq $Object) { return $null }
  if ($Object -is [Collections.IDictionary]) {
    foreach ($key in $Object.Keys) { if ("$key" -ieq $Name) { return $Object[$key] } }
    return $null
  }
  $p = $Object.PSObject.Properties[$Name]
  if ($p) { return $p.Value }
  return $null
}

function Protect-Message([hashtable]$C, [string]$Text) {
  foreach ($value in $C.Secrets) {
    if ($value) { $Text = $Text.Replace($value, '[REDACTED]') }
  }
  $Text = $Text -replace '(?i)(AccountKey=)[^;\s"<>]+', '$1[REDACTED]'
  $Text = $Text -replace '(?i)([?&]sig=)[^&\s"<>]+', '$1[REDACTED]'
  $Text = $Text -replace '(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+', '$1[REDACTED]'
  $Text = $Text -replace '(?i)("(?:client_secret|secretText|ANYRUN_API_KEY|AzureClientSecret)"\s*:\s*")[^"]*', '$1[REDACTED]'
  return $Text
}

function Get-PlainSecret([hashtable]$C, [SecureString]$Secret) {
  $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
  try {
    $text = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)
    $C.Secrets.Add($text)
    return $text
  } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}

function Get-Profile([hashtable]$C, [ValidateSet('Sandbox', 'Feeds')][string]$Kind) {
  $scope = "$($C.Options.TenantId)/$($C.Options.SubscriptionId)/$($C.Options.ResourceGroup)/$Kind".ToLowerInvariant()
  $digest = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($scope))
  $instance = [Convert]::ToHexString($digest).ToLowerInvariant().Substring(0, 16)
  $short = $instance.Substring(0, 10)
  $key = $Kind.ToLowerInvariant()
  $roles = @(if ($Kind -eq 'Sandbox') {
      @('Alert.ReadWrite.All', 'Machine.LiveResponse', 'Machine.ReadWrite.All', 'Ti.ReadWrite', 'Library.Manage')
    } else { @('Ti.ReadWrite') })
  $hashes = if ($Kind -eq 'Sandbox') {
    @{Function = '7ec9b88be91c791a9c028252eed1eb85bfa9e9f864d17265f329f58479f721c7'
      Logic = 'd71aff66069bc7a216449aa55ed09b5808b3540cbaf0ca2434cd7ef52516da5d'
      Package = 'ffbda7d9f3a806e05aa696ca490bdc62a455e91d4930372c2b91c4dc61d4d44d'
    }
  } else {
    @{Function = 'e93cd0a4c97bd66481919af35b9fbc6f15859a300c2d743cd36a03bf812c53f4'
      Logic = 'ddf86fc10ff613dc5df83e4d3dffc2d416fb3c78ae12c2ba18d337ea538a7d69'
      Package = '6f87fc5e7b5b6a51a645b3789c6b1c6756b5054c13e51374fd6b04bb6e9bcd41'
    }
  }
  return @{Kind = $Kind
    Instance = $instance
    Tag = "anyrun-customer:v1:${key}:$instance"
    Roles = $roles
    Hashes = $hashes
    Function = "anyrun-$key-mde-$short"
    Logic = "anyrun-$key-mde-la-$short"
    Storage = "ar$(if ($Kind -eq 'Sandbox') { 'sb' } else { 'fd' })$instance"
    Connection = "wdatp-anyrun-$short"
    AppName = "ANY.RUN $Kind MDE ($instance)"
    Handlers = @($(if ($Kind -eq 'Sandbox') { @('ANYRUN-Sandbox-MDE-FA', 'ANYRUN-Sandbox-MDE-Worker', 'ANYRUN-Sandbox-MDE-Status') }
        else { @('ANYRUN-Feeds-MDE-FA') }))
  }
}

function Get-Artifact([hashtable]$C, $Profiles) {
  $assets = Join-Path $C.Root 'Assets'
  $null = [IO.Directory]::CreateDirectory($assets)
  $commit = 'cf9308a0fe13db7209f5663b40f0e489bb4d6b87'
  $base = "https://raw.githubusercontent.com/yaestkit/anyrun-integration-microsoft/$commit/Microsoft%20Defender%20for%20Endpoint"
  foreach ($p in $Profiles) {
    $folder = if ($p.Kind -eq 'Sandbox') { 'ANYRUN-Sandbox-MDE' } else { 'ANYRUN-TI-Feeds-MDE' }
    $prefix = if ($p.Kind -eq 'Sandbox') { 'ANYRUN-Sandbox-MDE' } else { 'ANYRUN-Feeds-MDE' }
    foreach ($part in @('Function', 'Logic', 'Package')) {
      $path = if ($part -eq 'Package') { "Function%20App/$prefix-FA.zip" }
      elseif ($part -eq 'Function') { "Function%20App/$prefix-FA.json" } else { "Logic%20App/$prefix-LA.json" }
      $suffix = if ($part -eq 'Package') { 'zip' } else { "$part.json" }
      $file = Join-Path $assets "$($p.Kind).$suffix"
      Invoke-WebRequest -Uri "$base/$folder/$path" -OutFile $file -TimeoutSec 60 -ErrorAction Stop
      if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $p.Hashes[$part]) {
        throw "Downloaded $($p.Kind) $part failed SHA-256 verification; no Azure/Graph changes were made."
      }
      if ($part -ne 'Package') { Convert-DeploymentTemplate $file $p.Kind $part }
    }
    $zip = [IO.Compression.ZipFile]::OpenRead((Join-Path $assets "$($p.Kind).zip"))
    try {
      $names = @($zip.Entries | ForEach-Object FullName)
      foreach ($name in @('host.json', 'requirements.txt', "$($p.Handlers[0])/function.json")) {
        if ($name -notin $names) { throw "Invalid $($p.Kind) Function ZIP: missing $name." }
      }
    } finally { $zip.Dispose() }
  }
}

function Convert-DeploymentTemplate([string]$File, [string]$ConnectorKind, [string]$TemplateKind) {
  $t = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json -AsHashtable
  foreach ($key in @('InstallerInstance', 'InstallerAppObjectId', 'InstallerCredentialKeyId', 'DeploymentRegion')) {
    $t.parameters[$key] = @{type = 'string' }
  }
  $t.parameters.ResourceTags = @{type = 'object' }
  if ($TemplateKind -eq 'Function') {
    $t.parameters.PackageUri = @{type = 'securestring' }
    $t.parameters.DeploymentStorageBlobEndpoint = @{type = 'string' }
    $t.variables.storageRoleDefinitionId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
    if ($ConnectorKind -eq 'Sandbox') { $t.parameters.DefenderIndicatorGenerateAlert.defaultValue = $true }
    # Storage is created separately. ARM must not reset its account/network policy.
    $t.resources = @($t.resources | Where-Object {
        $_.type -notin @('Microsoft.Storage/storageAccounts', 'Microsoft.Storage/storageAccounts/blobServices',
          'Microsoft.Storage/storageAccounts/fileServices', 'Microsoft.Storage/storageAccounts/fileServices/shares')
      })
  } else {
    $t.parameters.WorkflowState = @{type = 'string'
      defaultValue = 'Enabled'
      allowedValues = @('Enabled', 'Disabled')
    }
    if ($ConnectorKind -eq 'Sandbox') {
      $t.parameters.ConnectionName = @{type = 'string' }
      $t.variables.wdatpConnectionName = "[parameters('ConnectionName')]"
      $t.variables.wdatpApiId = "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', parameters('DeploymentRegion'), '/managedApis/wdatp')]"
    }
  }
  foreach ($r in $t.resources) {
    if ($r.ContainsKey('location')) { $r.location = "[parameters('DeploymentRegion')]" }
    if ($r.ContainsKey('dependsOn')) {
      $r.dependsOn = @($r.dependsOn | Where-Object { $_ -notmatch "resourceId\('Microsoft.Storage/storageAccounts(?:/blobServices)?'," })
      if (-not $r.dependsOn.Count) { $null = $r.Remove('dependsOn') }
    }
    switch ($r.type) {
      'Microsoft.Web/sites' {
        $r.properties.functionAppConfig.deployment.storage.value = "[concat(parameters('DeploymentStorageBlobEndpoint'), variables('deploymentStorageContainerName'))]"
      }
      'Microsoft.Resources/deployments' {
        $r.name = "AssignFunctionStorageRole-$ConnectorKind"
      }
      'Microsoft.Web/sites/extensions' {
        $r.properties.packageUri = "[parameters('PackageUri')]"
        $r.dependsOn = @("[resourceId('Microsoft.Resources/deployments', 'AssignFunctionStorageRole-$ConnectorKind')]")
      }
      'Microsoft.Logic/workflows' {
        $null = $r.Remove('identity')
        $r.properties.state = "[parameters('WorkflowState')]"
      }
    }
    if ($r.type -in @('Microsoft.Web/sites', 'Microsoft.Web/serverfarms', 'Microsoft.Insights/components', 'Microsoft.Web/connections', 'Microsoft.Logic/workflows')) {
      $values = "'ANYRUNInstaller', 'customer-v1', 'ANYRUNInstance', parameters('InstallerInstance'), 'ANYRUNConnectorKind', '$ConnectorKind'"
      if ($r.type -in @('Microsoft.Web/sites', 'Microsoft.Web/connections', 'Microsoft.Logic/workflows')) {
        $values += ", 'ANYRUNApplicationObjectId', parameters('InstallerAppObjectId'), 'ANYRUNCredentialKeyId', parameters('InstallerCredentialKeyId')"
      }
      if ($r.type -eq 'Microsoft.Web/sites') { $values += ", 'ANYRUNApplicationId', parameters('AzureClientID')" }
      if ($r.type -eq 'Microsoft.Logic/workflows') {
        $values += ", 'Resource', 'Microsoft Defender XDR', 'PlaybookTrigger', 'Incident', 'Custom', 'ANYRUN', 'PlaybookType', 'Enrichment'"
      }
      $r.tags = "[union(parameters('ResourceTags')['$($r.type)'], createObject($values))]"
    }
  }
  $t | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $File -Encoding utf8NoBOM
}

function Initialize-Module([hashtable]$C) {
  $spec = [ordered]@{'Az.Functions' = '5.0.1'
    'Az.Accounts' = '5.5.3'
    'Az.Resources' = '10.2.1'
    'Az.Storage' = '9.7.2'
    'Az.OperationalInsights' = '3.4.1'
    'Microsoft.Graph.Authentication' = '2.40.0'
    'Microsoft.Graph.Applications' = '2.40.0'
  }
  foreach ($name in $spec.Keys) {
    $available = @(Get-Module -Name $name -ListAvailable | Where-Object Version -ge ([version]$spec[$name]) | Sort-Object Version -Descending)
    if (-not $available.Count) {
      if (-not $C.Options.InstallMissingModules) {
        throw "Missing $name >= $($spec[$name]). Re-run with -InstallMissingModules to install from PSGallery in CurrentUser scope."
      }
      Install-Module -Name $name -MinimumVersion $spec[$name] -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
      $available = @(Get-Module -Name $name -ListAvailable | Sort-Object Version -Descending)
    }
    if ($name -eq 'Microsoft.Graph.Applications') {
      $auth = Get-Module Microsoft.Graph.Authentication
      $available = @($available | Where-Object Version -eq $auth.Version)
      if (-not $available.Count) {
        throw 'Graph Authentication and Applications must use the same version. Install a matching pair, then start a new PowerShell session.'
      }
    }
    Import-Module -Name $name -RequiredVersion $available[0].Version -ErrorAction Stop
  }
}

function Connect-Cloud {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Az versions can return a transient plaintext access token; Graph requires SecureString.'
  )]
  param([hashtable]$C)
  $o = $C.Options
  $az = Get-AzContext
  if (-not $az -or ($o.TenantId -and $az.Tenant.Id -ne $o.TenantId)) {
    if ($o.NonInteractive) { throw 'Authenticate Azure in the requested tenant before a non-interactive installation.' }
    $argsForLogin = @{}
    if ($o.TenantId) { $argsForLogin.Tenant = $o.TenantId }
    $null = Connect-AzAccount @argsForLogin
    $az = Get-AzContext
  }
  if ($o.SubscriptionId) { $az = Set-AzContext -Tenant $az.Tenant.Id -SubscriptionId $o.SubscriptionId }
  if ($az.Environment.Name -ne 'AzureCloud') { throw 'The bundled connector supports Azure public cloud only.' }
  $o.TenantId = "$($az.Tenant.Id)"
  $o.SubscriptionId = "$($az.Subscription.Id)"
  $C.Azure = $az
  Write-Host "Tenant: $($o.TenantId)  Subscription: $($o.SubscriptionId)" -ForegroundColor Cyan
  Write-Host "Resource group: $($o.ResourceGroup)  Connectors: $($o.Connector)" -ForegroundColor Cyan
  if (-not $o.NonInteractive -and (Read-Host 'Continue in this tenant/subscription? [y/N]') -notmatch '^(y|yes)$') { throw 'Installation cancelled.' }
  $mg = Get-MgContext
  if ($mg) {
    if ($mg.TenantId -ne $o.TenantId -or $mg.AuthType -ne 'Delegated' -or
      ($o.GraphAuthMode -eq 'AzureToken' -and $mg.Account -ne $az.Account.Id)) {
      throw 'An incompatible Graph session is already open. Verify it, disconnect it yourself, and re-run. No existing session was replaced.'
    }
  } else {
    if ($o.GraphAuthMode -eq 'Interactive') {
      if ($o.NonInteractive) { throw 'Interactive Graph login cannot run with -NonInteractive.' }
      $null = Connect-MgGraph -TenantId $o.TenantId -Scopes 'User.Read', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -ContextScope Process -NoWelcome
    } else {
      $token = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/'
      $secure = if ($token.Token -is [SecureString]) { $token.Token }
      else { ConvertTo-SecureString "$($token.Token)" -AsPlainText -Force }
      $null = Connect-MgGraph -AccessToken $secure -NoWelcome
    }
    $C.GraphOwned = $true
    $mg = Get-MgContext
    if (-not $mg -or $mg.TenantId -ne $o.TenantId) {
      throw 'Graph did not confirm the requested tenant. Re-run with -GraphAuthMode Interactive; no authentication fallback was attempted.'
    }
  }
  $C.Operator = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id' -OutputType PSObject
}

function Read-Arm([hashtable]$C, [string]$Path, [string]$Method = 'GET') {
  for ($attempt = 0; $attempt -lt 4; $attempt++) {
    $status = 0
    $body = ''
    $cause = ''
    try {
      $r = Invoke-AzRestMethod -Method $Method -Path $Path -ErrorAction Stop
      $status = [int]$r.StatusCode
      $body = "$($r.Content)"
    } catch {
      $response = Get-Field $_.Exception 'Response'
      $status = [int](Get-Field $response 'StatusCode')
      if (-not $status) { $status = [int](Get-Field $_.Exception 'StatusCode') }
      if (-not $status) { $status = [int](Get-Field $_.Exception 'ResponseStatusCode') }
      if ($_.ErrorDetails) { $body = $_.ErrorDetails.Message }
      $cause = $_.Exception.Message
    }
    if ($status -eq 404) { return $null }
    if ($status -eq 200) { return ($body | ConvertFrom-Json -AsHashtable) }
    if ($status -in @(429, 500, 502, 503, 504) -and $attempt -lt 3) {
      Start-Sleep -Seconds ([Math]::Min(15, [Math]::Pow(2, $attempt + 1)))
      continue
    }
    $errorBody = $null
    try {
      $parsed = $body | ConvertFrom-Json -AsHashtable
      $errorBody = Get-Field $parsed 'error'
      if (-not $errorBody) { $errorBody = $parsed }
    } catch { $errorBody = $null }
    $code = "$(Get-Field $errorBody 'code')"
    $message = Protect-Message $C "$(Get-Field $errorBody 'message')"
    $failure = [InvalidOperationException]::new((Protect-Message $C "Azure read failed (HTTP $status) at $Path. $code $message $cause"))
    $failure.Data['HttpStatus'] = $status
    $failure.Data['ArmCode'] = $code
    $failure.Data['ArmMessage'] = $message
    throw $failure
  }
}

function Test-HostFailure([Management.Automation.ErrorRecord]$Record) {
  $data = $Record.Exception.Data
  if ($data['HttpStatus'] -notin @(400, 500, 502, 503, 504)) { return $false }
  if ($data['ArmCode'] -in @('HostRuntimeError', 'HostRuntimeUnavailable', 'FunctionsHostNotRunning')) { return $true }
  $generic = $data['ArmCode'] -in @('BadRequest', 'InternalServerError', 'ServiceUnavailable', 'BadGateway', 'GatewayTimeout')
  return $generic -and $data['ArmMessage'] -match
  'Encountered an error \((InternalServerError|ServiceUnavailable|BadGateway|GatewayTimeout)\) from host runtime|Functions host is not running|Azure Functions runtime is unreachable'
}

function Get-ResourcePath([hashtable]$C, [string]$Type, [string]$Name) {
  return "/subscriptions/$($C.Options.SubscriptionId)/resourceGroups/$($C.Options.ResourceGroup)/providers/$Type/$Name"
}

function Assert-Managed($Resource, [string]$Instance, [string]$Kind = '') {
  if (-not $Resource) { return }
  $tags = Get-Field $Resource 'tags'
  if ((Get-Field $tags 'ANYRUNInstaller') -ne 'customer-v1' -or (Get-Field $tags 'ANYRUNInstance') -ne $Instance -or
    ($Kind -and (Get-Field $tags 'ANYRUNConnectorKind') -ne $Kind)) {
    throw 'A selected resource is not owned by this customer installer instance. Existing integrations are never imported; resolve the name collision or use another group.'
  }
}

function Test-TagOption([hashtable]$C) {
  foreach ($key in $C.Options.Tags.Keys) {
    $value = $C.Options.Tags[$key]
    if ("$key" -match '^ANYRUN' -or "$key" -in @('Resource', 'PlaybookTrigger', 'Custom', 'PlaybookType')) { throw "Tag '$key' is reserved for the installer." }
    if (-not "$key" -or "$key".Length -gt 128 -or "$key" -match '[<>%&\\?/]' -or
      $value -isnot [string] -or $value.Length -gt 256) {
      throw 'Tags require valid names up to 128 characters and string values up to 256 characters.'
    }
  }
  if ($C.Options.Tags.Count -gt 40) { throw 'At most 40 customer tags are supported, reserving room for installer metadata.' }
}

function Get-CorporateTag([hashtable]$C, $Resource, [string[]]$TemplateKeys = @()) {
  $result = @{}
  $existing = Get-Field $Resource 'tags'
  if ($existing) {
    foreach ($key in $existing.Keys) {
      if ("$key" -notmatch '^ANYRUN' -and "$key" -notin $TemplateKeys) { $result[$key] = $existing[$key] }
    }
  }
  foreach ($key in $C.Options.Tags.Keys) { $result[$key] = $C.Options.Tags[$key] }
  if ($result.Count -gt 40) { throw 'Existing and requested corporate tags exceed the space reserved for installer metadata.' }
  return $result
}

function Test-RequestedTag([hashtable]$C, $Resource) {
  $actual = Get-Field $Resource 'tags'
  foreach ($key in $C.Options.Tags.Keys) {
    if ((Get-Field $actual "$key") -cne $C.Options.Tags[$key]) { return $true }
  }
  return $false
}

function Get-TemplateTarget([hashtable]$P, [string]$Kind) {
  $targets = @()
  if ($Kind -eq 'Function') {
    $targets += , @('Microsoft.Web/sites', $P.Function, '2024-11-01')
    $targets += , @('Microsoft.Web/serverfarms', $P.Function, '2024-11-01')
    $targets += , @('Microsoft.Insights/components', $P.Function, '2020-02-02')
  } else {
    if ($P.Kind -eq 'Sandbox') { $targets += , @('Microsoft.Web/connections', $P.Connection, '2016-06-01') }
    $targets += , @('Microsoft.Logic/workflows', $P.Logic, '2019-05-01')
  }
  return , $targets
}

function Get-TemplateTag([hashtable]$C, [hashtable]$P, [string]$Kind) {
  $result = @{}
  foreach ($target in (Get-TemplateTarget $P $Kind)) {
    $id = Get-ResourcePath $C $target[0] $target[1]
    $resource = Read-Arm $C "$id`?api-version=$($target[2])"
    Assert-Managed $resource $P.Instance $P.Kind
    $templateKeys = if ($target[0] -eq 'Microsoft.Logic/workflows') { @('Resource', 'PlaybookTrigger', 'Custom', 'PlaybookType') } else { @() }
    $result[$target[0]] = Get-CorporateTag $C $resource $templateKeys
  }
  return $result
}

function Get-RotationCommand([hashtable]$C, [hashtable]$P) {
  $entryPath = Get-Field $C 'EntryPath'
  if (-not $entryPath) { $entryPath = Join-Path $C.Root 'Deploy-ANYRUNMDEConnector.ps1' }
  $path = $entryPath.Replace("'", "''")
  $group = $C.Options.ResourceGroup.Replace("'", "''")
  $command = "& '$path' -Connector $($P.Kind) -TenantId '$($C.Options.TenantId)' " +
  "-SubscriptionId '$($C.Options.SubscriptionId)' -ResourceGroup '$group' -RotateSecret " +
  "-GraphAuthMode $($C.Options.GraphAuthMode)"
  if ($C.ExternalGroup) { $command += ' -UseExistingResourceGroup' }
  if ($C.Options.NonInteractive) { $command += ' -NonInteractive -ApproveDefenderPermissions' }
  return $command
}

function Test-CloudPreflight([hashtable]$C, $Profiles) {
  $o = $C.Options
  $C.Scope = "/subscriptions/$($o.SubscriptionId)/resourceGroups/$($o.ResourceGroup)"
  $C.GroupInstance = (Get-Profile $C Sandbox).Instance
  $C.Group = Read-Arm $C "$($C.Scope)?api-version=2021-04-01"
  $groupTags = Get-Field $C.Group 'tags'
  $ownedGroup = (Get-Field $groupTags 'ANYRUNInstaller') -eq 'customer-v1' -and
  (Get-Field $groupTags 'ANYRUNInstance') -eq $C.GroupInstance
  $C.ExternalGroup = $C.Group -and -not $ownedGroup
  if ($C.Group -and 'Region' -notin $C.Explicit) { $o.Region = $C.Group.location }
  $resourceRegions = [Collections.Generic.List[string]]::new()
  foreach ($p in $Profiles) {
    $selectedResources = @(
      @('Microsoft.Web/sites', $p.Function),
      @('Microsoft.Web/serverfarms', $p.Function),
      @('Microsoft.Insights/components', $p.Function),
      @('Microsoft.Logic/workflows', $p.Logic),
      @('Microsoft.Storage/storageAccounts', $p.Storage)
    )
    foreach ($pair in $selectedResources) {
      $version = switch -Wildcard ($pair[0]) {
        'Microsoft.Web/*' { '2024-11-01' }
        'Microsoft.Storage/*' { '2023-05-01' }
        'Microsoft.Insights/*' { '2020-02-02' }
        default { '2019-05-01' }
      }
      $r = Read-Arm $C "$(Get-ResourcePath $C $pair[0] $pair[1])?api-version=$version"
      Assert-Managed $r $p.Instance $p.Kind
      $templateKeys = if ($pair[0] -eq 'Microsoft.Logic/workflows') { @('Resource', 'PlaybookTrigger', 'Custom', 'PlaybookType') } else { @() }
      $null = Get-CorporateTag $C $r $templateKeys
      $location = Get-Field $r 'location'
      if ($location) { $resourceRegions.Add(("$location" -replace ' ', '').ToLowerInvariant()) }
    }
    if ($p.Kind -eq 'Sandbox') {
      Assert-Managed (Read-Arm $C "$(Get-ResourcePath $C Microsoft.Web/connections $p.Connection)?api-version=2016-06-01") $p.Instance $p.Kind
    }
  }
  $workspacePath = Get-ResourcePath $C Microsoft.OperationalInsights/workspaces "anyrun-mde-law-$($C.GroupInstance.Substring(0,10))"
  $workspace = Read-Arm $C "$workspacePath`?api-version=2023-09-01"
  Assert-Managed $workspace $C.GroupInstance
  $null = Get-CorporateTag $C $workspace
  $regions = @($resourceRegions | Sort-Object -Unique)
  if (-not $regions.Count -and 'Region' -notin $C.Explicit -and (Get-Field $workspace 'location')) {
    $o.Region = "$($workspace.location)"
  }
  if ($regions.Count -gt 1) { throw 'Selected managed resources span multiple regions. Review the installation before updating it.' }
  if ($regions.Count -eq 1) {
    if ('Region' -in $C.Explicit -and $o.Region.ToLowerInvariant() -ne $regions[0]) {
      throw 'Region differs from existing managed resources; resources cannot be moved by re-running the installer.'
    }
    $o.Region = $regions[0]
  }
  $locations = @(Get-AzFunctionAppAvailableLocation -PlanType FlexConsumption -SubscriptionId $o.SubscriptionId)
  if (-not @($locations | Where-Object { ("$($_.Name)" -replace ' ', '').ToLowerInvariant() -eq $o.Region.ToLowerInvariant() }).Count) {
    throw "Flex Consumption is unavailable in '$($o.Region)'. Choose a supported region."
  }
  if ($C.ExternalGroup -and -not $o.UseExistingResourceGroup) {
    if ($o.NonInteractive) { throw 'The resource group is not owned by this installer. Explicitly approve placement with -UseExistingResourceGroup.' }
    if ((Read-Host "Use existing group $($C.Scope) in resource region $($o.Region), without changing its tags? [y/N]") -notmatch '^(y|yes)$') {
      throw 'Existing resource group placement was declined.'
    }
  }
}

function Initialize-AzureResource([hashtable]$C) {
  if (-not $C.Group) {
    $groupTags = (Get-CorporateTag $C $null) + @{ANYRUNInstaller = 'customer-v1'
      ANYRUNInstance = $C.GroupInstance
    }
    $C.Group = New-AzResourceGroup -Name $C.Options.ResourceGroup -Location $C.Options.Region -Tag $groupTags
  }
  foreach ($namespace in @('Microsoft.Web', 'Microsoft.Storage', 'Microsoft.Insights', 'Microsoft.OperationalInsights', 'Microsoft.Logic')) {
    $provider = Get-AzResourceProvider -ProviderNamespace $namespace
    if ($provider.RegistrationState -ne 'Registered') {
      $null = Register-AzResourceProvider -ProviderNamespace $namespace
      for ($n = 0; $n -lt 30; $n++) {
        if ((Get-AzResourceProvider -ProviderNamespace $namespace).RegistrationState -eq 'Registered') { break }
        if ($n -eq 29) { throw "Provider $namespace is still registering. Re-run later." }
        Start-Sleep -Seconds 10
      }
    }
  }
}

function Get-Storage {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Azure returns plaintext Shared Key; secure ARM parameters require SecureString. Values are redacted.'
  )]
  param([hashtable]$C, [hashtable]$P)
  $resource = Read-Arm $C "$(Get-ResourcePath $C Microsoft.Storage/storageAccounts $P.Storage)?api-version=2023-05-01"
  Assert-Managed $resource $P.Instance $P.Kind
  $account = if ($resource) { Get-AzStorageAccount -ResourceGroupName $C.Options.ResourceGroup -Name $P.Storage -ErrorAction Stop }
  else { $null }
  if (-not $resource) {
    $available = Get-AzStorageAccountNameAvailability -Name $P.Storage
    if (-not $available.NameAvailable) { throw 'The generated Storage account name is unavailable. Choose a different resource group name.' }
    $account = New-AzStorageAccount -ResourceGroupName $C.Options.ResourceGroup -Name $P.Storage -Location $C.Options.Region -SkuName Standard_LRS -Kind StorageV2 `
      -EnableHttpsTrafficOnly $true -MinimumTlsVersion TLS1_2 -AllowBlobPublicAccess $false `
      -Tag ((Get-CorporateTag $C $null) + @{ANYRUNInstaller = 'customer-v1'
        ANYRUNInstance = $P.Instance
        ANYRUNConnectorKind = $P.Kind
      })
  }
  Assert-Managed $account $P.Instance $P.Kind
  if ((Get-Field $account 'AllowSharedKeyAccess') -eq $false -or (Get-Field $account 'PublicNetworkAccess') -eq 'Disabled' -or
    (Get-Field (Get-Field $account 'NetworkRuleSet') 'DefaultAction') -eq 'Deny') {
    throw 'Storage policy/network restrictions are incompatible with this deployment path. They will not be opened or disabled.'
  }
  $key = (Get-AzStorageAccountKey -ResourceGroupName $C.Options.ResourceGroup -Name $P.Storage)[0].Value
  $C.Secrets.Add($key)
  $connection = "DefaultEndpointsProtocol=https;AccountName=$($P.Storage);AccountKey=$key;EndpointSuffix=core.windows.net"
  $C.Secrets.Add($connection)
  return @{Account = $account
    Name = $P.Storage
    Key = (ConvertTo-SecureString $key -AsPlainText -Force)
    Connection = (ConvertTo-SecureString $connection -AsPlainText -Force)
    Context = (New-AzStorageContext -ConnectionString $connection)
  }
}

function Get-PrivateContainer([hashtable]$C, [hashtable]$Storage, [string]$Name) {
  $options = [Azure.Storage.Blobs.BlobClientOptions]::new()
  $options.Retry.NetworkTimeout = [TimeSpan]::FromSeconds(10)
  $options.Retry.MaxRetries = 1
  $service = [Azure.Storage.Blobs.BlobServiceClient]::new((Get-PlainSecret $C $Storage.Connection), $options)
  $container = $service.GetBlobContainerClient($Name)
  $cancel = [Threading.CancellationToken]::None
  $null = $container.CreateIfNotExists([Azure.Storage.Blobs.Models.PublicAccessType]::None, $null, $null, $cancel)
  if ($container.GetProperties($null, $cancel).Value.PublicAccess -ne [Azure.Storage.Blobs.Models.PublicAccessType]::None) {
    throw 'Installer containers must be private. Existing access policy will not be changed.'
  }
  return $container
}

function Get-GraphFailure([Management.Automation.ErrorRecord]$Record) {
  $exception = $Record.Exception
  $status = Get-Field $exception 'ResponseStatusCode'
  if (-not $status) { $status = Get-Field (Get-Field $exception 'Response') 'StatusCode' }
  $errorBody = $null
  if ($Record.ErrorDetails) {
    try { $errorBody = Get-Field ($Record.ErrorDetails.Message | ConvertFrom-Json -AsHashtable) 'error' }
    catch { $errorBody = $null }
  }
  $code = Get-Field $errorBody 'code'
  if (-not $code) { $code = Get-Field (Get-Field $exception 'Error') 'Code' }
  if (-not $code) { $code = Get-Field $exception 'Code' }
  if (-not $code -and $exception.Message -match '\[(Request_ResourceNotFound|ResourceNotFound|Request_BadRequest)\]') { $code = $Matches[1] }
  $details = @(Get-Field $errorBody 'details')
  $missing = $code -in @('Request_ResourceNotFound', 'ResourceNotFound')
  $backing = @($details | Where-Object { (Get-Field $_ 'code') -eq 'NoBackingApplicationObject' }).Count -gt 0
  $backing = $backing -or $code -eq 'NoBackingApplicationObject'
  $backing = $backing -or ($code -eq 'Request_BadRequest' -and $exception.Message -match 'does not reference a valid application object|NoBackingApplicationObject')
  return @{Status = [int]$status
    Missing = $missing
    MissingBackingApp = $backing
  }
}

function Invoke-GraphPropagation([hashtable]$C, [scriptblock]$Action, [string]$Operation) {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $spent = 0
  $attempt = 0
  try {
    while ($true) {

      try { return (& $Action) }
      catch {
        $failure = Get-GraphFailure $_
        $recognized = $failure.Missing -or ($Operation -eq 'ServicePrincipal' -and $failure.MissingBackingApp)
        $delay = [Math]::Min(20, [Math]::Pow(2, ++$attempt))
        $remaining = 90 - [Math]::Max($spent, $clock.Elapsed.TotalSeconds)
        if (-not $recognized -or $failure.Status -notin @(0, 400, 404) -or $remaining -lt $delay) { throw }
        Write-Host "$Operation`: waiting for Graph object propagation..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $delay
        $spent += $delay
      }
    }
  } finally { $clock.Stop() }
}

function Write-ConsentInstruction([hashtable]$C, [hashtable]$P, $App) {
  Write-Warning "Admin consent is required or not visible for $($P.Kind). No runtime secret was created."
  Write-Host "Tenant: $($C.Options.TenantId); application: $($P.AppName)" -ForegroundColor Cyan
  Write-Host "ClientId: $($App.AppId); ObjectId: $($App.Id)" -ForegroundColor Cyan
  Write-Host "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($App.AppId)/isMSAApp~/false" -ForegroundColor Cyan
  Write-Host 'Verify the tenant, then App registrations > All applications > select this ClientId > API permissions > Grant admin consent.'
  Write-Host 'If the portal link changes, use https://entra.microsoft.com and the navigation above. Then re-run the same command.'
}

function Get-CredentialInventory($Identity) {
  $credentials = @($Identity.App.PasswordCredentials | Where-Object { $_ })
  if ($Identity.NewCredential) { $credentials += $Identity.CurrentCredential }
  $credentials = @($credentials | Sort-Object KeyId -Unique)
  $current = @($credentials | Where-Object { "$($_.KeyId)" -eq $Identity.KeyId })
  if ($current.Count -ne 1 -or -not $current[0].EndDateTime) { throw 'Current credential expiry metadata is missing or ambiguous.' }
  $expires = [DateTimeOffset]$current[0].EndDateTime
  $days = [Math]::Floor(($expires - [DateTimeOffset]::UtcNow).TotalDays)
  Write-Host "Current credential: $($Identity.KeyId); expires $($expires.UtcDateTime.ToString('u')); remaining days: $days."
  if ($days -lt 30) {
    Write-Warning "The current password expires in $days days. Plan -RotateSecret and verified consumer cutover."
  }
  $previous = @($credentials | Where-Object { "$($_.KeyId)" -ne $Identity.KeyId } | ForEach-Object {
      $appId = "$($Identity.App.Id)".Replace("'", "''")
      $keyId = "$($_.KeyId)".Replace("'", "''")
      @{KeyId = "$($_.KeyId)"
        ExpiresUTC = ([DateTimeOffset]$_.EndDateTime).UtcDateTime.ToString('u')
        RevokeCommand = "Remove-MgApplicationPassword -ApplicationId '$appId' -KeyId '$keyId' -Confirm"
      }
    })
  return @{ExpiresUTC = $expires.UtcDateTime.ToString('u')
    Expired = $expires -le [DateTimeOffset]::UtcNow
    Previous = $previous
  }
}

function Get-Identity([hashtable]$C, [hashtable]$P, [hashtable]$Storage) {
  $defender = Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" -Property Id, AppRoles | Select-Object -First 1
  if (-not $defender) { throw 'WindowsDefenderATP service principal is unavailable in this tenant.' }
  $roles = @()
  foreach ($name in $P.Roles) {
    $role = @($defender.AppRoles | Where-Object { $_.Value -eq $name -and $_.IsEnabled -and 'Application' -in $_.AllowedMemberTypes })
    if ($role.Count -ne 1) {
      throw "Required Defender application role '$name' is unavailable. No substitute permission will be granted."
    }
    $roles += $role[0]
  }
  $recorded = Get-Field $Storage.Account.Tags 'ANYRUNApplicationObjectId'
  $properties = @('Id', 'AppId', 'DisplayName', 'Tags', 'SignInAudience', 'RequiredResourceAccess', 'PasswordCredentials', 'KeyCredentials')
  if ($recorded) {
    try {
      $candidates = @(Invoke-GraphPropagation $C {
          Get-MgApplication -ApplicationId $recorded -Property $properties
        } RecordedApplication)
    } catch {
      if (-not (Get-GraphFailure $_).Missing -and (Get-GraphFailure $_).Status -ne 404) { throw }
      throw ("Recorded application ObjectId '$recorded' is unavailable in tenant '$($C.Options.TenantId)'. " +
        'Restore the original App Registration or use a separately reviewed identity migration. ' +
        'Do not delete Storage metadata or substitute a same-name application.')
    }
    if (-not $candidates.Count) {
      throw "Recorded application ObjectId '$recorded' is missing. Restore the original App Registration or review identity migration; no replacement was created."
    }
  } else {
    $candidates = @(Get-MgApplication -Filter "displayName eq '$($P.AppName)'" -All -Property $properties)
  }
  if ($candidates.Count -gt 1) {
    throw 'More than one application matches this installer instance. Do not select one automatically; resolve the duplicate installation first.'
  }
  $required = @(@{ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
      ResourceAccess = @($roles | ForEach-Object { @{Id = $_.Id
            Type = 'Role'
          } })
    })

  if (-not $candidates.Count) {
    $app = New-MgApplication -BodyParameter @{DisplayName = $P.AppName
      SignInAudience = 'AzureADMyOrg'
      Tags = @($P.Tag)
      RequiredResourceAccess = $required
      'owners@odata.bind' = @("https://graph.microsoft.com/v1.0/users/$($C.Operator.id)")
    }
    if (-not $app.Id -or -not $app.AppId) { throw 'Graph creation returned incomplete application identifiers; no further changes are safe.' }

    $null = Update-AzTag -ResourceId $Storage.Account.Id -Operation Merge -Tag @{ANYRUNApplicationObjectId = "$($app.Id)"
      ANYRUNApplicationId = "$($app.AppId)"
    }
  } else { $app = $candidates[0] }
  $expectedIds = @($roles | ForEach-Object { "$($_.Id)" })
  $access = @($app.RequiredResourceAccess)
  $declared = @($access | ForEach-Object { $_.ResourceAccess })
  if ($app.SignInAudience -ne 'AzureADMyOrg' -or $P.Tag -notin @($app.Tags) -or $access.Count -ne 1 -or
    $access[0].ResourceAppId -ne 'fc780465-2017-40d4-a0c5-307022471b92' -or @($declared | ForEach-Object { "$($_.Id)" } | Sort-Object -Unique).Count -ne $expectedIds.Count -or
    @($declared | Where-Object { $_.Type -ne 'Role' -or "$($_.Id)" -notin $expectedIds }).Count) {
    throw 'Application marker/type/declared roles differ from this connector profile. No existing application will be repurposed or have its permissions expanded.'
  }
  $federated = @(Invoke-GraphPropagation $C {
      Get-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -All
    } FederatedCredentials)
  if (@($app.KeyCredentials | Where-Object { $_ }).Count -or @($federated | Where-Object { $_ }).Count -or
    @($app.PasswordCredentials | Where-Object { $_.DisplayName -notlike "$($P.Tag):password:*" }).Count) {
    throw 'The managed application has an unrecognized authentication path. Review it independently before continuing.'
  }

  if ($candidates.Count -and ((Get-Field $Storage.Account.Tags 'ANYRUNApplicationObjectId') -ne $app.Id -or
      (Get-Field $Storage.Account.Tags 'ANYRUNApplicationId') -ne $app.AppId)) {
    $null = Update-AzTag -ResourceId $Storage.Account.Id -Operation Merge -Tag @{ANYRUNApplicationObjectId = "$($app.Id)"
      ANYRUNApplicationId = "$($app.AppId)"
    }
  }
  $sp = Invoke-GraphPropagation $C {
    $existing = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -Property Id, PasswordCredentials, KeyCredentials | Select-Object -First 1
    if ($existing) { return $existing }
    New-MgServicePrincipal -AppId $app.AppId
  } ServicePrincipal
  if (@($sp.PasswordCredentials | Where-Object { $_ }).Count -or @($sp.KeyCredentials | Where-Object { $_ }).Count) {
    throw 'Service principal has an unmanaged credential. Installation stopped.'
  }
  $assignments = @(Invoke-GraphPropagation $C { Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All } RoleInventory)
  if (@($assignments | Where-Object { "$($_.ResourceId)" -ne "$($defender.Id)" -or "$($_.AppRoleId)" -notin $expectedIds }).Count) {
    throw 'Application has effective permissions outside this connector profile. Installation stopped before a runtime secret was issued.'
  }
  foreach ($role in $roles) {
    if ("$($role.Id)" -in @($assignments | ForEach-Object { "$($_.AppRoleId)" })) { continue }

    try {
      $null = Invoke-GraphPropagation $C {
        $visible = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All)
        if (@($visible | Where-Object { $_.ResourceId -eq $defender.Id -and $_.AppRoleId -eq $role.Id }).Count) { return }
        New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $defender.Id -BodyParameter @{principalId = $sp.Id
          resourceId = $defender.Id
          appRoleId = $role.Id
        }
      } RoleAssignment
    } catch {
      $message = $_.Exception.Message
      if ($message -notmatch '403|Authorization_RequestDenied|Insufficient privileges') { throw }
      Write-ConsentInstruction $C $P $app
      return @{App = $app
        ServicePrincipal = $sp
        PendingConsent = $true
      }
    }
  }
  for ($attempt = 0; $attempt -lt 12; $attempt++) {
    $granted = @(Invoke-GraphPropagation $C { Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All } RoleInventory)
    if (@($granted | Where-Object { "$($_.ResourceId)" -ne "$($defender.Id)" -or "$($_.AppRoleId)" -notin $expectedIds }).Count) {
      throw 'Permissions changed during consent. Installation stopped.'
    }
    if (-not @($expectedIds | Where-Object { $_ -notin @($granted | ForEach-Object { "$($_.AppRoleId)" }) }).Count) {
      return @{App = $app
        ServicePrincipal = $sp
        PendingConsent = $false
      }
    }
    if ($attempt -lt 11) { Start-Sleep -Seconds 10 }
  }
  Write-ConsentInstruction $C $P $app
  return @{App = $app
    ServicePrincipal = $sp
    PendingConsent = $true
  }
}

function Read-FunctionSetting([hashtable]$C, [hashtable]$P, $Site) {
  if (-not $Site) { return @{} }
  $body = Read-Arm $C "$(Get-ResourcePath $C Microsoft.Web/sites $P.Function)/config/appsettings/list?api-version=2024-04-01" POST
  if (-not $body) { return @{} }
  $settings = $body.properties
  foreach ($key in $settings.Keys) {
    if ($key -match '(?i)secret|key|connectionstring') { $C.Secrets.Add("$($settings[$key])") }
  }
  return $settings
}

function Test-Credential([hashtable]$C, [hashtable]$P, $Identity, [SecureString]$Secret) {
  $plain = Get-PlainSecret $C $Secret
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $spent = 0
  $attempt = 0
  try {
    do {
      $attempt++
      $stage = 'OAuth'
      $timeout = [Math]::Max(1, [Math]::Min(30, [int][Math]::Ceiling(300 - [Math]::Max($spent, $clock.Elapsed.TotalSeconds))))
      try {
        $token = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($C.Options.TenantId)/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' `
          -TimeoutSec $timeout -Body @{client_id = $Identity.App.AppId
          client_secret = $plain
          grant_type = 'client_credentials'
          scope = 'https://api.securitycenter.microsoft.com/.default'
        }
        if (-not $token.access_token -or $token.token_type -ne 'Bearer') { throw 'OAuth did not return a bearer token.' }
        $C.Secrets.Add($token.access_token)
        $stage = 'Defender'
        $endpoint = if ($P.Kind -eq 'Sandbox') { 'machines' }
        else { 'indicators' }
        $timeout = [Math]::Max(1, [Math]::Min(30, [int][Math]::Ceiling(300 - [Math]::Max($spent, $clock.Elapsed.TotalSeconds))))
        $null = Invoke-RestMethod -Method GET -Uri "https://api.securitycenter.microsoft.com/api/$endpoint`?`$top=1" -TimeoutSec $timeout -Headers @{Authorization = "Bearer $($token.access_token)" }
        return
      } catch {
        $response = Get-Field $_.Exception 'Response'
        $status = [int](Get-Field $response 'StatusCode')
        $details = Get-Field $_ 'ErrorDetails'
        $oauthError = $null
        if ($details) {
          try { $oauthError = $details.Message | ConvertFrom-Json -AsHashtable }
          catch {
            # Non-JSON responses are classified by HTTP status only.
            $oauthError = $null
          }
        }
        if ($stage -eq 'OAuth' -and 7000222 -in @(Get-Field $oauthError 'error_codes')) {
          throw ("Entra reports an expired client secret (AADSTS7000222), KeyId '$($Identity.KeyId)'. " +
            "Review the credential and re-run: $(Get-RotationCommand $C $P)")
        }
        $retry = $status -in @(429, 500, 502, 503, 504) -or ($stage -eq 'Defender' -and $status -in @(401, 403)) -or
        ($Identity.NewCredential -and $stage -eq 'OAuth' -and (Get-Field $oauthError 'error') -eq 'invalid_client' -and
        (-not (Get-Field $oauthError 'error_codes') -or 7000215 -in @(Get-Field $oauthError 'error_codes')))
        $remaining = 300 - [Math]::Max($spent, $clock.Elapsed.TotalSeconds)
        $delay = [Math]::Min(20, 5 * $attempt)
        if (-not $retry -or $remaining -le $delay) { throw }
        Write-Host "$($P.Kind): waiting for credential/consent propagation ($attempt)..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $delay
        $spent += $delay
      }
    } while ([Math]::Max($spent, $clock.Elapsed.TotalSeconds) -lt 300)
    throw 'Credential readiness timed out. Re-run after consent has propagated.'
  } finally {
    $clock.Stop()
    $plain = $null
  }
}

function Get-WorkflowValue($Node, [string]$Name) {
  if ($null -eq $Node -or $Node -is [string] -or $Node -is [ValueType]) { return }
  if ($Node -is [Collections.IDictionary]) {
    if ($Node.Contains('name') -and $Node.name -eq $Name -and $Node.Contains('value')) { return $Node.value }
    foreach ($value in $Node.Values) { Get-WorkflowValue $value $Name }
  } elseif ($Node -is [Collections.IEnumerable]) {
    foreach ($value in $Node) { Get-WorkflowValue $value $Name }
  }
}

function Get-Parameter([hashtable]$C, [hashtable]$P, $Storage, $Identity, [SecureString]$Secret, [SecureString]$ApiKey, $Settings, $Workflow) {
  $o = $C.Options
  $action = if ('IndicatorAction' -notin $C.Explicit -and (Get-Field $Settings 'DefenderIndicatorAction')) { $Settings.DefenderIndicatorAction }
  else { $o.IndicatorAction }
  if ($action -notin @('Audit', 'Block')) { throw 'Existing indicator action is invalid. Review the managed configuration.' }
  $fp = @{functionAppName = $P.Function
    AzureTenantID = $o.TenantId
    AzureClientID = $Identity.App.AppId
    AzureClientSecret = $Secret
    AzureStorageAccountName = $P.Storage
    AzureStorageConnectionString = $Storage.Connection
    LogAnalyticsWorkspaceName = $C.Workspace
    DeploymentStorageBlobEndpoint = $Storage.Account.PrimaryEndpoints.Blob
    InstallerInstance = $P.Instance
    InstallerAppObjectId = $Identity.App.Id
    InstallerCredentialKeyId = $Identity.KeyId
    DefenderIndicatorAction = $action
  }
  $lp = @{logicAppName = $P.Logic
    functionAppName = $P.Function
    InstallerInstance = $P.Instance
    InstallerAppObjectId = $Identity.App.Id
    InstallerCredentialKeyId = $Identity.KeyId
    WorkflowState = $(if ($Workflow -and (Get-Field $Workflow.properties 'state') -eq 'Disabled') { 'Disabled' }
      else { 'Enabled' })
  }
  if ($P.Kind -eq 'Sandbox') {
    $fp.AzureStorageAccountKey = $Storage.Key
    $fp.AzureBlobContainerName = 'anyrun-quarantine'
    $fp.ANYRUN_API_KEY = $ApiKey
    $fp.DefenderIndicatorGenerateAlert = $true
    $fp.ConfigureEvidenceLifecyclePolicy = $true
    $privacy = if ('SandboxPrivacy' -notin $C.Explicit -and $Workflow) {
      @(Get-WorkflowValue $Workflow.properties.definition 'opt_privacy_type') | Select-Object -First 1
    } else { $o.SandboxPrivacy }
    if ($privacy -notin @('owner', 'bylink')) { throw 'Existing analysis privacy is invalid. Set -SandboxPrivacy explicitly.' }
    $lp.azureTenantId = $o.TenantId
    $lp.azureClientId = $Identity.App.AppId
    $lp.azureClientSecret = $Secret
    $lp.ConnectionName = $P.Connection
    $lp.analysisPrivacyType = $privacy
  } else {
    $fp.anyrunApiKey = $ApiKey
    $interval = $o.FeedsIntervalHours
    $depth = $o.FeedsFetchDepthDays
    $confidence = $o.FeedsMinimumConfidence
    if ($Workflow) {
      if ('FeedsIntervalHours' -notin $C.Explicit) {
        $recurrence = $Workflow.properties.definition.triggers.Recurrence.recurrence
        if ($recurrence.frequency -ne 'Hour') { throw 'Set -FeedsIntervalHours explicitly for a non-hourly existing workflow.' }
        $interval = $recurrence.interval
      }
      if ('FeedsFetchDepthDays' -notin $C.Explicit) {
        $depth = @(Get-WorkflowValue $Workflow.properties.definition 'feed_fetch_depth') | Select-Object -First 1
      }
      if ('FeedsMinimumConfidence' -notin $C.Explicit) {
        $confidence = @(Get-WorkflowValue $Workflow.properties.definition 'minimum_confidence_threshold') | Select-Object -First 1
      }
    }
    if ($interval -lt 1 -or $interval -gt 168 -or $depth -lt 1 -or $depth -gt 365 -or $confidence -lt 1 -or $confidence -gt 100) {
      throw 'Existing Feeds schedule/filter is invalid. Set the corresponding parameters explicitly.'
    }
    $lp.intervalRecurrence = $interval
    $lp.feedFetchDepth = $depth
    $lp.minimum_confidence_threshold = $confidence
  }
  return @{Function = $fp
    Logic = $lp
  }
}

function Publish-Package {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Az returns a transient plaintext SAS; secure ARM PackageUri requires SecureString. URI is redacted.'
  )]
  param([hashtable]$C, [hashtable]$P, [hashtable]$Storage)

  $container = 'anyrun-installer-artifacts'
  $blob = "$($P.Hashes.Package).zip"
  $null = Get-PrivateContainer $C $Storage $container
  $null = Set-AzStorageBlobContent -File (Join-Path $C.Root "Assets/$($P.Kind).zip") -Container $container -Blob $blob -Context $Storage.Context -Force
  $sasOptions = @{
    Container = $container
    Blob = $blob
    Permission = 'r'
    Protocol = 'HttpsOnly'
    StartTime = [DateTime]::UtcNow.AddMinutes(-5)
    ExpiryTime = [DateTime]::UtcNow.AddHours(2)
    FullUri = $true
    Context = $Storage.Context
  }
  $uri = New-AzStorageBlobSASToken @sasOptions
  $C.Secrets.Add($uri)
  return (ConvertTo-SecureString $uri -AsPlainText -Force)
}

function Deploy-Template([hashtable]$C, [hashtable]$P, [string]$Kind, [hashtable]$Parameters) {
  $file = Join-Path $C.Root "Assets/$($P.Kind).$Kind.json"
  $Parameters.DeploymentRegion = $C.Options.Region
  $Parameters.ResourceTags = Get-TemplateTag $C $P $Kind
  for ($attempt = 1; $attempt -le 3; $attempt++) {

    $errors = @(Test-AzResourceGroupDeployment -ResourceGroupName $C.Options.ResourceGroup -TemplateFile $file -TemplateParameterObject $Parameters)
    if ($errors.Count) {
      throw ("$($P.Kind) $Kind validation failed: " + (($errors | ForEach-Object { $_.Message }) -join '; '))
    }
    $name = "anyrun-$($P.Kind.ToLowerInvariant())-$($Kind.ToLowerInvariant())-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
      $deploymentOptions = @{
        Name = $name
        ResourceGroupName = $C.Options.ResourceGroup
        TemplateFile = $file
        TemplateParameterObject = $Parameters
        Mode = 'Incremental'
        Debug = $false
        Verbose = $false
      }
      $result = New-AzResourceGroupDeployment @deploymentOptions
      if ($result.ProvisioningState -ne 'Succeeded') { throw "Deployment ended in $($result.ProvisioningState)." }
      break
    } catch {
      $message = $_.Exception.Message
      $operations = @(Get-AzResourceGroupDeploymentOperation -ResourceGroupName $C.Options.ResourceGroup `
          -DeploymentName $name -ErrorAction SilentlyContinue | Where-Object ProvisioningState -eq Failed)
      $details = @($operations | ForEach-Object { "$(Get-Field $_ 'TargetResource'): $(Get-Field $_ 'StatusMessage')" }) -join '; '
      $terminal = Get-AzResourceGroupDeployment -ResourceGroupName $C.Options.ResourceGroup -Name $name -ErrorAction SilentlyContinue
      if ($attempt -lt 3 -and $terminal -and $terminal.ProvisioningState -eq 'Failed' -and "$message $details" -match 'AuthorizationPermissionMismatch|StorageAccountAccessDenied|RBAC.*propagat') {
        Write-Host 'Waiting for Function storage RBAC propagation before retrying the failed deployment...' -ForegroundColor DarkGray
        Start-Sleep -Seconds 30
        continue
      }
      throw (Protect-Message $C "$($P.Kind) $Kind deployment failed: $message $details")
    }
  }
}

function Get-Handler([hashtable]$C, [hashtable]$P) {
  $body = Read-Arm $C "$(Get-ResourcePath $C Microsoft.Web/sites $P.Function)/functions?api-version=2024-11-01"
  if (-not $body) { return @() }
  if (-not $body.Contains('value') -or $null -eq $body.value -or (Get-Field $body 'nextLink')) {
    throw 'Function handler inventory is incomplete. No deployment will overwrite it.'
  }
  return @($body.value | ForEach-Object { ($_.name -split '/')[-1] })
}

function Test-Installation([hashtable]$C, [hashtable]$P) {
  $errors = [Collections.Generic.List[string]]::new()
  try {
    $handlers = @(Get-Handler $C $P)
    foreach ($handler in $P.Handlers) {
      if ($handler -notin $handlers) { $errors.Add("Missing Function handler: $handler") }
    }
  } catch { $errors.Add((Protect-Message $C $_.Exception.Message)) }
  foreach ($pair in @(@('Microsoft.Web/sites', $P.Function, '2024-11-01'), @('Microsoft.Logic/workflows', $P.Logic, '2019-05-01'))) {
    try {
      $resource = Read-Arm $C "$(Get-ResourcePath $C $pair[0] $pair[1])?api-version=$($pair[2])"
      $state = Get-Field (Get-Field $resource 'properties') $(if ($pair[0] -eq 'Microsoft.Web/sites') { 'state' }
        else { 'provisioningState' })
      if (-not $resource -or $state -notin @('Succeeded', 'Running')) { $errors.Add("$($pair[0]) provisioning state: $state") }
    } catch { $errors.Add((Protect-Message $C $_.Exception.Message)) }
  }
  if ($P.Kind -eq 'Sandbox') {
    try {
      $connection = Read-Arm $C "$(Get-ResourcePath $C Microsoft.Web/connections $P.Connection)?api-version=2016-06-01"
      if (-not @($connection.properties.statuses | Where-Object status -eq 'Connected').Count) {
        $errors.Add('Defender API connection is not Connected.')
      }
    } catch { $errors.Add((Protect-Message $C $_.Exception.Message)) }
  }
  if ($errors.Count) { throw ($errors -join "`n") }
}

function Install-Connector {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Graph and existing Function settings supply transient plaintext credentials; ARM requires SecureString. Values are redacted.'
  )]
  param([hashtable]$C, [hashtable]$P)
  Write-Host "Installing $($P.Kind)..." -ForegroundColor Cyan
  $storage = Get-Storage $C $P
  $null = Get-PrivateContainer $C $storage 'anyrun-installer-artifacts'
  if (Test-RequestedTag $C $storage.Account) {
    $null = Get-CorporateTag $C $storage.Account
    $null = Update-AzTag -ResourceId $storage.Account.Id -Operation Merge -Tag $C.Options.Tags
  }
  $site = Read-Arm $C "$(Get-ResourcePath $C Microsoft.Web/sites $P.Function)?api-version=2024-11-01"
  Assert-Managed $site $P.Instance $P.Kind
  if ($site -and (Get-Field $site 'kind') -notmatch '(^|,)functionapp(,|$)') { throw 'The managed site is not a Function App.' }
  $workflow = Read-Arm $C "$(Get-ResourcePath $C Microsoft.Logic/workflows $P.Logic)?api-version=2019-05-01"
  Assert-Managed $workflow $P.Instance $P.Kind
  $identity = Get-Identity $C $P $storage
  if ($identity.PendingConsent) {
    return @{Connector = $P.Kind
      Status = 'NeedsConsent'
      AppId = $identity.App.AppId
      ApplicationObjectId = $identity.App.Id
    }
  }
  $recordedApp = Get-Field (Get-Field $site 'tags') 'ANYRUNApplicationObjectId'
  if ($recordedApp -and $recordedApp -ne $identity.App.Id) { throw 'Function identity metadata differs from the managed application.' }
  $settings = Read-FunctionSetting $C $P $site
  if ((Get-Field $settings 'AzureClientID') -and $settings.AzureClientID -ne $identity.App.AppId) {
    throw 'Managed Function App uses another client ID. Its configuration will not be replaced.'
  }
  $savedId = Get-Field (Get-Field $site 'tags') 'ANYRUNCredentialKeyId'
  $secret = Get-Field $settings 'AzureClientSecret'
  $identity.NewCredential = $false
  if ($secret -and "$secret" -like '@Microsoft.KeyVault(*)') {
    throw 'This installer cannot resolve an externally configured Key Vault credential.'
  }
  if ($secret -and $savedId -notin @($identity.App.PasswordCredentials | ForEach-Object { "$($_.KeyId)" })) {
    throw 'Recorded Function credential KeyId does not match this application. Review the managed resource.'
  }
  $apiKey = $C.Options["$($P.Kind)ApiKey"]
  if (-not $apiKey) {
    $apiKeyName = if ($P.Kind -eq 'Sandbox') { 'ANYRUN_API_KEY' }
    else { 'ANYRUN_api_key' }
    $savedApiKey = Get-Field $settings $apiKeyName
    if ($savedApiKey -and "$savedApiKey" -like '@Microsoft.KeyVault(*)') {
      throw 'Pass the resolved API key explicitly for an externally configured Key Vault reference.'
    }
    if ($savedApiKey) { $apiKey = ConvertTo-SecureString ("$savedApiKey" -replace '^API-KEY\s+', '') -AsPlainText -Force }
    elseif ($C.Options.NonInteractive) { throw "NonInteractive installation requires -$($P.Kind)ApiKey as SecureString." }
    else { $apiKey = Read-Host "ANY.RUN $($P.Kind) API key" -AsSecureString }
  }
  if (-not $apiKey -or $apiKey.Length -eq 0) { throw 'ANY.RUN API key is empty.' }
  $null = Get-PlainSecret $C $apiKey
  if (-not $secret -or $C.Options.RotateSecret) {

    $credentialBody = @{passwordCredential = @{displayName = "$($P.Tag):password:$([Guid]::NewGuid())"
        endDateTime = [DateTimeOffset]::UtcNow.AddMonths(6)
      }
    }
    $new = Invoke-GraphPropagation $C { Add-MgApplicationPassword -ApplicationId $identity.App.Id -BodyParameter $credentialBody } PasswordCreation
    $identity.CurrentCredential = $new
    $secret = $new.SecretText
    $savedId = "$($new.KeyId)"
    $identity.NewCredential = $true
    Write-Host "Created credential $savedId; expires $($new.EndDateTime). Previous credentials are retained." -ForegroundColor DarkGray
  }
  $secretValue = ConvertTo-SecureString "$secret" -AsPlainText -Force
  $C.Secrets.Add("$secret")
  $identity.KeyId = $savedId
  $inventory = Get-CredentialInventory $identity
  if ($inventory.Expired) {
    throw "Current credential '$savedId' expired at $($inventory.ExpiresUTC). Re-run: $(Get-RotationCommand $C $P)"
  }
  Test-Credential $C $P $identity $secretValue
  $parameters = Get-Parameter $C $P $storage $identity $secretValue $apiKey $settings $workflow
  $law = Read-Arm $C "$(Get-ResourcePath $C Microsoft.OperationalInsights/workspaces $C.Workspace)?api-version=2023-09-01"
  Assert-Managed $law $C.GroupInstance
  if (-not $law) {
    $null = New-AzOperationalInsightsWorkspace -ResourceGroupName $C.Options.ResourceGroup -Name $C.Workspace -Location $C.Options.Region -Sku PerGB2018 `
      -Tag ((Get-CorporateTag $C $null) + @{ANYRUNInstaller = 'customer-v1'
        ANYRUNInstance = $C.GroupInstance
      })
  } elseif (Test-RequestedTag $C $law) {
    $null = Get-CorporateTag $C $law
    $lawId = Get-ResourcePath $C Microsoft.OperationalInsights/workspaces $C.Workspace
    $null = Update-AzTag -ResourceId $lawId -Operation Merge -Tag $C.Options.Tags
  }
  $parameters.Function.PackageUri = Publish-Package $C $P $storage
  Deploy-Template $C $P Function $parameters.Function
  for ($attempt = 0; $attempt -lt 18; $attempt++) {
    try { if ($P.Handlers[0] -in @(Get-Handler $C $P)) { break } }
    catch { if (-not (Test-HostFailure $_)) { throw } }
    if ($attempt -eq 17) {
      throw 'Function registration did not complete. Re-run the same command to repair this managed Function App.'
    }
    Start-Sleep -Seconds 10
  }
  Deploy-Template $C $P Logic $parameters.Logic
  Test-Installation $C $P
  if ($inventory.Previous.Count) {
    Write-Host 'Previous passwords are retained. Revoke the following exact KeyIds only after verifying ALL consumers have switched:' -ForegroundColor Yellow
    foreach ($credential in $inventory.Previous) {
      Write-Host "KeyId: $($credential.KeyId); expires $($credential.ExpiresUTC)"
      Write-Host $credential.RevokeCommand
    }
  }
  return @{Connector = $P.Kind
    Status = 'StructureVerified'
    AppId = $identity.App.AppId
    ApplicationObjectId = $identity.App.Id
    Function = $P.Function
    LogicApp = $P.Logic
    CurrentCredentialKeyId = $savedId
    CurrentCredentialExpiresUTC = $inventory.ExpiresUTC
    PreviousCredentials = $inventory.Previous
    Portal = "https://portal.azure.com/#resource$($C.Scope)"
  }
}

function Invoke-CustomerInstall([hashtable]$Options, [string[]]$Explicit, [string]$Root, [scriptblock]$ShouldProcess, [bool]$Offline = $false, [string]$EntryPath = '') {
  $c = @{Options = @{} + $Options
    Explicit = @($Explicit)
    Root = $Root
    EntryPath = $EntryPath
    ExternalGroup = $false
    GraphOwned = $false
    Secrets = [Collections.Generic.List[string]]::new()
    Results = [Collections.Generic.List[object]]::new()
    Group = $null
    Operator = $null
    Azure = $null
    GroupInstance = ''
    Scope = ''
    Workspace = ''
  }
  try {
    if (-not $c.Options.Connector) {
      if ($c.Options.NonInteractive -and -not $Offline -and -not $c.Options.PlanOnly) {
        throw 'NonInteractive installation requires -Connector Sandbox, Feeds, or Both.'
      }
      if ($Offline -or $c.Options.PlanOnly) { $c.Options.Connector = 'Both' }
      else {
        Write-Host 'Choose connectors: 1) Sandbox  2) TI Feeds  3) Both'
        $choice = Read-Host 'Selection [3]'
        $c.Options.Connector = switch ($choice) {
          '1' { 'Sandbox' }
          '2' { 'Feeds' }
          '' { 'Both' }
          '3' { 'Both' }
          default { throw 'Choose 1, 2, or 3.' }
        }
      }
    }
    $kinds = if ($c.Options.Connector -eq 'Both') { @('Sandbox', 'Feeds') }
    else { @($c.Options.Connector) }
    $profiles = @($kinds | ForEach-Object { Get-Profile $c $_ })
    Test-TagOption $c
    if ($Offline -or $c.Options.PlanOnly) {
      return @{Status = 'OfflinePlan'
        Connector = $c.Options.Connector
        ResourceGroup = $c.Options.ResourceGroup
        Region = $c.Options.Region
        Profiles = @($profiles | ForEach-Object { @{Connector = $_.Kind
              RequiredDefenderRoles = $_.Roles
              CredentialLifetimeMonths = 6
            } })
        Writes = @()
        LiveChecksPerformed = $false
        ArtifactDownloadsPerformed = $false
      }
    }
    if ($c.Options.NonInteractive -and (-not $c.Options.TenantId -or -not $c.Options.SubscriptionId -or -not $c.Options.ApproveDefenderPermissions)) {
      throw 'NonInteractive installation requires explicit TenantId, SubscriptionId and ApproveDefenderPermissions.'
    }
    Get-Artifact $c $profiles
    Initialize-Module $c
    Connect-Cloud $c
    $profiles = @($kinds | ForEach-Object { Get-Profile $c $_ })
    Test-CloudPreflight $c $profiles
    Write-Host ("Deployment: tenant $($c.Options.TenantId); subscription $($c.Options.SubscriptionId); " +
      "group $($c.Options.ResourceGroup); resource region $($c.Options.Region).") -ForegroundColor Cyan
    Write-Host 'Dedicated application permissions:' -ForegroundColor Yellow
    foreach ($p in $profiles) { Write-Host "  $($p.Kind): $($p.Roles -join ', ')" }
    if ('Sandbox' -in $kinds) {
      Write-Host 'Sandbox Live Response permits commands on managed devices. Review tenant policy before activation.' -ForegroundColor Yellow
    }
    if (-not $c.Options.ApproveDefenderPermissions -and (Read-Host 'Create these applications/resources and grant their permissions? [y/N]') -notmatch '^(y|yes)$') {
      throw 'Permission/deployment approval was declined.'
    }
    if (-not (& $ShouldProcess "$($c.Options.TenantId) / $($c.Options.SubscriptionId) / $($c.Options.ResourceGroup)" "Install $($c.Options.Connector) connectors in $($c.Options.Region)")) {
      return @{Status = 'Cancelled'
        Writes = @()
      }
    }
    Initialize-AzureResource $c
    $c.Workspace = "anyrun-mde-law-$($c.GroupInstance.Substring(0,10))"
    foreach ($p in $profiles) {
      try { $c.Results.Add((Install-Connector $c $p)) }
      catch {
        $c.Results.Add(@{Connector = $p.Kind
            Status = 'Failed'
            Error = (Protect-Message $c $_.Exception.Message)
          })
      }
    }
    $status = if (@($c.Results | Where-Object Status -eq Failed).Count) { 'Failed' }
    elseif (@($c.Results | Where-Object Status -eq NeedsConsent).Count) { 'NeedsConsent' }
    else { 'StructureVerified' }
    Write-Host 'Re-run the same command after a failure or manual consent. No Resume/state file is needed.' -ForegroundColor Cyan
    if ('Sandbox' -in $kinds) {
      Write-Host 'Sandbox requires Defender Live Response settings and the current unsigned-script policy described in README.md.' -ForegroundColor Yellow
    }
    Write-Host 'Monitor 6-month credential expiry. Rotation retains previous passwords; revoke exact old KeyIds only after verified cutover.' -ForegroundColor Yellow
    return @{Status = $status
      TenantId = $c.Options.TenantId
      SubscriptionId = $c.Options.SubscriptionId
      ResourceGroup = $c.Options.ResourceGroup
      Region = $c.Options.Region
      Results = $c.Results.ToArray()
      RuntimeMutationTestPerformed = $false
    }
  } catch { throw (Protect-Message $c $_.Exception.Message) }
  finally {
    if ($c.GraphOwned) { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue }
    $c.Secrets.Clear()
  }
}
# Pass the actual parameter values, including defaults, with explicitness separate.
$options = @{}
foreach ($name in $MyInvocation.MyCommand.Parameters.Keys) {
  $commonParameters = @(
    'WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
    'ProgressAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable',
    'OutVariable', 'OutBuffer', 'PipelineVariable'
  )
  if ($name -in $commonParameters) { continue }
  $options[$name] = (Get-Variable -Name $name -Scope Local).Value
}
$entryCmdlet = $PSCmdlet
$approval = { param($target, $action) $entryCmdlet.ShouldProcess($target, $action) }.GetNewClosure()
$work = $null
$workCreated = $false
try {
  if (-not $PlanOnly -and -not $WhatIfPreference) {
    $work = Join-Path ([IO.Path]::GetTempPath()) "anyrun-mde-$([Guid]::NewGuid().ToString('N'))"
    if (Test-Path -LiteralPath $work) { throw 'Temporary workspace already exists.' }
    if ($IsWindows) { $null = [IO.Directory]::CreateDirectory($work) }
    else { $null = [IO.Directory]::CreateDirectory($work, [IO.UnixFileMode]448) }
    $workCreated = $true
  }
  $result = Invoke-CustomerInstall -Options $options -Explicit @($PSBoundParameters.Keys) -Root $work -EntryPath $PSCommandPath `
    -ShouldProcess $approval -Offline ([bool]$WhatIfPreference)
} finally {
  if ($workCreated -and [IO.Directory]::Exists($work)) {
    try { [IO.Directory]::Delete($work, $true) }
    catch { Write-Warning "Remove leftover release files from $work after this process finishes." }
  }
}
$result | ConvertTo-Json -Depth 12
if ($result.Status -eq 'Failed') { exit 1 }
if ($result.Status -eq 'NeedsConsent') { exit 2 }
