#Requires -Version 7.0
# Executes the installer's orchestration with local HTTP fixtures and Azure/Graph
# stubs. Real hash checks, ZIP checks, template preparation and parameter wiring
# are retained. No network calls or live Azure deployments are performed.
param([string]$Root=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version 3
$installer=Join-Path $Root 'Scripts/Deploy-ANYRUNMDEConnector.ps1'
$source=Get-Content -LiteralPath $installer -Raw
$repoRoot=Split-Path $Root -Parent
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('anyrun-installer-flow-'+[Guid]::NewGuid().ToString('N')+'.ps1')
$fixture=@'
$global:AnyRunInstallerFlow.Downloads=[Collections.Generic.List[string]]::new()
$global:AnyRunInstallerFlow.Validations=[Collections.Generic.List[object]]::new()
$global:AnyRunInstallerFlow.Deployments=[Collections.Generic.List[object]]::new()
$global:AnyRunInstallerFlow.Identities=0
function Ensure-Module { param($Name,$MinimumVersion,$RequiredCommands) }
function Resolve-RepositoryCommit { param($RepositoryName,$Ref) return ('a'*40) }
function Connect-AzureSmart {
  param($RequestedTenantId,$RequestedSubscriptionId)
  return [pscustomobject]@{Tenant=@{Id=$RequestedTenantId};Subscription=@{Id=$RequestedSubscriptionId;Name='Fixture'}}
}
function Connect-GraphSmart { param($RequestedTenantId) }
function Get-AzResourceGroup { [CmdletBinding()]param($Name) }
function Ensure-ResourceProvider { param($ProviderNamespace) }
function Assert-FlexConsumptionRegion { param($Location) }
function Ensure-ResourceGroup { param($Name,$Location) [pscustomobject]@{Name=$Name;Location=$Location} }
function Get-AzResource {
  [CmdletBinding()]param($ResourceGroupName,$ResourceType,$Name,[switch]$ExpandProperties)
  if ($ExpandProperties -and $ResourceType -eq 'Microsoft.Web/sites') {
    return [pscustomobject]@{Properties=[pscustomobject]@{state='Running'}}
  }
  if (-not $ResourceType -and $global:AnyRunInstallerFlow.ContainsKey('SharedGroup')) {
    return [pscustomobject]@{ResourceType='Microsoft.Logic/workflows';Name='ANYRUN-Sandbox-MDE-demo01-LA'}
  }
}
function Test-EffectiveRoleAssignmentPermission { param($Scope) return $true }
function Get-AzRoleAssignment {
  [CmdletBinding()]param($Scope)
  [pscustomobject]@{RoleDefinitionName='Owner';DisplayName='hidden-account@example.com';ObjectType='User';Scope=$Scope}
}
function Assert-FunctionAppNameAvailable { param($Name) }
function Assert-StorageAccountUsable { param($Name) }
function Ensure-LogAnalyticsWorkspace { param($ResourceGroupName,$Name,$Location) [pscustomobject]@{Name=$Name} }
function Get-ExistingFunctionConfiguration { param($FunctionAppName) return $null }
function Ensure-StorageAccount {
  param($ResourceGroupName,$Name,$Location)
  [pscustomobject]@{Name=$Name;Key=(ConvertTo-SecureString 'fixture-storage-key' -AsPlainText -Force);
    ConnectionString=(ConvertTo-SecureString 'fixture-storage-connection' -AsPlainText -Force);Created=$true}
}
function Ensure-ConnectorIdentity {
  param($Label,$DisplayName,$ExistingAppId,$ExistingClientSecret,$RequiredRoleValues,$TrustedExistingFunctionBinding,[switch]$RotateSecret)
  $global:AnyRunInstallerFlow.Identities++
  $deferred=$global:AnyRunInstallerFlow.ContainsKey('Deferred') -and $global:AnyRunInstallerFlow.Deferred -eq $Label
  if ($deferred) {
    $script:DeferredConsentUrls.Add('https://login.microsoftonline.com/fixture/adminconsent?client_id=fixture')
    $script:DeferredConnectorLabels.Add($Label)
  }
  [pscustomobject]@{DisplayName=$DisplayName;ClientId='33333333-3333-3333-3333-333333333333';
    ClientSecret=(ConvertTo-SecureString 'fixture-client-secret' -AsPlainText -Force);
    ConsentDeferred=$deferred;NewCredentialKeyId=$null;ApplicationObjectId='fixture-object'}
}
function Remove-LegacyStorageRoleAssignment { param($StorageAccountName,$FunctionAppName,$ConnectorType,[switch]$SupersededOwner) }
function Remove-ConnectorDeploymentArtifacts { param($StorageAccountName,$AllowRoleCleanup) }
function Wait-FunctionRegistration { param($FunctionAppName,$FunctionName,$Attempts) }
function Invoke-AzRestMethod {
  [CmdletBinding()]param($Method,$Path)
  if ($Method -ne 'GET' -or $Path -notmatch '/Microsoft.Logic/workflows/([^/?]+)\?api-version=2016-06-01$') {
    throw "Unexpected verification request: $Method $Path"
  }
  $workflowName=$Matches[1]
  $id=$Path.Split('?')[0]
  if ($global:AnyRunInstallerFlow.ContainsKey('MissingWorkflow')) {
    return [pscustomobject]@{StatusCode=404;Content='{}'}
  }
  if ($global:AnyRunInstallerFlow.ContainsKey('WrongWorkflow')) {
    $id=$id.Replace($workflowName,'ANYRUN-Sandbox-MDE-demo01-LA')
    $workflowName='ANYRUN-Sandbox-MDE-demo01-LA'
  }
  $state=if ($global:AnyRunInstallerFlow.ContainsKey('DisabledWorkflow')) {'Disabled'} else {'Enabled'}
  $payload=@{id=$id;name=$workflowName;type='Microsoft.Logic/workflows';properties=@{provisioningState='Succeeded';state=$state}}
  [pscustomobject]@{StatusCode=200;Content=($payload|ConvertTo-Json -Depth 10 -Compress)}
}
function Get-ApiConnectionStatus { param($Name) return 'Connected' }
function Invoke-WebRequest {
  [CmdletBinding()]param([string]$Uri,[string]$OutFile)
  $prefix='https://raw.githubusercontent.com/'+$Repository+'/'+('a'*40)+'/'
  if (-not $Uri.StartsWith($prefix,[StringComparison]::Ordinal)) { throw "Unexpected fixture URL: $Uri" }
  $relative=[Uri]::UnescapeDataString($Uri.Substring($prefix.Length))
  $global:AnyRunInstallerFlow.Downloads.Add($relative)
  if ($global:AnyRunInstallerFlow.Missing -and $relative.EndsWith($global:AnyRunInstallerFlow.Missing)) {
    throw "Fixture HTTP 404: $relative"
  }
  $local=Join-Path $global:AnyRunInstallerFlow.RepoRoot $relative
  if (-not (Test-Path -LiteralPath $local -PathType Leaf)) { throw "Fixture HTTP 404: $relative" }
  Copy-Item -LiteralPath $local -Destination $OutFile
  if ($global:AnyRunInstallerFlow.Corrupt -and $relative.EndsWith($global:AnyRunInstallerFlow.Corrupt)) {
    [IO.File]::AppendAllText($OutFile,'fixture-corruption')
  }
}
function Assert-FixtureTemplateParameters {
  param($TemplateFile,$TemplateParameterObject)
  $t=Get-Content -LiteralPath $TemplateFile -Raw|ConvertFrom-Json
  $declared=@($t.parameters.PSObject.Properties.Name)
  foreach ($name in $TemplateParameterObject.Keys) {
    if ($name -notin $declared) { throw "Undeclared ARM parameter: $name" }
    $p=$t.parameters.$name
    if ($p.type -eq 'securestring' -and $TemplateParameterObject[$name] -isnot [SecureString]) {
      throw "Plaintext supplied for secure parameter $name"
    }
  }
  foreach ($p in $t.parameters.PSObject.Properties) {
    if ('defaultValue' -notin @($p.Value.PSObject.Properties.Name) -and -not $TemplateParameterObject.ContainsKey($p.Name)) {
      throw "Missing required ARM parameter: $($p.Name)"
    }
  }
  $extension=@($t.resources|Where-Object type -eq 'Microsoft.Web/sites/extensions')
  if ($extension.Count) {
    if ($extension[0].properties.packageUri -cne "[parameters('packageUri')]") {throw 'Template was rewritten instead of parameterized'}
    if ($TemplateParameterObject.packageUri -notmatch '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/') {throw 'Runtime is not pinned to resolved commit'}
    if ($TemplateParameterObject.hostingPlanName -notmatch '-demo01-Plan$') {throw 'New plan naming was not applied'}
    if ($TemplateParameterObject.appInsightsName -notmatch '-demo01-AI$') {throw 'New Insights naming was not applied'}
  }
  return $t
}
function Test-AzResourceGroupDeployment {
  [CmdletBinding()]param($ResourceGroupName,$TemplateFile,$TemplateParameterObject)
  $null=Assert-FixtureTemplateParameters $TemplateFile $TemplateParameterObject
  $global:AnyRunInstallerFlow.Validations.Add(@{Name=$TemplateParameterObject.functionAppName;Parameters=@($TemplateParameterObject.Keys)})
}
function New-AzResourceGroupDeployment {
  [CmdletBinding()]param($Name,$ResourceGroupName,$Mode,$TemplateFile,$TemplateObject,$TemplateParameterObject)
  if ($Mode -ne 'Incremental') { throw 'Unexpected destructive deployment mode' }
  if ($TemplateObject) {
    if ($TemplateObject.resources.Count) {throw 'Naming deployment must contain no resources'}
    return [pscustomobject]@{ProvisioningState='Succeeded';Outputs=@{nameHash=@{Value='abcdef'}}}
  }
  $t=Assert-FixtureTemplateParameters $TemplateFile $TemplateParameterObject
  $global:AnyRunInstallerFlow.Deployments.Add(@{Name=$Name;Parameters=@($TemplateParameterObject.Keys);Types=@($t.resources.type)})
  return [pscustomobject]@{ProvisioningState='Succeeded'}
}
'@
$marker='try {'+"`n"+'Write-Banner "ANY.RUN Microsoft Defender for Endpoint connector deployment"'
if (-not $source.Contains($marker)) {throw 'Installer orchestration entry not found'}
$instrumented=$source.Replace($marker,$fixture+"`n"+$marker)
[IO.File]::WriteAllText($temporary,$instrumented)
$passed=0
try {
  foreach ($kind in @('Sandbox','Feeds')) {
    $global:AnyRunInstallerFlow=@{RepoRoot=$repoRoot;Missing='';Corrupt=''}
    $p=@{Connector=$kind;TenantId='11111111-1111-1111-1111-111111111111';
      SubscriptionId='22222222-2222-2222-2222-222222222222';ResourceGroup='ANYRUN-MDE-RG';
      InstanceName='demo01';Region='eastus';NonInteractive=$true;ApproveDefenderPermissions=$true;
      SandboxApiKey=(ConvertTo-SecureString 'fixture-api-key' -AsPlainText -Force);
      FeedsApiKey=(ConvertTo-SecureString 'fixture-api-key' -AsPlainText -Force)}
    $output=@(& $temporary @p 6>&1)
    $count=1
    if ($global:AnyRunInstallerFlow.Identities -ne $count) {throw "Wrong identity count for $kind"}
    if ($global:AnyRunInstallerFlow.Validations.Count -ne 2*$count) {throw "Incomplete ARM validation for $kind"}
    if ($global:AnyRunInstallerFlow.Deployments.Count -ne 2*$count) {throw "Incomplete deployment for $kind"}
    if ($global:AnyRunInstallerFlow.Downloads.Count -ne 3*$count) {throw "Missing artifact download for $kind"}
    $log=$output|Out-String
    foreach($hidden in @('hidden-account@example.com','fixture-client-secret','fixture-api-key','fixture-storage-key','fixture-storage-connection')) {
      if ($log.Contains($hidden)) {throw "Console disclosed a fixture account/credential: $kind"}
    }
    if (-not $log.Contains('Deployment finished.')) {throw "Installer did not reach success for $kind"}
    $passed++
    Write-Host "PASS: $kind orchestration, real artifact hashes/ZIPs, parameter wiring, console privacy."
  }
  foreach ($fault in @('MissingTemplate','MissingPackage','WrongPackageHash')) {
    $global:AnyRunInstallerFlow=@{RepoRoot=$repoRoot;Missing='';Corrupt=''}
    if ($fault -eq 'MissingTemplate') {$global:AnyRunInstallerFlow.Missing='ANYRUN-Feeds-MDE-FA.json'}
    if ($fault -eq 'MissingPackage') {$global:AnyRunInstallerFlow.Missing='ANYRUN-Feeds-MDE-FA.zip'}
    if ($fault -eq 'WrongPackageHash') {$global:AnyRunInstallerFlow.Corrupt='ANYRUN-Feeds-MDE-FA.zip'}
    $p.Connector='Feeds';$errorMessage=''
    try { $null=@(& $temporary @p 6>&1) } catch {$errorMessage=$_.Exception.Message}
    $expected=if ($fault -eq 'WrongPackageHash') {'SHA-256 mismatch'} else {'Fixture HTTP 404'}
    if (-not $errorMessage.Contains($expected)) {throw "Unexpected $fault result: $errorMessage"}
    if ($global:AnyRunInstallerFlow.Identities -ne 0 -or $global:AnyRunInstallerFlow.Deployments.Count -ne 0) {
      throw "$fault was detected after identity/deployment writes"
    }
    $passed++
    Write-Host "PASS: $fault fails before identity/deployment writes."
  }
  foreach ($scenario in @('SharedGroup','SkipLogicApp','DeferredFeeds','DeferredSandbox','MissingWorkflow','WrongWorkflow','DisabledWorkflow')) {
    $global:AnyRunInstallerFlow=@{RepoRoot=$repoRoot;Missing='';Corrupt=''}
    $p.Connector='Feeds';$p.Remove('SkipLogicApp')
    if ($scenario -eq 'SharedGroup') {$global:AnyRunInstallerFlow.SharedGroup=$true}
    if ($scenario -eq 'SkipLogicApp') {$p.SkipLogicApp=$true}
    if ($scenario -eq 'DeferredFeeds') {$global:AnyRunInstallerFlow.Deferred='TI Feeds'}
    if ($scenario -eq 'DeferredSandbox') {$p.Connector='Sandbox';$global:AnyRunInstallerFlow.Deferred='Sandbox'}
    if ($scenario -in @('MissingWorkflow','WrongWorkflow','DisabledWorkflow')) {$global:AnyRunInstallerFlow[$scenario]=$true}
    $errorMessage='';$output=@()
    try {$output=@(& $temporary @p 6>&1)} catch {$errorMessage=$_.Exception.Message}
    $log=$output|Out-String
    if ($scenario -in @('MissingWorkflow','WrongWorkflow','DisabledWorkflow')) {
      $expected=switch($scenario) {'MissingWorkflow' {'verification failures'} 'WrongWorkflow' {'unexpected resource'} 'DisabledWorkflow' {'expected Enabled'}}
      if (-not $errorMessage.Contains($expected)) {throw "Unexpected $scenario result: $errorMessage"}
      if ($log.Contains('Deployment finished.')) {throw "$scenario reported deployment success"}
    } elseif ($scenario -in @('SkipLogicApp','DeferredFeeds','DeferredSandbox')) {
      if ($errorMessage) {throw $errorMessage}
      if ($log.Contains('Deployment finished.') -or -not $log.Contains('PARTIAL DEPLOYMENT')) {throw "$scenario did not report incomplete activation"}
      $expected=if ($scenario -eq 'SkipLogicApp') {'SKIPPED (-SkipLogicApp)'} else {'NOT DEPLOYED (Defender admin consent pending)'}
      if (-not $log.Contains($expected)) {throw "$scenario hid the skipped Logic App"}
      $count=1
      if ($global:AnyRunInstallerFlow.Deployments.Count -ne $count) {throw "$scenario deployed unexpected resources"}
    } else {
      if ($errorMessage) {throw $errorMessage}
      if (-not $log.Contains('Deployment finished.') -or -not $log.Contains('ANYRUN-Feeds-MDE-demo01-LA [Succeeded]')) {throw 'Shared group Feeds deployment was not verified'}
      if ($global:AnyRunInstallerFlow.Deployments.Count -ne 2) {throw 'Shared group Feeds deployment changed the Sandbox resource set'}
      if (-not $log.Contains('Confirmed Logic App ID')) {throw 'Workflow resource ID was not verified'}
    }
    $passed++
    Write-Host "PASS: $scenario validates actual workflow identity/state and deployment completion."
  }
  Write-Host "PASS: $passed installer-flow scenarios, no network or live Azure calls."
} finally {
  Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
  Remove-Variable -Name AnyRunInstallerFlow -Scope Global -ErrorAction SilentlyContinue
}
