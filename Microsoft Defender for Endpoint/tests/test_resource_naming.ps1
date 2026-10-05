# Offline tests: parse actual installer functions; mock Azure calls only.
# Run with PowerShell 7: ./test_resource_naming.ps1
param([string]$ExportFixtures)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
$root = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $root 'Scripts/Deploy-ANYRUNMDEConnector.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors.Message -join "`n") }
$wanted = @('Get-StableSuffix','Get-AzureAppNameHash','Get-ConnectorDefaultNames','Select-ExistingResourceName',
  'Set-FunctionSupportingResourceNames','Assert-FunctionName','Assert-LogicAppName')
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($node.Name -in $wanted) { Invoke-Expression $node.Extent.Text }
}
$text = Get-Content $scriptPath -Raw
$start = $text.IndexOf('$stableSuffix = Get-StableSuffix -InputText "$TenantId|$SubscriptionId|$ResourceGroup" -Length 8')
$end = $text.IndexOf('Write-Step "Checking permissions and global names before changing Entra ID..."', $start)
$mainNaming = [scriptblock]::Create($text.Substring($start, $end - $start))
$script:azureResources = @()
$script:armHash = 'abcdef'
$script:armState = 'Succeeded'
$script:armCalls = 0
$script:capturedTemplate = $null
function Write-Step { param([string]$Message) }
function Get-AzResource { [CmdletBinding()]param([string]$ResourceGroupName) $script:azureResources }
function New-AzResourceGroupDeployment {
  [CmdletBinding()]param([string]$Name,[string]$ResourceGroupName,[string]$Mode,[object]$TemplateObject,[object]$TemplateParameterObject)
  if ($Mode -ne 'Incremental' -or $TemplateObject.resources.Count -ne 0) { throw 'Naming must never deploy or delete resources.' }
  if (-not $TemplateParameterObject.instanceName) { throw 'Missing instance in ARM evaluation.' }
  $script:capturedTemplate = $TemplateObject
  $script:armCalls++
  [pscustomobject]@{ ProvisioningState = $script:armState; Outputs = @{ nameHash = @{ Value = $script:armHash } } }
}
function Invoke-NamingScenario {
  param([string]$Kind='Feeds',[string]$Instance='demo01',[bool]$InstancePassed=$true,
    [object[]]$Existing=@(),[hashtable]$Overrides=@{},[string]$Group='ANYRUN-MDE-RG')
  $TenantId = '11111111-1111-1111-1111-111111111111'
  $SubscriptionId = '22222222-2222-2222-2222-222222222222'
  $ResourceGroup = $Group
  $Connector = $Kind; $InstanceName = $Instance; $instanceNameWasPassed = $InstancePassed
  $deploySandbox = $Kind -in @('Sandbox','Both'); $deployFeeds = $Kind -in @('Feeds','Both')
  $sandboxDisplayNameWasPassed = $false; $feedsDisplayNameWasPassed = $false
  $SandboxAppDisplayName = 'ANYRUN-Sandbox-MDE-Connector'; $FeedsAppDisplayName = 'ANYRUN-Feeds-MDE-Connector'
  $SandboxFunctionName=$null; $SandboxLogicAppName=$null; $SandboxStorageAccountName=$null
  $FeedsFunctionName=$null; $FeedsLogicAppName=$null; $FeedsStorageAccountName=$null; $LogAnalyticsWorkspaceName=$null
  foreach ($key in $Overrides.Keys) { Set-Variable -Name $key -Value $Overrides[$key] }
  $script:azureResources = $Existing
  $existingResourceGroup = if ($Existing.Count -gt 0) { [pscustomobject]@{Name=$Group} } else { $null }
  function Read-Text { param($Prompt,$Default,$ValidationPattern,$ValidationMessage) $Default }
  . $mainNaming
  $result=@{InstanceName=$InstanceName; Legacy=$useLegacyNames; SandboxAppDisplayName=$SandboxAppDisplayName; FeedsAppDisplayName=$FeedsAppDisplayName}
  foreach ($key in $resourceNameTypes.Keys) { $result[$key]=Get-Variable -Name $key -ValueOnly }
  return $result
}
$script:checks=0
function Assert-Equal($actual,$expected,$message) {
  $script:checks++
  if ($actual -cne $expected) { throw "$message -- expected '$expected', got '$actual'" }
}
function Assert-True($condition,$message) {
  $script:checks++
  if (-not $condition) { throw $message }
}
function Assert-Throws([scriptblock]$body,$message) {
  $threw=$false
  try { & $body } catch { $threw=$true }
  Assert-True $threw $message
}

$feeds=Invoke-NamingScenario
Assert-Equal $feeds.FeedsLogicAppName 'ANYRUN-Feeds-MDE-demo01-LA' 'Feeds Logic casing'
Assert-Equal $feeds.FeedsFunctionName 'ANYRUN-Feeds-MDE-demo01-abcdef-FA' 'Function suffix and ARM hash'
Assert-Equal $feeds.FeedsStorageAccountName 'anyrunfeedsabcdefdemo01' 'Storage naming'
Assert-Equal $feeds.LogAnalyticsWorkspaceName 'ANYRUN-Feeds-MDE-demo01-LAW' 'Feeds workspace'
Assert-Equal $feeds.FeedsAppDisplayName 'ANYRUN-Feeds-MDE-demo01-abcdef-Connector' 'Dedicated instance identity'
$sandbox=Invoke-NamingScenario -Kind Sandbox
Assert-Equal $sandbox.SandboxLogicAppName 'ANYRUN-Sandbox-MDE-demo01-LA' 'Sandbox Logic casing'
Assert-Equal $sandbox.SandboxFunctionName 'ANYRUN-Sandbox-MDE-demo01-abcdef-FA' 'Sandbox Function casing'
Assert-Equal $sandbox.SandboxStorageAccountName 'anyrunsbabcdefdemo01' 'Sandbox storage'
Assert-Equal $sandbox.LogAnalyticsWorkspaceName 'ANYRUN-Sandbox-MDE-demo01-LAW' 'Sandbox workspace'
$both=Invoke-NamingScenario -Kind Both
Assert-Equal $both.LogAnalyticsWorkspaceName 'ANYRUN-MDE-demo01-LAW' 'Both share one workspace'
Assert-True ($both.SandboxFunctionName -ne $both.FeedsFunctionName) 'Connectors must have different names'
$repeat=Invoke-NamingScenario
Assert-Equal $repeat.FeedsFunctionName $feeds.FeedsFunctionName 'Repeated instance keeps Function'
$other=Invoke-NamingScenario -Instance demo02
Assert-True ($other.FeedsFunctionName -ne $feeds.FeedsFunctionName) 'New instance needs a distinct Function'
Assert-True ($other.FeedsStorageAccountName -ne $feeds.FeedsStorageAccountName) 'New instance needs distinct storage'
Assert-True ($other.FeedsAppDisplayName -ne $feeds.FeedsAppDisplayName) 'New instance needs a distinct identity'
$script:armHash='ghijkl'
$otherScope=Invoke-NamingScenario -Group ANYRUN-MDE-Other-RG
Assert-True ($otherScope.FeedsFunctionName -ne $feeds.FeedsFunctionName) 'Resource-group hash must reach the Function name'
$script:armHash='abcdef'
$max=Invoke-NamingScenario -Kind Both -Instance abcdefghijkl
Assert-Equal $max.FeedsStorageAccountName.Length 24 'Feeds storage 24-character limit'
Assert-Equal $max.SandboxStorageAccountName.Length 24 'Sandbox storage 24-character limit'
foreach ($name in @($max.FeedsStorageAccountName,$max.SandboxStorageAccountName)) {
  Assert-True ($name -cmatch '^[a-z0-9]{3,24}$') 'Storage must contain only lowercase letters and digits'
}
$auto1=Invoke-NamingScenario -Instance '' -InstancePassed $false
$auto2=Invoke-NamingScenario -Instance '' -InstancePassed $false
Assert-Equal $auto1.InstanceName $auto2.InstanceName 'Default instance is stable on re-run'
Assert-Equal $auto1.FeedsFunctionName $auto2.FeedsFunctionName 'Default Function is stable on re-run'
$autoCase=Invoke-NamingScenario -Instance '' -InstancePassed $false -Group anyrun-mde-rg
Assert-Equal $autoCase.InstanceName $auto1.InstanceName 'Group casing must not change default instance'
$overrides=@{FeedsFunctionName='Custom-FA';FeedsLogicAppName='Custom-LA';FeedsStorageAccountName='customstorage';LogAnalyticsWorkspaceName='Custom-LAW'}
$custom=Invoke-NamingScenario -Overrides $overrides
foreach($key in $overrides.Keys) { Assert-Equal $custom[$key] $overrides[$key] 'Explicit name has priority' }
$oldFunction=[pscustomobject]@{ResourceType='Microsoft.Web/sites';Name='anyrun-feeds-mde-demo01-abcdef'}
$oldLogic=[pscustomobject]@{ResourceType='Microsoft.Logic/workflows';Name='anyrun-feeds-mde-demo01-la'}
$existing=Invoke-NamingScenario -Existing @($oldFunction,$oldLogic)
Assert-Equal $existing.FeedsFunctionName $oldFunction.Name 'Reuse the original Azure App Function'
Assert-Equal $existing.FeedsLogicAppName $oldLogic.Name 'Reuse Logic regardless of casing'
$preferred=[pscustomobject]@{ResourceType='Microsoft.Web/sites';Name=$feeds.FeedsFunctionName}
$existingBoth=Invoke-NamingScenario -Existing @($oldFunction,$preferred)
Assert-Equal $existingBoth.FeedsFunctionName $preferred.Name 'Prefer current name when both exist'
$wrongType=[pscustomobject]@{ResourceType='Microsoft.Logic/workflows';Name=$oldFunction.Name}
$wrong=Invoke-NamingScenario -Existing @($wrongType)
Assert-Equal $wrong.FeedsFunctionName $feeds.FeedsFunctionName 'Do not adopt a resource of the wrong type'
$legacySuffix=Get-StableSuffix -InputText '11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|ANYRUN-MDE-RG' -Length 8
$legacyFunction=[pscustomobject]@{ResourceType='Microsoft.Web/sites';Name="anyrun-feeds-mde-$legacySuffix"}
$callsBefore=$script:armCalls
$legacy=Invoke-NamingScenario -Instance '' -InstancePassed $false -Existing @($legacyFunction)
Assert-True $legacy.Legacy 'Detect original installer deployment'
Assert-Equal $legacy.FeedsFunctionName $legacyFunction.Name 'Retain original installer Function'
Assert-Equal $legacy.FeedsLogicAppName "ANYRUN-Feeds-MDE-LA-$legacySuffix" 'Retain original installer Logic'
Assert-Equal $script:armCalls $callsBefore 'Legacy upgrade needs no naming deployment'
$newInstance=Invoke-NamingScenario -Instance demo01 -Existing @($legacyFunction)
Assert-Equal $newInstance.FeedsFunctionName $feeds.FeedsFunctionName 'Explicit instance creates a separate connector'
Assert-Throws { Get-ConnectorDefaultNames -ConnectorType Feeds -InstanceName 'ABCDEFGHIJKL' -NameHash abcdef } 'Reject uppercase instance input'
Assert-Throws { Get-ConnectorDefaultNames -ConnectorType Feeds -InstanceName 'abcdefghijklm' -NameHash abcdef } 'Reject instance over 12 characters'
Assert-Throws { Get-ConnectorDefaultNames -ConnectorType Feeds -InstanceName demo01 -NameHash ABCDEF } 'Reject invalid ARM hash'
$script:armState='Failed'
Assert-Throws { Get-AzureAppNameHash -ResourceGroupName ANYRUN-MDE-RG -InstanceName demo01 } 'Do not proceed after ARM failure'
$script:armState='Succeeded'; $script:armHash='bad'
Assert-Throws { Get-AzureAppNameHash -ResourceGroupName ANYRUN-MDE-RG -InstanceName demo01 } 'Do not proceed after invalid ARM output'
$script:armHash='abcdef'

$functionTemplatePath=Join-Path $root 'ANYRUN-Sandbox-MDE/Function App/ANYRUN-Sandbox-MDE-FA.json'
$raw=Get-Content $functionTemplatePath -Raw | ConvertFrom-Json
$named=Set-FunctionSupportingResourceNames -Template $raw -BaseName 'ANYRUN-Sandbox-MDE-demo01' -FunctionAppName $sandbox.SandboxFunctionName
Assert-Equal $named.variables.hostingPlanName 'ANYRUN-Sandbox-MDE-demo01-Plan' 'Hosting-plan name'
Assert-Equal $named.variables.appInsightsName 'ANYRUN-Sandbox-MDE-demo01-AI' 'Insights name'
$site=@($named.resources | Where-Object type -eq 'Microsoft.Web/sites')[0]
Assert-Equal $site.name "[parameters('functionAppName')]" 'Function reference remains unchanged'
Assert-Equal $site.properties.serverFarmId "[resourceId('Microsoft.Web/serverfarms', variables('hostingPlanName'))]" 'Function references the renamed plan'
$namedText=$named|ConvertTo-Json -Depth 100
Assert-True ($namedText -notmatch "resourceId\('Microsoft.Insights/components', parameters\('functionAppName'\)\)") 'Both Insights settings and dependencies reference new name'
$oldPlan=[pscustomobject]@{ResourceType='Microsoft.Web/serverfarms';Name=$sandbox.SandboxFunctionName}
$oldInsights=[pscustomobject]@{ResourceType='Microsoft.Insights/components';Name=$sandbox.SandboxFunctionName}
$raw=Get-Content $functionTemplatePath -Raw | ConvertFrom-Json
$kept=Set-FunctionSupportingResourceNames -Template $raw -BaseName 'ANYRUN-Sandbox-MDE-demo01' -FunctionAppName $sandbox.SandboxFunctionName -Resources @($oldPlan,$oldInsights)
Assert-Equal $kept.variables.hostingPlanName $oldPlan.Name 'Reuse original hosting plan'
Assert-Equal $kept.variables.appInsightsName $oldInsights.Name 'Reuse original Insights'
Write-Host "PASS: $script:checks offline naming checks; PowerShell parser; no live Azure calls."

if ($ExportFixtures) {
  $cases = foreach ($kind in @('Sandbox','Feeds')) {
    foreach ($instance in @('a','demo01','abcdefghijkl')) {
      @{ Connector=$kind; Instance=$instance; Names=(Get-ConnectorDefaultNames -ConnectorType $kind -InstanceName $instance -NameHash abcdef) }
    }
  }
  @{ Cases=@($cases); HashExpression=$script:capturedTemplate.outputs.nameHash.value } |
    ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ExportFixtures -Encoding utf8NoBOM
}
