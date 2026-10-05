# Offline checks of the real region-selection block and ARM validation function.
# Only Azure calls and interactive input are mocked; no deployment is performed.
param([string]$Root=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
$installer = Join-Path $Root 'Scripts/Deploy-ANYRUNMDEConnector.ps1'
$text = Get-Content -LiteralPath $installer -Raw
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join "`n") }
foreach ($node in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)) {
  if ($node.Name -eq 'Test-ArmDeployment') { Invoke-Expression $node.Extent.Text }
}
$start = $text.IndexOf('$existingResourceGroup = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue')
$end = $text.IndexOf('Write-Step "Checking Azure providers and Flex Consumption support', $start)
if ($start -lt 0 -or $end -lt 0) { throw 'Region-selection block not found' }
$regionBlock = [scriptblock]::Create($text.Substring($start, $end-$start))
$script:checks = 0
function Assert-True { param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}
function Get-AzResourceGroup { [CmdletBinding()]param($Name) return $script:fixtureGroup }
function Read-Text { param($Prompt, $Default, $HelpText)
  $script:promptCalls++
  return $script:chosenRegion
}
function Write-Step { param($Message) }
# Execute each scenario in a fresh scope, keeping the installer's actual statements.
$scenarios = @(
  @{Existing=$true; Explicit=$false; NonInteractive=$false; Expected='westeurope'; Prompts=0},
  @{Existing=$true; Explicit=$true; NonInteractive=$false; Expected='westeurope'; Prompts=0},
  @{Existing=$true; Explicit=$false; NonInteractive=$true; Expected='westeurope'; Prompts=0},
  @{Existing=$false; Explicit=$false; NonInteractive=$false; Expected='westeurope'; Prompts=1},
  @{Existing=$false; Explicit=$true; NonInteractive=$true; Expected='eastus'; Prompts=0},
  @{Existing=$false; Explicit=$false; NonInteractive=$true; Throws=$true; Prompts=0}
)
foreach ($case in $scenarios) {
  & {
    $ResourceGroup = 'ANYRUN-MDE-RG'; $Region = 'eastus'
    $regionWasPassed = $case.Explicit; $NonInteractive = $case.NonInteractive
    $script:fixtureGroup = if ($case.Existing) { [pscustomobject]@{Location='westeurope'} } else { $null }
    $script:promptCalls = 0; $script:chosenRegion = 'westeurope'
    $failure = $null; $output = @()
    try { $output = @(. $regionBlock 6>&1) } catch { $failure = $_ }
    if ($case.ContainsKey('Throws')) {
      Assert-True ($null -ne $failure -and $failure.ToString().Contains('explicit -Region')) 'Missing region must fail before deployment in non-interactive mode'
    } else {
      if ($failure) { throw $failure }
      Assert-True ($Region -eq $case.Expected) 'Wrong deployment region selected'
      if ($case.Existing) {
        Assert-True (($output | Out-String).Contains("Using existing resource group 'ANYRUN-MDE-RG' in 'westeurope'")) 'Existing group region is not explained in the log'
      }
    }
    Assert-True ($script:promptCalls -eq $case.Prompts) 'Unexpected region prompt'
  }
  $script:checks++
}
function Test-AzResourceGroupDeployment {
  [CmdletBinding()]param($ResourceGroupName, $TemplateFile, $TemplateParameterObject)
  foreach ($warning in $script:fixtureWarnings) { Write-Warning $warning }
  if ($script:fixtureError -eq 'return') { return [pscustomobject]@{Message='Fixture policy denial'} }
  if ($script:fixtureError -eq 'throw') { throw 'Fixture ARM request failure' }
}
$known = '(AssignFunctionStorageRole) NestedDeploymentShortCircuited: reference() cannot be evaluated'
$cases = @(
  @{Warnings=@(); Error=''; Success=$true},
  @{Warnings=@($known); Error=''; Deferred=$true},
  @{Warnings=@('Other Azure diagnostic'); Error=''; Deferred=$true},
  @{Warnings=@($known); Error='return'; ExpectedError='Fixture policy denial'},
  @{Warnings=@($known); Error='throw'; ExpectedError='Fixture ARM request failure'}
)
foreach ($case in $cases) {
  $ResourceGroup = 'ANYRUN-MDE-RG'
  $script:fixtureWarnings = $case.Warnings; $script:fixtureError = $case.Error
  $failure = $null
  try { $output = @(Test-ArmDeployment -Label 'Sandbox Function App' -TemplateFile 'fixture.json' -TemplateParameters @{} 3>&1 6>&1) }
  catch { $failure = $_ }
  if ($case.ContainsKey('ExpectedError')) {
    Assert-True ($null -ne $failure -and $failure.ToString().Contains($case.ExpectedError)) 'ARM errors must still stop installation'
  } else {
    if ($failure) { throw $failure }
    $log = $output | Out-String
    foreach ($warning in $case.Warnings) {
      Assert-True ($log.Contains($warning)) 'Original Azure warning was hidden'
    }
    if ($case.ContainsKey('Deferred')) {
      Assert-True ($log.Contains('ARM validation completed with diagnostics')) 'Partial validation was reported as a full success'
      Assert-True (-not $log.Contains('ARM validation succeeded')) 'Partial validation must not claim full success'
      if ($case.Warnings -contains $known) {
        Assert-True ($log.Contains('Azure will evaluate this part when deploying')) 'Deferred role validation is not explained'
      }
    } else {
      Assert-True ($log.Contains('ARM validation succeeded')) 'Clean validation is not reported as successful'
    }
  }
  $script:checks++
}
Write-Host "PASS: $script:checks region/ARM validation scenarios; real installer code; Azure/input mocked."
