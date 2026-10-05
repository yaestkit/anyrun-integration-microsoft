# Offline interaction and naming-timeout checks using the actual installer functions.
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
$installer = Join-Path $Root 'Scripts/Deploy-ANYRUNMDEConnector.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join "`n") }
$wanted = @('Read-Text','Read-Choice','Select-Connector','Confirm-Action','Read-RequiredSecret','Get-AzureAppNameHash','Write-Step')
foreach ($node in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)) {
  if ($node.Name -in $wanted) { Invoke-Expression $node.Extent.Text }
}
$script:checks = 0
function Assert-True([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
  $script:checks++
}
function Set-Answers([string[]]$Answers) {
  $script:answers = [Collections.Generic.Queue[string]]::new()
  foreach ($answer in $Answers) { $script:answers.Enqueue($answer) }
}
function Read-Host {
  param([string]$Prompt, [switch]$AsSecureString)
  if ($script:answers.Count -eq 0) { throw "Unexpected prompt: $Prompt" }
  $answer = $script:answers.Dequeue()
  if ($AsSecureString) {
    $value = [Security.SecureString]::new()
    foreach ($character in $answer.ToCharArray()) { $value.AppendChar($character) }
    return $value
  }
  return $answer
}
$NonInteractive = $false
foreach ($case in @(
  @{Answers=@('1'); Expected='Sandbox'},
  @{Answers=@('2'); Expected='Feeds'},
  @{Answers=@(' sandbox '); Expected='Sandbox'},
  @{Answers=@('fEeDs'); Expected='Feeds'},
  @{Answers=@('','Both','3','bogus','Feeds'); Expected='Feeds'}
)) {
  Set-Answers $case.Answers
  $captured = @(Select-Connector 6>&1)
  Assert-True ($captured[-1] -eq $case.Expected -and $script:answers.Count -eq 0) 'Connector choice selected an unintended default or failed to retry.'
  $log = $captured | Out-String
  Assert-True ($log.Contains('Sandbox -') -and $log.Contains('Feeds -') -and $log.Contains('no default')) 'Menu does not explain both options and absence of a default.'
}
Set-Answers @()
foreach ($choice in @('Sandbox','Feeds')) {
  Assert-True ((Select-Connector -RequestedConnector $choice) -eq $choice) 'Explicit connector should not prompt.'
}
$NonInteractive = $true
$failure = ''
try { $null = @(& $installer -NonInteractive 6>&1) } catch { $failure = $_.Exception.Message }
Assert-True ($failure.Contains('Supply -Connector Sandbox or Feeds')) 'Missing connector must fail before module loading or Azure calls in non-interactive mode.'
$failure = ''
try { $null = @(& $installer -Connector Both -NonInteractive 6>&1) } catch { $failure = $_.Exception.Message }
Assert-True ($failure.Contains('ValidateSet') -or $failure.Contains('does not belong to the set')) 'Both must be rejected at parameter binding.'
$NonInteractive = $false
Set-Answers @('', '2')
$result = @(Read-Choice -Prompt 'Secret choice' -Options @('Existing','New') -Default 0 6>&1)
Assert-True ($result[-1] -eq 2 -and $script:answers.Count -eq 0) 'A menu without a default must retry empty input.'
Set-Answers @('')
$result = @(Read-Choice -Prompt 'Secret choice' -Options @('Existing','New') -Default 1 6>&1)
Assert-True ($result[-1] -eq 1) 'Existing defaulted menus should still accept Enter.'
Set-Answers @('INVALID!', '  prod01  ')
$result = @(Read-Text -Prompt 'Instance' -Default 'demo01' -ValidationPattern '^[a-z0-9]{1,12}$' -HelpText 'Instance help' 6>&1)
Assert-True ($result[-1] -eq 'prod01') 'Text validation must retry invalid input and accept trimmed valid input.'
Set-Answers @('')
$result = @(Read-Text -Prompt 'Group' -Default 'ANYRUN-MDE-RG' -HelpText 'Group help' 6>&1)
Assert-True ($result[-1] -eq 'ANYRUN-MDE-RG' -and ($result | Out-String).Contains('Group help')) 'Text defaults and explanatory hints must work.'
Set-Answers @('maybe','')
$result = @(Confirm-Action -Prompt 'Consent' -Default $true 6>&1)
Assert-True ($result[-1] -eq $true -and ($result | Out-String).Contains('Enter selects Yes')) 'Consent Enter must select Yes after retrying invalid input.'
Set-Answers @('n')
$result = @(Confirm-Action -Prompt 'Consent' -Default $true 6>&1)
Assert-True ($result[-1] -eq $false) 'Explicit No must remain No.'
Set-Answers @('')
$result = @(Confirm-Action -Prompt 'Dedicated identity' -Default $false 6>&1)
Assert-True ($result[-1] -eq $false) 'Dedicated identity confirmation must keep its explicit No default.'
Set-Answers @('', 'fixture-secret-value')
$result = @(Read-RequiredSecret -Prompt 'Client secret' -HelpText 'Enter the secret VALUE, not the ID.' 6>&1)
Assert-True ($result[-1] -is [Security.SecureString] -and $result[-1].Length -eq 20) 'Secret prompts must retry blank input and return a SecureString.'
Assert-True (-not ($result | Out-String).Contains('fixture-secret-value')) 'Secret values must not appear in output.'

function Start-Sleep { param([int]$Seconds) $script:waits++ }
function New-AzResourceGroupDeployment {
  [CmdletBinding()]param($Name,$ResourceGroupName,$Mode,$TemplateObject,$TemplateParameterObject)
  $script:calls++
  if ($Name -ne 'ANYRUN-MDE-Names-demo01' -or $Mode -ne 'Incremental' -or $TemplateObject.resources.Count -ne 0) {
    throw 'Naming retries must use the same empty incremental deployment.'
  }
  if ($script:calls -le $script:failures) { throw $script:azureError }
  [pscustomobject]@{ProvisioningState='Succeeded'; Outputs=@{nameHash=@{Value='abcdef'}}}
}
foreach ($case in @(
  @{Failures=1; Error='The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing.'; Calls=2; Waits=1; Success=$true},
  @{Failures=1; Error='DeploymentActive'; Calls=2; Waits=1; Success=$true},
  @{Failures=9; Error='HttpClient.Timeout'; Calls=3; Waits=2; Success=$false},
  @{Failures=1; Error='AuthorizationFailed'; Calls=1; Waits=0; Success=$false}
)) {
  $script:calls=0; $script:waits=0; $script:failures=$case.Failures; $script:azureError=$case.Error
  $failure=''; $result=@()
  try { $result=@(Get-AzureAppNameHash -ResourceGroupName 'ANYRUN-MDE-RG' -InstanceName demo01 6>&1) } catch { $failure=$_.Exception.Message }
  Assert-True ($script:calls -eq $case.Calls -and $script:waits -eq $case.Waits) 'Unexpected naming retry count or retry on permanent error.'
  if ($case.Success) { Assert-True ($result[-1] -eq 'abcdef' -and -not $failure) 'Naming failed to recover from a transient timeout.' }
  else { Assert-True ([bool]$failure) 'Naming must stop after exhausted retries or a permanent error.' }
}
Write-Host "PASS: $script:checks interactive input / naming retry assertions; real installer functions; console and Azure IO mocked."
