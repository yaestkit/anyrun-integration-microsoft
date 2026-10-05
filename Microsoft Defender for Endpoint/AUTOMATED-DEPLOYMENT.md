# Automated deployment of ANY.RUN connectors for Microsoft Defender for Endpoint

`Scripts/Deploy-ANYRUNMDEConnector.ps1` deploys the Sandbox connector, the TI
Feeds connector, one at a time, from Azure Cloud Shell (PowerShell).

The Feeds standalone deployment files are included at:

- `ANYRUN-TI-Feeds-MDE/Function App/ANYRUN-Feeds-MDE-FA.json`
- `ANYRUN-TI-Feeds-MDE/Function App/ANYRUN-Feeds-MDE-FA.zip`
- `ANYRUN-TI-Feeds-MDE/Logic App/ANYRUN-Feeds-MDE-LA.json`

The installer resolves these paths at the reviewed repository commit and checks
the template/package hashes. Each standalone Function ZIP is identical to its
Azure App 1.1.3 `artifacts/` ZIP, including the ZIP nested in the deployable
`anyrun-*-mde-1.1.3.zip` bundle. Both deployment methods therefore use the same
Sandbox/Feeds runtime. Publish the installer, standalone templates/packages and
Azure App bundles together before deploying from the repository.


Sandbox recovery follow-up (2026-10-01) requires updating the Function ZIP and
the submission loop limits (480 / PT2H). See the recovery section in
[`ANYRUN-Sandbox-MDE/README.md`](ANYRUN-Sandbox-MDE/README.md#recovery-after-a-worker-restart).
The deployment archive does not publish artifacts to GitHub. Upload its
reviewed Sandbox package, Logic template and installer together before using
the GitHub-based installer; do not bypass a hash mismatch.

## Security model

The installer creates highly privileged workload identities. Use a dedicated
App Registration and a dedicated resource group for each environment. Anyone
who can read or change Function App configuration in that resource group may be
able to use the stored ANY.RUN key and Defender client credential. Review resource-group role assignments in Azure and remove unnecessary `Owner`,
`Contributor`, `Website Contributor`, and `User Access Administrator` access.

The installer applies these controls:

- connector App Registrations are marked with an installer ownership tag;
- an App ID recovered from Function settings is trusted only when that marker
  exists;
- reused registrations are rejected if they declare or hold application roles
  for APIs other than `WindowsDefenderATP`;
- requested Defender roles are displayed before tenant-wide consent;
- non-interactive consent requires `-ApproveDefenderPermissions`;
- tenant, subscription and client IDs are validated as canonical GUIDs;
- remote templates and ZIP packages are downloaded from an immutable commit and
  checked against built-in SHA-256 values;
- Function endpoints accept POST only, require HTTPS/TLS 1.2, and disable FTP
  and SCM basic publishing credentials;
- Storage Accounts require TLS 1.2 and disable public blob access;
- Microsoft Graph is disconnected when the run ends if the installer opened the
  session.

The Sandbox registration receives:

- `Alert.ReadWrite.All`
- `Machine.LiveResponse`
- `Machine.ReadWrite.All`
- `Ti.ReadWrite`
- `Library.Manage`

The TI Feeds registration receives only `Ti.ReadWrite`. Shared registrations are
unsupported: Feeds replaces indicators owned by its own client ID, so a shared
identity could delete another workload's indicators.

Client secrets are valid for six months by default. Use Conditional Access for
workload identities where licensed, monitor service-principal sign-ins, and plan
to move runtime secrets to Key Vault in a future connector revision.

## What the installer automates

1. Authenticates to Azure and Microsoft Graph and confirms the selected tenant
   and subscription.
2. Validates providers, region support, names, role-assignment permissions, ARM
   templates, artifacts, and Azure Policy before changing Entra ID.
3. Creates or reuses the resource group, Log Analytics workspace, and dedicated
   Storage Accounts.
4. Creates or validates dedicated App Registrations and grants the reviewed
   Defender application roles after explicit approval.
5. Reads secrets through masked `SecureString` prompts.
6. Deploys Function Apps and Logic Apps, retries only recognized transient RBAC
   propagation/onedeploy failures, and verifies the deployed resources.
7. Optionally starts a TI Feeds smoke test and reports its final run state.

For Sandbox, the starter Function call is deliberately short-lived. It validates
the request, creates a status record, writes a job to the `anyrun-mde-jobs`
Storage Queue, and returns HTTP 202. A queue-triggered Function performs Live
Response, waits for the ANY.RUN task, and enriches the Defender alert. The Logic
App then polls a short status Function, so its run history exposes both
**Evidence submitted to ANY.RUN** and **ANY.RUN verdict received** without
holding one HTTP request open for the potentially long sandbox analysis.

Safe progress and results are stored in the private `anyrun-job-status` blob
container. Queue jobs have up to three deliveries and resume saved task UUIDs;
exhausted messages move to `anyrun-mde-jobs-poison`. A submission intent without
a saved UUID stops with `RecoveryRequired` instead of sending a possible second
paid task. Heartbeats cover long operations, and the read-only Status endpoint
projects a nonterminal job as `failed/stale` after 15 minutes without updates.
Inspect the status blob and task link before recovery. Replay uses the original
queue payload and job ID; Logic App Resubmit creates a new job. See
[recovery documentation](ANYRUN-Sandbox-MDE/README.md#recovery-after-a-worker-restart).

Example Application Insights query for worker failures:

```kusto
traces
| where timestamp > ago(24h)
| where message startswith "ANY.RUN job" and message has "failed for alert"
| project timestamp, severityLevel, message, operation_Id
| order by timestamp desc
```

## Sandbox safety settings

```powershell
./Deploy-ANYRUNMDEConnector.ps1 `
  -Connector Sandbox `
  -DefenderIndicatorAction Audit `
  -DefenderIndicatorGenerateAlert $false `
  -SandboxAnalysisPrivacyType owner
```

`DefenderIndicatorGenerateAlert` defaults to `$false` to prevent an alert storm
from Audit-mode indicators. `owner` requires an ANY.RUN plan with private-task
support; choose `bylink` explicitly when that mode is unavailable. The installer
adds the one-day orphan-evidence and seven-day job-status lifecycle rules only
when it creates the dedicated Sandbox Storage Account. It does not replace the
lifecycle policy of an existing account.

The checked-in Function templates use the reviewed test repository and branch
`yaestkit/anyrun-integration-microsoft@asyncv2` for the
**Deploy to Azure** path and are not tied to a commit. For installer runs, the
requested repository ref is first resolved through GitHub to an immutable
40-character commit. Only the temporary verified deployment copy has its
`packageUri` rewritten to that commit. This avoids a template/package time-of-
check/time-of-use mismatch without permanently pinning checked-in templates.

## Prerequisites

- Microsoft Defender for Endpoint and the corresponding ANY.RUN subscription.
- An Azure subscription.
- Azure `Owner`, or `Contributor` plus `User Access Administrator`, at the target
  resource-group scope.
- An Entra role allowed to create applications and grant the requested
  `WindowsDefenderATP` application permissions. Tenant policy may impose
  additional restrictions.
- The bare ANY.RUN API key for each connector. Do not add `API-KEY `.
- Outbound access from Cloud Shell to GitHub and Microsoft endpoints.

The installer loads `Az.Accounts`, `Az.Resources`, `Az.Storage`,
`Az.OperationalInsights`, `Az.Functions`, `Microsoft.Graph.Authentication`, and
`Microsoft.Graph.Applications`. It keeps Az modules in one loaded bundle to
avoid `Az.Authorization.private` assembly conflicts. If a previous manual module
upgrade has already mixed assemblies, restart Cloud Shell before retrying.

## Quick start

Upload `Scripts/Deploy-ANYRUNMDEConnector.ps1` to Azure Cloud Shell, select the
PowerShell shell, then run one connector at a time:

```powershell
./Deploy-ANYRUNMDEConnector.ps1 -Connector Sandbox

./Deploy-ANYRUNMDEConnector.ps1 -Connector Feeds
```

To choose interactively, run without `-Connector`:

```powershell
./Deploy-ANYRUNMDEConnector.ps1
```

The menu offers `Sandbox` (Defender alert analysis) and `Feeds`
(scheduled TI indicator import). Type `1` / `Sandbox` or `2` / `Feeds`.
There is no default: empty or invalid input asks again.
`Both` is no longer supported. To install both connectors, run twice and reuse
the same resource group and instance name. In `-NonInteractive` mode an explicit
`-Connector Sandbox` or `-Connector Feeds` is required.

Each input prompt explains the expected value. Subscription selection uses a
list number with no default. Resource-group names and new-group region codes
include examples; an existing group automatically uses its region. Instance
names allow 1–12 lowercase letters or digits and must be kept for updates.
Text defaults appear in brackets and Enter accepts them. Confirmation prompts
explain Y/N and Enter; Defender permission consent uses `[Y/n]`.
API keys use masked input and distinguish Sandbox from TI Feeds. Existing Entra
credentials require the client secret **value**, not the secret ID or app ID.
App reuse and deferred-consent choices explain their deployment consequences.

Resource naming evaluates the same ARM expression as Azure App. Its empty
incremental deployment retries up to three times on timeout or an active previous
request, with a 10-second delay. Other errors stop immediately; after exhausted
retries, rerun with the same group and instance.

For East US, use `-Region 'eastus'`. The region is used only when the resource
group is created; an existing resource group's location wins.

The installer prompts for missing values. Secrets are masked and are not printed
in the summary. Never place a plaintext secret in the command line or shell
history, including through `ConvertTo-SecureString -AsPlainText` typed directly
at the prompt. Prefer interactive secret prompts. In CI, create `SecureString`
objects from the platform's protected secret store and clear temporary variables.
Review and clear PowerShell history if a plaintext secret was entered previously.

## Consent and automation

The installer shows the exact Defender permissions immediately before granting
them. Interactive runs require a yes/no confirmation. Non-interactive runs must
include `-ApproveDefenderPermissions` after the operator has reviewed the list:

```powershell
./Deploy-ANYRUNMDEConnector.ps1 `
  -Connector Feeds `
  -TenantId '<tenant-guid>' `
  -SubscriptionId '<subscription-guid>' `
  -ResourceGroup 'rg-anyrun-feeds-prod' `
  -Region 'eastus' `
  -NonInteractive `
  -ConfirmDedicatedAppRegistration `
  -ApproveDefenderPermissions
```

Supply API keys and client secrets as `SecureString` parameters for an actually
non-interactive execution.

Use `-DeferConsent` when another administrator must grant consent. The installer
deploys the Function App but skips the Logic App and prints a continuation
command. After consent, run that command with `-SkipFunctionApp`.

Graph authentication first reuses the Azure token, as in the VMRay approach. If
that is unavailable, it falls back to device code. Use `-ForceGraphDeviceCode`
to force an explicit sign-in.

## Existing App Registrations and rotation

Pass an explicit client ID to reuse a reviewed dedicated registration:

```powershell
./Deploy-ANYRUNMDEConnector.ps1 `
  -Connector Sandbox `
  -SandboxAppId '<application-client-id>' `
  -ConfirmDedicatedAppRegistration
```

The installer refuses an application with declared or granted roles outside
`WindowsDefenderATP`. First-time adoption adds a connector-specific ownership
tag. Later re-runs may recover the App ID from Function settings only if that tag
is present. An unmarked Function binding is never adopted implicitly.

Use `-RotateClientSecret` to create a replacement credential. This cannot be
combined with `-SkipFunctionApp`. Old installer-created credentials are removed
only after both connector deployments and verification succeed. Override the
six-month lifetime with `-SecretLifetimeMonths` (1 through 24).

The installer does not rotate credentials on a schedule. Create an Entra
credential-expiration alert and run again with `-RotateClientSecret` before the
displayed lifetime expires. Key Vault references and managed-identity-only
runtime storage access remain a future hardening item.

## Feeds settings

```powershell
./Deploy-ANYRUNMDEConnector.ps1 `
  -Connector Feeds `
  -FeedsIntervalHours 4 `
  -FeedsFetchDepthDays 14 `
  -FeedsMinimumConfidence 100 `
  -DefenderIndicatorAction Audit
```

`DefenderIndicatorAction` accepts only `Audit` or `Block`; `Audit` is the safe
default for both Sandbox and TI Feeds. `Machine.ReadWrite.All` is required by
the application-token calls that list/read MachineAction objects and obtain the
Live Response result download link; `Machine.LiveResponse` alone only permits
starting the action. The confidence setting is named
`minimum_confidence_threshold` across the Logic App and Function runtime.

Feeds downloads and validates a replacement set before deleting existing
ANY.RUN-owned indicators. It follows Microsoft XDR pagination, supports IPv4,
domain, URL, MD5, SHA-1, SHA-256, and certificate-thumbprint STIX patterns. It
records per-item rejections without discarding the accepted portion. Stale
indicators are preserved for an empty or limit-sized snapshot and when Defender
rejects an update to an existing value. A rejection affecting only a brand-new
value does not indefinitely block unrelated stale cleanup. The HTTP response and
Function logs contain downloaded/selected/prepared/imported/rejected/deleted
counts, truncation state, and sample rejection reasons.

Consumption Logic Apps have a finite synchronous HTTP timeout. A large first
import may outlive it while the Function continues. Inspect both Logic App run
history and Function logs before retrying. Workflow concurrency is limited to
one run and the Function action has automatic retries disabled, preventing
overlapping delete/import cycles.

## Artifact verification and development forks

Defaults in this test bundle are:

```text
Repository:    yaestkit/anyrun-integration-microsoft
RepositoryRef: refs/heads/asyncv2
```

The branch is resolved to a commit before downloading. Default SHA-256 values for
all four templates and both ZIP packages are embedded in the script. A mismatch
stops before deployment.

After changing any reviewed template or package, rebuild packages and update all
corresponding hashes in the installer in the same commit:

```powershell
python3 './Scripts/build_function_packages.py'
Get-FileHash './ANYRUN-Sandbox-MDE/Function App/ANYRUN-Sandbox-MDE-FA.zip' -Algorithm SHA256
Get-FileHash './ANYRUN-TI-Feeds-MDE/Function App/ANYRUN-Feeds-MDE-FA.zip' -Algorithm SHA256
```

For a reviewed development fork:

```powershell
./Deploy-ANYRUNMDEConnector.ps1 `
  -Connector Sandbox `
  -Repository 'owner/repository' `
  -RepositoryRef 'refs/heads/feature-branch' `
  -AllowUnverifiedArtifacts
```

`-AllowUnverifiedArtifacts` is an explicit development escape hatch: it permits
an alternative repository or hash mismatch and prints prominent warnings. Do
not use it for production. Local template parameters are intended for offline
review and test; the operator is responsible for the local file's provenance.

Before merging into the official repository, change the default repository,
ref, checked-in deployment links, and Function `packageUri` values back to the
official release branch in the same commit, then recalculate template hashes.

## Re-deployment and migration

New installations use the naming convention from Azure App 1.1.3. The default
resource group is `ANYRUN-MDE-RG`; an existing `rg-anyrun-mde` is still offered
when upgrading the original installer. Azure App itself uses the resource group
selected in the Azure deployment UI and does not assign its name.

Use `-InstanceName demo01` to choose an instance (1 to 12 lowercase letters or
digits). The interactive installer suggests a stable six-character value derived
from tenant, subscription and resource group; unattended re-runs use that same
value. Azure App's UI suggests a random six-character value instead. To update an
instance, use the same resource group and instance name.

| Resource | Example for Feeds |
| --- | --- |
| Logic App | `ANYRUN-Feeds-MDE-demo01-LA` |
| Function App | `ANYRUN-Feeds-MDE-demo01-<hash>-FA` |
| Hosting plan | `ANYRUN-Feeds-MDE-demo01-Plan` |
| Application Insights | `ANYRUN-Feeds-MDE-demo01-AI` |
| Log Analytics workspace | `ANYRUN-Feeds-MDE-demo01-LAW` |
| Storage Account | `anyrunfeeds<hash>demo01` |

Sandbox uses `ANYRUN-Sandbox-MDE` and the storage prefix `anyrunsb`. The installer
shares `ANYRUN-MDE-demo01-LAW` when deploying both connectors. The hash is exactly
`take(uniqueString(resourceGroup().id, instanceName), 6)`, evaluated by an
incremental ARM deployment with no resources. Storage names remain lowercase,
contain no hyphens and are limited to 24 characters. New Entra registration names
include the instance and hash so separate instances get separate identities.

Explicit resource-name parameters keep priority. When the original installer's
resources are found and no instance is specified, its old defaults are retained.
For a named Azure App instance, the installer reuses an existing Function App
without the new `-FA` suffix. Other existing names are matched without regard to
case, including old hosting-plan and Insights names. These changes do not rename
existing Azure resources.

When updating through Azure App 1.1.3, enter the same instance and fill in
**Existing Function App name (updates only)** if the original Function name did
not end in `-FA`; otherwise a new Function App would be created. An empty
instance retains version 1.1.1 resource names. Use a new instance value only when
intending to create another connector.

Historical role assignments are removed only when their exact legacy
deterministic name and current Function managed-identity principal both match.
The installer does not delete unrelated assignments.

Older Function templates that still contain `WaitSection` are rejected. Upgrade
to the reviewed checked-in templates, which use a nested scoped role assignment
with `principalType: ServicePrincipal`. The installer does not silently delete
resources from an older downloaded template.

## Manual Sandbox tenant settings

The installer does not change tenant-wide Defender or Intune policy. Before
using Sandbox, review in `security.microsoft.com`:

1. **Settings > Endpoints > Advanced features > Live Response**.
2. **Live Response for Servers**, if servers are in scope.
3. Unsigned Live Response scripts, only after accepting the risk.
4. Defender Antivirus quarantine/remediation policy.

## Verification and release gate

Before production:

1. Deploy each connector to an isolated test resource group.
2. Verify one end-to-end Sandbox enrichment and one Feeds import.
3. Run the same commands again and confirm idempotent reuse.
4. Inspect App Registration permissions, resource-group writers, Function logs,
   and Defender indicators.
5. Promote the exact reviewed commit and hashes to production.

The repository tests and ARM validation are release checks, not substitutes for
an Azure tenant test. A successful first deployment and re-deployment in a
non-production tenant/subscription remain mandatory release gates.

## Offline verification

Run the installer orchestration checks in PowerShell 7:

```powershell
./tests/test_installer_artifact_flow.ps1
./tests/test_resource_naming.ps1
```

The first test runs the actual installer separately for Sandbox and Feeds with local
artifact downloads and stubbed Azure/Graph calls. It retains real SHA-256, ZIP
checks, ARM parameter binding and template preparation, and verifies failure
before identity writes if a file is missing or a package hash differs. These
checks do not establish live Azure Policy, tenant permissions or runtime
connectivity.

## Verification and partial installation

The installer verifies each Logic App by its full resource ID through the
Microsoft.Logic workflow API in the selected subscription. A successful
deployment must return the expected ID, name and type, `Succeeded` provisioning
and `Enabled` workflow state. The verification log includes a direct portal link.
Sandbox and Feeds may share the same resource group; their workflow names differ.

With `-SkipLogicApp` or deferred Defender admin consent, the summary marks the
Logic App as skipped or not deployed and reports `PARTIAL DEPLOYMENT`. Continue
using the same resource group and instance name after consent, without
`-SkipLogicApp`; use `-SkipFunctionApp` to reuse the verified Function App.

## TI Feeds first run

The Feeds Logic App uses the same Recurrence schedule as AzureApp: no fixed
`startTime`, and an hourly interval configured by `-FeedsIntervalHours` (default
2). Azure schedules the first run after workflow deployment; subsequent runs
repeat at the configured interval. Deployment success does not confirm that
the import run has completed. Check the Logic App run history or explicitly
use `-TestFeedsInvocation` to request and wait for a test import.

Validate interactive prompts and resource-name timeout handling offline:

```powershell
pwsh -NoProfile -File 'tests/test_installer_prompts.ps1'
```

These checks execute the real input helpers and naming retry logic with mocked
console/Azure IO; they do not deploy to Azure.
