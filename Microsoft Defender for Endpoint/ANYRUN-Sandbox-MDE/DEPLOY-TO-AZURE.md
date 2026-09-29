# ANY.RUN Sandbox for MDE — Deploy to Azure

The automated installer is the recommended path because it validates identities,
permissions, artifacts, and both ARM templates. See
[`../AUTOMATED-DEPLOYMENT.md`](../AUTOMATED-DEPLOYMENT.md).

The direct buttons below track the official `main` branch and therefore are not
immutable releases. Use them only after reviewing the referenced commit. The
installer resolves `main` to a commit and verifies SHA-256 values before deploy.

The deploying account needs
`Microsoft.Authorization/roleAssignments/write` at the Storage Account scope.
The templates create a new managed identity and derive a scoped role-assignment
name from that principal, Storage Account, and role.

The Sandbox App Registration needs these Microsoft Defender for Endpoint
application permissions: `Alert.ReadWrite.All`, `Machine.LiveResponse`,
`Machine.Read.All`, `Machine.ReadWrite.All`, `Ti.ReadWrite`, and
`Library.Manage`. The automated installer grants this exact set after explicit
administrator approval.

## Asynchronous processing

The Logic App does not wait for Live Response or for the ANY.RUN analysis. The
HTTP Function validates the invocation, puts it on the `anyrun-mde-jobs` queue,
and returns HTTP 202. The `ANYRUN-Sandbox-MDE-Worker` queue-triggered Function
then downloads evidence, submits it to ANY.RUN, waits for the verdict, and
enriches the alert. Both functions are deployed in the same Function App and use
its existing `AzureWebJobsStorage` setting, so no additional Azure resource or
connection setting is required.

An accepted Logic App run therefore means that the job was queued, not that the
analysis finished. Use Function/Application Insights logs to follow the emitted
`job_id`. A failed job is placed in `anyrun-mde-jobs-poison`; it is not retried
automatically to avoid accidentally submitting the same sample more than once.

The worker stops new work after a 90-minute application budget so it can report
the failure before the two-hour Function timeout. Sandbox indicator match-alert
generation is disabled by default and can be enabled with
`DefenderIndicatorGenerateAlert`. The optional one-day evidence lifecycle rule
must only be enabled for a dedicated Storage Account; the automated installer
enables it only for an account it creates.

The Logic App parameter `analysisPrivacyType` defaults to `owner`, which
requires an ANY.RUN plan supporting private tasks. Deploy with `bylink` when
that mode is unavailable, after accepting that anyone with the task link can
open the analysis.

## Function App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fanyrun%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Fmain%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-Sandbox-MDE%2FFunction%2520App%2FANYRUN-Sandbox-MDE-FA.json)

ARM template:
<https://raw.githubusercontent.com/anyrun/anyrun-integration-microsoft/refs/heads/main/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE/Function%20App/ANYRUN-Sandbox-MDE-FA.json>

Function package:
<https://raw.githubusercontent.com/anyrun/anyrun-integration-microsoft/refs/heads/main/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE/Function%20App/ANYRUN-Sandbox-MDE-FA.zip>

## Logic App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fanyrun%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Fmain%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-Sandbox-MDE%2FLogic%2520App%2FANYRUN-Sandbox-MDE-LA.json)

ARM template:
<https://raw.githubusercontent.com/anyrun/anyrun-integration-microsoft/refs/heads/main/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE/Logic%20App/ANYRUN-Sandbox-MDE-LA.json>
