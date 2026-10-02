# ANY.RUN Sandbox for MDE — Deploy to Azure

The automated installer is the recommended path because it validates identities,
permissions, artifacts, and both ARM templates. See
[`../AUTOMATED-DEPLOYMENT.md`](../AUTOMATED-DEPLOYMENT.md).

The direct buttons below track the reviewed test branch
`yaestkit/anyrun-integration-microsoft@asyncv2` and
therefore are not immutable releases. Use them only after reviewing the
referenced commit. The installer resolves the branch to a commit and verifies
SHA-256 values before deploy.

The deploying account needs
`Microsoft.Authorization/roleAssignments/write` at the Storage Account scope.
The templates create a new managed identity and derive a scoped role-assignment
name from that principal, Storage Account, and role.

The Sandbox App Registration needs these Microsoft Defender for Endpoint
application permissions: `Alert.ReadWrite.All`, `Machine.LiveResponse`,
`Machine.Read.All`, `Machine.ReadWrite.All`, `Ti.ReadWrite`, and
`Library.Manage`. The automated installer grants this exact set after explicit
administrator approval.

## Asynchronous processing and visible result

The starter HTTP Function validates the invocation, creates a private status
record, puts the work on the `anyrun-mde-jobs` queue, and returns HTTP 202. The
`ANYRUN-Sandbox-MDE-Worker` queue-triggered Function then downloads evidence,
submits it to ANY.RUN, waits for the verdict, and enriches the alert. The Logic
App does not hold that HTTP request open. Instead, it polls the short
`ANYRUN-Sandbox-MDE-Status` Function and keeps the workflow run active.

The submission loop now permits 480 iterations / `PT2H` to cover recovery
inside the worker's 90-minute budget. Existing deployments need both limits
updated, not only the Function ZIP. Preserve your current `opt_timeout`, other
analysis options and connections when editing the workflow.

Report polling requires a positive completion status (`done`, `completed`, 100)
plus a verdict. Missing/unknown status does not mean completed. HTTP not-ready
and transient failures are retried with a bounded wait; auth failures are not.
Before tenant acceptance, capture the actual report schema for a running,
completed and manually extended task with `Scripts/capture_sandbox_report.py`.

In the Logic App run history, **Evidence submitted to ANY.RUN** displays the
job ID, safe evidence metadata, SHA-256, task UUID, and task link. **ANY.RUN
verdict received** displays the final state and an `analyses` array containing
every result, verdict, score, link, and IOC count. A worker error terminates the
Logic App as failed. Function/Application Insights remains the detailed source
for Live Response and SDK diagnostics.

All three Functions are deployed in the same Function App. The queue and the
private `anyrun-job-status` blob container use the existing Storage Account, so
no new service or connection is required. Job-status records contain no sample
bytes, credentials, API keys, or SAS query strings. On installer-created
dedicated Storage Accounts, lifecycle rules delete evidence after one day and
status records after seven days.

A queue job has up to three deliveries. Retries resume saved per-evidence task
UUIDs rather than submit again. After exhausted deliveries the message goes to
`anyrun-mde-jobs-poison`. An uncertain submission without a saved UUID fails
closed instead of guessing a matching task or paying again. See the recovery
section in [README.md](README.md); Logic App **Resubmit** still starts a new job.

The worker stops new work after a 90-minute application budget so it can report
the failure before the two-hour Function timeout. The 90-minute budget spans
retries. Heartbeat runs every minute; after 15 minutes without an update the
read-only Status endpoint returns `failed/stale` with recovery guidance. Sandbox indicator match-alert
generation is disabled by default and can be enabled with
`DefenderIndicatorGenerateAlert`. The optional one-day evidence lifecycle rule
must only be enabled for a dedicated Storage Account; the automated installer
enables it only for an account it creates.

The worker waits 10 seconds after a successful Live Response submission before
its first status check. Pending/InProgress polling remains every 30 seconds;
ordinary queue failure retry remains 60 seconds plus scheduling time.

Defender can briefly return `404 ResourceNotFound` when a newly accepted Live
Response action has not reached the `machineactions` read endpoint yet. The
worker retries only that response every 10 seconds for up to 3 minutes; other
HTTP errors remain terminal.

The Logic App parameter `analysisPrivacyType` defaults to `owner`, which
requires an ANY.RUN plan supporting private tasks. Deploy with `bylink` when
that mode is unavailable, after accepting that anyone with the task link can
open the analysis.

## Function App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyaestkit%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Fasyncv2%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-Sandbox-MDE%2FFunction%2520App%2FANYRUN-Sandbox-MDE-FA.json)

ARM template:
<https://raw.githubusercontent.com/yaestkit/anyrun-integration-microsoft/refs/heads/asyncv2/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE/Function%20App/ANYRUN-Sandbox-MDE-FA.json>

Function package:
<https://raw.githubusercontent.com/yaestkit/anyrun-integration-microsoft/refs/heads/asyncv2/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE/Function%20App/ANYRUN-Sandbox-MDE-FA.zip>

## Logic App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyaestkit%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Fasyncv2%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-Sandbox-MDE%2FLogic%2520App%2FANYRUN-Sandbox-MDE-LA.json)

ARM template:
<https://raw.githubusercontent.com/yaestkit/anyrun-integration-microsoft/refs/heads/asyncv2/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE/Logic%20App/ANYRUN-Sandbox-MDE-LA.json>
