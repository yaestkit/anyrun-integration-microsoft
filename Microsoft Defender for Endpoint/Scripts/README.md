# ANY.RUN MDE installer — readable single script

Test candidate, 2026-10-05. Customers need only `Deploy-ANYRUNMDEConnector.ps1`, PowerShell 7.4+ and online access to GitHub/Azure/Graph/Defender. No Base64, embedded ZIP, adjacent Assets, Python or builder is required.

```powershell
./Deploy-ANYRUNMDEConnector.ps1 -Connector Both -InstallMissingModules
# Or select Sandbox / Feeds.
```

`-InstallMissingModules` permits missing compatible Az/Graph modules to be installed from PSGallery for CurrentUser. The script asks for the tenant/subscription, permission approval and the selected ANY.RUN API keys. Omit `-Connector` for a menu. The operator must have Azure resource/deployment rights, Storage key access, role-assignment rights and appropriate Entra consent authority. Contributor alone cannot assign roles; access administration alone cannot create resources. Graph uses a delegated user; service-principal installation is not supported. Inspect Azure-token diagnostics before explicitly using `-GraphAuthMode Interactive`; no automatic fallback.

```powershell
./Deploy-ANYRUNMDEConnector.ps1 -Connector Feeds `
  -ResourceGroup rg-security-integrations -UseExistingResourceGroup `
  -Region westeurope -Tags @{CostCenter='SEC-1';Environment='Production'}
```

A new group defaults to eastus. An existing group supplies the initial region; selected managed resources/workspace retain priority. The final resource region is shown before deployment approval. Existing resources cannot be moved by `-Region`. External groups require placement approval; unrelated resources/group tags are preserved. Matching unmarked or foreign resources/apps are refused. This script does not adopt integrations created by older installers.

The six source files are downloaded from commit `cf9308a0fe13db7209f5663b40f0e489bb4d6b87` and checked against embedded SHA-256 before any Azure/Graph login or write. Verified ARM JSON is prepared locally: scoped Blob Data Contributor, independent resource/API region, private read-only package SAS, installer metadata, no unused Logic identity and alerts for Audit. Downloads are ordinary files in a temporary directory; no payload is decoded or executed as PowerShell. The current source is the yaestkit test fork; switch to an approved official release before public distribution.

Repeat the same command after interruption or manual consent. **Every real run reapplies both current templates for the selected connectors.** This deliberately replaces selective updates, per-resource fingerprints and phase repair. A valid stored password is reused; ordinary runs do not rotate it. Omitted saved action/privacy/schedule/filter and disabled workflow state are preserved. Choose `-Connector Feeds` when only Feeds should be reapplied; Both reapplies both connectors, even if only a Feeds option changes.

**Run serially.** The distributed Blob lock/background worker was removed. Concurrent installs/rotations of the same scope are unsupported. There is no state/resume/adoption/retirement framework or rollback of an unknown cloud write outcome. ARM validation and real SDK errors report permission/policy failures; this variant does not simulate effective Azure RBAC/deny/Policy before provisioning.

```powershell
./Deploy-ANYRUNMDEConnector.ps1 -Connector Both -RotateSecret
```

Passwords expire after six months; KeyId/expiry are printed and expiry below 30 days is warned about. Rotation is explicit; old passwords remain until expiry or reviewed revocation. The script prints old KeyIds/revoke commands after structural verification. Verify all consumers before revocation. After partial rotation failure, repeat without `-RotateSecret` to finish the switch. An expired saved credential gives a scoped command pointing to the original script.

`-PlanOnly` and `-WhatIf` are offline parameter/permission plans: they do not download or verify artifacts, authenticate or predict Azure Policy. Real execution verifies downloads and validates ARM. `StructureVerified` confirms token/read access, handlers, resource state and Sandbox API connection; it does not prove analysis, Feeds import/delete or Live Response. Use a controlled tenant test before activation.

Sandbox retains tenant-wide Machine.LiveResponse and Library.Manage; current LR scripts still require an approved unsigned-script policy. Storage uses Shared Key. Feeds keeps only Ti.ReadWrite. No tenant policy is changed automatically. SHA-256 and mutable resource/app markers are consistency/ownership bookkeeping, not publisher signatures or protection against malicious privileged operators.

Temporary release files are removed on normal success/error; forced termination or cleanup failure can leave a directory. No credentials are written into those local artifact files. To remove a connector, separately review workflows, resources, identities and consumers; never delete an entire shared group. Removing Azure resources does not remove Entra apps or Defender indicators/scripts.

Validation of this script: 104 PowerShell SDK-mock scenarios, 20 Python entry/template tests and configured PSScriptAnalyzer checks passed. All six GitHub downloads matched the pinned hashes. No live Azure/Graph deployment was performed. Developer/test files are outside this customer overlay.
