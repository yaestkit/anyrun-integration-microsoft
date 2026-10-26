# Deploy with the PowerShell installer

[`Deploy-ANYRUNMDEConnector.ps1`](https://github.com/anyrun/anyrun-integration-microsoft/blob/main/Microsoft%20Defender%20for%20Endpoint/Scripts/Deploy-ANYRUNMDEConnector.ps1) installs or
updates one ANY.RUN connector (**Sandbox** or **TI Feeds**) in your Azure
subscription. It creates the App Registration, grants the Defender permissions,
and deploys the Function App and Logic App.

To install a connector manually instead, follow the connector guide:
[Sandbox](https://github.com/anyrun/anyrun-integration-microsoft/tree/main/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE#manual-installation) or
[TI Feeds](https://github.com/anyrun/anyrun-integration-microsoft/tree/main/Microsoft%20Defender%20for%20Endpoint/ANYRUN-TI-Feeds-MDE#manual-installation).

## Before you start

- Azure role **Owner** (or **Contributor** + **User Access Administrator**) on
  the target subscription or resource group.
- Entra ID permission to create App Registrations and grant admin consent, or an
  administrator who can approve consent for you.
- Your ANY.RUN API key: the Sandbox key or the TI Feeds key, without the
  `API-KEY ` prefix.
- For Sandbox only: enable **Live Response** in
  [security.microsoft.com](https://security.microsoft.com) under
  **Settings > Endpoints > Advanced features**. Also enable
  **Live Response for Servers** if servers are in scope.

## Install

1. Open [Azure Cloud Shell](https://shell.azure.com) and select **PowerShell**.
2. Get the installer into Cloud Shell. Use either option.

   **Option A: download with a command**

   ```powershell
   Invoke-WebRequest -OutFile Deploy-ANYRUNMDEConnector.ps1 -Uri 'https://raw.githubusercontent.com/anyrun/anyrun-integration-microsoft/main/Microsoft%20Defender%20for%20Endpoint/Scripts/Deploy-ANYRUNMDEConnector.ps1'
   ```

   **Option B: upload the file with Manage files**

   1. Download
      [`Deploy-ANYRUNMDEConnector.ps1`](https://github.com/anyrun/anyrun-integration-microsoft/blob/main/Microsoft%20Defender%20for%20Endpoint/Scripts/Deploy-ANYRUNMDEConnector.ps1)
      to your computer: open it on GitHub and click **Download raw file**.
   2. In the Cloud Shell toolbar, select **Manage files > Upload** and choose
      the downloaded file. It is uploaded to your home directory.
   3. Go to the home directory:

      ```powershell
      cd ~
      ```

3. Run the installer:

   ```powershell
   ./Deploy-ANYRUNMDEConnector.ps1
   ```

4. Answer the prompts. Press **Enter** to accept the default shown in brackets.
   - Connector: `1` Sandbox or `2` TI Feeds
   - Subscription
   - Resource group (default `ANYRUN-MDE-RG`) and region (asked only for a new group)
   - Instance name: write it down, because you will need it for updates
   - Indicator action (Sandbox only):
     - `1` Audit (default): imports IOCs; Defender raises an alert on a match
     - `2` Block: imports IOCs and blocks them
     - `3` Do not import IOCs: keeps them only in the alert comments
   - ANY.RUN API key (masked input)
   - Approval of the listed Defender permissions
5. Wait for the summary. It shows the deployed resources and links to the
   Azure portal.

To install both connectors, run the installer twice: once for Sandbox and once
for TI Feeds. You can use the same resource group for both.

## Update

Run the installer again and enter the **same resource group and instance name**.
The ANY.RUN API key, client secret and indicator action are reused, so you are
not asked for them again.

The Logic App is redeployed from the template. Changes made in the Logic App
designer (for example, alert filters or analysis options) are overwritten.
Pass non-default options such as `-SandboxAnalysisPrivacyType owner` or
`-FeedsIntervalHours` again.


## Useful options

| Option | Purpose |
| --- | --- |
| `-Connector Sandbox` / `-Connector Feeds` | Skip the connector menu |
| `-DefenderIndicatorAction Audit\|Block\|Disabled` | Sandbox IOC handling (Feeds: `Audit` or `Block`) |
| `-SandboxAnalysisPrivacyType owner` | Private ANY.RUN tasks (default `bylink`; requires a plan that supports private tasks) |
| `-FeedsIntervalHours 2` | How often TI Feeds runs (hours) |
| `-FeedsMinimumConfidence 50` | Minimum indicator confidence for TI Feeds |
| `-RotateClientSecret` | Create a new client secret (default lifetime: 6 months) |

Run `Get-Help ./Deploy-ANYRUNMDEConnector.ps1` to list all options, including
unattended mode (`-NonInteractive`).

## Good to know

- Each connector gets its own App Registration with only the Defender
  permissions it needs. The installer shows them before granting.
  - Sandbox: `Alert.ReadWrite.All`, `Machine.LiveResponse`,
    `Machine.ReadWrite.All`, `Ti.ReadWrite`, `Library.Manage`
  - TI Feeds: `Ti.ReadWrite`
- The installer downloads templates and packages from this repository and
  checks their SHA-256 hashes. It stops if a hash does not match.
- The client secret expires after 6 months by default. Re-run the installer with
  `-RotateClientSecret` before it expires.
- Secrets are entered through masked prompts and are not shown in the output.
  Do not put API keys or secrets on the command line.
- If the script stops with an Az module assembly error, restart Cloud Shell and
  run it again.
