<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN Malware Sandbox Integration with Microsoft Defender for Endpoint 

## Overview

This connector integrates Microsoft Defender for Endpoint (MDE) with the [ANY.RUN Sandbox](https://any.run/features/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_tifeeds&utm_content=linktosandboxlanding) to enrich MDE alerts through automated malware analysis. It triggers automatically upon the registration of a new alert in MDE, extracting and analyzing entities such as URLs or files associated with the alert.

The enrichment process adds valuable context directly to the alert: comments include the ANY.RUN verdict, threat score, a link to the detailed analysis report, and any Indicators of Compromise (IOCs) discovered during the sandbox detonation. Extracted IoCs are also imported into MDE's local Threat Intelligence lists for enhanced detection and response.

This connector empowers SOC teams with deeper insights into potential threats, accelerating triage, reducing false positives, and enabling proactive hunting — all while leveraging ANY.RUN's interactive sandbox capabilities for real-time behavioral analysis.

## Requirements
- Microsoft Defender for Endpoint
- ANY.RUN API Key. To obtain it, please contact your [ANY.RUN account manager](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_sandbox&utm_content=linktocontactus) directly or fill out [the request form](https://any.run/demo/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_sandbox&utm_content=linktodemo).
- Microsoft Azure resources:
  - Logic App with Flex Consumption plan
  - Function App Flex Consumption plan
  - Blob Storage

For production deployments, use the automated installer described in
[`../AUTOMATED-DEPLOYMENT.md`](../AUTOMATED-DEPLOYMENT.md). Manual ARM deployment
details and the asynchronous runtime model are documented in
[`DEPLOY-TO-AZURE.md`](DEPLOY-TO-AZURE.md).

## Solution Overview

## Prerequisites

### App Registration

- You need to create a new application for your connector. To do this, go to **Microsoft Entra ID**.

![entra_id](images/003.png)

- Click **Add** > **App registration**.

![app_registration](images/004.png)

- Name your new application and click **Register**.

![register_app](images/005.png)

### Secret Value of created App

- To generate the Client Secret, go to your application's page and click **Generate Secret** in the **Certificates & secrets** tab.

![cert_and_secrets_tab](images/042.png)

- Specify the key name and its expiration date (optional).

![generate_secret](images/043.png)

- Copy and **save the Secret Value**. This value is required for deploying the connector later.

![save_secret](images/044.png)

### Microsoft Defender ATP API Permissions for new App

- For the created application, add the following permissions for API connections in the **Manage** > **API permissions** > **Add a permission** tab:

![add_permission](images/030.png)

- Add an API connection for **WindowsDefenderATP**. Select the corresponding API in the **APIs my organization uses** tab.

![select_defender_permission](images/031.png)

- Then, select **Application permissions**.

![add_defender_permission](images/032.png)

- Select the following permissions:

|       Category       |   Permission Name   | Description                                                            |
|----------------------|---------------------|------------------------------------------------------------------------|
| Alert                | Alert.ReadWrite.All | Needed to enrich alerts with sample information                        |
| Machine              | Machine.LiveResponse | Starts and cancels Live Response actions                              |
| Machine              | Machine.Read.All    | Retrieves machine information                                         |
| Machine              | Machine.ReadWrite.All | Lists and reads MachineAction objects and downloads Live Response results |
| Ti                   | Ti.ReadWrite        | Submits indicators found by ANY.RUN                                   |
| Library              | Library.Manage      | Needed to upload custom ps1 script for retrieving AV related evidences |

`Machine.ReadWrite.All` is required for application tokens by the
`machineactions` and `GetLiveResponseResultDownloadLink` APIs. Granting only
`Machine.LiveResponse` is not sufficient for this connector.

### Storage Account

- Go to Azure Storage Accounts.

![azure_sa](images/010.png)

- Click **Create**.

![azure_sa_create](images/011.png)

- Type the name of Storage Account and click **Review + Create**.

![azure_sa_review_and_create](images/012.png)

- Open your Storage Account. Go to **Data Storage** > **Containers**.

![sa_navigation](images/016.png)

- Click **Add container**, type the **Name** for it and **Create**.

![sa_container_create](images/017.png)

- Go to **Security + networking** > **Access keys**, copy and save **Key** and **Connection string**. These values are required for deploying the connector later.

![sa_key](images/013.png)
 
## Deployment

### Deploy Azure Function App

- Click below to deploy Azure Function App with **Flex Consumption plan**
 
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyaestkit%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Ffeat%2Fmde-async-and-feed-hardening%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-Sandbox-MDE%2FFunction%2520App%2FANYRUN-Sandbox-MDE-FA.json)

- Enter the parameters required for deploying the Function App and click **Review + create**.

![function_app_deployment](images/070.png)

- Description of the required parameters:

| Parameter Name               | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| functionAppName              | Workflow name.                                                              |
| AzureTenantID                | Azure Tenant ID for authentication.                                         |
| AzureClientID                | Azure Client ID for authentication (ID of the App Registration created before). |
| AzureClientSecret            | Azure Client Secret for authentication.                                     |
| AzureStorageAccountName      | Azure Blob Storage Account Name.                                            |
| AzureStorageAccountKey       | Azure Blob Storage Account Key.                                             |
| AzureStorageConnectionString | Azure Blob Storage Account Connection string.                               |
| AzureBlobContainerName       | Azure Blob Storage Container Name.                                          |
| ANYRUN_API_KEY               | API Key of your ANY.RUN Account.                                            |
| DefenderIndicatorAction      | `Audit` (default) or `Block` for malicious/suspicious indicators.           |
| DefenderIndicatorGenerateAlert | Generate a Defender alert on IOC match; disabled by default.              |
| ConfigureEvidenceLifecyclePolicy | Add one-day blob cleanup. Enable only for a dedicated Storage Account.  |
| LogAnalyticsWorkspaceName    | Log Analytics Workspace Name.                                               |

### Asynchronous execution

The Logic App call only validates and queues the request. The HTTP Function
returns `202 Accepted` immediately, and `ANYRUN-Sandbox-MDE-Worker` performs
Live Response, waits for ANY.RUN, and enriches the alert. The Logic App action
uses `DisableAsyncPattern` because this fire-and-forget response intentionally
has no `Location` status endpoint. A successful Logic App run means “queued,”
not “analysis completed.” Follow the `job_id` in Function/Application Insights
logs and in failure comments added to the Defender alert.

Live Response permits only one active session per device. RunScript can execute
for up to 10 minutes. The connector limits its own wait to 15 minutes and does
not cancel another product's session. Avoid running this connector and a
Sentinel playbook against the same device pool.

The worker also has a 90-minute application deadline, leaving time to add a
failure comment before the two-hour Azure Functions timeout. A missing EDR file
does not stop the remaining files or URLs. The AV script succeeds when at least
one requested file was uploaded; Python then reports missing blobs individually.
If RunScript itself fails, the connector makes a best-effort cleanup of every
planned blob.

Defender rejects script parameters containing shell metacharacters such as
`; & | ! $ ( )`. The connector therefore uses a versioned Base64URL envelope.
The Antivirus collection path uses a random blob name and a 30-minute,
create-only SAS scoped to that single blob.

The Function template contains an optional one-day lifecycle rule as a final
safety net for orphan evidence. Keep `ConfigureEvidenceLifecyclePolicy=false`
for a shared or existing Storage Account: Azure stores one lifecycle-policy
document per account, so replacing it could affect unrelated rules. The
automated installer enables this policy only when it created a dedicated
Sandbox Storage Account.

The `analysisPrivacyType` Logic App parameter defaults to `owner`. Private tasks
require a compatible ANY.RUN plan; select `bylink` during deployment if the
account does not support `owner`. A by-link analysis is accessible to anyone
who obtains its link and should be an explicit organizational decision.

### Deploy Azure Logic App

- Click below to deploy Azure Logic App with **Flex Consumption plan**
 
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyaestkit%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Ffeat%2Fmde-async-and-feed-hardening%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-Sandbox-MDE%2FLogic%2520App%2FANYRUN-Sandbox-MDE-LA.json)

- Enter the parameters required for deploying the Logic App and click **Review + create**.

![logic_app_deployment](images/001.png)

- Description of the required parameters:

| Parameter Name                  | Description                                                                 |
|---------------------------------|-----------------------------------------------------------------------------|
| logicAppName                    | Workflow name.                                                              |
| azureTenantId                   | Azure Tenant ID for authentication in connections.                          |
| azureClientId                   | Azure Client ID for authentication (ID of the App Registration created before). |
| azureClientSecret               | Azure Client Secret for authentication.                                     |
| functionAppName                 | Name of the Function App deplyed before.                                    |
| analysisPrivacyType             | `owner` (default, private-plan support required) or `bylink`.                |


## Microsoft Defender for Endpoint Configuration

> **Note:** To allow the connector to extract all files of interest from endpoints (including potentially dangerous ones), we recommend setting `Quarantine` as the default action for your MDE. **!ATTENTION!** Be careful when configuring antivirus policies, as this can be potentially dangerous. See:
>
> - [Configure remediation for Microsoft Defender Antivirus detections](https://learn.microsoft.com/en-us/defender-endpoint/configure-remediation-microsoft-defender-antivirus)
>
> - [Settings for Microsoft Defender Antivirus policy in Microsoft Intune for Windows devices](https://learn.microsoft.com/en-us/intune/intune-service/protect/antivirus-microsoft-defender-settings-windows)

### Enable Live Response Sessions

- Open your [MDE portal](https://security.microsoft.com).

- Navigate to **System** > **Settings** > **Endpoints** > **General** > **Advanced features**.

- Enable the following settings: **Live Response**, **Live Response for Servers**, and **Live Response unsigned script execution**.

![enable_live_response](images/002.png)

## Logic App Configuration (Optional)

### Customization of Analysis Parameters in the ANY.RUN Sandbox

- The parameters for launching URL or file analysis in the ANY.RUN Sandbox are defined in the deployed Logic App.

- Open your Logic App `ANYRUN-Sandbox-MDE-LA` and navigate to **Development Tools** > **Logic app Designer**.

- The following three actions are responsible for declaring the parameters:

  - `ANY.RUN general analysis options`

  - `ANY.RUN Windows analysis options`

  - `ANY.RUN Linux analysis options`

![parametrs_actions](images/020.png)

- In the `ANY.RUN general analysis options` action, you can modify parameters that define general, OS-independent options such as analysis duration, virtual machine network settings, privacy, and more. For example, if you need to **increase the initial analysis time** for a more detailed examination of the object, select the **opt_timeout** variable and set the desired value in seconds, for example `360`.

![general_parametrs_actions](images/021.png)

- In the `ANY.RUN Windows analysis options` and `ANY.RUN Linux analysis options` actions, you can modify parameters that affect OS-specific virtual machine settings, such as the OS version and configuration, initial object location and launch parameters, and more. For example, if you need to run the analysis on a virtual machine with Windows 11 instead of Windows 10, click on the `ANY.RUN Windows analysis options` action, select the **windows_env_version** variable, and set the value to `11`.

![os_parametrs_actions](images/022.png)

> **Note:** To see the full list of available parameters and their values, visit our **[API documentation](https://any.run/api-documentation/)**.

### Filtering Alerts and Objects for Analysis

Since the trigger in the Logic App for initiating the connector's work is the appearance of a new alert in Microsoft Defender, it is recommended to declare conditions by which the Logic App will filter alerts for subsequent enrichment in the ANY.RUN Sandbox. By default, the condition is specific modules of Microsoft Defender from which the alert came - `WindowsDefenderAtp` and `WindowsDefenderAv`. That is, the connector will process all alerts that come only from these two modules.

- If you need to add one or more additional conditions by which alerts will be filtered, open your Logic App `ANYRUN-Sandbox-MDE-LA` and navigate to **Development Tools** > **Logic app Designer**.

- Find the action `Check if the alert is from EDR or Antivirus` and after the `True` condition, click `+` and select `Add an action` to add a new action.

![add_new_action](images/045.png)

- In the window that appears on the right, in the search bar, find and select `Condition`.

![search_condition_action](images/046.png)

- Then, after the action is added, you need to configure it - change its name (optional) and set the condition itself.

![condition_rename](images/047.png)

- To filter alerts by their attributes, you can check the `Outputs` of the `Alerts - Get single alert` action.

![alert_output](images/048.png)

- After you have added the condition, after `False` add a `Terminate` action that will interrupt the further workflow for this alert.

![terminate_action](images/049.png)

- Drag the actions following the added condition (by default this is `Is machine has Windows OS`) to the `True` section.

![drag_action](images/050.png)

- Save the changes.

![save_changes](images/051.png)

#### Examples of Alert Filtering Conditions

1. Alert Criticality

   - You can enrich with the ANY.RUN Sandbox only alerts with the criticality you need, for example **Medium** or **High**.

   - In the created condition, in the Choose a value field, type `/` and select **Insert dynamic content**.
  
   ![insert_dynamic_content](images/052.png)

   - As the parameter to check, select `Alert Alert Severity` from the `Alerts - Get single alert` action.
  
   ![alert_alert_severity](images/053.png)

   - Replace the logical operator `AND` with `OR`, click `+ New item` and select `Add row`.
  
   ![add_new_row](images/054.png)

   - In the new row, also add `Alert Alert Severity`.

   - Set the values `High` and `Medium` for the added parameters.

   ![set_values](images/055.png)

   - Save the changes.
  
   ![save_changes_1](images/056.png)

2. Alert Category

   - With the ANY.RUN Sandbox, you can enrich only alerts of the category you need, for example **Malware**.

   - In the created condition, in the Choose a value field, type `/` and select **Insert dynamic content**.
  
   ![insert_dynamic_content](images/052.png)

   - As the parameter to check, select `Alert Category` from the `Alerts - Get single alert` action.

   ![insert_alert_category](images/057.png)
   
   - Set the value `Malware` for the added parameter.

   ![insert_categoty_malware](images/058.png)
   
   - Save the changes.

   ![save_changes_2](images/059.png)
   
3. Machine Properties

   - You can filter alerts depending on the Machine from which it came. For example, you can filter by **Machine tags** or by **RBAC groups** in which the Machine is included.
  
   - In the created condition, in the Choose a value field, type `/` and select **Insert dynamic content**.
  
   ![insert_dynamic_content](images/052.png)

   - As the parameter to check, select `Machine Machine tags` or `Machine RBAC group name` or any other suitable parameter from the `Machines - Get single machine` action.

   ![insert_single_machine](images/060.png)
   
   - Set the value corresponding to **your devices** for the added parameter.

   > **Note:** You can find information about your devices at MDE Portal in Assets > Devices tab.

   ![insert_tag_value](images/061.png)

   - Save the changes.

   ![save_changes_3](images/062.png)
