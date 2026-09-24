<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN Threat Intelligence Feeds Integration with Microsoft Defender for Endpoint  

## Overview

ANY.RUN’s [Threat Intelligence Feeds](https://any.run/threat-intelligence-feeds/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_tifeeds&utm_content=linktofeedslanding) (TI Feeds) is a continuously updated source of fresh network-based Indicators of Compromise (IOCs): IPs, domains, and URLs. 

The IOCs are extracted from real-time analyses done by experts from 15,000 companies in ANY.RUN’s Interactive Sandbox. 

### Connector’s functionality 

The connector for Threat Intelligence Feeds provides Microsoft Defender for Endpoint (MDE) users with simple, automated access to uniquely sourced and accurate indicators of compromise. 

- Get access to pre-processed IOCs with minimum false positives
- Detect threats early and prevent attacks using high-quality indicators 

### Key SOC benefits 

Connect TI Feeds with MDE for an easy access to all the benefits it brings:  

- Expanded Coverage: ANY.RUN’s exclusive IOCs come from Memory Dumps, Suricata IDS, in-browser data, and internal threat categorization systems, increasing the chance of detection of the most evasive threats.
- Reduced Workload: The indicators are pre-processed to avoid false positives and ready to be used for malware analysis or incident investigation.

## Requirements
- Microsoft Defender for Endpoint
- [ANY.RUN TI Feeds subscription](https://intelligence.any.run/plans/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_tifeeds&utm_content=linktotiplans) and ANY.RUN’s API key (without a prefix). To obtain one, [reach out to our sales team](https://any.run/enterprise/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=microsoftdefender&utm_content=linktoenterprise#contact-sales).
- Microsoft Azure resources:
  - Logic App with Flex Consumption plan
  - Function App Flex Consumption plan

Note:
Prefixed API keys and Basic Authentication for TI Feeds won’t be supported in future releases. 

## Prerequisites

### App Registration

- You need to create a new application for your connector. To do this, go to **Microsoft Entra ID**.

![entra_id](images/003.png)

- Click **Add** > **App registration**.

![app_registration](images/004.png)

- Name your new application and click **Register**.

![register_app](images/001.png)

### Secret Value of created App

- To generate the Client Secret, go to your application's page and click **Generate Secret** in the **Certificates & secrets** tab.

![cert_and_secrets_tab](images/005.png)

- Specify the key name and its expiration date (optional).

![generate_secret](images/006.png)

- Copy and **save the Secret Value**. This value is required for deploying the connector later.

![save_secret](images/007.png)

### Microsoft Defender ATP API Permissions for new App

- For the created application, add the following permissions for API connections in the **Manage** > **API permissions** > **Add a permission** tab:

![add_permission](images/008.png)

- Add an API connection for **WindowsDefenderATP**. Select the corresponding API in the **APIs my organization uses** tab.

![select_defender_permission](images/009.png)

- Then, select **Application permissions**.

![add_defender_permission](images/010.png)

- Select the following permissions:

|       Category       |   Permission Name   | Description                                                            |
|----------------------|---------------------|------------------------------------------------------------------------|
| Ti                   | Ti.Read.All         | Needed to retrieve indicators                                          |
| Ti                   | Ti.ReadWrite        | Needed to retrieve and submit indicators (application specific)        |
| Ti                   | Ti.ReadWrite.All    | Needed to retrieve and submit indicators (general)                     |

## Deployment

### Deploy Azure Function App

- Click below to deploy Azure Function App with **Flex Consumption plan**
 
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyaestkit%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Ffeat%2Fadd-install-script%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-TI-Feeds-MDE%2FFunction%2520App%2FANYRUN-Feeds-MDE-FA.json)

- Enter the parameters required for deploying the Logic App and click **Review + create**.

![function_app_deployment](images/015.png)

- Description of the required parameters:

| Parameter Name                  | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| functionAppName                 | Function name.                                                            |
| anyrunApiKey                | Your ANY.RUN API key to access TI Feeds data.                             |
| azureClientId                   | Client ID for authentication (ID of the App Registration created before). |
| azureClientSecret               | Client Secret for authentication.                                         |
| azureTenantId                   | Tenant ID for authentication in connections.                              |
| azureStorageAccountName         | Azure Blob Storage Account Name.                                          |
| azureStorageConnectionString    | Azure Blob Storage Account Connection string.                             |
| logAnalyticsWorkspaceName       | Log Analytics Workspace Name.                                             |


### Deploy Azure Logic App

- Click below to deploy Azure Logic App with **Flex Consumption plan**
 
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyaestkit%2Fanyrun-integration-microsoft%2Frefs%2Fheads%2Ffeat%2Fadd-install-script%2FMicrosoft%2520Defender%2520for%2520Endpoint%2FANYRUN-TI-Feeds-MDE%2FLogic%2520App%2FANYRUN-Feeds-MDE-LA.json)

- Enter the parameters required for deploying the Logic App and click **Review + create**.

![logic_app_deployment](images/011.png)

- Description of the required parameters:

| Parameter Name                  | Description                                                                 |
|---------------------------------|-----------------------------------------------------------------------------|
| logicAppName                    | Workflow name.                                                              |
| intervalRecurrence              | Interval of recurrence for the logic app (in hours).                        |
| feedFetchDepth                  | Depth of the feed to fetch (in days).                                       |
| minimum_confidence_threshold    | Minimum STIX confidence threshold, from 1 to 100 (default: 50).             |
| functionAppName                 | Name of the Function App deployed before.                                   |

## Logic App Configuration (Optional)

### Recurrence Interval

You can change the recurrence interval at which the Logic App will run and update the TI Feeds data.

- Open your Logic App ANYRUN-Feeds-MDE-LA, navigate to **Development tools** > **Logic app designer**.

- Select the `Recurrence` action and specify the required value in the `Interval` field.

![reccurence_interval](images/012.png)

### Indicator Fetch Depth

You can change the fetch depth of indicators in ANY.RUN TI Feeds. This parameter determines the period for which to extract data from ANY.RUN TI Feeds.

- Open your Logic App ANYRUN-Feeds-MDE-LA, navigate to **Development tools** > **Logic app designer**.

- Select the `Initialize variables` action and specify the required value in days in the `feed_fetch_depth` variable.

![feed_fetch_depth](images/013.png)

### Minimum Indicator Confidence

The connector filters every newly downloaded batch before importing it into Microsoft Defender for Endpoint. Only indicators whose STIX `confidence` value is greater than or equal to the Logic App's `minimum_confidence_threshold` variable are imported. The default value is `50`; adjust it when you are ready to evaluate indicators with a different confidence level.

- Open your Logic App **ANYRUN-Feeds-MDE-LA**, navigate to **Development tools** > **Logic app designer**.
- Open the `Initialize variables` action and change the value of `minimum_confidence_threshold` to an integer from `1` to `100`.
- Save the Logic App. The new threshold applies to the next downloaded feed batch without redeploying the workflow.
