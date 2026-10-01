# ANY.RUN Microsoft Sentinel to MDE synchronization

## Purpose

This mode promotes a curated ANY.RUN threat intelligence snapshot from
Microsoft Sentinel to Microsoft Defender for Endpoint. It complements the
existing direct connector and does not require the customer to build a custom
Logic App or Azure Function.

```text
ANY.RUN TAXII
    |
    v
Microsoft Sentinel Threat Intelligence
    |  exact Source + confidence + optional required tags
    v
ANYRUN-Feeds-MDE Function App
    |  reconcile, batch import, safe stale deletion
    v
Microsoft Defender for Endpoint indicators
```

Use `Sentinel` mode when Sentinel is the customer's policy and curation layer.
Use `Direct` mode when the customer wants the shortest path from ANY.RUN to MDE.
Do not schedule both modes with the same App Registration: the connector owns
and reconciles every MDE indicator created by its dedicated client ID.

## What is prebuilt

The package provides:

- scheduled execution through the existing Logic App;
- managed identity authentication to Azure Resource Manager;
- the Microsoft Sentinel `queryIndicators` API, version `2025-09-01`;
- server-side filtering by exact Source and minimum confidence;
- optional client-side required-tag filtering;
- rejection of revoked, defanged, expired, not-yet-valid, malformed, and
  unsupported indicators;
- MDE mapping for IP, domain, URL, MD5, SHA-1, SHA-256, and certificate
  thumbprint STIX patterns;
- case-insensitive deduplication where the MDE indicator type permits it;
- MDE import batches of no more than 500 indicators;
- pagination and a configurable 15,000-indicator upper bound;
- safe replacement: an empty, truncated, or failed Sentinel snapshot cannot
  delete the last known-good MDE set;
- deletion scoped to indicators created by the connector's dedicated MDE App
  Registration.

## Prerequisites

1. Connect the ANY.RUN TAXII collection to Microsoft Sentinel.
2. In Sentinel Threat Intelligence, identify the exact **Source** value shown
   for those indicators. Source matching is case-insensitive but otherwise
   exact. The deployment default is `ANY.RUN`.
3. Optionally use a Sentinel ingestion rule or TI management workflow to add a
   policy tag such as `promote-to-mde`.
4. Create a dedicated Entra App Registration with the WindowsDefenderATP
   application permission `Ti.ReadWrite` and grant admin consent.
5. Deploy the Function App and Logic App into the same resource group as the
   Sentinel Log Analytics workspace. The deployment identity must be able to
   create role assignments.

The ARM template assigns the Function App system identity the built-in
**Microsoft Sentinel Reader** role at the workspace. It does not give the
managed identity write access to Sentinel.

## Deployment parameters

Use the existing automated installer with the additional Feeds parameters:

```powershell
./Deploy-ANYRUNMDEConnector.ps1 `
  -Connector Feeds `
  -FeedsIndicatorSource Sentinel `
  -FeedsSentinelIndicatorSources "ANY.RUN" `
  -FeedsSentinelRequiredTags "promote-to-mde" `
  -FeedsMinimumConfidence 80 `
  -DefenderIndicatorAction Audit
```

Start with `Audit`. Change the action to `Block` only after reviewing the
resulting MDE indicator set and confirming that MDE custom network indicators
and Network Protection are configured for the intended device groups.

`FeedsApiKey` is not required in Sentinel mode. The ANY.RUN credentials belong
to the TAXII data connector configured in Sentinel.

## Selection policy

An indicator is promoted only when all conditions are true:

- its `source` equals one of `SentinelIndicatorSources`;
- confidence is greater than or equal to `FeedsMinimumConfidence`;
- every configured `SentinelRequiredTags` value is present;
- it is not revoked or defanged;
- `validFrom` is absent or has started;
- `validUntil` is absent or is in the future;
- its STIX pattern maps to a supported MDE indicator type.

Use a dedicated tag when analysts or Sentinel ingestion rules must explicitly
approve promotion. Leave `SentinelRequiredTags` empty for automatic promotion
of all active ANY.RUN indicators that meet the source and confidence policy.

## Failure and deletion behavior

The connector fetches and validates the replacement snapshot before it changes
MDE. It preserves existing connector-owned MDE indicators when:

- Sentinel authentication or API calls fail;
- pagination is invalid;
- the snapshot reaches `SentinelMaxIndicators`;
- Sentinel returns an empty selected set while MDE already contains indicators;
- all selected patterns are invalid or unsupported;
- MDE rejects an update to an existing indicator.

These checks intentionally prefer stale protection over accidental mass
deletion. Review Application Insights after a preserved run and correct the
source name, tags, RBAC, or snapshot limit before retrying.

## Operational notes

- A dedicated MDE App Registration is the ownership boundary. Do not reuse it
  for manual indicators, another connector, or a second source mode.
- The Logic App is configured for one concurrent run and the Function action
  does not retry the entire synchronization automatically.
- Sentinel mode queries the Sentinel management plane rather than the retired
  Microsoft Graph `tiIndicator` API or the legacy
  `ThreatIntelligenceIndicator` Log Analytics table.
- Changing the Sentinel source or required tags changes the desired snapshot on
  the next run. Test policy changes with MDE action `Audit` first.
