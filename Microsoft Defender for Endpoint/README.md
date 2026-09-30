<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN Integration with Microsoft Defender for Endpoint 

This repository provides connectors that enable interoperability between Microsoft Defender for Endpoint (MDE) and [ANY.RUN](https://any.run/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_main&utm_content=linktolanding)'s services:  

* [Interactive Sandbox](https://any.run/features/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_main&utm_content=linktosandboxlanding)
* [Threat Intelligence Feeds](https://any.run/threat-intelligence-feeds/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_main&utm_term=310725&utm_content=linktofeedslanding) 

The connector automates threat analysis from MDE alerts by retrieving up-to-date data from sandbox detonations of associated objects, enriching alerts with relevant intelligence to optimize investigations.

## Choose MDE or Sentinel integration

Use this **Microsoft Defender for Endpoint** integration when Defender/XDR
alerts are processed directly without Sentinel orchestration. Use the repository's
**Microsoft Sentinel** integration when incidents are handled by Sentinel
playbooks. Do not enable both integrations for the same alerts or endpoint pool:
both can submit the same evidence and compete for the device's single active
Live Response session, producing `ActiveRequestAlreadyExists`, duplicate ANY.RUN
tasks, and duplicate indicators.

## Malware Sandbox Connector

**Latest Version:** 1.1.1
**Release Date:** 28/09/2026

The connector automatically sends MDE alerts’ suspicious files and URLs to ANY.RUN’s Interactive Sandbox for analysis and attaches the results (verdict, risk score, malware details) to the alert as comments. This helps SOC teams gain real-time insights into evasive threats, enabling faster triage, reduced false positives, and proactive response to minimize remediation time.

[Open connector page](https://github.com/yaestkit/anyrun-integration-microsoft/tree/asyncv2/Microsoft%20Defender%20for%20Endpoint/ANYRUN-Sandbox-MDE)

## Threat Intelligence Feeds Connector

**Latest Version:** 1.2.1
**Release Date:** 28/09/2026

The connector pulls fresh, high-fidelity threat indicators (IPs, domains, URLs, and file hashes), extracted from real-time detonations of the latest threats inside ANY.RUN’s Interactive Sandbox, and feeds them straight into MDE’s threat lists. Updated in real time with threat data from over 15,000 SOCs around the world, TI Feeds enable teams to spot new threats sooner, block them faster, and connect the dots between alerts for smarter investigations and quicker response. 

[Open connector page](https://github.com/yaestkit/anyrun-integration-microsoft/tree/asyncv2/Microsoft%20Defender%20for%20Endpoint/ANYRUN-TI-Feeds-MDE)

### Request support or access to ANY.RUN’s products 

Feel free to reach out to us for sales, demo, or quote inqueries via the [contact us form](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=ms_defender_main&utm_content=linktocontactus) or write to [techsupport@any.run](mailto:techsupport@any.run) for technical assistance. 
