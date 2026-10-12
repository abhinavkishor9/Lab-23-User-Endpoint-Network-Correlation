# Lab-23-User-Endpoint-Network-Correlation
## Overview
User + Endpoint + Network Correlation is a SOC investigation technique that combines evidence from multiple telemetry sources to understand what a user account was doing on a Windows endpoint and whether that activity involved network communication of interest.
A single event rarely provides enough context to determine whether activity is malicious. For example, a failed logon may be caused by an incorrect password, a PowerShell process may be part of routine administration, and a network connection to port 443 may represent ordinary HTTPS traffic. When these events are examined together, however, they may reveal a more meaningful sequence of activity that deserves investigation.

This lab investigates how user authentication, endpoint process execution, and network connection telemetry can be examined together to support a SOC investigation using Elastic Security and ES|QL.

The objective is to establish a defensible sequence of observations across multiple telemetry sources, identify relationships between events, and document limitations that prevent stronger conclusions.

The investigation uses an existing Windows 11 lab endpoint monitored by Elastic Agent and Sysmon.

## Lab Objectives

By the end of this lab, you will be able to:

- **Assess telemetry availability:** Identify which Windows authentication, Sysmon process-creation, and network-connection events are available in Elastic.
- **Investigate authentication activity:** Examine Windows Security Event IDs 4624 and 4625 to understand successful and failed logon activity when the required records are available.
- **Analyze endpoint execution:** Use Sysmon Event ID 1 to investigate process names, executable paths, command-line arguments, parent processes, and user context.
- **Examine network activity:** Use Sysmon Event ID 3 to inspect network connections, source and destination addresses, ports, and associated processes.
- **Correlate multiple evidence sources:** Compare timestamps, hostnames, usernames, process identifiers, and network attributes to assess potential relationships between events.
- **Construct an investigation timeline:** Arrange relevant observations chronologically and distinguish confirmed facts from suspected relationships.
- **Troubleshoot telemetry gaps:** Investigate missing authentication events by examining local Windows audit settings, Elastic integration configuration, and event ingestion.
- **Evaluate investigative confidence:** Recognize the limitations of incomplete telemetry, reused process IDs, and timestamp-only correlation.
- **Document defensible findings:** Record evidence, unresolved questions, collection limitations, and recommended follow-up actions without making unsupported assumptions.

## Lab Scenario

A SOC analyst is investigating activity on a Windows 11 endpoint monitored by Elastic Agent and Sysmon. The objective is to determine whether the available telemetry provides sufficient context to connect user authentication, endpoint process execution, and network communication into a coherent sequence of events.

During the investigation, Sysmon process-creation events (Event ID 1) and network-connection events (Event ID 3) are found in Elastic. The records include processes such as `powershell.exe` and `Zoho Mail - Desktop.exe`, along with associated host, user, process ID, and network attributes. However, the Windows Security authentication query for Event IDs 4624 and 4625 returns no results.

Further investigation of the local Windows Security log identifies Event ID 4624, while Event ID 4625 is not found during the checks performed. This raises questions about audit policy configuration, Security event collection, and ingestion into Elastic.

The analyst must investigate the available evidence without assuming that the observed processes or network connections are malicious.

### Investigation Tasks

- Verify Elastic Agent health and identify the telemetry available in the selected data streams.
- Examine authentication, process-creation, and network-connection events using ES|QL.
- Compare timestamps, hostnames, usernames, process IDs, and network attributes to assess potential relationships.
- Investigate why the expected authentication events are missing from the Elastic query.
- Construct a chronological timeline and document confirmed observations, unresolved questions, and telemetry limitations.

The investigation is considered successful when the analyst produces an evidence-based assessment of the available telemetry and explains whether the collected records support reliable cross-source correlation. Discovering a security incident is not mandatory; identifying and documenting insufficient evidence is also a valid outcome.
  
## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 11 |
| Hostname | `DESKTOP-9MMM37V` / `desktop-9mmm37v` as displayed in different outputs |
| SIEM and investigation platform | Elastic Security / Kibana |
| Query language | ES|QL |
| Data pattern | `logs-*` |
| Endpoint telemetry | Sysmon |
| Elastic Agent version | 9.5.4 |
| Agent policy | `Windows-SOC-Lab` |
| Primary datasets | `windows.sysmon_operational` |
| Network interface address observed | `192.168.1.6` |

## Investigation Scope

The investigation examines three evidence categories.

### 1. User authentication

Windows Security Event IDs:

- `4624` — successful logon.
- `4625` — failed logon.

The investigation checks whether these records are available in Elastic and whether local Windows Security logs contain the corresponding events.

### 2. Endpoint process activity

Sysmon Event ID `1` records process creation when configured and collected.

Relevant fields include:

- `host.name`
- `user.name`
- `process.pid`
- `process.name`
- `process.executable`
- `process.command_line`
- `process.parent.pid`
- `process.parent.name`

### 3. Network activity

Sysmon Event ID `3` records network connections when enabled in the Sysmon configuration.

Relevant fields include:

- `host.name`
- `user.name`
- `process.pid`
- `process.name`
- `source.ip`
- `source.port`
- `destination.ip`
- `destination.port`
- `network.transport`

## Investigation Workflow

1. Verify Elastic Agent and Fleet health.
2. Inventory available datasets and event IDs.
3. Examine authentication events.
4. Investigate process creation.
5. Investigate network connections.
6. Compare event context and identifiers.
7. Construct a chronological timeline.
8. Document findings, limitations, and follow-up actions.

## Key Findings

- Elastic Agent reported `HEALTHY` status and a connected Fleet state.
- The dataset inventory processed 630 documents in the displayed 15-minute window.
- Sysmon Event IDs `1`, `11`, and `13` were present in the inventory output.
- Sysmon Event IDs `1` and `3` returned process-creation and network-connection records.
- Process-creation records included `powershell.exe` running under `SYSTEM`.
- Network-connection records included `Zoho Mail - Desktop.exe` under the account `Dell`, with source address `192.168.1.6`.
- The authentication query filtering for Event IDs `4624` and `4625` returned zero documents.
- A local Windows Security log query returned Event ID `4624`, while Event ID `4625` was not found during the checks performed.

These findings establish that endpoint and network telemetry were available. They do not establish a malicious incident or prove that the observed process and network activity were related to suspicious authentication.

## Important Limitations

- Windows Security authentication events were not returned by the current Elastic query.
- Event ID `4625` was not found locally during the initial troubleshooting checks.
- The absence of these events from the query does not prove that no failed logons occurred.
- A process name, destination port, or timestamp alone is insufficient to classify activity as malicious.
- Process IDs may be reused and should be evaluated with host and timestamp context.
- A shared hostname or nearby timestamps do not independently prove that events belong to the same user session.
- Sysmon Event ID `3` availability depends on the applicable Sysmon configuration.
- The investigation did not establish a complete user-to-process-to-network attack sequence.

