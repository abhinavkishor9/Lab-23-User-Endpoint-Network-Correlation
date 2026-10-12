# Lab 23 — User + Endpoint + Network Correlation

## Overview

This lab investigates how user authentication, endpoint process execution, and network connection telemetry can be examined together to support a SOC investigation using Elastic Security and ES|QL.

The objective is to establish a defensible sequence of observations across multiple telemetry sources, identify relationships between events, and document limitations that prevent stronger conclusions.

The investigation uses an existing Windows 11 lab endpoint monitored by Elastic Agent and Sysmon.

## Objectives

- Verify Elastic Agent and Fleet health before investigating.
- Identify the telemetry datasets and event IDs available in Elastic.
- Examine Sysmon process-creation events (Event ID 1).
- Examine Sysmon network-connection events (Event ID 3).
- Investigate Windows Security authentication events (Event IDs 4624 and 4625).
- Compare hostnames, usernames, process IDs, IP addresses, and timestamps.
- Build a chronological investigation timeline.
- Identify telemetry gaps and document their impact on correlation.
- Separate confirmed observations from plausible relationships and unresolved questions.

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

## Conclusion

This lab demonstrates how Elastic Security and ES|QL can be used to examine endpoint process activity and network connections while assessing the availability of authentication telemetry.

The available evidence supports process and network investigation on the monitored endpoint. Authentication correlation remains incomplete because the expected Windows Security events were not available through the current Elastic query, and Event ID `4625` was not found in the local checks.

The appropriate outcome is to document the telemetry gap, investigate the Security event collection path, and repeat the correlation analysis when the required evidence is available.

The central principle is to follow the evidence, not the assumption.

## Disclaimer

This is a controlled learning-lab investigation. Observed events are not automatically indicators of compromise. Conclusions should be limited to the evidence collected and the telemetry available during the investigation.
