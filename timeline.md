# Lab 23 — Investigation Timeline

## 1. Overview

**Investigation:** User + Endpoint + Network Correlation

**Endpoint:** `DESKTOP-9MMM37V` / `desktop-9mmm37v`

**Platform:** Elastic Security / Kibana

**Timezone:** Kibana display timezone for the timestamps reproduced below. Confirm the configured timezone before comparing these values with local Windows logs.

This timeline records the investigation activities and selected telemetry observations. The observed process and network events are not assumed to form a single attack sequence.

## 2. Observed Telemetry

The following records were visible in the supplied Kibana results.

| Timestamp displayed in Kibana | Host | User | Event ID | Observation |
|---|---|---|---|---|
| Oct 11, 2026 07:08:19.401 | `desktop-9mmm37v` | `SYSTEM` | 1 | `powershell.exe` process-creation record; PID `3120`. |
| Oct 11, 2026 07:08:23.738 | `desktop-9mmm37v` | `Dell` | 3 | `Zoho Mail - Desktop.exe` network-connection record; PID `15892`. |
| Oct 11, 2026 07:08:24.550 | `desktop-9mmm37v` | `SYSTEM` | 1 | `powershell.exe` process-creation record; PID `6780`. |
| Oct 12, 2026 06:56:20.220 | `desktop-9mmm37v` | `Dell` | 3 | `Zoho Mail - Desktop.exe` network-connection record; PID `15892`; source IP `192.168.1.6`; source port `57572`. |
| Oct 12, 2026 06:56:20.225 | `desktop-9mmm37v` | `Dell` | 3 | `Zoho Mail - Desktop.exe` network-connection record; PID `15892`; source IP `192.168.1.6`; source port `57571`. |
| Oct 12, 2026 06:56:20.247 | `desktop-9mmm37v` | `Dell` | 3 | `Zoho Mail - Desktop.exe` network-connection record; PID `15892`; source IP `192.168.1.6`; source port `16791`. |
| Oct 12, 2026 06:56:47.426 | `desktop-9mmm37v` | `SYSTEM` | 1 | `powershell.exe` process-creation record; PID `13204`. |
| Oct 12, 2026 06:56:52.609 | `desktop-9mmm37v` | `SYSTEM` | 1 | `powershell.exe` process-creation record; PID `19096`. |
| Oct 12, 2026 06:56:57.762 | `desktop-9mmm37v` | `SYSTEM` | 1 | `powershell.exe` process-creation record; PID `3112`. |

**Important:** These are selected observations from the provided screenshots, not a complete export of all events. The source and destination details for the network connections were not fully established by the supplied excerpts.

## 3. Investigation Activity Timeline

| Stage | Activity | Result |
|---|---|---|
| 1 | Checked Elastic Agent status | Fleet and Elastic Agent reported healthy status. |
| 2 | Inventoried datasets and event IDs | Sysmon Event IDs `1`, `11`, and `13` appeared in the displayed inventory. |
| 3 | Queried Windows Security Event IDs `4624` and `4625` in Elastic | Zero documents returned. |
| 4 | Queried Sysmon Event ID `1` | Process-creation records returned. |
| 5 | Queried Sysmon Event ID `3` | Network-connection records returned. |
| 6 | Combined Sysmon process and network records | Both event types were available in one chronological result set. |
| 7 | Checked local Windows Security logs | Event ID `4624` was found; Event ID `4625` was not found during the checks performed. |
| 8 | Assessed cross-source correlation | Endpoint and network activity could be examined, but complete authentication correlation remained unresolved. |

## 4. Correlation Notes

### Authentication

- Elastic query for Event IDs `4624` and `4625`: zero documents.
- Local Event ID `4624`: found.
- Local Event ID `4625`: not found during the checks performed.
- Result: the authentication evidence was insufficient to establish a complete user activity sequence.

### Process Activity

- Sysmon Event ID `1` was available.
- Process-creation records included `powershell.exe` under `SYSTEM`.
- Additional validation of command lines, parent processes, and execution purpose is required before assessing whether a process is suspicious.

### Network Activity

- Sysmon Event ID `3` was available.
- Network records included `Zoho Mail - Desktop.exe` under the account `Dell`.
- Source IP `192.168.1.6` and several source ports were visible.
- The supplied excerpts do not establish the complete destination details or whether any connection was suspicious.

### Cross-Source Correlation

The displayed process and network records establish that both types of activity were recorded on the endpoint. They do not establish a relationship between a particular authentication event and a particular network connection.

No single attack sequence is asserted from these observations.

## 5. Outstanding Questions

- Is the Windows Security channel configured in the applicable Elastic integration?
- Why are locally observed Event ID `4624` records not returned by the current Elastic query?
- Is Logon failure auditing enabled, and can a controlled test generate Event ID `4625`?
- Can the network records be linked to their corresponding process-creation records using complete event details?
- Are the event timestamps being compared in the same timezone?
- Does further evidence support a benign explanation or require additional investigation?

## 6. Conclusion

The timeline demonstrates that Elastic received Sysmon process-creation and network-connection telemetry from the monitored Windows endpoint.

The authentication evidence remains incomplete because the relevant Elastic query returned no records, and Event ID `4625` was not found locally during the checks performed.

The investigation does not establish a confirmed security incident or a complete user-to-endpoint-to-network chain. The next step is to resolve the authentication telemetry gap and repeat the correlation using validated event records.

Missing evidence must remain documented as a limitation rather than being interpreted as proof that an event did or did not occur.
