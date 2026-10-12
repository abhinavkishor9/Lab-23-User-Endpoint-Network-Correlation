# Lab 23 — Investigation Notes

## 1. Evidence Collection

### 1.1 Elastic Agent Health

The following command was used to check agent status:

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status --output full
```

Observed results:

- Fleet status: `HEALTHY` — Connected.
- Elastic Agent status: `HEALTHY` — Running.
- Agent version: `9.5.4+build202609161310`.
- Agent policy in use: `Windows-SOC-Lab`.

**Assessment:** The agent reported a healthy connection to Fleet. This confirms reported agent health but does not independently prove that every required Windows event channel is configured and being ingested.

### 1.2 Dataset Inventory

The following ES|QL query was used:

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY event.dataset, event.code
| SORT event_count DESC
| LIMIT 100
```

Observed results:

- Documents processed: `630`.
- Displayed time range: Last 15 minutes.
- `windows.sysmon_operational` was present.
- Event IDs `1`, `11`, and `13` appeared in the displayed inventory.

**Assessment:** Sysmon telemetry was available in the selected data pattern during the displayed time window.

The inventory output did not establish that Windows Security authentication events were being collected.

### 1.3 Process-Creation Events

The following query was used:

```esql
FROM logs-*
| WHERE event.dataset == "windows.sysmon_operational"
| WHERE event.code == "1"
| KEEP @timestamp, host.name, user.name,
       process.pid, process.name,
       process.executable, process.command_line,
       process.parent.pid, process.parent.name
| SORT @timestamp DESC
| LIMIT 100
```

Observed results:

- Documents processed: `100`.
- Host: `desktop-9mmm37v`.
- Process name: `powershell.exe`.
- User context included `SYSTEM`.
- Process IDs and executable paths were present.

Some command-line values were truncated in the Kibana table.

**Assessment:** Process-creation telemetry was available. The presence of PowerShell under `SYSTEM` is not, by itself, evidence of malicious activity. Process command lines, parent processes, execution context, and the purpose of the activity must be examined before drawing conclusions.

### 1.4 Network-Connection Events

The following query was used:

```esql
FROM logs-*
| WHERE event.dataset == "windows.sysmon_operational"
| WHERE event.code == "3"
| KEEP @timestamp, host.name, user.name,
       process.pid, process.name,
       source.ip, source.port,
       destination.ip, destination.port,
       network.transport
| SORT @timestamp DESC
| LIMIT 100
```

Observed results:

- Documents processed: `100`.
- Host: `desktop-9mmm37v`.
- User: `Dell`.
- Process: `Zoho Mail - Desktop.exe`.
- Process ID: `15892`.
- Source IP: `192.168.1.6`.
- Multiple source ports were visible.

The supplied result excerpts did not establish the destinations or intent of these connections.

**Assessment:** Sysmon network-connection telemetry was available. The process name and source IP alone do not establish whether the connections were benign or suspicious.

### 1.5 Combined Process and Network View

The following query was used:

```esql
FROM logs-*
| WHERE event.dataset == "windows.sysmon_operational"
| WHERE event.code IN ("1", "3")
| KEEP @timestamp, host.name, user.name,
       event.code, event.action,
       process.pid, process.name,
       process.executable, process.command_line,
       process.parent.pid, process.parent.name,
       source.ip, source.port,
       destination.ip, destination.port,
       network.transport
| SORT @timestamp ASC
| LIMIT 200
```

Observed results:

- Documents processed: `200`.
- Event ID `1` appeared with process-creation records.
- Event ID `3` appeared with network-connection records.
- `powershell.exe` appeared in process-creation records.
- `Zoho Mail - Desktop.exe` appeared in a network-connection record.

**Assessment:** The combined view provided a convenient way to inspect process and network records chronologically. It did not prove that the selected events formed a single activity chain.

### 1.6 Authentication Events

The following query was used:

```esql
FROM logs-*
| WHERE event.code IN ("4624", "4625")
| KEEP @timestamp, host.name, user.name,
       event.dataset, event.code, event.action,
       source.ip, winlog.event_data.LogonType
| SORT @timestamp DESC
| LIMIT 100
```

Observed result:

- Documents processed: `0`.
- No results matched the selected query.

A local Windows Security log query subsequently found Event ID `4624`. Event ID `4625` was not found during the checks performed.

**Assessment:** The expected authentication records were not available through the current Elastic query. The local presence of Event ID `4624` suggests that at least some successful-logon auditing was occurring, but the ingestion path still requires investigation.

The missing Event ID `4625` requires separate verification of audit policy, test conditions, and local Security log contents.

## 2. Correlation Assessment

| Evidence relationship | Current assessment | Reason |
|---|---|---|
| User to authentication | Incomplete | Authentication records were not returned by the Elastic query. |
| Authentication to process | Unresolved | The available evidence does not establish a matching authentication session. |
| Process to network | Requires event-level validation | Process and network events are available, but each relationship must be checked using host, PID, time, and event context. |
| Endpoint activity chronology | Partially established | Process and network events can be examined in timestamp order. |
| Complete user-to-endpoint-to-network chain | Not established | Authentication evidence and validated cross-event relationships are insufficient. |

### Correlation Rules

- Compare hostnames before relating records from different sources.
- Compare event timestamps using a consistent timezone.
- Validate process IDs against the relevant host and event time.
- Check whether usernames represent the same account context.
- Examine destination IP addresses and ports when available.
- Do not assume that an empty field means the associated activity did not occur.
- Do not classify activity as malicious solely because it uses PowerShell or network port `443`.

## 3. Findings

### Confirmed Observations

1. Elastic Agent reported a healthy connection to Fleet.
2. Sysmon Event IDs `1` and `3` were available in Elastic.
3. Process-creation events included `powershell.exe` under `SYSTEM`.
4. Network-connection events included `Zoho Mail - Desktop.exe` under the account `Dell`.
5. The authentication query returned zero documents.
6. Local Windows Security checks found Event ID `4624`.
7. Event ID `4625` was not found during the local checks performed.

### Unresolved Questions

- Is the Windows Security channel configured for collection by the installed Elastic integrations?
- Is the relevant integration writing Security events into the selected `logs-*` data streams?
- Is failure auditing enabled for the applicable logon audit subcategory?
- Does a controlled failed-logon test produce Event ID `4625`?
- Can the process and network events be linked using the same host, process ID, and relevant time interval?
- Are destination addresses and connection details sufficient to support a more specific assessment?

