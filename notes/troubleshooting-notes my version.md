# Lab 23 — Troubleshooting Notes

## 1. Elastic Agent Health Verification

### Symptom

Authentication events were missing from the query results, raising the question of whether Elastic Agent was disconnected or unhealthy.

### Command

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status --output full
```

### Observed Output

- Fleet: `HEALTHY` — Connected.
- Elastic Agent: `HEALTHY` — Running.
- Agent version: `9.5.4+build202609161310`.

### Assessment

Elastic Agent reported healthy status and a connection to Fleet.

This makes a complete agent outage less likely, but it does not confirm that the Windows Security channel is configured, readable, or successfully ingested.

### Next Action

Keep the existing agent enrollment. Inspect the installed integrations and their collection settings before considering any changes.

## 2. Dataset Inventory

### Symptom

The authentication query returned zero documents, while other Windows telemetry was visible.

### Command

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY event.dataset, event.code
| SORT event_count DESC
| LIMIT 100
```

### Observed Output

- Documents processed: `630`.
- Displayed time range: Last 15 minutes.
- Dataset: `windows.sysmon_operational`.
- Event IDs included `1`, `11`, and `13`.

### Assessment

The selected data pattern contained Sysmon events. The inventory did not establish the presence of Windows Security authentication records.

### Next Action

Inspect the available datasets and determine whether the Security event channel is collected into the selected data streams.

Do not assume that Sysmon telemetry automatically includes Windows Security events.

## 3. Missing Authentication Events in Elastic

### Symptom

The following query returned zero documents:

```esql
FROM logs-*
| WHERE event.code IN ("4624", "4625")
| KEEP @timestamp, host.name, user.name,
       event.dataset, event.code, event.action,
       source.ip, winlog.event_data.LogonType
| SORT @timestamp DESC
| LIMIT 100
```

### Initial Assessment

The query syntax was accepted, but no records matched the event-code filter.

Possible explanations include:

- Windows Security events are not being collected.
- The relevant Security channel is not configured in the installed integration.
- The events are being written to a different data stream or index pattern.
- The selected time range does not include the relevant events.
- The expected fields or event-code values differ from those in the collected documents.

The zero-result query alone cannot distinguish among these explanations.

### Verification Performed

A local Windows Security log check found Event ID `4624`, while Event ID `4625` was not found during the checks performed.

### Next Action

1. Confirm that the `Security` channel is included in the applicable Elastic integration.
2. Verify the integration's status and data stream.
3. Expand the time range to include the local event timestamp.
4. Inspect available Windows event datasets and field values.
5. Rerun the query after verifying collection.

## 4. Event ID 4625 Not Found Locally

### Symptom

The local Windows Security log query returned Event ID `4624` but did not return Event ID `4625`.

### Initial Check

Run PowerShell as Administrator:

```powershell
auditpol /get /subcategory:"Logon"
```

Inspect whether failure auditing is enabled for the Logon subcategory.

### If Failure Auditing Is Disabled

Enable it with:

```powershell
auditpol /set /subcategory:"Logon" /failure:enable
```

Verify the resulting policy:

```powershell
auditpol /get /subcategory:"Logon"
```

If a domain or local Group Policy setting controls auditing, verify whether that policy overrides the local setting.

### Controlled Test

Perform one controlled failed-logon attempt using your own lab account, then sign in normally.

Avoid repeated incorrect attempts because account lockout policies may apply.

Check for a newly generated Event ID `4625`:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

### Interpretation

- If Event ID `4625` appears, investigate why the original query did not find it and verify whether Elastic subsequently ingests it.
- If it remains absent, verify the effective audit policy, the test conditions, and the local Security log.
- If the command reports an error, record the exact error before changing the configuration.

Do not conclude that failed logons never occurred simply because the query returns no records.

## 5. Sysmon Process and Network Events

### Symptom

The investigation needed to confirm that process-creation and network-connection telemetry was available.

### Process-Creation Query

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

### Network-Connection Query

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

### Observed Results

- Event ID `1` returned process-creation records.
- Event ID `3` returned network-connection records.
- `powershell.exe` appeared in process-creation records.
- `Zoho Mail - Desktop.exe` appeared in network-connection records.

### Assessment

The relevant Sysmon event types were available in Elastic. Their presence does not establish a security incident.

### Next Action

Compare event timestamps, hostnames, process IDs, and available user context. Inspect complete event details before attributing a network connection to a specific process or account.

If Event ID `3` is missing in a future test, verify that Sysmon network-connection logging is enabled and that the relevant channel is being ingested.

## 6. Correlation Limitations

### Problem

A combined chronological result set can contain authentication, process, and network records without establishing that they belong to the same activity.

### Recommended Approach

- Compare the hostname across records.
- Validate process IDs against the same host and relevant execution time.
- Review the process creation event and network event details.
- Compare timestamps in a consistent timezone.
- Verify user context where the fields are available.
- Record unresolved relationships explicitly.

A matching process ID is not sufficient on its own because Windows can reuse process IDs. Likewise, temporal proximity does not prove causation.

## 7. Troubleshooting Status

| Item | Status |
|---|---|
| Elastic Agent connected to Fleet | Confirmed |
| Sysmon Event ID 1 available | Confirmed |
| Sysmon Event ID 3 available | Confirmed |
| Local Event ID 4624 found | Confirmed |
| Event ID 4625 found locally | Not found during checks |
| Authentication events returned by Elastic query | Not returned |
| Security channel collection configuration | Requires verification |
| Complete user-to-process-to-network correlation | Not established |

