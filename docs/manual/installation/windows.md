# Windows (service)

Extract the release `.zip` and put `opcua-audit-gateway.exe` where only
administrators can change it; the config gets its own directory, which
`init` creates. In PowerShell, as administrator:

```powershell
$exe = "C:\Program Files\OPC UA Audit Gateway\opcua-audit-gateway.exe"
$cfg = "C:\ProgramData\OPC UA Audit Gateway\config.toml"
& $exe --config $cfg init
& $exe --config $cfg user passwd admin      # the first admin password (a service has no console)
& $exe --config $cfg service install
Start-Service OpcUaAuditGateway
```

The web UI is on http://127.0.0.1:8080; log in as `admin` with that password
and choose a new one (see [First login](../first-login.md)).

- The service runs under its own virtual account
  (`NT SERVICE\OpcUaAuditGateway`), not as LocalSystem. `service install`
  restricts the config, data, certificate and log directories to that
  account, SYSTEM and administrators; don't point them at shared directories.
- Logs go to `logs` next to the config (daily files, kept 14 days). Any
  command accepts `--log-dir` to log to files instead of the console.
- **Upgrade:** `Stop-Service OpcUaAuditGateway`, replace the exe,
  `Start-Service OpcUaAuditGateway`. Config and data are kept.
- `service uninstall` removes the service.

The Windows service installation has not been tested for real yet.
