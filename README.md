# Windows first pass

`windows-first-pass.ps1` prints a fixed, read-only snapshot when you first reach a Windows host. It uses Windows PowerShell 5.1 and has no required parameters.

Clone the repository and run the script locally:

```powershell
git clone https://github.com/soloclz/windows-first-pass.git
cd windows-first-pass
powershell.exe -NoProfile -File .\windows-first-pass.ps1
```

The script prints plain text to the console and can be piped to `Tee-Object`. It does not write a report, contact another host, recursively search files, or print file contents, environment variable values, process command lines, or credential secret values. A shell transcript made outside the script can still capture the displayed host and account metadata.

## What it checks

| Section | Source | Scope and output |
| --- | --- | --- |
| Identity and token | `whoami /all` | Current process token: user, groups, privileges, and integrity information. |
| Operating system | `Win32_OperatingSystem` via `Get-CimInstance` | Local OS name, version, build, and architecture. |
| Logon sessions | `quser` | Sessions visible on the local host to the current account, including state and logon time. |
| Network endpoints | `Get-NetTCPConnection` filtered to `State=Listen`, `Get-NetUDPEndpoint` | All local TCP listeners and bound UDP endpoints, with address, port, and PID. |
| Owners | `Win32_Process`, `Win32_Service` via `Get-CimInstance` | Process name and executable path, and service names, for endpoint PIDs only. |
| User profile | `Environment.SpecialFolder.UserProfile`, `Get-ChildItem` | Current user profile path, up to 100 top-level names, and up to 100 names, byte lengths, and modification times immediately inside `.ssh`; no file contents or recursion. Total entry counts show when output was capped. |
| Credential Manager | `cmdkey /list` | Current user's stored target and account metadata; no stored passwords. |
| Environment | Process environment variable names | Only names matching the built-in password, token, secret, credential, auth, cookie, session, private, or key terms. Values are never read for display. |

Each probe shows its source, scope, and status. `FOUND` means the probe returned rows or the named path exists. `QUERY_OK` means `cmdkey /list` ran successfully; inspect its displayed text to tell whether entries are present. `NONE` means the query succeeded with no rows or the `.ssh` directory is absent. `DENIED` means access was refused, `ERROR` means a query failed, `UNAVAILABLE` means its command is missing, and `NOT_RUN` means a dependent query was skipped. An endpoint can disappear between the network and process queries, so a missing owner at query time needs a fresh check.

The snapshot is an index of leads. Investigate a specific process, service, store, or path with your normal notes after reviewing the output.

The script has passed static review on macOS. Execution on Windows PowerShell 5.1 has not yet been verified; check the output statuses on the target host before relying on an empty result.
