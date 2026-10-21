# Host first pass

`windows-first-pass.ps1` prints a fixed, read-only snapshot when you first reach a Windows host. It uses Windows PowerShell 5.1 and has no required parameters.

Clone the repository and run the script locally:

```powershell
git clone https://github.com/soloclz/host-first-pass.git
cd host-first-pass
powershell.exe -NoProfile -File .\windows-first-pass.ps1
```

The default run prints every environment variable name and value in the current PowerShell process. To see every name without values, use:

```powershell
powershell.exe -NoProfile -File .\windows-first-pass.ps1 -EnvironmentNamesOnly
```

The script prints plain text to the console and can be piped to `Tee-Object`. It does not write a report, contact another host, recursively search files, or print file contents, process command lines, or Credential Manager secret values. Environment values can contain secrets; a shell transcript or a pipeline that saves the output will capture them.

The environment section uses PowerShell's `[Environment]::GetEnvironmentVariables('Process')`. For a manual check in PowerShell, run `Get-ChildItem Env:`. In CMD, `set` prints `name=value` pairs; in PowerShell, bare `set` is an alias for `Set-Variable`.

## What it checks

| Section | Source | Scope and output |
| --- | --- | --- |
| Identity and token | `whoami /all` | Current process token: user, groups, privileges, and integrity information. Highlights Event Log Readers SID (`S-1-5-32-573`) when present; inspect its attributes and check Security log access separately. |
| Operating system | `Win32_OperatingSystem` via `Get-CimInstance`; `CurrentBuild` and `UBR` in `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Local OS name, version, architecture, base build, and full build when both registry values exist. |
| Installed OS updates | `Win32_QuickFixEngineering` via `Get-CimInstance` | Every CBS-reported QFE record: `HotFixID`, `InstalledOn`, and record count. `InstalledOn` is shown as returned by PowerShell, without date sorting. |
| UAC policy | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | Raw `EnableLUA` and `ConsentPromptBehaviorAdmin` values. `EnableLUA=1` enables Admin Approval Mode; `ConsentPromptBehaviorAdmin=5` is the default prompt for consent for non-Windows binaries. Compare the policy with the current process token above when assessing elevation. |
| Windows Installer policy | `AlwaysInstallElevated` in `HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer` and `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer` | Reports each value and type. The summary distinguishes both values enabled, HKLM enabled with HKCU not yet enabled, HKLM not enabled, and uncertain registry reads. A missing key or value is reported as `NONE` for that registry read. |
| Running processes | `tasklist /v /fo csv /nh` | Local process PID, image name, session number, and reported account. `N/A` accounts are shown as `(not reported)`; unexpected CSV is reported as `ERROR`. |
| Logon sessions | `quser` | Sessions visible on the local host to the current account, including state and logon time. |
| Kerberos tickets | `klist` | Tickets cached in the current logon session; read the displayed ticket count, principals, and times. |
| Network endpoints | `Get-NetTCPConnection` filtered to `State=Listen`, `Get-NetUDPEndpoint` | All local TCP listeners and bound UDP endpoints, with address, port, and PID. |
| Endpoint PID metadata | `Win32_Process`, `Win32_Service` via `Get-CimInstance` | Process name and any reported executable path, plus service names mapped by PID, for endpoint PIDs only. The output counts linked process records and paths returned. |
| User profile | `Environment.SpecialFolder.UserProfile`, `Get-ChildItem` | Current user profile path, up to 100 top-level names, and up to 100 names, byte lengths, and modification times immediately inside `.ssh`; no file contents or recursion. Total entry counts show when output was capped. |
| Sticky Notes database | `Environment.SpecialFolder.LocalApplicationData`, `Test-Path` | Checks whether `plum.sqlite` exists at the current user's fixed Sticky Notes package path; prints the path when found, not the notes. |
| Credential Manager | `cmdkey /list` | Current user's stored target and account metadata; no stored passwords. |
| Environment | `[Environment]::GetEnvironmentVariables('Process')` | All names and values in the current PowerShell process by default; all names without values with `-EnvironmentNamesOnly`. Names and values are JSON-escaped so each pair stays on one console line. |

Each probe shows its source, scope, and status. `FOUND` means the probe returned rows or the named path exists. `QUERY_OK` means `cmdkey /list` or `klist` ran successfully; inspect the displayed text to tell whether stored targets or cached tickets are present. `NONE` means the query succeeded with no rows, the user profile path is unavailable, or the `.ssh` directory is absent. `DENIED` means access was refused, `ERROR` means a query failed, `UNAVAILABLE` means its command is missing, and `NOT_RUN` means a dependent query was skipped. An endpoint can disappear between the network and process queries, so a missing process record at query time needs a fresh check. `path=(not reported)` means `Win32_Process.ExecutablePath` returned no value for that process; the current token can see a PID without access to its path. Service names are mapped by PID and do not establish which service in a shared process owns a socket. [Win32_Process](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process) · [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)

For `Elevated MSI policy condition`, `FOUND` means both values are `REG_DWORD 1` for the current user and host; verify the token of any process launched by the MSI. `CANDIDATE` means HKLM is `REG_DWORD 1` while HKCU is known to differ or is absent; the current user can set HKCU to `REG_DWORD 1` and recheck. `NONE` means HKLM is known not to be `REG_DWORD 1`, so changing HKCU alone cannot enable this policy. `DENIED` or `ERROR` means a necessary registry read failed and the policy condition is uncertain.

QFE records are patch leads for a specific CVE. `Win32_QuickFixEngineering` reports CBS updates, not every update source; a KB absent from its rows does not establish that the fix is absent because Windows cumulative updates include earlier fixes. Compare the full build with the relevant Microsoft update history and the CVE conditions. [QFE class](https://learn.microsoft.com/en-us/windows/desktop/CIMWin32Prov/win32-quickfixengineering) · [Cumulative updates](https://learn.microsoft.com/en-us/windows/deployment/update/servicing-stack-updates)

The snapshot is an index of leads. Investigate a specific process, service, store, or path with your normal notes after reviewing the output.

With an IIS application pool identity, `GetFolderPath(UserProfile)` can return no path. The script reports `NONE` for the profile and skips its directory checks. Native queries such as `quser` and `klist` can return a nonzero exit code for this token; read their reported error instead of treating it as an empty result.
