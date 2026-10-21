# Host first pass

Read-only first-pass snapshots for a newly reached host. Run the script that matches the target OS; both write to stdout and do not modify the target files they inspect.

## Linux

Run on the Linux target with Bash:

```bash
bash ./linux-first-pass.sh
```

By default the script prints every environment variable name and value in its own process. Each pair is shell-escaped to keep embedded newlines on one output line. To print names only:

```bash
bash ./linux-first-pass.sh --environment-names-only
```

The default output can contain secrets from environment values, paths, account names, and mount metadata. Save a transcript only in restricted engagement evidence. The script prints file candidate paths and metadata, not file contents or matching lines. Its content probes read selected small files to decide whether they contain a marker, then print matching paths only.

### Linux checks

| Section | Source and scope |
| --- | --- |
| Identity, OS and runtime | Current `id`, hostname, `/etc/os-release`, `uname -a`, `lscpu`, PATH, all exported environment pairs, `/etc/shells`, and noninteractive `sudo -n -l`. The sudo query never prompts for a password. Installed-package probes use `dpkg-query`, `rpm`, `pacman`, or `apk` when present; apk-tools v3 uses `apk list --installed --manifest '*'`, while v2 uses `apk info -v`. |
| Processes and local defenses | Visible process owner/PID/parent/start time/full command line via `ps`, active systemd services and timers when available, cron path metadata, and optional SELinux/AppArmor/UFW status. The script reports whether `nft`, `iptables`, `fail2ban-client`, and `snort` commands exist; command presence is only a lead, not proof that a defense is active. Process command lines may contain secrets. |
| Login sessions and namespace | `who -u`, `w`, and `loginctl list-sessions` for visible login records and TTY activity; `/proc/1/cgroup`, `/proc/1/ns`, `/proc/self/ns`, and `findmnt -T /` for the current process/mount context. A cgroup or namespace path alone does not prove where the host boundary lies. |
| Accounts and homes | Selected `/etc/passwd` fields (account, UID/GID, home, shell, password-field state), selected `/etc/group` fields, `/home` and current home top levels, current `.ssh` top level, and current shell-history path metadata. Password hashes, SSH key contents, and history contents are not printed. These account lists are local files; NSS can resolve additional users or groups. |
| Network | `ip address`, route and neighbor cache, `ss` TCP listeners and UDP endpoints, and resolver nameserver/search/domain directives. |
| Storage | `lsblk`, `findmnt` target/source/type, `df -h`, and noncomment `/etc/fstab` entries with option values suppressed. The fstab summary flags a credential-like option for follow-up. Optional printer status comes from `lpstat`. |
| Interesting files | Independent root-filesystem sweeps start at `/`: common shell and other script extensions are listed with path and metadata; readable regular files smaller than 256 KiB are checked for credential-like text markers, with matching paths only; selected candidate filenames are listed separately. Hidden names in current home (depth 4) and `/home` (depth 2); all regular files in current home (depth 4) and `/home` (depth 3), including ordinary and hidden names; entries in `/tmp`, `/var/tmp`, `/dev/shm` (depth 2); config-like filenames and content markers in current home, `/etc`, `/opt`, `/srv`, `/app`, `/usr/local/etc`, `/var/www`, `/var/backups`, `/var/lib`, `/mnt`, `/media`, `/root` (depth 3, current home depth 4). |
| Writable and privilege-related files | A `/` sweep reports writable regular files, writable traversable directories, and SUID/SGID regular files on the root filesystem. Focused scans also check writable directories (write and execute access) and writable files in current home, `/etc`, `/usr/local`, `/opt`, `/srv`, `/app`, `/var/www`, `/var/backups`, the three temporary roots, `/mnt`, `/media`, and `/root` (depth 3, current home depth 4); SUID/SGID files in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local`, `/opt`, `/srv`, `/app`, `/var/www`, `/mnt`, `/media` (depth 3); optional `getcap -r` on selected application and binary roots. |

The `/` sweeps use GNU `find -xdev`, so they stay on the filesystem that contains `/`. They do not descend into a separate `/home`, `/mnt`, or other child mount; the named scans cover selected mount roots. Review `findmnt` and run a focused check on any other relevant mount. Root metadata sweeps have a 30-second limit each. The shell script probe lists `.sh`, `.bash`, `.zsh`, and `.ksh`; the other script probe lists `.py`, `.pl`, `.rb`, `.php`, `.lua`, `.js`, and `.ps1`. Script probes are separate from other filename candidates so those results do not consume the same capture limit. Scripts without these extensions can still appear in home listings or process, service, and job paths. The root content sweep has a 90-second limit, reads regular files smaller than 262,144 bytes that the current identity can open, and skips binary-looking files through `grep -I`. It checks case-insensitive password, passwd, secret, token, credential, API key, and private key markers in files including scripts. A match is a path to inspect, not the file content.

Named file discovery uses GNU `find` with `-xdev` and the displayed depth limit, and GNU `timeout` with an eight-second limit per scan. The optional `getcap -r` check is recursive within its named roots and bounded by the same time limit. Named config-content scans only read readable, config-like regular files smaller than 1 MiB. Hidden-name and home inventories do not depend on content markers. Optional commands and absent roots are reported as `UNAVAILABLE`. A `DENIED` scan can include paths found before access failed.

Every probe prints its source, scope, and status. `FOUND` means output rows were returned, not that a vulnerability or secret was confirmed. `NONE` means the query completed within its stated scope with no rows. `AUTH_REQUIRED` means `sudo -n -l` needs authentication. `DENIED` is an access failure, `ERROR` is another query failure, and `UNAVAILABLE` means a command or root is absent. `INCOMPLETE` means the probe stopped at its displayed time limit or its capture reached 500 lines or 128 KiB; any displayed rows are partial. The script caps captured output while the command runs, so it does not first hold an unlimited process or file listing in memory. The producer may stop with a broken-pipe exit code when the capture cap is reached. `LC_ALL=C` makes status checks for command errors consistent. These limits apply to each probe, not to the total transcript.

To continue an incomplete probe, choose the directory or process question from its `scope` field and run a focused command. These examples show the uncapped form; narrow the path or use a pager for large results:

```bash
ps -eo user,pid,ppid,lstart,cmd --forest -ww | less -S
env | less -S
find /home -xdev -maxdepth 3 -type f -printf '%p | uid=%U gid=%G mode=%m size=%s\n' 2>&1 | less -S
find / -xdev -type f \( -iname '*.sh' -o -iname '*.bash' -o -iname '*.zsh' -o -iname '*.ksh' \) -ls 2>&1 | less -S
find / -xdev -type f -size -262144c -readable -exec grep -IilE 'pass(word|wd)?|secret|token|credential|api[_-]?key|private[_-]?key' -- {} + 2>&1 | less -S
find "$HOME" -xdev -maxdepth 4 -name '.*' -ls 2>&1
find /etc -xdev -maxdepth 3 -type f -writable -printf '%p | uid=%U gid=%G mode=%m size=%s\n' 2>&1
```

Read a selected candidate file with the commands in the pentest notes after confirming its path and access. The script itself does not read candidate contents into stdout.

## Windows

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

### Windows checks

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
