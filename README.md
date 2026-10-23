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

The default output can contain secrets from environment values, process and cron command lines, policy directives, paths, account names, and mount metadata. Save a transcript only in restricted engagement evidence. File discovery probes print candidate paths and metadata; content-marker probes read selected readable files and print matching paths only. The system cron and password-policy probes print selected noncomment lines from their source files.

Run only the file searches you need by selecting one or more short flags. A selected run does not run the host snapshot. `-p` changes the start directory; without it, a selected search starts at `/` and stays on that filesystem.

```bash
bash ./linux-first-pass.sh -n                 # credential-related filenames
bash ./linux-first-pass.sh -c -s -p /srv/app  # config and source files in an application
bash ./linux-first-pass.sh -k -p /var/www     # credential-like text in small readable files
```

| Flag | File search |
| --- | --- |
| `-n` | Credential-related names: `*password*`, `*passwd*`, `*secret*`, `*credential*`, `*token*`, `*note*`, `*.env`, `.env.*`, `.netrc`, `.git-credentials`, `.pgpass`, `.my.cnf`, `credentials`, `config`, `kubeconfig`, `*.keytab`, `*.ccache`, `*.kdbx`; `id_*` in home paths, or anywhere under a selected `-p DIR` other than `/`. Without `-p`, it also scans the current `$HOME` when that is on another filesystem. |
| `-c` | Config names: `*.conf`, `*.config`, `*.ini`, `*.yaml`, `*.yml`, `*.json`, `*.xml`, `*.toml`, `*.properties`, the file `config`, `.env`, and `.env.*`. |
| `-s` | Shell scripts (`.sh`, `.bash`, `.zsh`, `.ksh`) and other source/script files (`.py`, `.pl`, `.rb`, `.php`, `.lua`, `.js`, `.ps1`). |
| `-a` | `*_hist`, `*_history`, backup, log, SQL, archive, and database filenames. |
| `-k` | Case-insensitive credential-like text in readable regular files smaller than 128 KiB. Prints matching paths only. |

Use the actual application path from a process, service, Web configuration, or mount for `-p DIR`; a Web root is not necessarily `/var/www`. The selected start may itself be a symlink or a separate filesystem. Each search follows its start and stays on that filesystem. Inspect a selected file to confirm its content and purpose.
When a filename matches both `-n` and `-c`, it appears in each selected category's metadata probe.

The `=== ... ===` lines divide the Linux output into topics; the `[FOUND]`, `[DENIED]`, and other status lines mark individual probes within each topic. `grep -n '^=== ' first-pass.txt` lists all topics with line numbers. In `less -S first-pass.txt`, search `/^=== ` to move between topics or `/^\[` to move between probe results, then press `n` for the next match or `N` for the previous one. Each probe displays at most 500 whole stdout lines or 128 KiB. Its status reports how many observed lines were not displayed and prints a full-output follow-up when needed.

### Linux checks

| Section | Source and scope |
| --- | --- |
| Identity and host runtime | Current `id`, hostname, OS release, running kernel and architecture, CPU, valid login shells, and a separate Debian/Ubuntu query for the package matching the running kernel. A missing local kernel image package is reported explicitly. |
| PATH and environment | The script process's PATH entries in search order, write/enter checks for each directory, and exported environment pairs (or names with `--environment-names-only`). |
| Sudo, packages and tools | `sudo -n -l` and `sudo -V` first, then `pkexec` mode, owner, and Debian package build; the package inventory available through `dpkg-query`, `rpm`, `pacman`, or `apk`; and common tool paths. The sudo rule query never prompts for a password. |
| Accounts and home directories | Selected fields from local `/etc/passwd` and `/etc/group`, common password-policy directives and domain-join clues, plus the top level of `/home` and the current home, current `.ssh`, and history path metadata. Hashes, SSH key contents, and history contents are not printed; NSS may resolve additional accounts. |
| Privileged group resources | Printed only when `id` lists `adm`, `docker`, `lxd`, or `disk`: bounded readable `/var/log` metadata, known daemon-socket access, or block-device access as relevant. Docker image inventory is a separate, group-independent query. |
| Processes and login sessions | Visible process owner, PID, parent, start time, and full command line via `ps`; `who -u`, `w`, `loginctl list-sessions`, `lastlog`, and `last -a` for current and past login records. Process command lines may contain secrets. |
| Services and local defenses | Running systemd services, installed service/socket unit files (including disabled and static units), loaded sockets, SELinux/AppArmor/UFW state when available, and presence of `nft`, `iptables`, `fail2ban-client`, and `snort`. Command presence is a lead, not proof that a defense is active. |
| Scheduled jobs and log rotation | Systemd timers, cron path metadata, system cron schedule lines, current-user crontab, and cron directory entries; `logrotate --version` and mode/UID/GID/readability of standard logrotate configuration paths. Configuration contents and effective logrotate rules need selected-path follow-up. |
| Container and namespace context | User namespace limit values, PID 1 cgroup, PID 1 and script namespace links, and root mount. When the Docker client and a writable local Unix socket are present, lists images already stored in each reachable local daemon with an eight-second limit; aliases to the same socket are queried once. This may start a socket-activated daemon. |
| Network | `ip address`, routes, neighbor cache, TCP listeners and connections, UDP endpoints, Unix sockets, `/etc/hosts`, and resolver directives. |
| Storage and mounts | `lsblk`, `findmnt`, bounded `df -h`, selected `/etc/fstab` entries, local NFS export configuration from `/etc/exports` and immediate `*.exports` files, and optional printer status. The fstab summary suppresses option values and flags credential-like options for follow-up. |
| SUID, SGID and file capabilities | SUID/SGID regular files from `/` and selected roots, plus bounded `getcap -r` on selected application and binary roots. When `readlink` is available, named starts that resolve to the same directory are scanned once after a successful scan; the skipped alias is printed. A failed or incomplete scan leaves its alias available for another attempt. |
| Writable paths and logs | Writable regular files and traversable directories from `/` and focused roots; deduplicated writable log candidates with access and metadata for each file, directory, and parent. |
| Credential-like content markers | One bounded query of readable regular files smaller than 128 KiB on the filesystem containing `/`; matching paths only. `-k` runs the same check alone, optionally from `-p DIR`. |

When a process, service, cron entry, or sudo rule identifies an executable, inspect that path with `namei -l /path/to/program` and `file /path/to/program`. When a scheduled job identifies an output directory, use `find /path/to/output -xdev -type f -mtime -7 -ls` to review recent files there. Compare a selected output file's timestamps across a job interval to see whether it changes; modification time alone does not identify the writer.

The PATH probe prints the raw value, the script's physical current directory, and every entry in search order, including empty entries and duplicates. Each entry shows the path checked and whether the current identity can write to and enter that directory. An empty entry or `.` checks the current directory; other relative entries use the script's current directory. `not-confirmed` means the shell could not confirm the path exists, which can also occur when access is blocked. These checks describe this script process; a sudo rule, service, or scheduled job can use another PATH and current directory.

GNU `find -xdev` stays on the filesystem containing its start. The `/` searches do not enter separate child mounts; use `findmnt` to identify a relevant mount, then rerun selected categories with `-p DIR`. `-p` follows a symlink used as the start and does not limit depth. Root metadata searches have a 30-second limit each; content searches have a 90-second limit. Baseline SUID/SGID and writable scans also use bounded named roots with printed depth limits. The optional `getcap -r` check uses selected application and binary roots with an eight-second limit.

The content marker checks look for `password`, `passwd`, `passphrase`, a `pass` assignment key, `secret`, `token`, `credential`, `api key`, and `private key`, ignoring case. `grep -I` skips binary-looking files. The 128 KiB cutoff applies to the file size, not the displayed output size. A match is a path to inspect; larger files need a selected-directory search from the notes. Filename inventories use GNU `find -ls` so embedded newlines in names are escaped and each match stays on one output row. Content matches use Bash `%q` to escape path names. Optional commands and absent roots are reported as `UNAVAILABLE`. A `DENIED` scan can include paths found before access failed.

`Writable log candidates` includes writable `*.log` and `*.log.*` files anywhere scanned, plus writable regular files under `/var/log` even without a `.log` suffix. The focused `/var/log` scan covers that directory if it is a separate filesystem. Candidate rows show access for the current identity; `parent_writable=yes parent_enterable=yes` is a lead for checking whether the log directory can be renamed, not a logrotate finding. The candidate probe inherits the time limits and filesystem scopes of its source scans. Its sort has an eight-second limit, and metadata output stops between candidate paths after eight seconds. If a source writable scan fails, the candidate summary reports a non-success status and its `observed` count is partial. Check source-scan statuses to locate the gap; custom log names outside `/var/log` need selected-path follow-up.

Each status line names its source and scope; queries that ran also show elapsed whole seconds for the query and capture. `FOUND` means output lines were returned, not that a vulnerability or secret was confirmed. `NONE` means the query completed within its stated scope with no output lines. `AUTH_REQUIRED` means `sudo -n -l` needs authentication. `DENIED` is an access failure, `ERROR` is another query failure, and `UNAVAILABLE` means a command or root is absent. `INCOMPLETE` means the producer hit its time limit or ended before completion. The count unit is **stdout lines**: a `find -ls` path inventory emits one line per matching path, while a content probe emits one line per matching path, not one per file inspected; a command such as `lastlog` also emits a heading. For a successful scan, `matched`, `shown`, and `undisplayed` are exact counts of stdout lines within its stated scope. `display=TRUNCATED` means only the first 500 whole lines or at most 128 KiB are shown; it does not stop the scan. If the scan times out or fails, `observed`, `shown`, and `undisplayed-observed` count lines produced before failure, and `unscanned=unknown` means the unseen search space cannot be counted. Stderr is counted separately as `stderr-lines`, `stderr-shown`, and `stderr-undisplayed`; the first eight whole lines or 8 KiB are shown. The printed full-output command saves all rerun stderr in `$HOME/first-pass-full.err`. The script drains stdout, keeps only the display prefix in a restricted temporary directory, then removes that directory on exit. Full counting can take longer than the old display-stop behavior, up to the stated time limit for each bounded scan. `LC_ALL=C` makes status checks for command errors consistent. These limits apply to each probe, not to the total transcript.

### Linux full-output follow-up

If a probe has undisplayed lines or an incomplete scan, it prints a rerun command that saves stdout and stderr separately, prints the exit code, then opens the saved stdout in `less`. A `find` scan rerun has no time limit; it can take much longer after an `INCOMPLETE` content scan. Other timed probes get a 30-second rerun limit; if one also times out, its unscanned range remains unknown. For a stalled `df -h`, `df -h -l` checks local filesystems separately while you investigate the remote mount. Helper probes use `--full-helper NAME` when the script is saved as a file; this runs only that helper without the display cap. When the script was streamed through stdin, save a copy first or use the matching helper key below. A full query can still fail on inaccessible directories; keep its stderr and exit code rather than treating its output count as a complete inventory.

For a truncated file probe, copy its printed `full-output command`. The command includes the selected `-p` start directory, the exact `find` predicate, a restricted output file, separate stderr, the exit status, and `less`. A selected query is still limited to one filesystem; choose another start with `-p DIR` when the relevant files are on a separate mount.

Helper probes have these full-output sources:

| Printed key | Full command or source |
| --- | --- |
| `scan_capabilities` | `getcap -r /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /srv /app` (remove absent roots). |
| `show_environment` | Recheck the current process environment with `env -0` and the Bash NUL loop below. A later shell has its own current environment, which can differ from the earlier script process. |
| `show_path` | `bash ./linux-first-pass.sh --full-helper show_path` prints the uncapped PATH entries and directory checks for the rerun process. |
| `show_passwd_accounts`, `show_groups` | `cat /etc/passwd`, `cat /etc/group` respectively; the script's summaries omit raw password fields. |
| `show_group_sockets`, `show_disk_device_access` | Recheck known Docker/LXD Unix sockets or `/dev` block nodes for the current identity. Socket path access errors are reported separately from absent paths. The disk helper allows 30 seconds on a full-output rerun. The script only runs each check when `id -nG` contains its matching group; a later session can have different group membership. |
| `show_resolver`, `show_fstab` | `cat /etc/resolv.conf`, `cat /etc/fstab` respectively; the script selects resolver directives and suppresses fstab option values. |
| `show_nfs_export_configs` | `bash ./linux-first-pass.sh --full-helper show_nfs_export_configs` prints metadata and noncomment lines from readable `/etc/exports` and immediate `/etc/exports.d/*.exports` files without the display cap. |
| `show_dpkg_packages` | The output prints a complete uncapped `dpkg-query` and `awk` rerun command. It selects rows whose package status indicates installed. |
| `show_running_kernel_package` | `bash ./linux-first-pass.sh --full-helper show_running_kernel_package` rechecks `uname -r` and only its matching signed and unsigned `linux-image` package names in the local dpkg database. |
| `show_user_namespace_limits` | `bash ./linux-first-pass.sh --full-helper show_user_namespace_limits` rereads the two named `/proc/sys` files and prints each value, absence, or read failure without creating a namespace. |
| `show_pkexec` | `bash ./linux-first-pass.sh --full-helper show_pkexec` rechecks `/usr/bin/pkexec` mode/owner and its exact owning Debian package build without the display cap. A missing dpkg owner is reported explicitly. |
| `show_apk_packages` | `apk info -v` on apk-tools v2 or `apk list --installed --manifest '*'` on v3. |
| `show_current_ssh`, `show_history_paths` | `ls -la "$HOME/.ssh"`; `ls -ld "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"` (omit absent files). |
| `show_cron_paths`, `show_cron_directory_entries` | `ls -ld /etc/cron* /var/spool/cron /var/spool/cron/crontabs`; `find` each existing cron directory at `-mindepth 1 -maxdepth 1 -ls`. |
| `show_system_cron_entries`, `show_current_crontab` | Read noncomment lines of `/etc/crontab` and each readable file in `/etc/cron.d`; `crontab -l` respectively. |
| `show_logrotate_configs` | List current-user readability and metadata for `/etc/logrotate.conf` and immediate `/etc/logrotate.d/*` files. |
| `show_writable_log_candidates` | `bash ./linux-first-pass.sh --full-helper show_writable_log_candidates` reruns the log candidate checks with longer time limits, no display cap, and the same file, directory, and parent metadata. It reports a nonzero exit if a source scan or the 120-second candidate summary fails or times out. |
| `show_password_policy_clues` | Read noncomment lines of existing `/etc/login.defs`, `/etc/security/pwquality.conf`, `/etc/security/pwhistory.conf`, `/etc/pam.d/common-password`, `/etc/pam.d/system-auth`, and `/etc/pam.d/password-auth`. |
| `show_ad_join_clues` | `realm list` when installed, then `ls -ldb /etc/sssd/sssd.conf /etc/krb5.conf /etc/realmd.conf` for existing files. |
| `show_defense_tools`, `show_common_tools` | Run `command -v` on the tool names shown in the first-pass scope; these probes print one presence row per checked name. |

For the `show_environment` key, this prints each current `name=value` pair on one shell-escaped line, as the first pass does by default. Replace the `printf` with `printf '%q\n' "$name"` for names only.

```bash
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  value=${entry#*=}
  printf '%q=%q\n' "$name" "$value"
done < <(env -0)
```

Read a selected candidate file with the commands in the pentest notes after confirming its path and access. The discovery probes do not print candidate file contents.

## Windows

`windows-first-pass.ps1` uses Windows PowerShell 5.1. With no flags, it prints a read-only host snapshot. File search flags run only the selected searches and skip the host snapshot.

Clone the repository and run the script locally:

```powershell
git clone https://github.com/soloclz/host-first-pass.git
cd host-first-pass
powershell.exe -NoProfile -File .\windows-first-pass.ps1
```

The default snapshot prints every environment variable name and value in the current PowerShell process. It also includes service command lines and scheduled task arguments, which may contain secrets. Save its transcript in restricted engagement evidence. The script writes to stdout and creates no report file.

Run selected file searches with one or more short flags:

```powershell
powershell.exe -NoProfile -File .\windows-first-pass.ps1 -n
powershell.exe -NoProfile -File .\windows-first-pass.ps1 -c -s -p "C:\inetpub\wwwroot"
powershell.exe -NoProfile -File .\windows-first-pass.ps1 -k -p "C:\inetpub\wwwroot" -SearchSeconds 180
```

| Flag | Selected file search |
| --- | --- |
| `-n` | Credential-related filenames: names containing `password`, `passwd`, `passphrase`, `secret`, `credential`, `token`, `note`, `unattend`, or `sysprep`; `.env` variants, selected SSH/key files, registry hive names, and selected credential-store or configuration exports. |
| `-c` | Configuration filenames: `.conf`, `.config`, `.ini`, `.yaml`, `.yml`, `.json`, `.xml`, `.toml`, `.properties`, `config`, and `.env` variants. |
| `-s` | Script and source filenames, including PowerShell, batch/CMD, VBScript, JavaScript, Python, PHP, ASP/ASPX, Java, C#, and related extensions. |
| `-a` | History, backup, log, SQL, database, and archive filenames. |
| `-k` | Case-insensitive credential-like text in readable files smaller than 128 KiB. It prints matching paths, not matching text. UTF-16 files need a BOM; files with NUL bytes after decoding are skipped as binary. |
| `-p PATH` | Use one selected absolute directory on a local fixed or removable drive. Without `-p`, a selected search starts at every ready local fixed-drive root, such as `C:\` and `D:\`. UNC and mapped network paths are excluded. |
| `-FullOutput` | Print every observed match while scanning instead of retaining only a display prefix. The time limit still applies. |
| `-SearchSeconds N` | Set the cooperative time limit for the selected traversal, from 1 to 3600 seconds; default 90. |

The selected categories share one traversal, so combining flags does not walk the same root once per category. Searches include hidden entries, skip nested reparse points, and stay within the selected local roots. `-p` also rejects a start whose ancestor is a reparse point. A filename matching multiple categories appears in each selected category. The script checks the time between entries; a slow directory operation can finish after the stated limit. Use a discovered application directory with `-p` to focus the search. A current directory such as `C:\Windows\System32\inetsrv` identifies IIS tools, not the site's physical path; inspect site or virtual-directory configuration to choose that path.

The default snapshot does not recursively search files or print file contents, Credential Manager secret values, or running-process command lines from `tasklist`. It does print configured service `PathName` and scheduled task action `Execute`/`Arguments`. The selected `-k` search reads eligible files but prints only paths. The environment section uses `[Environment]::GetEnvironmentVariables('Process')`. For a manual check in PowerShell, run `Get-ChildItem Env:`. In CMD, `set` prints `name=value` pairs; bare `set` in PowerShell is an alias for `Set-Variable`.

### Windows checks

| Section | Source | Scope and output |
| --- | --- | --- |
| Identity and token | `whoami /all` | Current process token: user, groups, privileges, and integrity information. Highlights Event Log Readers SID (`S-1-5-32-573`) when present; inspect its attributes and check Security log access separately. |
| Operating system | `Win32_OperatingSystem` via `Get-CimInstance`; `CurrentBuild` and `UBR` in `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Local OS name, version, architecture, base build, and full build when both registry values exist. |
| Host role, local accounts and shares | `Win32_ComputerSystem`, `Win32_UserAccount`, `Win32_Group`, `Win32_Share` | Domain role and join state; local SAM users and groups on non-DC hosts; local share definitions and paths. A DC skips the local SAM inventory. Each query has its own status. |
| Installed OS updates | `Win32_QuickFixEngineering` via `Get-CimInstance` | Every CBS-reported QFE record: `HotFixID`, `InstalledOn`, and record count. `InstalledOn` is shown as returned by PowerShell, without date sorting. |
| UAC policy | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | Raw `EnableLUA` and `ConsentPromptBehaviorAdmin` values. `EnableLUA=1` enables Admin Approval Mode; `ConsentPromptBehaviorAdmin=5` is the default prompt for consent for non-Windows binaries. Compare the policy with the current process token above when assessing elevation. |
| Windows Installer policy | `AlwaysInstallElevated` in `HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer` and `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer` | Reports each value and type. The summary distinguishes both values enabled, HKLM enabled with HKCU not yet enabled, HKLM not enabled, and uncertain registry reads. A missing key or value is reported as `NONE` for that registry read. |
| Running processes | `tasklist /v /fo csv /nh` | Local process PID, image name, session number, and reported account. `N/A` accounts are shown as `(not reported)`; unexpected CSV is reported as `ERROR`. |
| Services and scheduled tasks | `Win32_Service`, `Get-ScheduledTask` | Every returned service name, state, start mode, run account, PID, and configured command; every returned task with principal, state, actions and trigger summaries. Endpoint mapping reuses the service query. A denied query is reported without treating it as an empty inventory. |
| Logon sessions | `quser` | Sessions visible on the local host to the current account, including state and logon time. |
| Kerberos tickets | `klist` | Tickets cached in the current logon session; read the displayed ticket count, principals, and times. |
| Network configuration | `ipconfig /all`, `route print`, `Get-NetNeighbor` (or `arp -a` when unavailable) | Reported interfaces, addresses, DNS, IPv4/IPv6 routes, and up to 100 neighbor entries. `arp -a` covers IPv4 only. |
| Network endpoints | `Get-NetTCPConnection` for `State=Listen` and `State=Established`; `Get-NetUDPEndpoint` | All local TCP listeners and bound UDP endpoints, plus the first 100 established TCP connections with local/remote address, port, and PID. Established connections report total, shown, and not shown counts. |
| Endpoint PID metadata | `Win32_Process`, `Win32_Service` via `Get-CimInstance` | Process name and any reported executable path, plus service names mapped by PID, for endpoint PIDs only. The output counts linked process records and paths returned. |
| Logical drives and top-level names | `Win32_LogicalDisk`, `Get-ChildItem -Force` | Drive type, filesystem, capacity and provider; up to 100 top-level entries per local fixed drive. The directory listing does not recurse into `C:\` or other drive roots. |
| User profile | `Environment.SpecialFolder.UserProfile`, `Get-ChildItem` | Current user profile path, up to 100 top-level names, and up to 100 names, byte lengths, and modification times immediately inside `.ssh`; no file contents or recursion. Each list reports total, shown, and not shown counts. |
| Sticky Notes database | `Environment.SpecialFolder.LocalApplicationData`, `Test-Path` | Checks whether `plum.sqlite` exists at the current user's fixed Sticky Notes package path; prints the path when found, not the notes. |
| PSReadLine history | `Get-PSReadLineOption`, `Get-Item` | Current PowerShell host's history path, save style, and file size/modification time when present; no history content. |
| Credential Manager | `cmdkey /list` | Current user's stored target and account metadata; no stored passwords. |
| Environment | `[Environment]::GetEnvironmentVariables('Process')` | All names and values in the current PowerShell process. Names and values are JSON-escaped so each pair stays on one console line. |

For profile, `.ssh`, fixed-drive top-level, neighbor, and TCP established connection lists, `display: TRUNCATED` means `not shown` rows were counted but omitted from the console. In the same user's PowerShell session, rerun the relevant query to see the full list. These queries produce a new snapshot; network entries may change between runs.

```powershell
$profilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
Get-ChildItem -LiteralPath $profilePath -Force | Sort-Object Name |
    Format-List FullName,Mode,Length,LastWriteTime
$sshPath = Join-Path -Path $profilePath -ChildPath '.ssh'
if (Test-Path -LiteralPath $sshPath -PathType Container) {
    Get-ChildItem -LiteralPath $sshPath -Force | Sort-Object Name |
        Format-List FullName,Mode,Length,LastWriteTime
}
Get-NetTCPConnection -State Established |
    Sort-Object LocalPort,LocalAddress,RemotePort,RemoteAddress,OwningProcess |
    Format-List LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
Get-NetNeighbor | Format-List InterfaceIndex,IPAddress,LinkLayerAddress,State
Get-ChildItem -LiteralPath 'C:\' -Force | Sort-Object Name |
    Format-List FullName,Mode,Length,LastWriteTime
```

The TCP query lists all connection endpoints and PIDs. For a selected PID, inspect `Win32_Process` and `Win32_Service` to recover process path and service name where accessible.

Each optional search reports its exact root, observed `matched` paths, `shown` paths, `undisplayed-observed` paths, access failures, and whether unscanned space remains. Without `-FullOutput`, each category shows at most 500 path lines or 128 KiB of displayed path text; a truncated category prints a command to rerun that category with `-FullOutput`. The rerun still obeys `-SearchSeconds`. `INCOMPLETE` means the traversal reached its time limit or a directory, file metadata, or content read failed; `unscanned=unknown` means no complete inventory exists for that scope. On timeout, the script prints a rerun command with the same categories and root plus a larger `-SearchSeconds`, up to 3600. A search can show `display=COMPLETE` and still be `INCOMPLETE`: the display label covers only the matches observed so far. The final counters include visited directories and files, skipped reparse points, files at least 128 KiB, and binary files skipped by `-k`. A match is a candidate path to inspect, not a confirmed credential.

To retain all observed paths from a focused rerun, redirect output in PowerShell:

```powershell
powershell.exe -NoProfile -File .\windows-first-pass.ps1 -c -s -p "C:\inetpub\wwwroot" -FullOutput -SearchSeconds 300 > .\first-pass-files.txt
```

Each default snapshot probe shows its source, scope, and status. `FOUND` means the probe returned rows or the named path exists. `QUERY_OK` means `cmdkey /list` or `klist` ran successfully; inspect the displayed text to tell whether stored targets or cached tickets are present. `NONE` means the query succeeded with no rows, the user profile path is unavailable, or the `.ssh` directory is absent. `DENIED` means access was refused, `ERROR` means a query failed, `UNAVAILABLE` means its command is missing, and `NOT_RUN` means a dependent query was skipped. An endpoint can disappear between the network and process queries, so a missing process record at query time needs a fresh check. `path=(not reported)` means `Win32_Process.ExecutablePath` returned no value for that process; the current token can see a PID without access to its path. Service names are mapped by PID and do not establish which service in a shared process owns a socket. [Win32_Process](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process) · [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)

For `Elevated MSI policy condition`, `FOUND` means both values are `REG_DWORD 1` for the current user and host; verify the token of any process launched by the MSI. `CANDIDATE` means HKLM is `REG_DWORD 1` while HKCU is known to differ or is absent; the current user can set HKCU to `REG_DWORD 1` and recheck. `NONE` means HKLM is known not to be `REG_DWORD 1`, so changing HKCU alone cannot enable this policy. `DENIED` or `ERROR` means a necessary registry read failed and the policy condition is uncertain.

QFE records are patch leads for a specific CVE. `Win32_QuickFixEngineering` reports CBS updates, not every update source; a KB absent from its rows does not establish that the fix is absent because Windows cumulative updates include earlier fixes. Compare the full build with the relevant Microsoft update history and the CVE conditions. [QFE class](https://learn.microsoft.com/en-us/windows/desktop/CIMWin32Prov/win32-quickfixengineering) · [Cumulative updates](https://learn.microsoft.com/en-us/windows/deployment/update/servicing-stack-updates)

The snapshot is an index of leads. Investigate a specific process, service, store, or path with your normal notes after reviewing the output.

With an IIS application pool identity, `GetFolderPath(UserProfile)` can return no path. The script reports `NONE` for the profile and skips its directory checks. Native queries such as `quser` and `klist` can return a nonzero exit code for this token; read their reported error instead of treating it as an empty result.
