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

The default output can contain secrets from environment values, process and cron command lines, policy directives, paths, account names, and mount metadata. Save a transcript only in restricted engagement evidence. File discovery probes print candidate paths and metadata; content-marker probes read selected small files and print matching paths only. The system cron and password-policy probes print selected noncomment lines from their source files.

### Linux checks

| Section | Source and scope |
| --- | --- |
| Identity, OS and runtime | Current `id`, hostname, `/etc/os-release`, `uname -a`, `lscpu`, PATH, all exported environment pairs, `/etc/shells`, noninteractive `sudo -n -l`, and `sudo -V`. The sudo rules query never prompts for a password. Installed-package probes use `dpkg-query`, `rpm`, `pacman`, or `apk` when present; apk-tools v3 uses `apk list --installed --manifest '*'`, while v2 uses `apk info -v`. `command -v` reports the presence and path of common transfer, interpreter, build, discovery, and trace tools. |
| Processes and local defenses | Visible process owner/PID/parent/start time/full command line via `ps`, running systemd services, installed service/socket unit files (including disabled or static units), loaded socket units, and timers when available. System cron schedule lines, current-user crontab, cron directory entry metadata, and optional SELinux/AppArmor/UFW status are separate probes. The script reports whether `nft`, `iptables`, `fail2ban-client`, and `snort` commands exist; command presence is only a lead, not proof that a defense is active. Process and cron command lines may contain secrets. |
| Login sessions and namespace | `who -u`, `w`, `loginctl list-sessions`, `lastlog`, and `last -a` for current and past login records; `/proc/1/cgroup`, `/proc/1/ns`, `/proc/self/ns`, and `findmnt -T /` for the current process/mount context. A cgroup or namespace path alone does not prove where the host boundary lies. |
| Accounts and homes | Selected `/etc/passwd` fields (account, UID/GID, home, shell, password-field state), selected `/etc/group` fields, common `/etc/login.defs` and PAM password-policy directives, `realm list` when available, and metadata for `/etc/sssd/sssd.conf`, `/etc/krb5.conf`, and `/etc/realmd.conf`. Policy lines and join configuration paths are clues; inspect the active configuration before deciding whether a policy is enforced or the host is domain-joined. Also lists `/home` and current home top levels, current `.ssh` top level, and current shell-history path metadata. Password hashes, SSH key contents, and history contents are not printed. These account lists are local files; NSS can resolve additional users or groups. |
| Network | `ip address`, route and neighbor cache, `ss` TCP listeners/UDP endpoints, all TCP states (including established connections), Unix sockets, `/etc/hosts`, and resolver nameserver/search/domain directives. |
| Storage | `lsblk`, `findmnt` target/source/type, `df -h` with an eight-second limit, and noncomment `/etc/fstab` entries with option values suppressed. `df` can wait on an unresponsive remote mount; its `INCOMPLETE` result leaves those capacities unknown. The fstab summary flags a credential-like option for follow-up. Optional printer status comes from `lpstat`. |
| Interesting files | Independent root-filesystem sweeps start at `/`: common shell and other script extensions, interesting and config-like filenames (including `.xml`), special `*_hist`/`*_history` filenames, backup/log/SQL/database filenames, and regular files modified within the last seven days are listed with metadata. Recent modification is one snapshot; determine a recurring pattern by checking a selected path again later. Readable regular files smaller than 256 KiB are checked for general credential-like text markers, with matching paths only. Executable candidates are listed in selected application, home, and temporary roots at depth four; this is a path inventory, not proof that a file is compiled. Hidden names in current home (depth 4) and `/home` (depth 2); all regular files in current home (depth 4) and `/home` (depth 3), including ordinary and hidden names; entries in `/tmp`, `/var/tmp`, `/dev/shm` and file metadata in `/var/mail`, `/var/spool` (depth 2); config-like filenames and content markers in current home, `/etc`, `/opt`, `/srv`, `/app`, `/usr/local/etc`, `/var/www`, `/var/backups`, `/var/lib`, `/run`, `/mnt`, `/media`, `/root` (depth 3, current home depth 4). |
| Writable and privilege-related files | A `/` sweep reports writable regular files, writable traversable directories, and SUID/SGID regular files on the root filesystem. Focused scans also check writable directories (write and execute access) and writable files in current home, `/etc`, `/usr/local`, `/opt`, `/srv`, `/app`, `/var/www`, `/var/backups`, the three temporary roots, `/mnt`, `/media`, and `/root` (depth 3, current home depth 4); SUID/SGID files in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local`, `/opt`, `/srv`, `/app`, `/var/www`, `/mnt`, `/media` (depth 3); optional `getcap -r` on selected application and binary roots. |

The PATH probe prints the raw value, the script's physical current directory, and every entry in search order, including empty entries and duplicates. Each entry shows the path checked and whether the current identity can write to and enter that directory. An empty entry or `.` checks the current directory; other relative entries use the script's current directory. `not-confirmed` means the shell could not confirm the path exists, which can also occur when access is blocked. These checks describe this script process; a sudo rule, service, or scheduled job can use another PATH and current directory.

The `/` sweeps use GNU `find -xdev`, so they stay on the filesystem that contains `/`. They do not descend into a separate `/home`, `/run`, `/mnt`, or other child mount; the named scans cover selected mount roots, including `/run` config paths. Review `findmnt` and run a focused check on any other relevant mount. Root metadata sweeps have a 30-second limit each. The shell script probe lists `.sh`, `.bash`, `.zsh`, and `.ksh`; the other script probe lists `.py`, `.pl`, `.rb`, `.php`, `.lua`, `.js`, and `.ps1`. Script probes are separate from other filename candidates so their displayed rows have separate limits. Scripts without these extensions can still appear in home listings or process, service, and job paths. The root content sweep has a 90-second limit, reads regular files smaller than 262,144 bytes that the current identity can open, and skips binary-looking files through `grep -I`. It checks case-insensitive password, passwd, secret, token, credential, API key, and private key markers in files including scripts. A match is a path to inspect, not the file content. Filename inventories use GNU `find -ls` so embedded newlines in names are escaped and each match stays on one output row. Content matches use Bash `%q` to escape path names.

Named file discovery uses GNU `find -H` to follow a symlink used as a starting root, `-xdev` to stay on that root's filesystem, the displayed depth limit, and GNU `timeout` with an eight-second limit per scan. The optional `getcap -r` check is recursive within its named roots and bounded by the same time limit. Named config-content scans only read readable, config-like regular files smaller than 1 MiB. The `/var/www` config scan can surface a `*config*.php` file even when the general `.php` script list exceeds its display limit. The `/var/mail` and `/var/spool` scans list file metadata only. The `/run` scan includes paths such as `/run/tmpfiles.d`, `/run/NetworkManager`, and `/run/systemd/resolve` when present. Hidden-name and home inventories do not depend on content markers. Optional commands and absent roots are reported as `UNAVAILABLE`. A `DENIED` scan can include paths found before access failed.

Each status line names its source and scope; queries that ran also show elapsed whole seconds for the query and capture. `FOUND` means output lines were returned, not that a vulnerability or secret was confirmed. `NONE` means the query completed within its stated scope with no output lines. `AUTH_REQUIRED` means `sudo -n -l` needs authentication. `DENIED` is an access failure, `ERROR` is another query failure, and `UNAVAILABLE` means a command or root is absent. `INCOMPLETE` means the producer hit its time limit or ended before completion. The count unit is **stdout lines**: a `find -ls` path inventory emits one line per matching path, whereas a command such as `lastlog` also emits a heading. For a successful scan, `matched`, `shown`, and `undisplayed` are exact counts of stdout lines within its stated scope. `display=TRUNCATED` means only the first 500 whole lines or at most 128 KiB are shown; it does not stop the scan. If the scan times out or fails, `observed`, `shown`, and `undisplayed-observed` count lines produced before failure, and `unscanned=unknown` means the unseen search space cannot be counted. Stderr is counted separately as `stderr-lines`, `stderr-shown`, and `stderr-undisplayed`; the first eight whole lines or 8 KiB are shown. The printed full-output command saves all rerun stderr in `$HOME/first-pass-full.err`. The script drains stdout, keeps only the display prefix in a restricted temporary directory, then removes that directory on exit. Full counting can take longer than the old display-stop behavior, up to the stated time limit for each bounded scan. `LC_ALL=C` makes status checks for command errors consistent. These limits apply to each probe, not to the total transcript.

### Linux full-output follow-up

If a probe has undisplayed lines or an incomplete scan, it prints a rerun command that saves stdout and stderr separately, prints the exit code, then opens the saved stdout in `less`. A timed probe gets a longer 30-second rerun limit; if it also times out, its unscanned range remains unknown. For a stalled `df -h`, `df -h -l` checks local filesystems separately while you investigate the remote mount. Helper probes use `--full-helper NAME` when the script is saved as a file; this runs only that helper without the display cap. When the script was streamed through stdin, save a copy first or use the matching helper key below. A full query can still fail on inaccessible directories; keep its stderr and exit code rather than treating its output count as a complete inventory.

For a root key, run the corresponding query from this table. All queries start at `/`, stay on its filesystem, and use the exact predicate in the first pass. Substitute the query for `find ...` in this save-and-review pattern when the output is large:

```bash
umask 077
find ... > "$HOME/first-pass-full.txt" 2> "$HOME/first-pass-full.err"
printf 'find exit=%s\n' "$?"
wc -l "$HOME/first-pass-full.txt"
less -S "$HOME/first-pass-full.txt"
```

| Printed root key | Full query |
| --- | --- |
| `root:shell-scripts` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -iname '*.sh' -o -iname '*.bash' -o -iname '*.zsh' -o -iname '*.ksh' \) -ls` |
| `root:other-scripts` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -iname '*.py' -o -iname '*.pl' -o -iname '*.rb' -o -iname '*.php' -o -iname '*.lua' -o -iname '*.js' -o -iname '*.ps1' \) -ls` |
| `root:candidate-names` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -iname '*password*' -o -iname '*secret*' -o -iname '*credential*' -o -iname '*token*' -o -iname '*note*' -o -iname '*.env' \) -ls` |
| `root:config-names` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini' -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json' -o -iname '*.xml' -o -name 'config' \) -ls` |
| `root:history-names` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -iname '*_hist' -o -iname '*_history' \) -ls` |
| `root:backup-log-names` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -iname '*backup*' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.log' -o -iname '*.log.*' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.tgz' -o -iname '*.tar.gz' -o -iname '*.zip' -o -iname '*.db' -o -iname '*.sqlite' -o -iname '*.sqlite3' \) -ls` |
| `root:recent-files` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f -mtime -7 -ls` |
| `root:writable` | `find / -xdev -ignore_readdir_race -mindepth 1 \( \( -type d -writable -executable \) -o \( -type f -writable \) \) -ls` |
| `root:suid-sgid` | `find / -xdev -ignore_readdir_race -mindepth 1 -type f \( -perm -4000 -o -perm -2000 \) -ls` |

For `root:credential-content`, use the same size, access, binary, and marker predicates. The query prints shell-escaped matching paths and reports grep read errors to stderr:

```bash
find / -xdev -ignore_readdir_race -type f -size -262144c -readable \
  -exec bash -c '
    pattern=$1
    shift
    grep -IilEZ "$pattern" -- "$@" |
      while IFS= read -r -d "" path; do
        printf "%q\n" "$path" || exit 141
      done
    result=("${PIPESTATUS[@]}")
    if (( result[1] != 0 )); then exit "${result[1]}"; fi
    if (( result[0] > 1 )); then exit 1; fi
    exit 0
  ' bash 'pass(word|wd)?|secret|token|credential|api[_-]?key|private[_-]?key' '{}' +
```

For `path:KIND`, set `ROOT` and `DEPTH` to the printed parameters. The first pass follows a symlink starting root, tests only paths at depth one or deeper, and does not cross filesystems from that root. `find -ls` escapes unusual characters so each item stays on one row:

```bash
ROOT=/etc
DEPTH=3
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -name '.*' -ls                 # path:hidden
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -ls                           # path:temp
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -type f -ls                   # path:all-files
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -type d -writable -executable -ls # path:writable-dirs
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -type f -writable -ls         # path:writable-files
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -type f \( -perm -4000 -o -perm -2000 \) -ls # path:suid-sgid
```

For mail and spool metadata, set `ROOT` to `/var/mail` or `/var/spool` and `DEPTH=2`, then use `path:all-files`.

For `path:config-names`, use this query. For `path:config-content`, use the next query; it limits readable files to less than 1 MiB and prints shell-escaped paths that contain the general marker pattern.

```bash
find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -type f \
  \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini' \
     -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json' \
     -o -iname '*.xml' -o -iname '*config*.php' \
     -o -name '.env' -o -name 'config' -o -name 'credentials' \) -ls

find -H "$ROOT" -xdev -maxdepth "$DEPTH" -mindepth 1 -type f -size -1048576c -readable \
  \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini' \
     -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json' \
     -o -iname '*.xml' -o -iname '*config*.php' \
     -o -name '.env' -o -name 'config' -o -name 'credentials' \) \
  -exec bash -c '
    pattern=$1
    shift
    grep -IilEZ "$pattern" -- "$@" |
      while IFS= read -r -d "" path; do
        printf "%q\n" "$path" || exit 141
      done
    result=("${PIPESTATUS[@]}")
    if (( result[1] != 0 )); then exit "${result[1]}"; fi
    if (( result[0] > 1 )); then exit 1; fi
    exit 0
  ' bash 'pass(word|wd)?|secret|token|credential|api[_-]?key|private[_-]?key' '{}' +
```

The remaining helper keys use these full commands:

| Printed key | Full command or source |
| --- | --- |
| `scan_application_executables` | `find /usr/local/bin /usr/local/sbin /opt /srv /app /home /tmp /var/tmp /dev/shm -xdev -maxdepth 4 -type f -executable -ls` (remove any absent start paths, as the script does). |
| `scan_capabilities` | `getcap -r /usr/bin /usr/sbin /usr/local/bin /opt /srv /app` (remove absent roots). |
| `show_environment` | Recheck the current process environment with `env -0` and the Bash NUL loop below. A later shell has its own current environment, which can differ from the earlier script process. |
| `show_path` | `bash ./linux-first-pass.sh --full-helper show_path` prints the uncapped PATH entries and directory checks for the rerun process. |
| `show_passwd_accounts`, `show_groups` | `cat /etc/passwd`, `cat /etc/group` respectively; the script's summaries omit raw password fields. |
| `show_resolver`, `show_fstab` | `cat /etc/resolv.conf`, `cat /etc/fstab` respectively; the script selects resolver directives and suppresses fstab option values. |
| `show_dpkg_packages` | The output prints a complete uncapped `dpkg-query` and `awk` rerun command. It selects rows whose package status indicates installed. |
| `show_apk_packages` | `apk info -v` on apk-tools v2 or `apk list --installed --manifest '*'` on v3. |
| `show_current_ssh`, `show_history_paths` | `ls -la "$HOME/.ssh"`; `ls -ld "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"` (omit absent files). |
| `show_cron_paths`, `show_cron_directory_entries` | `ls -ld /etc/cron* /var/spool/cron /var/spool/cron/crontabs`; `find` each existing cron directory at `-mindepth 1 -maxdepth 1 -ls`. |
| `show_system_cron_entries`, `show_current_crontab` | Read noncomment lines of `/etc/crontab` and each readable file in `/etc/cron.d`; `crontab -l` respectively. |
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
| Network endpoints | `Get-NetTCPConnection` for `State=Listen` and `State=Established`; `Get-NetUDPEndpoint` | All local TCP listeners and bound UDP endpoints, plus the first 100 established TCP connections with local/remote address, port, and PID. Established connections report total, shown, and not shown counts. |
| Endpoint PID metadata | `Win32_Process`, `Win32_Service` via `Get-CimInstance` | Process name and any reported executable path, plus service names mapped by PID, for endpoint PIDs only. The output counts linked process records and paths returned. |
| User profile | `Environment.SpecialFolder.UserProfile`, `Get-ChildItem` | Current user profile path, up to 100 top-level names, and up to 100 names, byte lengths, and modification times immediately inside `.ssh`; no file contents or recursion. Each list reports total, shown, and not shown counts. |
| Sticky Notes database | `Environment.SpecialFolder.LocalApplicationData`, `Test-Path` | Checks whether `plum.sqlite` exists at the current user's fixed Sticky Notes package path; prints the path when found, not the notes. |
| Credential Manager | `cmdkey /list` | Current user's stored target and account metadata; no stored passwords. |
| Environment | `[Environment]::GetEnvironmentVariables('Process')` | All names and values in the current PowerShell process by default; all names without values with `-EnvironmentNamesOnly`. Names and values are JSON-escaped so each pair stays on one console line. |

For profile, `.ssh`, and TCP established connection lists, `display: TRUNCATED` means `not shown` rows were counted but omitted from the console. In the same user's PowerShell session, rerun the relevant query to see the full list. These queries produce a new snapshot; network connections may change between runs.

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
```

The TCP query lists all connection endpoints and PIDs. For a selected PID, inspect `Win32_Process` and `Win32_Service` to recover process path and service name where accessible.

Each probe shows its source, scope, and status. `FOUND` means the probe returned rows or the named path exists. `QUERY_OK` means `cmdkey /list` or `klist` ran successfully; inspect the displayed text to tell whether stored targets or cached tickets are present. `NONE` means the query succeeded with no rows, the user profile path is unavailable, or the `.ssh` directory is absent. `DENIED` means access was refused, `ERROR` means a query failed, `UNAVAILABLE` means its command is missing, and `NOT_RUN` means a dependent query was skipped. An endpoint can disappear between the network and process queries, so a missing process record at query time needs a fresh check. `path=(not reported)` means `Win32_Process.ExecutablePath` returned no value for that process; the current token can see a PID without access to its path. Service names are mapped by PID and do not establish which service in a shared process owns a socket. [Win32_Process](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process) · [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)

For `Elevated MSI policy condition`, `FOUND` means both values are `REG_DWORD 1` for the current user and host; verify the token of any process launched by the MSI. `CANDIDATE` means HKLM is `REG_DWORD 1` while HKCU is known to differ or is absent; the current user can set HKCU to `REG_DWORD 1` and recheck. `NONE` means HKLM is known not to be `REG_DWORD 1`, so changing HKCU alone cannot enable this policy. `DENIED` or `ERROR` means a necessary registry read failed and the policy condition is uncertain.

QFE records are patch leads for a specific CVE. `Win32_QuickFixEngineering` reports CBS updates, not every update source; a KB absent from its rows does not establish that the fix is absent because Windows cumulative updates include earlier fixes. Compare the full build with the relevant Microsoft update history and the CVE conditions. [QFE class](https://learn.microsoft.com/en-us/windows/desktop/CIMWin32Prov/win32-quickfixengineering) · [Cumulative updates](https://learn.microsoft.com/en-us/windows/deployment/update/servicing-stack-updates)

The snapshot is an index of leads. Investigate a specific process, service, store, or path with your normal notes after reviewing the output.

With an IIS application pool identity, `GetFolderPath(UserProfile)` can return no path. The script reports `NONE` for the profile and skips its directory checks. Native queries such as `quser` and `klist` can return a nonzero exit code for this token; read their reported error instead of treating it as an empty result.
