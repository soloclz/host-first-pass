#!/usr/bin/env bash
# Fixed, read-only first pass for a new Linux host. Bash + common GNU Linux tools.
set -u
set -o pipefail
export LC_ALL=C

MAX_LINES=500
MAX_BYTES=131072
SCAN_SECONDS=8
ROOT_METADATA_SECONDS=30
ROOT_CONTENT_SECONDS=90
ROOT_FILE_BYTES=262144
ENV_NAMES_ONLY=0
CURRENT_HOME=${HOME:-}

usage() {
  cat <<'USAGE'
Usage: bash linux-first-pass.sh [--environment-names-only]
Prints a local host snapshot and bounded file candidates to stdout.
USAGE
}

case $# in
  0) ;;
  1)
    case $1 in
      --environment-names-only) ENV_NAMES_ONLY=1 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
    ;;
  *) usage >&2; exit 2 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

safe_line() {
  local line=$1
  line=${line//$'\033'/[ESC]}
  line=${line//$'\r'/ }
  line=${line//$'\t'/  }
  printf '%s' "$line"
}

run_probe() {
  local title=$1 source=$2 scope=$3
  shift 3
  local output rc status detail line total=0 shown=0 bytes limited=0

  if ! have "$1"; then
    printf '[UNAVAILABLE] %s | source: %s | scope: %s | command unavailable: %s\n' \
      "$title" "$source" "$scope" "$1"
    return
  fi

  # Pipefail preserves a short-output query failure. The two heads also bound
  # memory while capturing a noisy process, environment, or find probe.
  output=$("$@" 2>&1 | head -n "$((MAX_LINES + 1))" | head -c "$((MAX_BYTES + 1))")
  rc=$?
  bytes=${#output}
  if (( bytes > MAX_BYTES )); then
    output=${output:0:MAX_BYTES}
    limited=1
  fi
  if [[ -n $output ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      ((total+=1))
    done <<< "$output"
  fi
  if (( total > MAX_LINES )); then limited=1; fi

  if (( limited || rc == 124 || rc == 137 || rc == 141 )); then
    status=INCOMPLETE
  elif (( rc == 0 )); then
    if [[ -n $output ]]; then status=FOUND; else status=NONE; fi
  elif [[ $output == *'a password is required'* || $output == *'a terminal is required'* ]]; then
    status=AUTH_REQUIRED
  elif [[ $output == *'Permission denied'* || $output == *'permission denied'* ||
          $output == *'Operation not permitted'* || $output == *'not allowed to run sudo'* ||
          $output == *'is not in the sudoers file'* ||
          $output == *'You need to be root'* ]]; then
    status=DENIED
  elif (( rc == 127 || rc == 4 )); then
    status=UNAVAILABLE
  else
    status=ERROR
  fi

  detail="exit: $rc"
  if (( limited )); then
    detail="$detail; capture INCOMPLETE: first $MAX_LINES lines or $MAX_BYTES bytes; remainder unknown"
  elif (( rc == 124 || rc == 137 )); then
    detail="$detail; scan stopped at the stated time limit; query partial"
  elif (( rc == 141 )); then
    detail="$detail; producer stopped before completion"
  fi
  printf '[%s] %s | source: %s | scope: %s | %s\n' \
    "$status" "$title" "$source" "$scope" "$detail"

  if [[ -n $output ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      if (( shown < MAX_LINES )); then
        printf '  %s\n' "$(safe_line "$line")"
        ((shown+=1))
      fi
    done <<< "$output"
  fi
  if [[ $status == INCOMPLETE ]]; then
    printf '  ... partial result; see README manual follow-up examples and the selected topic in pentest notes\n'
  fi
}

section() { printf '\n=== %s ===\n' "$1"; }

show_path() { printf '%q\n' "${PATH-}"; }

show_environment() {
  if ! have env || ! env -0 >/dev/null 2>&1; then
    printf 'env -0 is unavailable\n' >&2
    return 127
  fi
  local entry name value
  while IFS= read -r -d '' entry; do
    name=${entry%%=*}
    if (( ENV_NAMES_ONLY )); then
      printf '%q\n' "$name" || return 141
    else
      value=${entry#*=}
      printf '%q=%q\n' "$name" "$value" || return 141
    fi
  done < <(env -0)
}

show_passwd_accounts() {
  awk -F: '
    {
      if ($2 == "x") state = "shadow";
      else if ($2 == "") state = "empty";
      else if ($2 ~ /^[!*]/) state = "locked-or-disabled";
      else state = "inspect-field";
      printf "%s uid=%s gid=%s home=%s shell=%s password-field=%s\n",
        $1, $3, $4, $6, $7, state
    }
  ' /etc/passwd
}

show_groups() {
  awk -F: '{ printf "%s gid=%s members=%s\n", $1, $3, $4 }' /etc/group
}

show_resolver() {
  awk '$1 == "nameserver" || $1 == "search" || $1 == "domain" { print }' /etc/resolv.conf
}

show_fstab() {
  awk '
    NF && $1 !~ /^#/ {
      marker = (tolower($4) ~ /(password|credentials|username|user=|pass=)/) \
        ? "credential-option-candidate" : "-"
      printf "source=%s target=%s type=%s options=%s\n", $1, $2, $3, marker
    }
  ' /etc/fstab
}

scan_paths() {
  local root=$1 depth=$2 kind=$3
  if [[ ! -d $root ]]; then
    printf 'root absent: %s\n' "$root" >&2
    return 4
  fi
  if ! have find || ! have timeout; then
    printf 'find or timeout unavailable\n' >&2
    return 127
  fi
  case $kind in
    hidden)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -name '.*' \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    temp)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    all-files)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -type f \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    config-names)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -type f \
        \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini' \
           -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json' \
           -o -name '.env' -o -name 'config' -o -name 'credentials' \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    config-content)
      if ! have grep; then
        printf 'grep unavailable\n' >&2
        return 127
      fi
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -type f -size -1024k -readable \
        \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini' \
           -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json' \
           -o -name '.env' -o -name 'config' -o -name 'credentials' \) \
        -exec sh -c '
          pattern=$1
          shift
          failed=0
          for path do
            grep -IilE "$pattern" -- "$path"
            code=$?
            if [ "$code" -gt 1 ]; then
              printf "grep read error: %s\n" "$path" >&2
              failed=1
            fi
          done
          exit "$failed"
        ' sh 'pass(word|wd)?|secret|token|credential|api[_-]?key|private[_-]?key' '{}' +
      ;;
    writable-dirs)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -type d -writable -executable \
        -printf '%p | uid=%U gid=%G mode=%m\n'
      ;;
    writable-files)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -type f -writable \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    suid-sgid)
      timeout "${SCAN_SECONDS}s" find "$root" -xdev -maxdepth "$depth" \
        -mindepth 1 -type f \( -perm -4000 -o -perm -2000 \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    *)
      printf 'unknown scan kind: %s\n' "$kind" >&2
      return 2
      ;;
  esac
}

scan_root() {
  local kind=$1 seconds=$ROOT_METADATA_SECONDS
  if ! have find || ! have timeout; then
    printf 'find or timeout unavailable\n' >&2
    return 127
  fi
  case $kind in
    credential-content)
      if ! have grep; then
        printf 'grep unavailable\n' >&2
        return 127
      fi
      seconds=$ROOT_CONTENT_SECONDS
      # -size with c is byte-accurate; -readable limits the content query to
      # files this identity can open. GNU find still reports denied directories.
      timeout -k 2s "${seconds}s" find / -xdev -ignore_readdir_race \
        -type f -size "-${ROOT_FILE_BYTES}c" -readable \
        -exec sh -c '
          grep -IilE "pass(word|wd)?|secret|token|credential|api[_-]?key|private[_-]?key" -- "$@"
          code=$?
          [ "$code" -eq 0 ] || [ "$code" -eq 1 ]
        ' sh '{}' +
      ;;
    shell-scripts)
      timeout -k 2s "${seconds}s" find / -xdev -ignore_readdir_race \
        -mindepth 1 -type f \
        \( -iname '*.sh' -o -iname '*.bash' -o -iname '*.zsh' -o -iname '*.ksh' \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    other-scripts)
      timeout -k 2s "${seconds}s" find / -xdev -ignore_readdir_race \
        -mindepth 1 -type f \
        \( -iname '*.py' -o -iname '*.pl' -o -iname '*.rb' \
           -o -iname '*.php' -o -iname '*.lua' -o -iname '*.js' \
           -o -iname '*.ps1' \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    candidate-names)
      timeout -k 2s "${seconds}s" find / -xdev -ignore_readdir_race \
        -mindepth 1 -type f \
        \( -iname '*password*' -o -iname '*secret*' \
           -o -iname '*credential*' -o -iname '*token*' -o -iname '*note*' \
           -o -iname '*.env' -o -iname '*.bak' -o -iname '*.old' \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    writable)
      timeout -k 2s "${seconds}s" find / -xdev -ignore_readdir_race \
        -mindepth 1 \
        \( \( -type d -writable -executable \) -o \( -type f -writable \) \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    suid-sgid)
      timeout -k 2s "${seconds}s" find / -xdev -ignore_readdir_race \
        -mindepth 1 -type f \( -perm -4000 -o -perm -2000 \) \
        -printf '%p | uid=%U gid=%G mode=%m size=%s\n'
      ;;
    *)
      printf 'unknown root scan kind: %s\n' "$kind" >&2
      return 2
      ;;
  esac
}

show_defense_tools() {
  local tool path
  for tool in nft iptables fail2ban-client snort; do
    if have "$tool"; then
      path=$(command -v "$tool")
      printf '%s present path=%s\n' "$tool" "$path"
    else
      printf '%s absent\n' "$tool"
    fi
  done
}

show_dpkg_packages() {
  if ! have dpkg-query || ! have awk; then
    printf 'dpkg-query or awk unavailable\n' >&2
    return 127
  fi
  dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' |
    awk -F '\t' 'substr($1, 2, 1) == "i" { print }'
}

show_apk_packages() {
  if ! have apk; then
    printf 'apk unavailable\n' >&2
    return 127
  fi
  local version major
  version=$(apk --version 2>&1) || {
    printf '%s\n' "$version" >&2
    return 2
  }
  if [[ $version =~ apk-tools[[:space:]]+([0-9]+)\. ]]; then
    major=${BASH_REMATCH[1]}
    if (( major >= 3 )); then
      apk list --installed --manifest '*'
    else
      apk info -v
    fi
  else
    printf 'unrecognized apk version: %s\n' "$version" >&2
    return 2
  fi
}

show_current_ssh() {
  [[ -n ${HOME:-} && -d ${HOME:-}/.ssh ]] || return 0
  ls -la -- "$HOME/.ssh"
}

show_history_paths() {
  [[ -n ${HOME:-} ]] || return 0
  local path failed=0
  for path in "$HOME/.bash_history" "$HOME/.zsh_history" \
              "$HOME/.local/share/fish/fish_history"; do
    if [[ -e $path || -L $path ]]; then
      ls -ld -- "$path" || failed=1
    fi
  done
  return "$failed"
}

show_cron_paths() {
  local path failed=0
  for path in /etc/cron* /var/spool/cron /var/spool/cron/crontabs; do
    if [[ -e $path || -L $path ]]; then
      ls -ld -- "$path" || failed=1
    fi
  done
  return "$failed"
}

scan_capabilities() {
  if ! have getcap || ! have timeout; then
    printf 'getcap or timeout unavailable\n' >&2
    return 127
  fi
  local root
  local -a roots=()
  for root in /usr/bin /usr/sbin /usr/local/bin /opt /srv /app; do
    [[ -d $root ]] && roots+=("$root")
  done
  if (( ${#roots[@]} == 0 )); then
    printf 'no capability scan roots exist\n' >&2
    return 4
  fi
  timeout "${SCAN_SECONDS}s" getcap -r "${roots[@]}"
}

printf 'Linux first pass\n'
printf 'Time: %s | Host: %s | Identity: %s\n' \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unavailable)" \
  "$(hostname 2>/dev/null || printf unavailable)" \
  "$(id -un 2>/dev/null || printf unavailable)"
printf 'Scope: local Linux host, current identity, root filesystem starting at /, and named bounded file roots.\n'
printf 'Named find scans: max depth 2-4, one filesystem per root, %ss per scan. Capture cap per probe: %d lines or %d bytes.\n' \
  "$SCAN_SECONDS" "$MAX_LINES" "$MAX_BYTES"
printf 'Root find scans: / on one filesystem, %ss metadata or %ss content per scan; content files < %d bytes.\n' \
  "$ROOT_METADATA_SECONDS" "$ROOT_CONTENT_SECONDS" "$ROOT_FILE_BYTES"
if (( ENV_NAMES_ONLY )); then
  printf 'Environment: names only from this script process.\n'
else
  printf 'Environment: names and values from this script process (shell-escaped); output may contain secrets.\n'
fi

section 'Identity, OS and runtime'
run_probe 'Current identity' 'id' 'current process credentials' id
run_probe 'Host name' 'hostname' 'local host' hostname
run_probe 'OS release' '/etc/os-release' 'local OS release file' cat /etc/os-release
run_probe 'Kernel and architecture' 'uname -a' 'running kernel' uname -a
run_probe 'CPU' 'lscpu' 'local CPU inventory' lscpu
run_probe 'PATH' 'script process PATH' 'current script process' show_path
run_probe 'Environment' 'env -0' 'current script process; all exported pairs' show_environment
run_probe 'Valid login shells' '/etc/shells' 'local shell list' cat /etc/shells
run_probe 'Debian installed packages' 'dpkg-query -W' 'local dpkg database; installed rows' show_dpkg_packages
run_probe 'RPM installed packages' 'rpm -qa' 'local RPM database' \
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{EPOCH}\n'
run_probe 'Arch installed packages' 'pacman -Q' 'local pacman database' pacman -Q
run_probe 'Alpine installed packages' 'apk v2 info -v / v3 list --installed --manifest' \
  'local apk database; command selected by apk-tools major version' show_apk_packages
run_probe 'Sudo rules' 'sudo -n -l' 'current identity; no password prompt' env LC_ALL=C sudo -n -l

section 'Processes and local defenses'
run_probe 'Running processes' 'ps -eo user,pid,ppid,lstart,cmd --forest -ww' \
  'local visible process owners, PIDs, parents, start times and command lines' \
  ps -eo user,pid,ppid,lstart,cmd --forest -ww
run_probe 'Login sessions' 'who -u' 'visible utmp login sessions' who -u
run_probe 'TTY activity' 'w' 'visible utmp users and current commands' w
run_probe 'Systemd login sessions' 'loginctl list-sessions' \
  'sessions visible through systemd-logind if available' \
  loginctl list-sessions --no-pager
run_probe 'Running services' 'systemctl list-units' \
  'active systemd service units if systemd is available' \
  systemctl list-units --type=service --state=running --no-legend --no-pager
run_probe 'SELinux state' 'getenforce' 'local SELinux mode if tool is installed' getenforce
run_probe 'AppArmor state' 'aa-status' 'local AppArmor status if tool is installed' aa-status
run_probe 'UFW state' 'ufw status' 'local firewall status if tool is installed' ufw status
run_probe 'Other defense tools' 'command -v' \
  'nft, iptables, fail2ban-client, snort command presence only' show_defense_tools
run_probe 'Systemd timers' 'systemctl list-timers --all' \
  'local systemd timer units if systemd is available' \
  systemctl list-timers --all --no-legend --no-pager
run_probe 'Cron path metadata' 'ls -ld /etc/cron*' \
  'known local cron paths; names and metadata only' show_cron_paths

section 'Container and namespace context'
run_probe 'PID 1 cgroup' '/proc/1/cgroup' 'PID 1 in current PID namespace' cat /proc/1/cgroup
run_probe 'PID 1 and script namespace links' '/proc/1/ns and /proc/self/ns' \
  'namespace links visible in current procfs' ls -l /proc/1/ns /proc/self/ns
run_probe 'Root mount' 'findmnt -T /' 'filesystem containing / in current mount namespace' findmnt -T /

section 'Accounts and home directories'
run_probe 'Local passwd accounts' '/etc/passwd (selected fields)' \
  'local passwd file; hash values suppressed; NSS users may be elsewhere' show_passwd_accounts
run_probe 'Local groups' '/etc/group (selected fields)' \
  'local group file; NSS groups may be elsewhere' show_groups
run_probe 'Home root' 'ls -la /home' 'top level of /home' ls -la /home
if [[ -n ${HOME:-} && -d ${HOME:-} ]]; then
  run_probe 'Current home' 'ls -la' "top level of $HOME" ls -la "$HOME"
  run_probe 'Current .ssh' 'ls -la' "$HOME/.ssh top level; no file contents" show_current_ssh
  run_probe 'History paths' 'ls -ld' "$HOME shell history metadata; no contents" show_history_paths
else
  printf '[UNAVAILABLE] Current home, .ssh and history | source: HOME | scope: current script process | HOME unset or not a directory\n'
fi

section 'Network'
run_probe 'Interfaces and addresses' 'ip address show' 'local network interfaces' ip address show
run_probe 'Routes' 'ip route show' 'current network namespace routes' ip route show
run_probe 'Neighbor cache' 'ip neigh show' 'current network namespace cache' ip neigh show
run_probe 'TCP listeners and UDP endpoints' 'ss -lntup' \
  'current network namespace; process metadata visible to current user' ss -lntup
run_probe 'Resolver' '/etc/resolv.conf (selected directives)' \
  'nameserver/search/domain directives only' show_resolver

section 'Storage and mounts'
run_probe 'Block devices' 'lsblk' 'local block devices and mount points' \
  lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT
run_probe 'Current mounts' 'findmnt' 'current mount namespace; target/source/type only' \
  findmnt -rno TARGET,SOURCE,FSTYPE
run_probe 'Filesystem capacity' 'df -h' 'mounted filesystems' df -h
run_probe 'Static mount entries' '/etc/fstab (selected fields)' \
  'noncomment fstab entries; options values suppressed' show_fstab
run_probe 'Printers' 'lpstat -p -d' 'local printer status if tool is installed' lpstat -p -d

section 'Interesting file candidates'
run_probe 'Shell script candidates from /' 'find / -xdev -type f (shell script extensions)' \
  "/ on root filesystem; .sh/.bash/.zsh/.ksh paths and metadata; ${ROOT_METADATA_SECONDS}s" \
  scan_root shell-scripts
run_probe 'Other script candidates from /' 'find / -xdev -type f (script extensions)' \
  "/ on root filesystem; .py/.pl/.rb/.php/.lua/.js/.ps1 paths and metadata; ${ROOT_METADATA_SECONDS}s" \
  scan_root other-scripts
run_probe 'Credential-like text markers from /' 'find / -xdev + grep -IilE' \
  "/ on root filesystem; readable regular files <${ROOT_FILE_BYTES} bytes; paths only; ${ROOT_CONTENT_SECONDS}s" \
  scan_root credential-content
run_probe 'Interesting filenames from /' 'find / -xdev -type f' \
  "/ on root filesystem; selected name patterns; metadata only; ${ROOT_METADATA_SECONDS}s" \
  scan_root candidate-names
if [[ -n ${HOME:-} && -d ${HOME:-} ]]; then
  run_probe 'Hidden paths in current home' 'find hidden names' \
    "$HOME; depth<=4; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$HOME" 4 hidden
else
  printf '[UNAVAILABLE] Current-home file scans | source: HOME | scope: current script process | HOME unset or not a directory\n'
fi
run_probe 'Hidden paths in /home' 'find hidden names' \
  "/home; depth<=2; same filesystem; ${SCAN_SECONDS}s" \
  scan_paths /home 2 hidden
if [[ -n ${HOME:-} && -d ${HOME:-} ]]; then
  run_probe 'All files in current home' 'find -type f' \
    "$HOME; depth<=4; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$HOME" 4 all-files
fi
run_probe 'All files in /home' 'find -type f' \
  "/home; depth<=3; same filesystem; ${SCAN_SECONDS}s" \
  scan_paths /home 3 all-files
for root in /tmp /var/tmp /dev/shm; do
  run_probe "Entries in $root" 'find file metadata' \
    "$root; depth<=2; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" 2 temp
done

for root in "${HOME:-}" /etc /opt /srv /app /usr/local/etc /var/www /var/backups /var/lib /mnt /media /root; do
  [[ -n $root ]] || continue
  depth=3
  [[ -n $CURRENT_HOME && $root == "$CURRENT_HOME" ]] && depth=4
  run_probe "Config-like filenames in $root" 'find config-like names' \
    "$root; depth<=$depth; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" "$depth" config-names
  run_probe "Config content markers in $root" 'find + grep -IilE' \
    "$root; depth<=$depth; readable config-like files <1 MiB; paths only; ${SCAN_SECONDS}s" \
    scan_paths "$root" "$depth" config-content
done

section 'Writable and privilege-related file candidates'
run_probe 'Writable paths from /' 'find / -xdev -writable' \
  "/ on root filesystem; writable regular files and writable traversable directories; ${ROOT_METADATA_SECONDS}s" \
  scan_root writable
run_probe 'SUID or SGID files from /' 'find / -xdev -perm -4000/-2000' \
  "/ on root filesystem; regular files; ${ROOT_METADATA_SECONDS}s" \
  scan_root suid-sgid
for root in "${HOME:-}" /etc /usr/local /opt /srv /app /var/www /var/backups /tmp /var/tmp /dev/shm /mnt /media /root; do
  [[ -n $root ]] || continue
  depth=3
  [[ -n $CURRENT_HOME && $root == "$CURRENT_HOME" ]] && depth=4
  run_probe "Writable directories in $root" 'find -type d -writable -executable' \
    "$root; depth<=$depth; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" "$depth" writable-dirs
  run_probe "Writable files in $root" 'find -type f -writable' \
    "$root; depth<=$depth; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" "$depth" writable-files
done
for root in /bin /sbin /usr/bin /usr/sbin /usr/local /opt /srv /app /var/www /mnt /media; do
  run_probe "SUID or SGID files in $root" 'find -perm -4000/-2000' \
    "$root; depth<=3; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" 3 suid-sgid
done
run_probe 'File capabilities' 'getcap -r' \
  "existing /usr/bin /usr/sbin /usr/local/bin /opt /srv /app; ${SCAN_SECONDS}s" \
  scan_capabilities

printf '\nCandidate paths are leads. Read a selected file to verify content and context. For an INCOMPLETE probe, use the focused commands in README and the selected topic in pentest notes.\n'
