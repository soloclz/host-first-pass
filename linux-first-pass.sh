#!/usr/bin/env bash
# Fixed, read-only first pass for a new Linux host. Bash + common GNU Linux tools.
set -u
set -o pipefail
export LC_ALL=C

MAX_LINES=500
MAX_BYTES=131072
MAX_STDERR_LINES=8
MAX_STDERR_BYTES=8192
SCAN_SECONDS=8
ROOT_METADATA_SECONDS=30
ROOT_CONTENT_SECONDS=90
ROOT_FILE_BYTES=262144
CONTENT_MARKERS='pass(word|wd)?|secret|token|credential|api[_-]?key|private[_-]?key'
CONTENT_GREP_BATCH='
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
'
ENV_NAMES_ONLY=0
FULL_HELPER=
CURRENT_HOME=${HOME:-}
WRITABLE_ROOTS=("${HOME:-}" /etc /usr/local /opt /srv /app /var/www /var/backups
  /var/log /tmp /var/tmp /dev/shm /mnt /media /root)
LOG_CANDIDATE_ARGS=( -type f \( -iname '*.log' -o -iname '*.log.*' -o -path '/var/log/*' \) )
umask 077
PROBE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/linux-first-pass.XXXXXXXX") || {
  printf 'Cannot create temporary probe buffer\n' >&2
  exit 1
}
trap 'rm -rf -- "$PROBE_DIR"' EXIT

usage() {
  cat <<'USAGE'
Usage: bash linux-first-pass.sh [--environment-names-only]
       bash linux-first-pass.sh --full-helper NAME
       bash linux-first-pass.sh --full-helper show_environment --environment-names-only
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
  2)
    if [[ $1 == --full-helper ]]; then
      case $2 in
        show_path|show_environment|show_passwd_accounts|show_groups|show_resolver|show_fstab|show_nfs_export_configs|\
        show_defense_tools|show_common_tools|show_system_cron_entries|\
        show_cron_directory_entries|show_current_crontab|show_password_policy_clues|\
        show_ad_join_clues|show_dpkg_packages|show_running_kernel_package|show_user_namespace_limits|show_pkexec|show_apk_packages|show_current_ssh|\
        show_history_paths|show_cron_paths|show_group_sockets|\
        show_disk_device_access|show_logrotate_configs|show_writable_log_candidates) FULL_HELPER=$2 ;;
        *) usage >&2; exit 2 ;;
      esac
    else
      usage >&2
      exit 2
    fi
    ;;
  3)
    if [[ $1 == --full-helper && $2 == show_environment && $3 == --environment-names-only ]]; then
      FULL_HELPER=show_environment
      ENV_NAMES_ONLY=1
    else
      usage >&2
      exit 2
    fi
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
  local rc capture_rc stderr_capture_rc status detail line matched=0 shown=0 bytes=0
  local started=$SECONDS elapsed
  local stderr_total=0 stderr_shown=0 stderr_bytes=0
  local -a pipeline_status=()

  if ! have "$1"; then
    printf '[UNAVAILABLE] %s | source: %s | scope: %s | command unavailable: %s\n' \
      "$title" "$source" "$scope" "$1"
    return
  fi

  : > "$PROBE_DIR/stdout"
  : > "$PROBE_DIR/stderr"
  rm -f -- "$PROBE_DIR/meta"
  # Drain the producer even after the display limit. Only complete records
  # enter the bounded buffer; stderr never uses an output row.
  "$@" 2>"$PROBE_DIR/stderr" | awk \
    -v line_limit="$MAX_LINES" -v byte_limit="$MAX_BYTES" \
    -v display="$PROBE_DIR/stdout" -v meta="$PROBE_DIR/meta" '
      {
        matched++
        row_bytes = length($0) + 1
        if (!truncated && shown < line_limit && bytes + row_bytes <= byte_limit) {
          print $0 >> display
          shown++
          bytes += row_bytes
        } else {
          truncated = 1
        }
      }
      END {
        printf "%d %d %d\n", matched, shown, bytes > meta
        close(display)
        close(meta)
      }
    '
  pipeline_status=("${PIPESTATUS[@]}")
  rc=${pipeline_status[0]}
  capture_rc=${pipeline_status[1]}
  if [[ -f $PROBE_DIR/meta ]]; then
    read -r matched shown bytes < "$PROBE_DIR/meta"
  fi
  : > "$PROBE_DIR/stderr-display"
  rm -f -- "$PROBE_DIR/stderr-meta"
  awk -v line_limit="$MAX_STDERR_LINES" -v byte_limit="$MAX_STDERR_BYTES" \
    -v display="$PROBE_DIR/stderr-display" -v meta="$PROBE_DIR/stderr-meta" '
      {
        total++
        row_bytes = length($0) + 1
        if (!truncated && shown < line_limit && bytes + row_bytes <= byte_limit) {
          print $0 >> display
          shown++
          bytes += row_bytes
        } else {
          truncated = 1
        }
      }
      END {
        printf "%d %d %d\n", total, shown, bytes > meta
        close(display)
        close(meta)
      }
    ' "$PROBE_DIR/stderr"
  stderr_capture_rc=$?
  if [[ -f $PROBE_DIR/stderr-meta ]]; then
    read -r stderr_total stderr_shown stderr_bytes < "$PROBE_DIR/stderr-meta"
  fi
  elapsed=$((SECONDS - started))

  if (( capture_rc != 0 || stderr_capture_rc != 0 )); then
    status=ERROR
  elif (( rc == 124 || rc == 137 || rc == 141 )); then
    status=INCOMPLETE
  elif (( rc == 0 )); then
    if (( matched > 0 )); then status=FOUND; else status=NONE; fi
  elif grep -qiE 'a password is required|a terminal is required' "$PROBE_DIR/stderr"; then
    status=AUTH_REQUIRED
  elif grep -qiE 'permission denied|operation not permitted|not allowed to run sudo|is not in the sudoers file|you need to be root' "$PROBE_DIR/stderr"; then
    status=DENIED
  elif (( rc == 127 || rc == 4 )); then
    status=UNAVAILABLE
  else
    status=ERROR
  fi

  if [[ $status != FOUND && $status != NONE ]] && (( rc != 4 )); then
    if [[ $1 == scan_root && ${2:-} == writable ]] ||
       [[ $1 == scan_paths && ${4:-} == writable-files ]]; then
      printf '%s\n' "$status" >> "$PROBE_DIR/writable-source-status"
    fi
  fi

  detail="exit=$rc; elapsed=${elapsed}s; count-unit=stdout-lines"
  if (( capture_rc != 0 )); then
    detail="$detail; capture exit=$capture_rc"
  fi
  if (( stderr_capture_rc != 0 )); then
    detail="$detail; stderr capture exit=$stderr_capture_rc"
  fi
  if (( rc == 0 && capture_rc == 0 && stderr_capture_rc == 0 )); then
    detail="$detail; matched=$matched shown=$shown undisplayed=$((matched - shown))"
  else
    detail="$detail; observed=$matched shown=$shown undisplayed-observed=$((matched - shown)); unscanned=unknown"
  fi
  if (( matched > shown )); then
    detail="$detail; display=TRUNCATED (${MAX_LINES} lines or ${MAX_BYTES} bytes per probe)"
  fi
  if (( stderr_total > 0 )); then
    detail="$detail; stderr-lines=$stderr_total stderr-shown=$stderr_shown stderr-undisplayed=$((stderr_total - stderr_shown))"
  fi
  if (( rc == 124 || rc == 137 )); then
    detail="$detail; time limit reached"
  elif (( rc == 141 )); then
    detail="$detail; producer ended before completion"
  fi
  printf '[%s] %s | source: %s | scope: %s | %s\n' \
    "$status" "$title" "$source" "$scope" "$detail"

  while IFS= read -r line || [[ -n $line ]]; do
    printf '  %s\n' "$(safe_line "$line")"
  done < "$PROBE_DIR/stdout"
  if (( stderr_total > 0 )); then
    printf '  stderr (first %d lines or %d bytes):\n' "$MAX_STDERR_LINES" "$MAX_STDERR_BYTES"
    while IFS= read -r line || [[ -n $line ]]; do
      printf '    %s\n' "$(safe_line "$line")"
    done < "$PROBE_DIR/stderr-display"
    if (( stderr_total > stderr_shown )); then
      printf '    ... %d stderr lines undisplayed\n' "$((stderr_total - stderr_shown))"
    fi
  fi
  if (( matched > shown || rc != 0 || capture_rc != 0 || stderr_capture_rc != 0 || stderr_total > stderr_shown )); then
    show_followup "$@"
  fi
}

show_followup() {
  case $1 in
    scan_root)
      if build_root_scan "$2"; then
        printf '  full-output command: umask 077; LC_ALL=C '
        printf '%q ' find "${ROOT_SCAN_ARGS[@]}"
        print_save_tail
      else
        printf '  full-output: README.md Linux full-output follow-up key=root:%s\n' "$2"
      fi
      ;;
    scan_paths)
      if build_path_scan "$2" "$3" "$4"; then
        printf '  full-output command: umask 077; LC_ALL=C '
        printf '%q ' find "${PATH_SCAN_ARGS[@]}"
        print_save_tail
      else
        printf '  full-output: README.md Linux full-output follow-up key=path:%s root=%q depth=%q\n' \
          "$4" "$2" "$3"
      fi
      ;;
    scan_capabilities)
      if build_capability_roots; then
        printf '  full-output command: umask 077; LC_ALL=C '
        printf '%q ' getcap -r "${CAPABILITY_ROOTS[@]}"
        print_save_tail
      else
        printf '  full-output: README.md Linux full-output follow-up key=scan_capabilities\n'
      fi
      ;;
    scan_application_executables)
      if build_application_roots; then
        printf '  full-output command: umask 077; LC_ALL=C '
        printf '%q ' find "${APPLICATION_ROOTS[@]}" -xdev -maxdepth 4 -type f -executable -ls
        print_save_tail
      else
        printf '  full-output: README.md Linux full-output follow-up key=scan_application_executables\n'
      fi
      ;;
    show_dpkg_packages)
      printf '  full-output command: umask 077; set -o pipefail; { '
      printf '%q ' dpkg-query -W '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n'
      printf '| '
      printf '%q ' awk -F '\t' 'substr($1, 2, 1) == "i" { print }'
      printf '; } '
      print_save_tail
      ;;
    show_*)
      if [[ -f ${BASH_SOURCE[0]} ]]; then
        printf '  full-output command: umask 077; '
        printf '%q ' bash "${BASH_SOURCE[0]}" --full-helper "$1"
        if [[ $1 == show_environment ]] && (( ENV_NAMES_ONLY )); then
          printf '%q ' --environment-names-only
        fi
        print_save_tail
      else
        printf '  full-output: save linux-first-pass.sh, then run bash SCRIPT_PATH --full-helper %q\n' "$1"
        printf '  save rerun stdout/stderr separately; see README.md Linux full-output follow-up key=%s\n' "$1"
      fi
      ;;
    timeout)
      shift 2
      printf '  longer bounded rerun command: umask 077; '
      printf '%q ' timeout 30s "$@"
      print_save_tail
      ;;
    *)
      printf '  full-output command: umask 077; '
      printf '%q ' "$@"
      print_save_tail
      ;;
  esac
}

print_save_tail() {
  printf '%s\n' '> "$HOME/first-pass-full.txt" 2> "$HOME/first-pass-full.err"; rc=$?; printf "exit=%s\n" "$rc"; wc -l "$HOME/first-pass-full.txt"; less -S "$HOME/first-pass-full.txt"'
}

section() { printf '\n=== %s ===\n' "$1"; }

show_path() {
  local remaining=${PATH-} token checked kind exists directory writable enterable cwd
  local index=0 more

  printf 'raw=%q\n' "${PATH-}" || return 141
  cwd=$(builtin pwd -P 2>/dev/null) || cwd=
  printf 'cwd=%q\n' "${cwd:-<unavailable>}" || return 141
  while :; do
    if [[ $remaining == *:* ]]; then
      token=${remaining%%:*}
      remaining=${remaining#*:}
      more=1
    else
      token=$remaining
      more=0
    fi
    ((index += 1))

    case $token in
      '') kind=current-directory-empty-entry; checked=${cwd:-.} ;;
      .) kind=current-directory; checked=${cwd:-.} ;;
      /*) kind=absolute; checked=$token ;;
      *)
        kind=relative
        checked=$token
        if [[ -n $cwd ]]; then checked=${cwd%/}/$token; fi
        ;;
    esac

    exists=not-confirmed
    directory=not-confirmed
    writable=not-confirmed
    enterable=not-confirmed
    if [[ -e $checked ]]; then
      exists=yes
      directory=no
      writable=n/a
      enterable=n/a
      if [[ -d $checked ]]; then
        directory=yes
        writable=no
        enterable=no
        [[ -w $checked ]] && writable=yes
        [[ -x $checked ]] && enterable=yes
      fi
    fi
    printf 'entry=%d token=%q checked=%q kind=%s exists=%s directory=%s writable=%s enterable=%s\n' \
      "$index" "$token" "$checked" "$kind" "$exists" "$directory" "$writable" "$enterable" || return 141

    (( more )) || break
  done
}

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

in_group() {
  local names
  names=$(id -nG) || return 1
  [[ " $names " == *" $1 "* ]]
}

show_group_sockets() {
  if ! have stat; then
    printf 'stat unavailable\n' >&2
    return 127
  fi
  local group path prior writable metadata duplicate failed=0
  local -a seen=()
  for group in docker lxd; do
    in_group "$group" || continue
    if [[ $group == docker ]]; then
      set -- /var/run/docker.sock /run/docker.sock
    else
      set -- /var/snap/lxd/common/lxd/unix.socket /var/lib/lxd/unix.socket
    fi
    for path; do
      metadata=$(stat -Lc 'mode=%A owner=%U group=%G' -- "$path" 2>&1) || {
        if [[ $metadata != *'No such file or directory'* ]]; then
          printf '%s\n' "$metadata" >&2
          failed=1
        fi
        continue
      }
      [[ -S $path ]] || continue
      duplicate=0
      for prior in "${seen[@]}"; do
        [[ $path -ef $prior ]] && { duplicate=1; break; }
      done
      (( duplicate )) && continue
      seen+=("$path")
      writable=no
      [[ -w $path ]] && writable=yes
      printf 'group=%s path=%q writable=%s %s\n' \
        "$group" "$path" "$writable" "$metadata" || return 141
    done
  done
  return "$failed"
}

probe_docker_images() {
  local socket prior duplicate socket_label found=0
  local -a candidates=(/var/run/docker.sock /run/docker.sock)
  local -a seen=()

  if [[ -n ${XDG_RUNTIME_DIR:-} ]]; then
    candidates+=("${XDG_RUNTIME_DIR%/}/docker.sock")
  fi
  candidates+=("/run/user/${EUID}/docker.sock")

  if ! have docker; then
    printf '[UNAVAILABLE] Docker local images | source: docker image ls --all | scope: known local Unix sockets | docker command unavailable\n'
    return
  fi
  if ! have timeout; then
    printf '[UNAVAILABLE] Docker local images | source: docker image ls --all | scope: known local Unix sockets | timeout command unavailable\n'
    return
  fi

  for socket in "${candidates[@]}"; do
    [[ -S $socket ]] || continue
    duplicate=0
    for prior in "${seen[@]}"; do
      [[ $socket -ef $prior ]] && { duplicate=1; break; }
    done
    (( duplicate )) && continue
    seen+=("$socket")
    found=1
    printf -v socket_label '%q' "$socket"
    if [[ ! -w $socket ]]; then
      printf '[DENIED] Docker local images | source: docker image ls --all | scope: socket=%s | socket not writable by current identity\n' "$socket_label"
      continue
    fi
    run_probe 'Docker local images' 'docker image ls --all --no-trunc --format' \
      "socket=$socket_label; local daemon image cache including untagged images; no pull; ${SCAN_SECONDS}s" \
      timeout "${SCAN_SECONDS}s" docker -H "unix://$socket" image ls --all --no-trunc \
        --format 'repository={{.Repository}} tag={{.Tag}} id={{.ID}} size={{.Size}}'
  done

  if (( ! found )); then
    printf '[UNAVAILABLE] Docker local images | source: docker image ls --all | scope: known local Unix sockets | no Unix socket visible at checked paths\n'
  fi
}

show_disk_device_access() {
  in_group disk || return 0
  if ! have find || ! have stat || ! have timeout; then
    printf 'find, stat or timeout unavailable\n' >&2
    return 127
  fi
  local seconds=$SCAN_SECONDS
  [[ $FULL_HELPER == show_disk_device_access ]] && seconds=30
  timeout "${seconds}s" find /dev -xdev -type b -exec bash -c '
    failed=0
    for path; do
      readable=no; writable=no
      [[ -r $path ]] && readable=yes
      [[ -w $path ]] && writable=yes
      metadata=$(stat -Lc "mode=%A owner=%U group=%G" -- "$path") || {
        failed=1
        continue
      }
      printf "path=%q readable=%s writable=%s %s\n" \
        "$path" "$readable" "$writable" "$metadata" || exit 141
    done
    exit "$failed"
  ' bash '{}' +
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

show_nfs_export_configs() {
  local path metadata readable found=0 failed=0
  if ! have stat || ! have awk; then return 127; fi
  if [[ -d /etc/exports.d && ( ! -r /etc/exports.d || ! -x /etc/exports.d ) ]]; then
    printf 'Permission denied: /etc/exports.d\n' >&2
    failed=1
  fi
  for path in /etc/exports /etc/exports.d/*.exports; do
    [[ -e $path || -L $path ]] || continue
    [[ -f $path || -L $path ]] || continue
    found=1
    readable=no
    [[ -r $path ]] && readable=yes
    metadata=$(stat -Lc 'mode=%A uid=%u gid=%g' -- "$path" 2>/dev/null) || {
      printf 'Metadata unavailable: %s\n' "$path" >&2
      failed=1
      continue
    }
    printf 'path=%q readable=%s %s\n' "$path" "$readable" "$metadata" || return 141
    if [[ $readable == yes ]]; then
      awk 'NF && $1 !~ /^#/ { print "  " $0 }' "$path" || failed=1
    else
      printf 'Permission denied: %s\n' "$path" >&2
      failed=1
    fi
  done
  if (( !found && !failed )); then return 4; fi
  return "$failed"
}

PATH_SCAN_ARGS=()

build_path_scan() {
  local root=$1 depth=$2 kind=$3
  PATH_SCAN_ARGS=(-H "$root" -xdev -maxdepth "$depth" -mindepth 1)
  case $kind in
    hidden)
      PATH_SCAN_ARGS+=(-name '.*' -ls)
      ;;
    temp)
      PATH_SCAN_ARGS+=(-ls)
      ;;
    all-files)
      PATH_SCAN_ARGS+=(-type f -ls)
      ;;
    readable-files)
      PATH_SCAN_ARGS+=(-type f -readable -ls)
      ;;
    config-names)
      PATH_SCAN_ARGS+=(-type f
        \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini'
           -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json'
           -o -iname '*.xml' -o -iname '*config*.php'
           -o -name '.env' -o -name 'config' -o -name 'credentials' \) -ls)
      ;;
    config-content)
      if ! have grep; then
        printf 'grep unavailable\n' >&2
        return 127
      fi
      PATH_SCAN_ARGS+=(-type f -size -1048576c -readable
        \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini'
           -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json'
           -o -iname '*.xml' -o -iname '*config*.php'
           -o -name '.env' -o -name 'config' -o -name 'credentials' \)
        -exec bash -c "$CONTENT_GREP_BATCH" bash "$CONTENT_MARKERS" '{}' +)
      ;;
    writable-dirs)
      PATH_SCAN_ARGS+=(-type d -writable -executable -ls)
      ;;
    writable-files)
      PATH_SCAN_ARGS+=(-type f -writable -ls)
      ;;
    suid-sgid)
      PATH_SCAN_ARGS+=(-type f \( -perm -4000 -o -perm -2000 \) -ls)
      ;;
    *)
      printf 'unknown scan kind: %s\n' "$kind" >&2
      return 2
      ;;
  esac
}

scan_paths() {
  local root=$1 depth=$2 kind=$3
  local capture
  if [[ ! -d $root ]]; then
    printf 'root absent: %s\n' "$root" >&2
    return 4
  fi
  if ! have find || ! have timeout; then
    printf 'find or timeout unavailable\n' >&2
    return 127
  fi
  build_path_scan "$root" "$depth" "$kind" || return $?
  if [[ $kind == writable-files ]]; then
    capture=$(mktemp "$PROBE_DIR/writable-logs.XXXXXXXX") || return 1
    timeout "${SCAN_SECONDS}s" find "${PATH_SCAN_ARGS[@]}" \
      "${LOG_CANDIDATE_ARGS[@]}" -fprint0 "$capture"
  else
    timeout "${SCAN_SECONDS}s" find "${PATH_SCAN_ARGS[@]}"
  fi
}

ROOT_SCAN_ARGS=()
ROOT_SCAN_SECONDS=$ROOT_METADATA_SECONDS

build_root_scan() {
  local kind=$1
  ROOT_SCAN_ARGS=(/ -xdev -ignore_readdir_race)
  ROOT_SCAN_SECONDS=$ROOT_METADATA_SECONDS
  case $kind in
    credential-content)
      if ! have grep; then
        printf 'grep unavailable\n' >&2
        return 127
      fi
      ROOT_SCAN_SECONDS=$ROOT_CONTENT_SECONDS
      ROOT_SCAN_ARGS+=(-type f -size "-${ROOT_FILE_BYTES}c" -readable
        -exec bash -c "$CONTENT_GREP_BATCH" bash "$CONTENT_MARKERS" '{}' +)
      ;;
    shell-scripts)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -iname '*.sh' -o -iname '*.bash' -o -iname '*.zsh' -o -iname '*.ksh' \) -ls)
      ;;
    other-scripts)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -iname '*.py' -o -iname '*.pl' -o -iname '*.rb'
           -o -iname '*.php' -o -iname '*.lua' -o -iname '*.js'
           -o -iname '*.ps1' \) -ls)
      ;;
    candidate-names)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -iname '*password*' -o -iname '*secret*'
           -o -iname '*credential*' -o -iname '*token*' -o -iname '*note*'
           -o -iname '*.env' \) -ls)
      ;;
    config-names)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -iname '*.conf' -o -iname '*.config' -o -iname '*.ini'
           -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.json'
           -o -iname '*.xml'
           -o -name 'config' \) -ls)
      ;;
    history-names)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -iname '*_hist' -o -iname '*_history' \) -ls)
      ;;
    backup-log-names)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -iname '*backup*' -o -iname '*.bak' -o -iname '*.old'
           -o -iname '*.log' -o -iname '*.log.*' -o -iname '*.sql'
           -o -iname '*.sql.gz' -o -iname '*.tgz'
           -o -iname '*.tar.gz' -o -iname '*.zip' -o -iname '*.db'
           -o -iname '*.sqlite' -o -iname '*.sqlite3' \) -ls)
      ;;
    recent-files)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f -mtime -7 -ls)
      ;;
    writable)
      ROOT_SCAN_ARGS+=(-mindepth 1
        \( \( -type d -writable -executable \) -o \( -type f -writable \) \) -ls)
      ;;
    suid-sgid)
      ROOT_SCAN_ARGS+=(-mindepth 1 -type f
        \( -perm -4000 -o -perm -2000 \) -ls)
      ;;
    *)
      printf 'unknown root scan kind: %s\n' "$kind" >&2
      return 2
      ;;
  esac
}

scan_root() {
  local capture
  if ! have find || ! have timeout; then
    printf 'find or timeout unavailable\n' >&2
    return 127
  fi
  build_root_scan "$1" || return $?
  if [[ $1 == writable ]]; then
    capture=$(mktemp "$PROBE_DIR/writable-logs.XXXXXXXX") || return 1
    timeout -k 2s "${ROOT_SCAN_SECONDS}s" find "${ROOT_SCAN_ARGS[@]}" \
      "${LOG_CANDIDATE_ARGS[@]}" -fprint0 "$capture"
  else
    timeout -k 2s "${ROOT_SCAN_SECONDS}s" find "${ROOT_SCAN_ARGS[@]}"
  fi
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

show_common_tools() {
  local tool path
  for tool in nc ncat netcat socat python3 python2 perl ruby nmap tcpdump \
              gcc cc make curl wget openssl ssh scp rsync jq strace file \
              docker lxc debugfs; do
    if have "$tool"; then
      path=$(command -v "$tool")
      printf '%s present path=%q\n' "$tool" "$path"
    else
      printf '%s absent\n' "$tool"
    fi
  done
}

show_system_cron_entries() {
  local path failed=0
  for path in /etc/crontab /etc/cron.d/*; do
    [[ -f $path ]] || continue
    if [[ -r $path ]]; then
      awk -v label="$path" 'NF && $1 !~ /^#/ {
        printf "%s:%d:%s\n", label, FNR, $0
      }' "$path" || failed=1
    else
      printf 'Permission denied: %s\n' "$path" >&2
      failed=1
    fi
  done
  return "$failed"
}

show_cron_directory_entries() {
  local root found=0 failed=0
  for root in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
              /etc/cron.monthly /etc/cron.d /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d $root ]] || continue
    found=1
    find "$root" -xdev -mindepth 1 -maxdepth 1 -ls || failed=1
  done
  (( found )) || return 4
  return "$failed"
}

show_current_crontab() {
  if ! have crontab; then
    printf 'crontab unavailable\n' >&2
    return 127
  fi
  local rc
  crontab -l 2>"$PROBE_DIR/crontab.stderr"
  rc=$?
  if (( rc == 0 )); then return 0; fi
  if grep -q '^no crontab for ' "$PROBE_DIR/crontab.stderr"; then return 0; fi
  cat "$PROBE_DIR/crontab.stderr" >&2
  return "$rc"
}

show_password_policy_clues() {
  local path failed=0
  for path in /etc/login.defs /etc/security/pwquality.conf \
              /etc/security/pwhistory.conf /etc/pam.d/common-password \
              /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [[ -e $path ]] || continue
    if [[ -r $path ]]; then
      awk 'NF && $1 !~ /^#/ {
        printf "%s:%d:%s\n", FILENAME, FNR, $0
      }' "$path" || failed=1
    else
      printf 'Permission denied: %s\n' "$path" >&2
      failed=1
    fi
  done
  return "$failed"
}

show_ad_join_clues() {
  local path failed=0 realm_rc=0
  if have realm; then
    timeout "${SCAN_SECONDS}s" realm list || realm_rc=$?
  fi
  for path in /etc/sssd/sssd.conf /etc/krb5.conf /etc/realmd.conf; do
    [[ -e $path || -L $path ]] || continue
    ls -ldb -- "$path" || failed=1
  done
  if (( realm_rc == 124 || realm_rc == 137 )); then return "$realm_rc"; fi
  if (( realm_rc != 0 )); then failed=1; fi
  return "$failed"
}

APPLICATION_ROOTS=()
build_application_roots() {
  local root
  APPLICATION_ROOTS=()
  for root in /usr/local/bin /usr/local/sbin /opt /srv /app /home \
              /tmp /var/tmp /dev/shm; do
    [[ -d $root ]] && APPLICATION_ROOTS+=("$root")
  done
  if (( ${#APPLICATION_ROOTS[@]} == 0 )); then
    printf 'no application scan roots exist\n' >&2
    return 4
  fi
}

scan_application_executables() {
  if ! have find || ! have timeout; then
    printf 'find or timeout unavailable\n' >&2
    return 127
  fi
  build_application_roots || return $?
  timeout -k 2s "${ROOT_METADATA_SECONDS}s" find "${APPLICATION_ROOTS[@]}" \
    -xdev -maxdepth 4 -type f -executable -ls
}

show_dpkg_packages() {
  if ! have dpkg-query || ! have awk; then
    printf 'dpkg-query or awk unavailable\n' >&2
    return 127
  fi
  dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' |
    awk -F '\t' 'substr($1, 2, 1) == "i" { print }'
}

show_running_kernel_package() {
  if ! have uname || ! have dpkg-query; then
    printf 'uname or dpkg-query unavailable\n' >&2
    return 127
  fi
  local release package row status name version query_rc found=0
  release=$(uname -r) || return $?
  printf 'running_kernel=%s\n' "$release"
  for package in "linux-image-$release" "linux-image-unsigned-$release"; do
    row=$(dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' \
      -- "$package" 2>"$PROBE_DIR/kernel-dpkg-error")
    query_rc=$?
    if (( query_rc != 0 )); then
      if (( query_rc == 1 )) &&
         grep -q '^dpkg-query: no packages found matching ' "$PROBE_DIR/kernel-dpkg-error"; then
        continue
      fi
      cat "$PROBE_DIR/kernel-dpkg-error" >&2
      return "$query_rc"
    fi
    IFS=$'\t' read -r status name version <<< "$row"
    if [[ ${status:1:1} == i ]]; then
      printf 'installed_image_package=%s version=%s\n' "$name" "$version"
      found=1
    fi
  done
  if (( ! found )); then
    printf 'installed_image_package=not found in local dpkg database for running kernel\n'
  fi
}

show_user_namespace_limits() {
  local path value failed=0
  for path in /proc/sys/kernel/unprivileged_userns_clone /proc/sys/user/max_user_namespaces; do
    if [[ ! -e $path ]]; then
      printf 'path=%s status=absent\n' "$path" || return 141
    elif IFS= read -r value < "$path"; then
      printf 'path=%s status=readable value=%q\n' "$path" "$value" || return 141
    else
      printf 'path=%s status=read-failed\n' "$path" || return 141
      failed=1
    fi
  done
  return "$failed"
}

show_pkexec() {
  local path=/usr/bin/pkexec resolved metadata owner_row package row status name version rc
  [[ -e $path || -L $path ]] || return 0
  if ! have readlink || ! have stat; then
    printf 'readlink or stat unavailable\n' >&2
    return 127
  fi
  resolved=$(readlink -f -- "$path") || return $?
  metadata=$(stat -Lc 'mode=%A(%a) owner=%U:%G uid=%u gid=%g' -- "$path") || return $?
  printf 'path=%q resolved=%q %s\n' "$path" "$resolved" "$metadata"

  if ! have dpkg-query; then
    printf 'owning_package=unavailable (dpkg-query unavailable)\n'
    return 0
  fi
  owner_row=$(dpkg-query -S -- "$resolved" 2>"$PROBE_DIR/pkexec-dpkg-error")
  rc=$?
  if (( rc != 0 )); then
    if (( rc == 1 )) &&
       grep -q '^dpkg-query: no path found matching pattern ' "$PROBE_DIR/pkexec-dpkg-error"; then
      printf 'owning_package=not found in dpkg database\n'
      return 0
    fi
    cat "$PROBE_DIR/pkexec-dpkg-error" >&2
    return "$rc"
  fi
  if [[ $owner_row != *': '* || $owner_row == *$'\n'* ]]; then
    printf 'unexpected dpkg ownership result: %s\n' "$owner_row" >&2
    return 2
  fi
  package=${owner_row%%: *}
  if [[ -z $package || $package == *,* ]]; then
    printf 'ambiguous dpkg ownership result: %s\n' "$owner_row" >&2
    return 2
  fi
  row=$(dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' \
    -- "$package") || return $?
  IFS=$'\t' read -r status name version <<< "$row"
  if [[ ${status:1:1} != i || -z $name || -z $version ]]; then
    printf 'owning package is not installed in dpkg database: %s\n' "$package" >&2
    return 2
  fi
  printf 'owning_package=%s version=%s\n' "$name" "$version"
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

show_logrotate_configs() {
  local path readable metadata failed=0
  if ! have stat; then return 127; fi
  if [[ -d /etc/logrotate.d && ( ! -r /etc/logrotate.d || ! -x /etc/logrotate.d ) ]]; then
    printf 'Permission denied: /etc/logrotate.d\n' >&2
    failed=1
  fi
  for path in /etc/logrotate.conf /etc/logrotate.d/*; do
    [[ -e $path || -L $path ]] || continue
    [[ -f $path || -L $path ]] || continue
    readable=no
    [[ -r $path ]] && readable=yes
    metadata=$(stat -Lc 'mode=%A uid=%u gid=%g' -- "$path" 2>/dev/null) || {
      printf 'Metadata unavailable: %s\n' "$path" >&2
      failed=1
      continue
    }
    printf 'path=%q readable=%s %s\n' "$path" "$readable" "$metadata" || return 141
  done
  return "$failed"
}

capture_full_writable_log_paths() {
  local root depth capture scan_rc rc=0
  if ! have find || ! have timeout; then return 127; fi

  capture=$(mktemp "$PROBE_DIR/writable-logs.XXXXXXXX") || return 1
  scan_rc=0
  timeout -k 2s 90s find / -xdev -ignore_readdir_race -mindepth 1 \
    -type f -writable "${LOG_CANDIDATE_ARGS[@]}" -fprint0 "$capture" || scan_rc=$?
  (( scan_rc == 0 )) || rc=$scan_rc

  for root in "${WRITABLE_ROOTS[@]}"; do
    [[ -n $root && -d $root ]] || continue
    depth=3
    [[ -n $CURRENT_HOME && $root == "$CURRENT_HOME" ]] && depth=4
    [[ $root == /var/log ]] && depth=5
    capture=$(mktemp "$PROBE_DIR/writable-logs.XXXXXXXX") || return 1
    scan_rc=0
    timeout -k 2s 30s find -H "$root" -xdev -maxdepth "$depth" -mindepth 1 \
      -type f -writable "${LOG_CANDIDATE_ARGS[@]}" -fprint0 "$capture" || scan_rc=$?
    if (( scan_rc != 0 && rc == 0 )); then rc=$scan_rc; fi
  done
  return "$rc"
}

show_writable_log_candidates() {
  local capture path directory parent file_meta directory_meta parent_meta sorted
  local file_writable directory_writable directory_enterable parent_writable parent_enterable
  local scan_rc=0 started limit=$SCAN_SECONDS cached_directory= cached_parent=
  local -a captures=() sort_status=()
  if ! have stat || ! have sort; then return 127; fi
  if [[ $FULL_HELPER == show_writable_log_candidates ]]; then
    limit=120
    capture_full_writable_log_paths || scan_rc=$?
  fi
  for capture in "$PROBE_DIR"/writable-logs.*; do
    [[ -f $capture ]] && captures+=("$capture")
  done
  if (( ${#captures[@]} == 0 )); then
    if [[ -z $FULL_HELPER && -s $PROBE_DIR/writable-source-status ]]; then
      printf 'One or more source writable scans did not complete; review their status lines.\n' >&2
      if grep -qx INCOMPLETE "$PROBE_DIR/writable-source-status"; then return 124; fi
      if grep -qx DENIED "$PROBE_DIR/writable-source-status"; then
        printf 'Permission denied in a source writable scan.\n' >&2
        return 1
      fi
      return 2
    fi
    return "$scan_rc"
  fi
  sorted=$(mktemp "$PROBE_DIR/writable-logs-sorted.XXXXXXXX") || return 1
  started=$SECONDS
  cat -- "${captures[@]}" | timeout -k 2s "${limit}s" sort -zu > "$sorted"
  sort_status=("${PIPESTATUS[@]}")
  if (( sort_status[0] != 0 )); then return "${sort_status[0]}"; fi
  if (( sort_status[1] != 0 )); then return "${sort_status[1]}"; fi

  while IFS= read -r -d '' path; do
      if (( SECONDS - started >= limit )); then return 124; fi
      file_meta=$(stat -Lc 'mode=%A uid=%u gid=%g' -- "$path" 2>/dev/null) || {
        printf 'path=%q state=missing-or-inaccessible-after-scan\n' "$path" || return 141
        continue
      }
      directory=${path%/*}
      [[ -n $directory ]] || directory=/
      parent=${directory%/*}
      [[ -n $parent ]] || parent=/
      file_writable=no; [[ -w $path ]] && file_writable=yes
      if [[ $directory != "$cached_directory" ]]; then
        directory_meta=$(stat -Lc 'mode=%A uid=%u gid=%g' -- "$directory" 2>/dev/null) || directory_meta=metadata-unavailable
        directory_writable=no; [[ -w $directory ]] && directory_writable=yes
        directory_enterable=no; [[ -x $directory ]] && directory_enterable=yes
        cached_directory=$directory
      fi
      if [[ $parent != "$cached_parent" ]]; then
        parent_meta=$(stat -Lc 'mode=%A uid=%u gid=%g' -- "$parent" 2>/dev/null) || parent_meta=metadata-unavailable
        parent_writable=no; [[ -w $parent ]] && parent_writable=yes
        parent_enterable=no; [[ -x $parent ]] && parent_enterable=yes
        cached_parent=$parent
      fi
      printf 'path=%q file_writable=%s file_%s log_directory=%q directory_writable=%s directory_enterable=%s directory_%s parent=%q parent_writable=%s parent_enterable=%s parent_%s\n' \
        "$path" "$file_writable" "$file_meta" "$directory" "$directory_writable" \
        "$directory_enterable" "$directory_meta" "$parent" "$parent_writable" \
        "$parent_enterable" "$parent_meta" || return 141
  done < "$sorted"
  if [[ -z $FULL_HELPER && -s $PROBE_DIR/writable-source-status ]]; then
    printf 'One or more source writable scans did not complete; review their status lines.\n' >&2
    if grep -qx INCOMPLETE "$PROBE_DIR/writable-source-status"; then return 124; fi
    if grep -qx DENIED "$PROBE_DIR/writable-source-status"; then
      printf 'Permission denied in a source writable scan.\n' >&2
      return 1
    fi
    return 2
  fi
  return "$scan_rc"
}

CAPABILITY_ROOTS=()
build_capability_roots() {
  local root
  CAPABILITY_ROOTS=()
  for root in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /srv /app; do
    [[ -d $root ]] && CAPABILITY_ROOTS+=("$root")
  done
  if (( ${#CAPABILITY_ROOTS[@]} == 0 )); then
    printf 'no capability scan roots exist\n' >&2
    return 4
  fi
}

scan_capabilities() {
  if ! have getcap || ! have timeout; then
    printf 'getcap or timeout unavailable\n' >&2
    return 127
  fi
  build_capability_roots || return $?
  timeout "${SCAN_SECONDS}s" getcap -r "${CAPABILITY_ROOTS[@]}"
}

if [[ -n $FULL_HELPER ]]; then
  "$FULL_HELPER"
  exit $?
fi

printf 'Linux first pass\n'
printf 'Time: %s | Host: %s | Identity: %s\n' \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unavailable)" \
  "$(hostname 2>/dev/null || printf unavailable)" \
  "$(id -un 2>/dev/null || printf unavailable)"
printf 'Scope: local Linux host, current identity, root filesystem starting at /, and named bounded file roots.\n'
printf 'Named find scans: max depth 2-5, one filesystem per root, %ss per scan. Display cap per probe: %d lines or %d bytes.\n' \
  "$SCAN_SECONDS" "$MAX_LINES" "$MAX_BYTES"
printf 'Root find scans: / on one filesystem, %ss metadata or %ss content per scan; content files < %d bytes.\n' \
  "$ROOT_METADATA_SECONDS" "$ROOT_CONTENT_SECONDS" "$ROOT_FILE_BYTES"
if (( ENV_NAMES_ONLY )); then
  printf 'Environment: names only from this script process.\n'
else
  printf 'Environment: names and values from this script process (shell-escaped); output may contain secrets.\n'
fi

section 'Identity and host runtime'
run_probe 'Current identity' 'id' 'current process credentials' id
run_probe 'Host name' 'hostname' 'local host' hostname
run_probe 'OS release' '/etc/os-release' 'local OS release file' cat /etc/os-release
run_probe 'Kernel and architecture' 'uname -a' 'running kernel' uname -a
run_probe 'Running kernel image package' 'uname -r; targeted dpkg-query -W' \
  'running kernel release; installed Debian/Ubuntu image package matching that release' show_running_kernel_package
run_probe 'CPU' 'lscpu' 'local CPU inventory' lscpu
run_probe 'Valid login shells' '/etc/shells' 'local shell list' cat /etc/shells

section 'PATH and environment'
run_probe 'PATH' 'script process PATH and directory checks' \
  'current script process and identity; entries in search order' show_path
run_probe 'Environment' 'env -0' 'current script process; all exported pairs' show_environment

section 'Sudo, packages and tools'
run_probe 'Sudo rules' 'sudo -n -l' 'current identity; no password prompt' env LC_ALL=C sudo -n -l
run_probe 'Sudo version' 'sudo -V' 'local sudo version and plugin information' timeout "${SCAN_SECONDS}s" sudo -V
run_probe 'pkexec mode and package' 'stat -L; targeted dpkg-query -S/-W' \
  '/usr/bin/pkexec if present; resolved file mode/owner and Debian owning package build' show_pkexec
run_probe 'Debian installed packages' 'dpkg-query -W' 'local dpkg database; installed rows' show_dpkg_packages
run_probe 'RPM installed packages' 'rpm -qa' 'local RPM database' \
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{EPOCH}\n'
run_probe 'Arch installed packages' 'pacman -Q' 'local pacman database' pacman -Q
run_probe 'Alpine installed packages' 'apk v2 info -v / v3 list --installed --manifest' \
  'local apk database; command selected by apk-tools major version' show_apk_packages
run_probe 'Common tool presence' 'command -v' \
  'common transfer, interpreter, build, discovery, trace, container and filesystem commands; PATH lookup only' show_common_tools

section 'Accounts and home directories'
run_probe 'Local passwd accounts' '/etc/passwd (selected fields)' \
  'local passwd file; hash values suppressed; NSS users may be elsewhere' show_passwd_accounts
run_probe 'Local groups' '/etc/group (selected fields)' \
  'local group file; NSS groups may be elsewhere' show_groups
run_probe 'Password policy file clues' 'login.defs, security and PAM files' \
  'noncomment lines of common local policy files; effective PAM path requires follow-up' show_password_policy_clues
run_probe 'AD join clues' 'realm list and identity configuration paths' \
  'realm list when installed, plus metadata for sssd.conf, krb5.conf and realmd.conf' show_ad_join_clues
run_probe 'Home root' 'ls -la /home' 'top level of /home' ls -la /home
if [[ -n ${HOME:-} && -d ${HOME:-} ]]; then
  run_probe 'Current home' 'ls -la' "top level of $HOME" ls -la "$HOME"
  run_probe 'Current .ssh' 'ls -la' "$HOME/.ssh top level; no file contents" show_current_ssh
  run_probe 'History paths' 'ls -ld' "$HOME shell history metadata; no contents" show_history_paths
else
  printf '[UNAVAILABLE] Current home, .ssh and history | source: HOME | scope: current script process | HOME unset or not a directory\n'
fi

if in_group adm || in_group docker || in_group lxd || in_group disk; then
  section 'Privileged group resources'
  if in_group adm; then
    run_probe 'adm readable logs' 'find /var/log -xdev -type f -readable -ls' \
      "/var/log; depth<=5; same filesystem; file metadata only; ${SCAN_SECONDS}s" \
      scan_paths /var/log 5 readable-files
  fi
  if in_group docker || in_group lxd; then
    run_probe 'docker/lxd sockets' 'stat known local Unix sockets + test -w' \
      'current identity; /var/run/docker.sock, /run/docker.sock, and common LXD sockets; metadata and writable test only' \
      show_group_sockets
  fi
  if in_group disk; then
    run_probe 'disk block devices' 'find /dev -xdev -type b + test -r/-w + stat' \
      "/dev; current identity; effective readable/writable checks; ${SCAN_SECONDS}s" \
      show_disk_device_access
  fi
fi

section 'Processes and login sessions'
run_probe 'Running processes' 'ps -eo user,pid,ppid,lstart,cmd --forest -ww' \
  'local visible process owners, PIDs, parents, start times and command lines' \
  ps -eo user,pid,ppid,lstart,cmd --forest -ww
run_probe 'Login sessions' 'who -u' 'visible utmp login sessions' who -u
run_probe 'TTY activity' 'w' 'visible utmp users and current commands' w
run_probe 'Systemd login sessions' 'loginctl list-sessions' \
  'sessions visible through systemd-logind if available' \
  loginctl list-sessions --no-pager
run_probe 'Last login per account' 'lastlog' 'local lastlog database; account login timestamps' \
  timeout "${SCAN_SECONDS}s" lastlog
run_probe 'Recent login history' 'last -a' 'local wtmp database; all available records' \
  timeout "${SCAN_SECONDS}s" last -a

section 'Services and local defenses'
run_probe 'Running services' 'systemctl list-units' \
  'active systemd service units if systemd is available' \
  systemctl list-units --type=service --state=running --no-legend --no-pager
run_probe 'Systemd service and socket unit files' 'systemctl list-unit-files' \
  'installed service and socket unit files, including disabled and static states' \
  timeout "${SCAN_SECONDS}s" systemctl list-unit-files --type=service,socket --no-legend --no-pager
run_probe 'Systemd sockets' 'systemctl list-sockets --all' \
  'loaded systemd socket units, active and inactive when systemd is available' \
  timeout "${SCAN_SECONDS}s" systemctl list-sockets --all --no-legend --no-pager
run_probe 'SELinux state' 'getenforce' 'local SELinux mode if tool is installed' getenforce
run_probe 'AppArmor state' 'aa-status' 'local AppArmor status if tool is installed' aa-status
run_probe 'UFW state' 'ufw status' 'local firewall status if tool is installed' ufw status
run_probe 'Other defense tools' 'command -v' \
  'nft, iptables, fail2ban-client, snort command presence only' show_defense_tools

section 'Scheduled jobs and log rotation'
run_probe 'Systemd timers' 'systemctl list-timers --all' \
  'local systemd timer units if systemd is available' \
  systemctl list-timers --all --no-legend --no-pager
run_probe 'Cron path metadata' 'ls -ld /etc/cron*' \
  'known local cron paths; names and metadata only' show_cron_paths
run_probe 'System cron entries' '/etc/crontab and /etc/cron.d' \
  'readable system cron schedule lines; comments omitted' show_system_cron_entries
run_probe 'Cron directory entries' 'find cron roots -maxdepth 1 -ls' \
  'existing /etc/cron.* and /var/spool/cron directories; immediate entry metadata' show_cron_directory_entries
run_probe 'Current crontab' 'crontab -l' \
  'current identity; own scheduled jobs when crontab is available' show_current_crontab
run_probe 'Logrotate version' 'logrotate --version 2>&1' \
  'installed logrotate version if available; no rotation triggered' \
  timeout "${SCAN_SECONDS}s" bash -c 'logrotate --version 2>&1'
run_probe 'Logrotate configuration paths' '/etc/logrotate.conf and /etc/logrotate.d/*' \
  'standard config paths; immediate files and symlinks; metadata and current-user readability only' \
  show_logrotate_configs

section 'Container and namespace context'
run_probe 'User namespace limits' '/proc/sys/kernel/unprivileged_userns_clone; /proc/sys/user/max_user_namespaces' \
  'current procfs; read-only sysctl values or absence, not a namespace creation test' show_user_namespace_limits
run_probe 'PID 1 cgroup' '/proc/1/cgroup' 'PID 1 in current PID namespace' cat /proc/1/cgroup
run_probe 'PID 1 and script namespace links' '/proc/1/ns and /proc/self/ns' \
  'namespace links visible in current procfs' ls -l /proc/1/ns /proc/self/ns
run_probe 'Root mount' 'findmnt -T /' 'filesystem containing / in current mount namespace' findmnt -T /
probe_docker_images

section 'Network'
run_probe 'Interfaces and addresses' 'ip address show' 'local network interfaces' ip address show
run_probe 'Routes' 'ip route show' 'current network namespace routes' ip route show
run_probe 'Neighbor cache' 'ip neigh show' 'current network namespace cache' ip neigh show
run_probe 'TCP listeners and UDP endpoints' 'ss -lntup' \
  'current network namespace; process metadata visible to current user' ss -lntup
run_probe 'TCP connections' 'ss -tanp' \
  'current network namespace; all TCP states including established connections' ss -tanp
run_probe 'Unix sockets' 'ss -xap' \
  'current network namespace; Unix socket endpoints and visible process metadata' ss -xap
run_probe 'Resolver' '/etc/resolv.conf (selected directives)' \
  'nameserver/search/domain directives only' show_resolver
run_probe 'Hosts file' '/etc/hosts' 'local static host mappings and comments' cat /etc/hosts

section 'Storage and mounts'
run_probe 'Block devices' 'lsblk' 'local block devices and mount points' \
  lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT
run_probe 'Current mounts' 'findmnt' 'current mount namespace; target/source/type only' \
  findmnt -rno TARGET,SOURCE,FSTYPE
run_probe 'Filesystem capacity' 'df -h' 'mounted filesystems; 8s limit for unresponsive mounts' \
  timeout "${SCAN_SECONDS}s" df -h
run_probe 'Static mount entries' '/etc/fstab (selected fields)' \
  'noncomment fstab entries; options values suppressed' show_fstab
run_probe 'NFS export configuration' '/etc/exports and /etc/exports.d/*.exports' \
  'local NFS server config; file metadata and readable noncomment lines' \
  show_nfs_export_configs
run_probe 'Printers' 'lpstat -p -d' 'local printer status if tool is installed' lpstat -p -d

section 'SUID, SGID and file capabilities'
run_probe 'SUID or SGID files from /' 'find / -xdev -perm -4000/-2000' \
  "/ on root filesystem; regular files; ${ROOT_METADATA_SECONDS}s" \
  scan_root suid-sgid
for root in /bin /sbin /usr/bin /usr/sbin /usr/local /opt /srv /app /var/www /mnt /media; do
  run_probe "SUID or SGID files in $root" 'find -perm -4000/-2000' \
    "$root; depth<=3; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" 3 suid-sgid
done
run_probe 'File capabilities' 'getcap -r' \
  "existing /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /srv /app; ${SCAN_SECONDS}s" \
  scan_capabilities

section 'Writable paths and logs'
run_probe 'Writable paths from /' 'find / -xdev -writable' \
  "/ on root filesystem; writable regular files and writable traversable directories; ${ROOT_METADATA_SECONDS}s" \
  scan_root writable
for root in "${WRITABLE_ROOTS[@]}"; do
  [[ -n $root ]] || continue
  depth=3
  [[ -n $CURRENT_HOME && $root == "$CURRENT_HOME" ]] && depth=4
  [[ $root == /var/log ]] && depth=5
  run_probe "Writable directories in $root" 'find -type d -writable -executable' \
    "$root; depth<=$depth; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" "$depth" writable-dirs
  run_probe "Writable files in $root" 'find -type f -writable' \
    "$root; depth<=$depth; same filesystem; ${SCAN_SECONDS}s" \
    scan_paths "$root" "$depth" writable-files
done
run_probe 'Writable log candidates' 'root:writable and focused writable-files scans' \
  'deduplicated writable *.log/*.log.* paths and files under /var/log; file, log directory and parent access; upstream scan limits apply' \
  show_writable_log_candidates

section 'Scripts from /'
run_probe 'Shell script candidates from /' 'find / -xdev -type f (shell script extensions)' \
  "/ on root filesystem; .sh/.bash/.zsh/.ksh paths and metadata; ${ROOT_METADATA_SECONDS}s" \
  scan_root shell-scripts
run_probe 'Other script candidates from /' 'find / -xdev -type f (script extensions)' \
  "/ on root filesystem; .py/.pl/.rb/.php/.lua/.js/.ps1 paths and metadata; ${ROOT_METADATA_SECONDS}s" \
  scan_root other-scripts

section 'Content and filename candidates from /'
run_probe 'Credential-like text markers from /' 'find / -xdev + grep -IilE' \
  "/ on root filesystem; readable regular files <${ROOT_FILE_BYTES} bytes; paths only; ${ROOT_CONTENT_SECONDS}s" \
  scan_root credential-content
run_probe 'Interesting filenames from /' 'find / -xdev -type f' \
  "/ on root filesystem; selected name patterns; metadata only; ${ROOT_METADATA_SECONDS}s" \
  scan_root candidate-names
run_probe 'Config file candidates from /' 'find / -xdev -type f (config names)' \
  "/ on root filesystem; common config extensions including .xml, plus the file named config; ${ROOT_METADATA_SECONDS}s" \
  scan_root config-names
run_probe 'History file candidates from /' 'find / -xdev -type f (history names)' \
  "/ on root filesystem; *_hist/*_history names and metadata; ${ROOT_METADATA_SECONDS}s" \
  scan_root history-names
run_probe 'Backup, log and database filename candidates from /' 'find / -xdev -type f (backup/log/database names)' \
  "/ on root filesystem; backup, log, SQL, .db/.sqlite/.sqlite3 names and metadata; ${ROOT_METADATA_SECONDS}s" \
  scan_root backup-log-names

section 'Application executables and recent files'
run_probe 'Executable candidates in application roots' 'find custom roots -executable -ls' \
  "/usr/local/bin,/usr/local/sbin,/opt,/srv,/app,/home and temporary roots; depth<=4; ${ROOT_METADATA_SECONDS}s" \
  scan_application_executables
run_probe 'Recently modified file candidates from /' 'find / -xdev -mtime -7 -ls' \
  "/ on root filesystem; regular files modified within 7 days; one metadata snapshot; ${ROOT_METADATA_SECONDS}s" \
  scan_root recent-files

section 'Home, temporary and mail candidates'
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
for root in /var/mail /var/spool; do
  run_probe "Files in $root" 'find -type f -ls' \
    "$root; depth<=2; same filesystem; file metadata only; ${SCAN_SECONDS}s" \
    scan_paths "$root" 2 all-files
done

section 'Config candidates in selected roots'
for root in "${HOME:-}" /etc /opt /srv /app /usr/local/etc /var/www /var/backups /var/lib /run /mnt /media /root; do
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

printf '\nCandidate paths are leads. Read a selected file to verify content and context. For undisplayed rows or incomplete scans, use the printed full-output follow-up.\n'
