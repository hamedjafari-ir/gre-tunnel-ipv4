#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (IPv4 only)
# Created by: Hamed Jafari
# Version: 1.4 (AWS-aware + better debug)
# ==========================================================

SCRIPT_VERSION="1.4"

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; CYAN="\033[0;36m"; NC="\033[0m"; BOLD="\033[1m"

die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo). Example: sudo ./gre-tunnel-wizard.sh"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# ---------- Banner ----------
print_banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  cat <<'EOF'
  ██████╗ ██████╗ ███████╗
 ██╔════╝ ██╔══██╗██╔════╝
 ██║  ███╗██████╔╝█████╗
 ██║   ██║██╔══██╗██╔══╝
 ╚██████╔╝██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═╝╚══════╝

  ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
  ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
     ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
     ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
     ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
     ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
EOF
  echo -e "${NC}"
  echo "GRE Tunnel Wizard (IPv4)  |  Created by: Hamed Jafari  |  Version: ${SCRIPT_VERSION}"
  echo
}

# ---------- Spinner ----------
SPINNER_PID=""
spinner_start() {
  local msg="$1"
  (
    local frames='-\|/'
    local i=0
    while true; do
      printf "\r%-64s %s" "$msg" "${frames:i%4:1}"
      i=$((i+1))
      sleep 0.12
    done
  ) &
  SPINNER_PID=$!
  disown "$SPINNER_PID" 2>/dev/null || true
}
spinner_stop_ok() {
  local msg="$1"
  if [[ -n "${SPINNER_PID:-}" ]]; then
    kill "$SPINNER_PID" >/dev/null 2>&1 || true
    wait "$SPINNER_PID" >/dev/null 2>&1 || true
    SPINNER_PID=""
  fi
  printf "\r%-64s ✓\n" "$msg"
}
spinner_stop_fail() {
  local msg="$1"
  if [[ -n "${SPINNER_PID:-}" ]]; then
    kill "$SPINNER_PID" >/dev/null 2>&1 || true
    wait "$SPINNER_PID" >/dev/null 2>&1 || true
    SPINNER_PID=""
  fi
  printf "\r%-64s ✗\n" "$msg"
}

pause() { read -r -p "Press Enter to continue... " _; }

# ---------- IP utils ----------
is_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

detect_ipv4() {
  local ip=""
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
  if [[ -z "${ip:-}" ]]; then
    ip="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1 || true)"
  fi
  echo "${ip:-}"
}

# ---------- deps (local only; no apt) ----------
ensure_local_deps() {
  command_exists ip       || die "'ip' is missing (iproute2)."
  command_exists iptables || die "'iptables' is missing."
  command_exists sysctl   || die "'sysctl' is missing."
  command_exists ssh      || die "'ssh' is missing."
  command_exists ping     || die "'ping' is missing."
  command_exists nc       || die "'nc' is missing."
  command_exists timeout  || die "'timeout' is missing."
  command_exists base64   || die "'base64' is missing."
  if ! command_exists sshpass; then
    warn "'sshpass' not found. SSH password auth will not work (SSH key auth is fine)."
  fi
}

# ---------- SSH ----------
KNOWN_HOSTS_TMP="/tmp/gre_tunnel_known_hosts.$$"
cleanup() { rm -f "$KNOWN_HOSTS_TMP" >/dev/null 2>&1 || true; }
trap cleanup EXIT

SSH_OPTS_COMMON=(
  -o UserKnownHostsFile="$KNOWN_HOSTS_TMP"
  -o GlobalKnownHostsFile=/dev/null
  -o StrictHostKeyChecking=yes
  -o LogLevel=ERROR
  -o ConnectionAttempts=1
  -o ConnectTimeout=8
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=2
  -o GSSAPIAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o ChallengeResponseAuthentication=no
  -o PreferredAuthentications=publickey,password
)
SSH_TTY_OPTS=(-tt)

ssh_trust_hostkey() {
  local host="$1" port="$2"
  : >"$KNOWN_HOSTS_TMP"
  timeout 8 ssh-keyscan -p "$port" -T 5 "$host" >>"$KNOWN_HOSTS_TMP" 2>/dev/null || return 1
  grep -qE "ssh-(rsa|ed25519|ecdsa)" "$KNOWN_HOSTS_TMP" || return 1
  return 0
}

check_tcp_port() {
  local host="$1" port="$2"
  nc -zvw3 "$host" "$port" >/dev/null 2>&1
}

ssh_run_password() {
  local host="$1" port="$2" user="$3" pass="$4" remote="$5"
  command_exists sshpass || die "sshpass not installed but SSH password provided."
  timeout 180 sshpass -p "$pass" ssh -p "$port" \
    "${SSH_TTY_OPTS[@]}" \
    "${SSH_OPTS_COMMON[@]}" \
    -o BatchMode=no \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=yes \
    -o NumberOfPasswordPrompts=1 \
    "$user@$host" "$remote"
}

ssh_run_key() {
  local host="$1" port="$2" user="$3" remote="$4"
  timeout 180 ssh -p "$port" \
    "${SSH_TTY_OPTS[@]}" \
    "${SSH_OPTS_COMMON[@]}" \
    -o BatchMode=yes \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o NumberOfPasswordPrompts=0 \
    "$user@$host" "$remote"
}

ssh_login_check() {
  local host="$1" port="$2" user="$3" pass="$4"
  if [[ -n "${pass:-}" ]]; then
    ssh_run_password "$host" "$port" "$user" "$pass" "echo OK" >/dev/null 2>&1
  else
    ssh_run_key "$host" "$port" "$user" "echo OK" >/dev/null 2>&1
  fi
}

# Captures stdout+stderr into tmp file and returns its path (even on failure)
remote_exec_capture() {
  local host="$1" port="$2" user="$3" ssh_pass="$4" cmd="$5"
  local tmp; tmp="$(mktemp)"
  if [[ -n "${ssh_pass:-}" ]]; then
    ssh_run_password "$host" "$port" "$user" "$ssh_pass" "$cmd" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  else
    ssh_run_key "$host" "$port" "$user" "$cmd" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  fi
  echo "$tmp"
}

# ---------- Remote payload runner (base64 + root/sudo -i) ----------
run_remote_payload_b64_capture() {
  local host="$1" port="$2" user="$3" ssh_pass="$4" sudo_pass="$5" payload="$6"

  local payload_b64 remote_script remote_cmd tmp
  tmp="$(mktemp)"
  payload_b64="$(printf "%s" "$payload" | base64 -w0)"

  remote_script="$(cat <<'RS'
set -euo pipefail

PAYLOAD_B64="$PAYLOAD_B64"
SUDO_PASS="${SUDO_PASS:-}"

PAY="/tmp/gre_payload_$$.sh"
cleanup() { rm -f "$PAY" >/dev/null 2>&1 || true; }
trap cleanup EXIT

printf "%s" "$PAYLOAD_B64" | base64 -d >"$PAY"
chmod +x "$PAY"

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    bash "$PAY"
    exit 0
  fi

  # try passwordless sudo first
  if sudo -n true >/dev/null 2>&1; then
    sudo -i bash "$PAY"
    exit 0
  fi

  # if password provided, use it
  if [[ -n "$SUDO_PASS" ]]; then
    printf "%s\n" "$SUDO_PASS" | sudo -S -p "" -k true >/dev/null 2>&1 || { echo "SUDO_AUTH_FAILED" >&2; exit 51; }
    printf "%s\n" "$SUDO_PASS" | sudo -S -p "" -i bash "$PAY"
    exit 0
  fi

  echo "SUDO_PASSWORD_REQUIRED" >&2
  exit 52
}

run_as_root
RS
)"

  remote_cmd="PAYLOAD_B64=$(printf "%q" "$payload_b64") SUDO_PASS=$(printf "%q" "${sudo_pass:-}") bash -lc $(printf "%q" "$remote_script")"

  if [[ -n "${ssh_pass:-}" ]]; then
    ssh_run_password "$host" "$port" "$user" "$ssh_pass" "$remote_cmd" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  else
    ssh_run_key "$host" "$port" "$user" "$remote_cmd" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  fi

  echo "$tmp"
}

# ---------- idempotent helpers ----------
del_tunnel_if_exists() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}
add_iptables_rule_once() {
  iptables -C "$@" >/dev/null 2>&1 && return 0
  iptables "$@"
}

# ---------- Globals ----------
IRAN_IP=""
KHAREJ_IS_AWS="false"
KHAREJ_PUBLIC_IP=""
KHAREJ_PRIVATE_IP=""     # only when AWS=true
KHAREJ_LOCAL_GRE_IP=""   # what we use for "local" on Kharej GRE
SSH_PORT="22"
SSH_USER="root"
SSH_PASS=""
SUDO_PASS=""
DEBUG="false"

prompt_inputs() {
  local detected is_auto

  detected="$(detect_ipv4)"
  [[ -n "$detected" ]] || warn "Could not auto-detect local IPv4."

  echo
  echo "Auto-detected Iran IPv4: ${detected:-N/A}"
  read -r -p "Use this Iran IPv4? (true/false) [true]: " is_auto
  is_auto="${is_auto:-true}"

  if [[ "$is_auto" == "true" ]]; then
    [[ -n "$detected" ]] || die "Auto-detection failed. Rerun and set false to enter Iran IP."
    IRAN_IP="$detected"
  elif [[ "$is_auto" == "false" ]]; then
    while true; do
      read -r -p "Enter Iran IPv4: " IRAN_IP
      is_valid_ipv4 "$IRAN_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  else
    die "Only 'true' or 'false' allowed."
  fi

  echo
  read -r -p "Is Kharej server on AWS (Public IP + Private IP)? (true/false) [false]: " KHAREJ_IS_AWS
  KHAREJ_IS_AWS="${KHAREJ_IS_AWS:-false}"
  [[ "$KHAREJ_IS_AWS" == "true" || "$KHAREJ_IS_AWS" == "false" ]] || die "Only true/false allowed."

  while true; do
    read -r -p "Enter Kharej PUBLIC IPv4 (reachable IP for SSH): " KHAREJ_PUBLIC_IP
    is_valid_ipv4 "$KHAREJ_PUBLIC_IP" && break
    echo -e "${RED}Invalid IP format.${NC}"
  done

  if [[ "$KHAREJ_IS_AWS" == "true" ]]; then
    while true; do
      read -r -p "Enter Kharej PRIVATE IPv4 (AWS private, e.g. 172.x.x.x): " KHAREJ_PRIVATE_IP
      is_valid_ipv4 "$KHAREJ_PRIVATE_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  fi

  read -r -p "SSH port [22]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-22}"

  read -r -p "SSH user [root]: " SSH_USER
  SSH_USER="${SSH_USER:-root}"

  read -r -s -p "SSH password (leave empty if using SSH key): " SSH_PASS
  echo

  read -r -p "Debug logs on failure? (true/false) [false]: " DEBUG
  DEBUG="${DEBUG:-false}"

  echo
  echo "Summary:"
  echo "  Iran IPv4           : $IRAN_IP"
  echo "  Kharej PUBLIC IPv4  : $KHAREJ_PUBLIC_IP"
  if [[ "$KHAREJ_IS_AWS" == "true" ]]; then
    echo "  Kharej PRIVATE IPv4 : $KHAREJ_PRIVATE_IP"
  fi
  echo "  SSH                 : $SSH_USER@$KHAREJ_PUBLIC_IP:$SSH_PORT"
  echo "  Kharej on AWS       : $KHAREJ_IS_AWS"
  echo
}

preflight_ssh() {
  spinner_start "Checking TCP connectivity to Kharej:$SSH_PORT"
  if ! check_tcp_port "$KHAREJ_PUBLIC_IP" "$SSH_PORT"; then
    spinner_stop_fail "Checking TCP connectivity to Kharej:$SSH_PORT"
    die "Port $SSH_PORT is not reachable from Iran."
  fi
  spinner_stop_ok "TCP port reachable"

  spinner_start "Trusting SSH host key (no fingerprint prompts)"
  if ! ssh_trust_hostkey "$KHAREJ_PUBLIC_IP" "$SSH_PORT"; then
    spinner_stop_fail "Trusting SSH host key (no fingerprint prompts)"
    die "Cannot pre-trust host key."
  fi
  spinner_stop_ok "Host key trusted"

  spinner_start "Checking SSH login (non-interactive)"
  if ! ssh_login_check "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS"; then
    spinner_stop_fail "Checking SSH login (non-interactive)"
    die "SSH login failed."
  fi
  spinner_stop_ok "SSH login OK"

  # Choose GRE local IP on Kharej
  if [[ "$KHAREJ_IS_AWS" == "true" ]]; then
    KHAREJ_LOCAL_GRE_IP="$KHAREJ_PRIVATE_IP"
    ok "Kharej: local IP for GRE set to PRIVATE IP: $KHAREJ_LOCAL_GRE_IP"
  else
    KHAREJ_LOCAL_GRE_IP="$KHAREJ_PUBLIC_IP"
    ok "Kharej: local IP for GRE set to PUBLIC IP: $KHAREJ_LOCAL_GRE_IP"
  fi

  # SUDO handling: only if not root
  if [[ "$SSH_USER" == "root" ]]; then
    SUDO_PASS=""
    ok "Remote: root user detected (no sudo needed)"
  else
    # ask once; allow empty => try passwordless sudo (-n)
    read -r -s -p "Sudo password (one-time) [leave empty if NOPASSWD sudo is enabled]: " SUDO_PASS
    echo
    if [[ -n "${SUDO_PASS:-}" ]]; then
      ok "Sudo password captured"
    else
      warn "No sudo password provided; will try passwordless sudo (-n)."
    fi
  fi
}

# ---------- Main action ----------
configure_gre_ipv4() {
  info "--- Iran Server (Local) Configuration ---"
  prompt_inputs
  preflight_ssh

  # Remote payload (Kharej)
  local remote_payload
  remote_payload=$(
    cat <<'EOF'
set -euo pipefail

command -v ip >/dev/null 2>&1 || { echo "Missing dependency: ip (iproute2)" >&2; exit 20; }

# Ensure GRE module exists (usually built-in, but harmless)
modprobe ip_gre >/dev/null 2>&1 || true

# Clean old tunnel
ip link show To_IR >/dev/null 2>&1 && ip tunnel del To_IR >/dev/null 2>&1 || true

# Create GRE on Kharej: local=<KHAREJ_LOCAL_GRE_IP> remote=<IRAN_PUBLIC_IP>
ip tunnel add To_IR mode gre local <KHAREJ_LOCAL_GRE_IP> remote <IRAN_PUBLIC_IP> ttl 255
ip addr add 172.20.20.2/30 dev To_IR
ip link set To_IR mtu 1436
ip link set To_IR up

# Optional: enable forwarding (doesn't hurt)
sysctl -w net.ipv4.ip_forward=1 >/dev/null || true

# Show status for debug
ip -d tunnel show To_IR || true
ip -o -4 addr show dev To_IR || true
EOF
  )
  remote_payload="${remote_payload//<KHAREJ_LOCAL_GRE_IP>/$KHAREJ_LOCAL_GRE_IP}"
  remote_payload="${remote_payload//<IRAN_PUBLIC_IP>/$IRAN_IP}"

  spinner_start "Configuring Kharej server (remote GRE setup)"
  local log=""
  if ! log="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$remote_payload")"; then
    spinner_stop_fail "Configuring Kharej server (remote GRE setup)"
    echo -e "${RED}Remote output:${NC}" >&2
    if [[ -n "${log:-}" && -f "$log" ]]; then
      cat "$log" >&2
      rm -f "$log" >/dev/null 2>&1 || true
    else
      echo "(no remote log captured)" >&2
    fi
    die "Remote GRE configuration failed."
  fi
  spinner_stop_ok "Kharej configured"

  if [[ "$DEBUG" == "true" && -f "$log" ]]; then
    echo -e "${CYAN}Remote output (debug):${NC}"
    cat "$log" || true
  fi
  rm -f "$log" >/dev/null 2>&1 || true

  # Local (Iran) GRE
  spinner_start "Configuring Iran GRE interface"
  del_tunnel_if_exists "To_Kharej"

  # Iran always uses remote=Kharej PUBLIC (reachable on Internet)
  ip tunnel add To_Kharej mode gre local "$IRAN_IP" remote "$KHAREJ_PUBLIC_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up
  spinner_stop_ok "Iran GRE interface configured"

  spinner_start "Enabling forwarding (Iran)"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  spinner_stop_ok "Forwarding enabled"

  spinner_start "Testing tunnel from Iran (ping 172.20.20.2)"
  if ping -c 3 -W 2 172.20.20.2 >/dev/null 2>&1; then
    spinner_stop_ok "Ping OK (Iran -> Kharej)"
  else
    spinner_stop_fail "Ping failed (Iran -> Kharej)"
    warn "Tunnel interface may exist, but traffic isn't passing."
  fi

  # Also test reverse from Kharej -> Iran (helps a lot for AWS debugging)
  spinner_start "Testing tunnel from Kharej (ping 172.20.20.1)"
  local test_cmd
  test_cmd="ping -c 3 -W 2 172.20.20.1 >/dev/null 2>&1 && echo OK || echo FAIL"
  local out_file=""
  if out_file="$(remote_exec_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$test_cmd")"; then
    if grep -q "OK" "$out_file" 2>/dev/null; then
      spinner_stop_ok "Reverse ping OK (Kharej -> Iran)"
    else
      spinner_stop_fail "Reverse ping failed (Kharej -> Iran)"
      warn "Check firewall / security group / protocol 47 (GRE)."
    fi
  else
    spinner_stop_fail "Reverse ping test (SSH command failed)"
    warn "Could not run reverse ping test."
  fi
  [[ -n "${out_file:-}" && -f "$out_file" ]] && rm -f "$out_file" >/dev/null 2>&1 || true

  echo
  warn "AWS reminder (only if AWS=true): Security Group + NACL must allow GRE (Protocol 47) inbound/outbound."
  ok "END."
}

show_status() {
  echo
  echo -e "${CYAN}${BOLD}=== Status (Local) ===${NC}"
  echo "Version: ${SCRIPT_VERSION}"
  echo "IPv4 forwarding: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo N/A)"
  echo

  echo -e "${BOLD}Interfaces:${NC}"
  for ifc in To_Kharej; do
    if ip link show "$ifc" >/dev/null 2>&1; then
      echo "  - $ifc: PRESENT"
      ip -o -4 addr show dev "$ifc" 2>/dev/null | awk '{print "      IPv4:", $4}'
      ip -o link show "$ifc" 2>/dev/null | sed 's/^[0-9]\+:\s*//'
    else
      echo "  - $ifc: MISSING"
    fi
  done
  echo

  echo -e "${BOLD}ip tunnel show:${NC}"
  ip tunnel show 2>/dev/null || true
  echo
}

show_info() {
  echo -e "${CYAN}GRE Tunnel Wizard (IPv4)${NC}"
  echo "Created by: Hamed Jafari"
  echo "Version: ${SCRIPT_VERSION}"
  echo "Behavior:"
  echo "  - Asks if Kharej is AWS (default false)."
  echo "  - AWS=false: uses Kharej PUBLIC IP as GRE local (old behavior)."
  echo "  - AWS=true : uses Kharej PRIVATE IP as GRE local (AWS-safe)."
}

main_menu() {
  print_banner
  echo "1) Configure GRE (IPv4)"
  echo "2) Status"
  echo "3) Info"
  echo "0) Exit"
  echo
  read -r -p "Select: " choice
  case "$choice" in
    1) configure_gre_ipv4; pause ;;
    2) show_status; pause ;;
    3) show_info; pause ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}"; pause ;;
  esac
}

need_root
ensure_local_deps
while true; do
  main_menu
done
