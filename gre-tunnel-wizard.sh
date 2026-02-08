#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel (GRE over IPv4) - Wizard
# Created by: Hamed Jafari
# ==========================================================

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; CYAN="\033[0;36m"; NC="\033[0m"
die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo). Example: sudo ./gre-tunnel-wizard.sh"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# ---------- Banner ----------
print_banner() {
  clear
  echo -e "${CYAN}"
  cat <<'EOF'
   ________  ____  ______      ______                       __
  / ____/ / / / / / / __ \    /_  __/_  ______  ____  ___  / /
 / / __/ /_/ / /_/ / /_/ /____ / / / / / / __ \/ __ \/ _ \/ /
/ /_/ / __  / __  / ____/____// / / /_/ / / / / / / /  __/ /
\____/_/ /_/_/ /_/_/         /_/  \__,_/_/ /_/_/ /_/\___/_/

EOF
  echo -e "${NC}"
  echo "GRE Tunnel (IPv4)  |  Created by: Hamed Jafari"
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
      printf "\r%-62s %s" "$msg" "${frames:i%4:1}"
      i=$((i+1))
      sleep 0.12
    done
  ) &
  SPINNER_PID=$!
  disown "$SPINNER_PID" 2>/dev/null || true
}
spinner_stop_ok() {
  local msg="$1"
  [[ -n "${SPINNER_PID:-}" ]] && kill "$SPINNER_PID" >/dev/null 2>&1 || true
  [[ -n "${SPINNER_PID:-}" ]] && wait "$SPINNER_PID" >/dev/null 2>&1 || true
  SPINNER_PID=""
  printf "\r%-62s ✓\n" "$msg"
}
spinner_stop_fail() {
  local msg="$1"
  [[ -n "${SPINNER_PID:-}" ]] && kill "$SPINNER_PID" >/dev/null 2>&1 || true
  [[ -n "${SPINNER_PID:-}" ]] && wait "$SPINNER_PID" >/dev/null 2>&1 || true
  SPINNER_PID=""
  printf "\r%-62s ✗\n" "$msg"
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
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
  [[ -z "${ip:-}" ]] && ip="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1 || true)"
  echo "${ip:-}"
}

# ---------- deps ----------
APT_UPDATED=0
apt_update_once() {
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    apt-get update -y >/dev/null 2>&1 || true
    APT_UPDATED=1
  fi
}

ensure_local_deps() {
  if command_exists apt-get; then
    spinner_start "Checking/Installing dependencies on Iran server"
    apt_update_once
    apt-get install -y iproute2 iptables openssh-client iputils-ping netcat-openbsd sshpass >/dev/null 2>&1 || true
    spinner_stop_ok "Dependencies ready"
  else
    command_exists ip || die "'ip' is missing."
    command_exists iptables || die "'iptables' is missing."
    command_exists ssh || die "'ssh' is missing."
    command_exists ping || die "'ping' is missing."
    command_exists nc || die "'nc' is missing."
    command_exists sshpass || die "'sshpass' is missing."
  fi
}

# ---------- SSH (no prompts) ----------
KNOWN_HOSTS_TMP="/tmp/gre_tunnel_known_hosts"
touch "$KNOWN_HOSTS_TMP" 2>/dev/null || true
chmod 600 "$KNOWN_HOSTS_TMP" 2>/dev/null || true

SSH_OPTS_COMMON=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile="$KNOWN_HOSTS_TMP"
  -o GlobalKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectionAttempts=1
  -o ConnectTimeout=8
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=1
  -o GSSAPIAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o ChallengeResponseAuthentication=no
)

# ---------- Checks ----------
check_tcp_port() {
  local host="$1" port="$2"
  # fast tcp test (3s)
  nc -zvw3 "$host" "$port" >/dev/null 2>&1
}

ssh_handshake_check() {
  # This only tests SSH server response (no auth). Useful to catch weird timeouts early.
  local host="$1" port="$2"
  timeout 8 ssh -p "$port" \
    "${SSH_OPTS_COMMON[@]}" \
    -o BatchMode=yes \
    -o PreferredAuthentications=none \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=no \
    -o NumberOfPasswordPrompts=0 \
    "test@$host" "exit" >/dev/null 2>&1
  # It will usually fail (because no auth), but it must NOT hang/time out.
  return 0
}

ssh_run_password_capture() {
  local host="$1" port="$2" user="$3" pass="$4" remote="$5"
  local tmp; tmp="$(mktemp)"
  # IMPORTANT: BatchMode=no here (more reliable with sshpass)
  timeout 15 sshpass -p "$pass" ssh -p "$port" \
    "${SSH_OPTS_COMMON[@]}" \
    -o BatchMode=no \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=yes \
    -o NumberOfPasswordPrompts=1 \
    "$user@$host" "$remote" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  echo "$tmp"
}

ssh_run_key_capture() {
  local host="$1" port="$2" user="$3" remote="$4"
  local tmp; tmp="$(mktemp)"
  timeout 15 ssh -p "$port" \
    "${SSH_OPTS_COMMON[@]}" \
    -o BatchMode=yes \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o NumberOfPasswordPrompts=0 \
    "$user@$host" "$remote" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  echo "$tmp"
}

ssh_login_check() {
  local host="$1" port="$2" user="$3" pass="$4"
  local out=""
  if [[ -n "${pass:-}" ]]; then
    out="$(ssh_run_password_capture "$host" "$port" "$user" "$pass" "echo OK")" || return 1
    rm -f "$out" >/dev/null 2>&1 || true
    return 0
  else
    out="$(ssh_run_key_capture "$host" "$port" "$user" "echo OK")" || return 1
    rm -f "$out" >/dev/null 2>&1 || true
    return 0
  fi
}

run_remote_capture() {
  local host="$1" port="$2" user="$3" pass="$4" cmd="$5"
  local out=""
  if [[ -n "${pass:-}" ]]; then
    out="$(ssh_run_password_capture "$host" "$port" "$user" "$pass" "bash -lc '$cmd'")" || { echo "$out"; return 1; }
    echo "$out"
  else
    out="$(ssh_run_key_capture "$host" "$port" "$user" "bash -lc '$cmd'")" || { echo "$out"; return 1; }
    echo "$out"
  fi
}

explain_ssh_failure() {
  local logfile="$1"
  echo
  echo -e "${YELLOW}SSH failed. Last output:${NC}"
  tail -n 25 "$logfile" 2>/dev/null || true
  echo
  echo -e "${YELLOW}What to check on Kharej server:${NC}"
  echo "  - Is the username correct? (root vs ubuntu/debian/etc.)"
  echo "  - If using root: PermitRootLogin yes"
  echo "  - If using password: PasswordAuthentication yes"
  echo "  - If using key: your public key must be in ~/.ssh/authorized_keys"
  echo "  - If provider blocks root/password: use a normal user and sudo (needs NOPASSWD for automation)"
}

# ---------- idempotent ----------
del_tunnel_if_exists() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}

add_iptables_rule_once() {
  iptables -C "$@" >/dev/null 2>&1 && return 0
  iptables "$@"
}

# ---------- Main action ----------
configure_gre_ipv4() {
  info "--- Iran Server (Local) Configuration ---"

  local detected IRAN_IP KHAREJ_IP SSH_PORT SSH_USER SSH_PASS DEBUG
  detected="$(detect_ipv4)"
  [[ -n "$detected" ]] || warn "Could not auto-detect Iran IPv4. You may need to enter it manually."

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

  while true; do
    read -r -p "Enter Kharej IPv4 (IP Kharej): " KHAREJ_IP
    is_valid_ipv4 "$KHAREJ_IP" && break
    echo -e "${RED}Invalid IP format.${NC}"
  done

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
  echo "  Iran IPv4  : $IRAN_IP"
  echo "  Kharej IPv4: $KHAREJ_IP"
  echo "  SSH        : $SSH_USER@$KHAREJ_IP:$SSH_PORT"
  echo

  spinner_start "Checking TCP connectivity to Kharej:$SSH_PORT"
  if ! check_tcp_port "$KHAREJ_IP" "$SSH_PORT"; then
    spinner_stop_fail "Checking TCP connectivity to Kharej:$SSH_PORT"
    die "Port $SSH_PORT is not reachable from Iran."
  fi
  spinner_stop_ok "TCP port reachable"

  spinner_start "Checking SSH handshake (no auth)"
  if ! ssh_handshake_check "$KHAREJ_IP" "$SSH_PORT"; then
    spinner_stop_fail "Checking SSH handshake (no auth)"
    die "SSH handshake failed (network/proxy/firewall issue)."
  fi
  spinner_stop_ok "SSH handshake OK"

  if [[ -z "${SSH_PASS:-}" ]]; then
    warn "Password is empty => using SSH KEY auth."
    warn "If you don't have a key installed for this user, login will fail."
  fi

  spinner_start "Checking SSH login (non-interactive)"
  if ! ssh_login_check "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS"; then
    spinner_stop_fail "Checking SSH login (non-interactive)"
    # run one more time to capture logs for user
    local logf=""
    if [[ -n "${SSH_PASS:-}" ]]; then
      logf="$(ssh_run_password_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "echo OK")" || true
    else
      logf="$(ssh_run_key_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "echo OK")" || true
    fi
    [[ -n "${logf:-}" && -f "$logf" ]] && explain_ssh_failure "$logf"
    [[ -n "${logf:-}" && -f "$logf" ]] && [[ "$DEBUG" == "true" ]] && { echo -e "${RED}Full debug output:${NC}"; cat "$logf" >&2; }
    [[ -n "${logf:-}" && -f "$logf" ]] && rm -f "$logf" >/dev/null 2>&1 || true
    die "SSH login failed. Check credentials / SSH key / root login settings."
  fi
  spinner_stop_ok "SSH login OK"

  # ---------- Remote preflight + GRE ----------
  local remote_cmd
  remote_cmd=$(
    cat <<'EOF'
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    sudo -n true >/dev/null 2>&1 || { echo "Need passwordless sudo (NOPASSWD) for automation." >&2; exit 30; }
    SUDO="sudo"
  else
    echo "Not root and sudo not available." >&2
    exit 31
  fi
else
  SUDO=""
fi

if ! command -v ip >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y >/dev/null 2>&1 || true
    $SUDO apt-get install -y iproute2 >/dev/null 2>&1
  else
    echo "Missing dependency: ip (iproute2)" >&2
    exit 20
  fi
fi

$SUDO ip link show To_IR >/dev/null 2>&1 && $SUDO ip tunnel del To_IR >/dev/null 2>&1 || true

$SUDO ip tunnel add To_IR mode gre remote <IP_IRAN> local <IP_KHAREJ> ttl 255
$SUDO ip addr add 172.20.20.2/30 dev To_IR
$SUDO ip link set To_IR mtu 1436
$SUDO ip link set To_IR up
EOF
  )
  remote_cmd="${remote_cmd//<IP_IRAN>/$IRAN_IP}"
  remote_cmd="${remote_cmd//<IP_KHAREJ>/$KHAREJ_IP}"

  spinner_start "Configuring Kharej server (GRE)"
  local out=""
  if ! out="$(run_remote_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_cmd")"; then
    spinner_stop_fail "Configuring Kharej server (GRE)"
    if [[ -f "${out:-}" ]]; then
      explain_ssh_failure "$out"
      [[ "$DEBUG" == "true" ]] && { echo -e "${RED}Full debug output:${NC}"; cat "$out" >&2; }
      rm -f "$out" >/dev/null 2>&1 || true
    fi
    die "Remote GRE configuration failed."
  fi
  rm -f "$out" >/dev/null 2>&1 || true
  spinner_stop_ok "Kharej configured"

  # ---------- Local GRE ----------
  spinner_start "Configuring Iran GRE interface"
  del_tunnel_if_exists "To_Kharej"
  ip tunnel add To_Kharej mode gre remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up
  spinner_stop_ok "Iran GRE interface configured"

  # ---------- NAT / Forward ----------
  spinner_start "Enabling forwarding and NAT rules"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  add_iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.20.20.1
  add_iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination 172.20.20.2
  add_iptables_rule_once -t nat -A POSTROUTING -j MASQUERADE
  spinner_stop_ok "Forwarding/NAT configured"

  # ---------- Test ----------
  spinner_start "Testing tunnel (ping 172.20.20.2)"
  if ping -c 3 -W 2 172.20.20.2 >/dev/null 2>&1; then
    spinner_stop_ok "Tunnel OK"
    ok "END: Tunnel created successfully."
  else
    spinner_stop_fail "Ping failed"
    warn "END (warning): Tunnel is up, but ping failed."
    echo "Check firewall/provider: GRE protocol 47 must be allowed."
  fi
}

show_info() {
  echo -e "${CYAN}GRE Tunnel${NC}"
  echo "Created by: Hamed Jafari"
  echo "Configures GRE tunnel (IPv4) between Iran and Kharej via SSH."
}

main_menu() {
  print_banner
  echo "1) Configure GRE (IPv4)"
  echo "2) Info"
  echo "0) Exit"
  echo
  read -r -p "Select: " choice
  case "$choice" in
    1) configure_gre_ipv4; pause ;;
    2) show_info; pause ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}"; pause ;;
  esac
}

need_root
ensure_local_deps
while true; do
  main_menu
done
