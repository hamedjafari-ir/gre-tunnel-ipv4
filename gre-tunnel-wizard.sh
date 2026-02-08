#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (GRE over IPv4)
# Created by: Hamed Jafari
# ==========================================================

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
NC="\033[0m"

die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo). Example: sudo ./gre-tunnel-wizard.sh"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

# ---------------- Spinner (always show activity) ----------------
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

cleanup_on_exit() {
  # stop spinner if still running
  if [[ -n "${SPINNER_PID:-}" ]]; then
    kill "$SPINNER_PID" >/dev/null 2>&1 || true
    wait "$SPINNER_PID" >/dev/null 2>&1 || true
    SPINNER_PID=""
    echo
  fi
}
trap cleanup_on_exit EXIT

pause() { read -r -p "Press Enter to continue... " _; }

# ---------------- Pretty banner / logo ----------------
banner() {
  clear
  echo -e "${MAGENTA}"
  cat <<'ASCII'
   ██████╗ ██████╗ ███████╗    ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
  ██╔════╝ ██╔══██╗██╔════╝    ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
  ██║  ███╗██████╔╝█████╗         ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
  ██║   ██║██╔══██╗██╔══╝         ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
  ╚██████╔╝██║  ██║███████╗       ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═════╝ ╚═╝  ╚═╝╚══════╝       ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝

                 GRE Tunnel Wizard (IPv4)  |  Created by: Hamed Jafari
ASCII
  echo -e "${NC}"
}

# ---------------- IP utils ----------------
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
  if [[ -z "${ip:-}" ]]; then
    ip="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1 || true)"
  fi
  echo "${ip:-}"
}

# ---------------- Local deps (Iran server) ----------------
APT_UPDATED=0
apt_update_once() {
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    apt-get update -y >/dev/null 2>&1 || true
    APT_UPDATED=1
  fi
}

ensure_local_deps() {
  if command_exists apt-get; then
    spinner_start "Checking/Installing local dependencies (Iran server)"
    apt_update_once
    apt-get install -y iproute2 iptables openssh-client iputils-ping sshpass coreutils >/dev/null 2>&1 || true
    spinner_stop_ok "Local dependencies ready"
  else
    command_exists ip       || die "'ip' is missing."
    command_exists iptables || die "'iptables' is missing."
    command_exists ssh      || die "'ssh' is missing."
    command_exists ping     || die "'ping' is missing."
    command_exists sshpass  || die "'sshpass' is missing (install it manually)."
    command_exists timeout  || die "'timeout' is missing (install coreutils)."
  fi
}

# ---------------- SSH (no prompts) ----------------
# We solve the fingerprint prompt properly:
# 1) ssh-keyscan -> write host key to a temp known_hosts
# 2) run ssh with StrictHostKeyChecking=yes and UserKnownHostsFile=temp
KNOWN_HOSTS_TMP=""

ssh_prepare_known_hosts() {
  local host="$1" port="$2"
  KNOWN_HOSTS_TMP="$(mktemp)"
  # keyscan can hang if network blocks; wrap with timeout
  timeout 6 ssh-keyscan -p "$port" -T 5 "$host" >"$KNOWN_HOSTS_TMP" 2>/dev/null || true

  # Ensure file is not empty, otherwise we can't use StrictHostKeyChecking=yes safely
  if [[ ! -s "$KNOWN_HOSTS_TMP" ]]; then
    rm -f "$KNOWN_HOSTS_TMP" 2>/dev/null || true
    KNOWN_HOSTS_TMP=""
    return 1
  fi
  return 0
}

ssh_cleanup_known_hosts() {
  if [[ -n "${KNOWN_HOSTS_TMP:-}" && -f "$KNOWN_HOSTS_TMP" ]]; then
    rm -f "$KNOWN_HOSTS_TMP" >/dev/null 2>&1 || true
  fi
  KNOWN_HOSTS_TMP=""
}

trap ssh_cleanup_known_hosts EXIT

SSH_BASE_OPTS=(
  -o LogLevel=ERROR
  -o ConnectionAttempts=1
  -o ConnectTimeout=5
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=1
  -o GSSAPIAuthentication=no
  -o PubkeyAuthentication=no
)

ssh_cmd_password() {
  local host="$1" port="$2" user="$3" pass="$4" remote="$5"
  sshpass -p "$pass" ssh -p "$port" \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS_TMP" \
    -o GlobalKnownHostsFile=/dev/null \
    "${SSH_BASE_OPTS[@]}" \
    -o PreferredAuthentications=password \
    -o PasswordAuthentication=yes \
    -o NumberOfPasswordPrompts=1 \
    "$user@$host" "$remote"
}

ssh_cmd_key() {
  local host="$1" port="$2" user="$3" remote="$4"
  ssh -p "$port" \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS_TMP" \
    -o GlobalKnownHostsFile=/dev/null \
    "${SSH_BASE_OPTS[@]}" \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o NumberOfPasswordPrompts=0 \
    "$user@$host" "$remote"
}

tcp_port_check() {
  local host="$1" port="$2"
  # fast and reliable check (no DNS, no ssh)
  timeout 4 bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
}

quick_ssh_check() {
  local host="$1" port="$2" user="$3" pass="$4"
  if [[ -n "${pass:-}" ]]; then
    timeout 8 ssh_cmd_password "$host" "$port" "$user" "$pass" "echo OK" >/dev/null 2>&1
  else
    timeout 8 ssh_cmd_key "$host" "$port" "$user" "echo OK" >/dev/null 2>&1
  fi
}

run_remote_capture() {
  local host="$1" port="$2" user="$3" pass="$4" cmd="$5"
  local tmp; tmp="$(mktemp)"

  if [[ -n "${pass:-}" ]]; then
    timeout 30 ssh_cmd_password "$host" "$port" "$user" "$pass" "bash -lc '$cmd'" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  else
    timeout 30 ssh_cmd_key "$host" "$port" "$user" "bash -lc '$cmd'" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  fi

  echo "$tmp"
  return 0
}

# ---------------- Idempotent helpers ----------------
del_tunnel_if_exists() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}

add_iptables_rule_once() {
  if iptables -C "$@" >/dev/null 2>&1; then
    return 0
  fi
  iptables "$@"
}

# ---------------- Main action ----------------
configure_gre_ipv4() {
  info "--- Iran Server (Local) Configuration ---"

  local detected IRAN_IP KHAREJ_IP SSH_PORT SSH_USER SSH_PASS DEBUG
  detected="$(detect_ipv4)"
  [[ -n "$detected" ]] || warn "Could not auto-detect IPv4. You may need to enter it manually."

  echo
  echo "Auto-detected Iran IPv4: ${detected:-N/A}"
  read -r -p "Is this the correct Iran server IPv4? (true/false) [true]: " is_auto
  is_auto="${is_auto:-true}"

  if [[ "$is_auto" == "true" ]]; then
    [[ -n "$detected" ]] || die "Auto-detection failed. Rerun and set false to enter Iran IP manually."
    IRAN_IP="$detected"
  elif [[ "$is_auto" == "false" ]]; then
    while true; do
      read -r -p "Enter Iran IPv4: " IRAN_IP
      is_valid_ipv4 "$IRAN_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  else
    die "Only 'true' or 'false' is allowed."
  fi

  while true; do
    read -r -p "Enter Kharej server IPv4 (IP Kharej): " KHAREJ_IP
    is_valid_ipv4 "$KHAREJ_IP" && break
    echo -e "${RED}Invalid IP format.${NC}"
  done

  read -r -p "SSH port [22]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-22}"

  read -r -p "SSH user [root]: " SSH_USER
  SSH_USER="${SSH_USER:-root}"

  read -r -s -p "SSH password (leave empty if using SSH key): " SSH_PASS
  echo

  read -r -p "Enable debug logs if remote fails? (true/false) [false]: " DEBUG
  DEBUG="${DEBUG:-false}"

  echo
  echo "Summary:"
  echo "  Iran IPv4  : $IRAN_IP"
  echo "  Kharej IPv4: $KHAREJ_IP"
  echo "  SSH        : $SSH_USER@$KHAREJ_IP:$SSH_PORT"
  echo

  # 0) Port check (fast fail, no hangs)
  spinner_start "Checking TCP port $SSH_PORT on Kharej"
  if ! tcp_port_check "$KHAREJ_IP" "$SSH_PORT"; then
    spinner_stop_fail "Checking TCP port $SSH_PORT on Kharej"
    die "Port $SSH_PORT is not reachable from Iran server (firewall/provider/sshd down)."
  fi
  spinner_stop_ok "TCP port reachable"

  # 1) Prepare fingerprint (NO user prompt, safe mode)
  spinner_start "Fetching SSH fingerprint (ssh-keyscan)"
  if ! ssh_prepare_known_hosts "$KHAREJ_IP" "$SSH_PORT"; then
    spinner_stop_fail "Fetching SSH fingerprint (ssh-keyscan)"
    die "ssh-keyscan failed. Network filtering or SSH not responding properly."
  fi
  spinner_stop_ok "SSH fingerprint ready"

  # 2) Quick SSH check (FAST + hard timeout)
  spinner_start "Testing SSH login to Kharej (fast check)"
  if ! quick_ssh_check "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS"; then
    spinner_stop_fail "Testing SSH login to Kharej (fast check)"
    die "SSH login failed. Check credentials / SSH key / root login settings."
  fi
  spinner_stop_ok "SSH login OK"

  # ---------- Remote preflight + GRE config ----------
  local remote_cmd
  remote_cmd=$(
    cat <<'EOF'
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

# Preflight: ensure "ip" exists
if ! command -v ip >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y >/dev/null 2>&1 || true
    $SUDO apt-get install -y iproute2 >/dev/null 2>&1
  else
    echo "Missing dependency: ip (iproute2)" >&2
    exit 20
  fi
fi

# Cleanup old tunnel
$SUDO ip link show To_IR >/dev/null 2>&1 && $SUDO ip tunnel del To_IR >/dev/null 2>&1 || true

# Configure GRE on Kharej
$SUDO ip tunnel add To_IR mode gre remote <IP_IRAN> local <IP_KHAREJ> ttl 255
$SUDO ip addr add 172.20.20.2/30 dev To_IR
$SUDO ip link set To_IR mtu 1436
$SUDO ip link set To_IR up
EOF
  )
  remote_cmd="${remote_cmd//<IP_IRAN>/$IRAN_IP}"
  remote_cmd="${remote_cmd//<IP_KHAREJ>/$KHAREJ_IP}"

  spinner_start "Configuring Kharej GRE interface (remote)"
  local out=""
  if ! out="$(run_remote_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_cmd")"; then
    spinner_stop_fail "Configuring Kharej GRE interface (remote)"
    if [[ "$DEBUG" == "true" ]]; then
      echo -e "${RED}Remote output (debug):${NC}"
      cat "$out" >&2
    fi
    rm -f "$out" 2>/dev/null || true
    die "Remote GRE configuration failed."
  fi
  rm -f "$out" 2>/dev/null || true
  spinner_stop_ok "Kharej GRE configured"

  # ---------- Local (Iran) config ----------
  spinner_start "Configuring Iran GRE interface (local)"
  del_tunnel_if_exists "To_Kharej"
  ip tunnel add To_Kharej mode gre remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up
  spinner_stop_ok "Iran GRE configured"

  # ---------- Forwarding & NAT (Iran) ----------
  spinner_start "Enabling forwarding + applying NAT rules (local)"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  add_iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.20.20.1
  add_iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination 172.20.20.2
  add_iptables_rule_once -t nat -A POSTROUTING -j MASQUERADE
  spinner_stop_ok "Forwarding/NAT applied"

  # ---------- Test ----------
  spinner_start "Testing tunnel (ping 172.20.20.2 from Iran)"
  if ping -c 3 -W 2 172.20.20.2 >/dev/null 2>&1; then
    spinner_stop_ok "Tunnel OK"
    ok "END: Tunnel created successfully."
  else
    spinner_stop_fail "Tunnel ping failed"
    warn "END (with warning): Tunnel is up, but ping failed."
    echo "Check firewall/provider: GRE protocol 47 must be allowed."
  fi
}

show_info() {
  echo -e "${CYAN}GRE Tunnel Wizard${NC}"
  echo "Created by: Hamed Jafari"
  echo
  echo "This tool configures a GRE (IPv4) tunnel between Iran and Kharej."
}

main_menu() {
  banner
  echo "1) Configure GRE tunnel (IPv4)"
  echo "2) Info"
  echo "0) Exit"
  echo
  read -r -p "Select an option: " choice
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
