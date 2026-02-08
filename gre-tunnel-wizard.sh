#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (IPv4 + IPv6 over SIT + IP6GRE)
# Created by: Hamed Jafari
# ==========================================================

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; CYAN="\033[0;36m"; NC="\033[0m"; BOLD="\033[1m"

die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo). Example: sudo ./gre-tunnel-wizard.sh"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# ---------- Banner (safe ASCII, no weird fonts) ----------
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
  echo "GRE Tunnel Wizard (IPv4 + IPv6)  |  Created by: Hamed Jafari"
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
    spinner_start "Checking/Installing dependencies (Iran server)"
    apt_update_once
    # timeout is from coreutils (usually installed), but keep it in mind.
    apt-get install -y iproute2 iptables openssh-client iputils-ping netcat-openbsd sshpass >/dev/null 2>&1 || true
    spinner_stop_ok "Dependencies ready"
  else
    command_exists ip       || die "'ip' is missing."
    command_exists iptables || die "'iptables' is missing."
    command_exists ssh      || die "'ssh' is missing."
    command_exists ping     || die "'ping' is missing."
    command_exists ping6    || warn "'ping6' not found (usually provided by iputils-ping). IPv6 test might fail."
    command_exists nc       || die "'nc' is missing."
    command_exists sshpass  || die "'sshpass' is missing."
    command_exists timeout  || die "'timeout' is missing."
  fi
}

# ---------- SSH (no prompts) ----------
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
  timeout 25 sshpass -p "$pass" ssh -p "$port" \
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
  timeout 25 ssh -p "$port" \
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

run_remote_capture() {
  local host="$1" port="$2" user="$3" pass="$4" cmd="$5"
  local tmp; tmp="$(mktemp)"
  if [[ -n "${pass:-}" ]]; then
    ssh_run_password "$host" "$port" "$user" "$pass" "bash -lc '$cmd'" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  else
    ssh_run_key "$host" "$port" "$user" "bash -lc '$cmd'" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  fi
  echo "$tmp"
}

# ---------- idempotent helpers ----------
del_tunnel_if_exists_v4() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}
del_tunnel_if_exists_v6() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip -6 tunnel del "$name" >/dev/null 2>&1 || true
}
add_iptables_rule_once() {
  iptables -C "$@" >/dev/null 2>&1 && return 0
  iptables "$@"
}

iface_state() {
  local ifc="$1"
  if ip link show "$ifc" >/dev/null 2>&1; then
    local st; st="$(ip -o link show "$ifc" | awk '{print $9}' | head -n1 || true)"
    echo "${st:-UNKNOWN}"
  else
    echo "MISSING"
  fi
}

show_iface_block() {
  local ifc="$1" title="$2"
  echo -e "${BOLD}$title${NC}  (${ifc})"
  if ip link show "$ifc" >/dev/null 2>&1; then
    echo "  State : $(iface_state "$ifc")"
    echo "  Link  : $(ip -o link show "$ifc" | sed 's/^[0-9]\+://')"
    echo "  IPv4  : $(ip -o -4 addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd ',' -)"
    echo "  IPv6  : $(ip -o -6 addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd ',' -)"
  else
    echo "  State : MISSING"
  fi
  echo
}

prompt_iran_kharej_ipv4_and_ssh() {
  local detected is_auto
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

  export IRAN_IP KHAREJ_IP SSH_PORT SSH_USER SSH_PASS DEBUG
}

preflight_ssh() {
  spinner_start "Checking TCP connectivity to Kharej:$SSH_PORT"
  if ! check_tcp_port "$KHAREJ_IP" "$SSH_PORT"; then
    spinner_stop_fail "Checking TCP connectivity to Kharej:$SSH_PORT"
    die "Port $SSH_PORT is not reachable from Iran."
  fi
  spinner_stop_ok "TCP port reachable"

  spinner_start "Trusting SSH host key (no fingerprint prompts)"
  if ! ssh_trust_hostkey "$KHAREJ_IP" "$SSH_PORT"; then
    spinner_stop_fail "Trusting SSH host key (no fingerprint prompts)"
    echo
    warn "ssh-keyscan failed. This usually means:"
    echo "  - Provider blocks keyscan, or"
    echo "  - Network drops packets after handshake, or"
    echo "  - SSH is behind some protection / rate limit."
    echo
    die "Cannot pre-trust host key. Try manually: ssh -p $SSH_PORT $SSH_USER@$KHAREJ_IP (once), then rerun."
  fi
  spinner_stop_ok "Host key trusted"

  if [[ -z "${SSH_PASS:-}" ]]; then
    warn "Password is empty => using SSH KEY auth."
    warn "Make sure Iran server has a working key for: $SSH_USER@$KHAREJ_IP"
  fi

  spinner_start "Checking SSH login (non-interactive)"
  if ! ssh_login_check "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS"; then
    spinner_stop_fail "Checking SSH login (non-interactive)"
    echo
    echo -e "${YELLOW}What to check on Kharej server:${NC}"
    echo "  - correct username/password"
    echo "  - if using root: PermitRootLogin yes"
    echo "  - if using password: PasswordAuthentication yes"
    echo "  - if using SSH key: ~/.ssh/authorized_keys must contain Iran server public key"
    echo
    die "SSH login failed. Check credentials / SSH key / root login settings."
  fi
  spinner_stop_ok "SSH login OK"
}

# ==========================================================
# IPv4 GRE (your original flow; kept same behaviour)
# ==========================================================
configure_gre_ipv4() {
  info "--- Iran Server (Local) Configuration ---"

  prompt_iran_kharej_ipv4_and_ssh

  echo
  echo "Summary:"
  echo "  Iran IPv4  : $IRAN_IP"
  echo "  Kharej IPv4: $KHAREJ_IP"
  echo "  SSH        : $SSH_USER@$KHAREJ_IP:$SSH_PORT"
  echo

  preflight_ssh

  # Remote GRE config (IPv4 GRE)
  local remote_cmd
  remote_cmd=$(
    cat <<'EOF'
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
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

  spinner_start "Configuring Kharej server (remote GRE setup)"
  local out=""
  if ! out="$(run_remote_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_cmd")"; then
    spinner_stop_fail "Configuring Kharej server (remote GRE setup)"
    if [[ "$DEBUG" == "true" ]]; then
      echo -e "${RED}Remote output (debug):${NC}"
      cat "$out" >&2
    fi
    rm -f "$out" 2>/dev/null || true
    die "Remote GRE configuration failed."
  fi
  rm -f "$out" 2>/dev/null || true
  spinner_stop_ok "Kharej configured"

  spinner_start "Configuring Iran GRE interface"
  del_tunnel_if_exists_v4 "To_Kharej"
  ip tunnel add To_Kharej mode gre remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up
  spinner_stop_ok "Iran GRE interface configured"

  spinner_start "Enabling forwarding and applying NAT rules"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  add_iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.20.20.1
  add_iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination 172.20.20.2
  add_iptables_rule_once -t nat -A POSTROUTING -j MASQUERADE
  spinner_stop_ok "Forwarding/NAT configured"

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

# ==========================================================
# IPv6: SIT (6to4-style) + GRE over IPv6 (ip6gre)
# You asked: keep it exactly with your commands/addresses.
# ==========================================================
# 
V6_IRAN="fde8:b030:25cf::de01"
V6_KHAREJ="fde8:b030:25cf::de02"
V6_PREFIX="fde8:b030:25cf::/64"

configure_ipv6_sit_and_ip6gre() {
  info "--- IPv6 (SIT + IP6GRE) Configuration ---"

  prompt_iran_kharej_ipv4_and_ssh

  echo
  echo "IPv6 Plan:"
  echo "  SIT Iran  iface : 6to4_To_KH  -> $V6_IRAN/64"
  echo "  SIT Kharej iface: 6to4_To_IR  -> $V6_KHAREJ/64"
  echo "  GRE over IPv6 Iran  iface : GRE6Tun_To_KH (IPv4 inside) -> 172.20.20.1/30"
  echo "  GRE over IPv6 Kharej iface: GRE6Tun_To_IR (IPv4 inside) -> 172.20.20.2/30"
  echo

  preflight_ssh

  # 1) Remote: create SIT + assign IPv6 + up
  local remote_sit
  remote_sit=$(
    cat <<'EOF'
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then SUDO="sudo"; else SUDO=""; fi

if ! command -v ip >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y >/dev/null 2>&1 || true
    $SUDO apt-get install -y iproute2 >/dev/null 2>&1
  else
    echo "Missing dependency: ip (iproute2)" >&2
    exit 20
  fi
fi

# Clean old
$SUDO ip link show 6to4_To_IR >/dev/null 2>&1 && $SUDO ip tunnel del 6to4_To_IR >/dev/null 2>&1 || true

# SIT over IPv4
$SUDO ip tunnel add 6to4_To_IR mode sit remote <IPv4_IRAN> local <IPv4_KHAREJ>
$SUDO ip -6 addr add <V6_KHAREJ>/64 dev 6to4_To_IR
$SUDO ip link set 6to4_To_IR mtu 1480
$SUDO ip link set 6to4_To_IR up
EOF
  )
  remote_sit="${remote_sit//<IPv4_IRAN>/$IRAN_IP}"
  remote_sit="${remote_sit//<IPv4_KHAREJ>/$KHAREJ_IP}"
  remote_sit="${remote_sit//<V6_KHAREJ>/$V6_KHAREJ}"

  spinner_start "Configuring Kharej SIT (6to4_To_IR) + IPv6 addr"
  local out=""
  if ! out="$(run_remote_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_sit")"; then
    spinner_stop_fail "Configuring Kharej SIT (6to4_To_IR) + IPv6 addr"
    if [[ "$DEBUG" == "true" ]]; then
      echo -e "${RED}Remote output (debug):${NC}"
      cat "$out" >&2
    fi
    rm -f "$out" 2>/dev/null || true
    die "Remote SIT configuration failed."
  fi
  rm -f "$out" 2>/dev/null || true
  spinner_stop_ok "Kharej SIT configured"

  # Local SIT
  spinner_start "Configuring Iran SIT (6to4_To_KH) + IPv6 addr"
  del_tunnel_if_exists_v4 "6to4_To_KH"
  ip tunnel add 6to4_To_KH mode sit remote "$KHAREJ_IP" local "$IRAN_IP"
  ip -6 addr add "$V6_IRAN/64" dev 6to4_To_KH
  ip link set 6to4_To_KH mtu 1480
  ip link set 6to4_To_KH up
  spinner_stop_ok "Iran SIT configured"

  # SIT test: ping6 between de01 and de02
  spinner_start "Testing SIT IPv6 link (ping6 $V6_KHAREJ)"
  if ping6 -c 3 -W 2 "$V6_KHAREJ" >/dev/null 2>&1; then
    spinner_stop_ok "SIT IPv6 OK"
  else
    spinner_stop_fail "SIT IPv6 ping failed"
    warn "SIT is up, but ping6 failed. Check firewall/provider: protocol 41 (IPv6-in-IPv4) must be allowed."
    warn "Continuing anyway, but GRE-over-IPv6 will probably fail too."
  fi

  # 2) Remote: create ip6gre using those ULA v6 addrs
  local remote_ip6gre
  remote_ip6gre=$(
    cat <<'EOF'
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then SUDO="sudo"; else SUDO=""; fi

# Clean old
$SUDO ip link show GRE6Tun_To_IR >/dev/null 2>&1 && $SUDO ip -6 tunnel del GRE6Tun_To_IR >/dev/null 2>&1 || true

$SUDO ip -6 tunnel add GRE6Tun_To_IR mode ip6gre remote <V6_IRAN> local <V6_KHAREJ>
$SUDO ip addr add 172.20.20.2/30 dev GRE6Tun_To_IR
$SUDO ip link set GRE6Tun_To_IR mtu 1436
$SUDO ip link set GRE6Tun_To_IR up
EOF
  )
  remote_ip6gre="${remote_ip6gre//<V6_IRAN>/$V6_IRAN}"
  remote_ip6gre="${remote_ip6gre//<V6_KHAREJ>/$V6_KHAREJ}"

  spinner_start "Configuring Kharej GRE over IPv6 (GRE6Tun_To_IR)"
  if ! out="$(run_remote_capture "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_ip6gre")"; then
    spinner_stop_fail "Configuring Kharej GRE over IPv6 (GRE6Tun_To_IR)"
    if [[ "$DEBUG" == "true" ]]; then
      echo -e "${RED}Remote output (debug):${NC}"
      cat "$out" >&2
    fi
    rm -f "$out" 2>/dev/null || true
    die "Remote ip6gre configuration failed."
  fi
  rm -f "$out" 2>/dev/null || true
  spinner_stop_ok "Kharej GRE6 configured"

  # Local ip6gre
  spinner_start "Configuring Iran GRE over IPv6 (GRE6Tun_To_KH)"
  del_tunnel_if_exists_v6 "GRE6Tun_To_KH"
  ip -6 tunnel add GRE6Tun_To_KH mode ip6gre remote "$V6_KHAREJ" local "$V6_IRAN"
  ip addr add 172.20.20.1/30 dev GRE6Tun_To_KH
  ip link set GRE6Tun_To_KH mtu 1436
  ip link set GRE6Tun_To_KH up
  spinner_stop_ok "Iran GRE6 configured"

  # Test GRE6 inner IPv4
  spinner_start "Testing GRE6 (ping 172.20.20.2)"
  if ping -c 3 -W 2 172.20.20.2 >/dev/null 2>&1; then
    spinner_stop_ok "GRE6 OK"
    ok "END: IPv6 SIT + GRE-over-IPv6 created successfully."
  else
    spinner_stop_fail "Ping failed"
    warn "END (warning): GRE6 interfaces are up, but ping failed."
    echo "Check firewall/provider: IPv6 GRE (ip6gre) and protocol 41 might be blocked."
  fi
}

# ==========================================================
# Settings / Status (menu based on active tunnels)
# 
# ==========================================================
show_settings_status() {
  echo
  echo -e "${CYAN}${BOLD}=== Settings / Status (Local Iran Server) ===${NC}"
  echo

  # GRE IPv4
  show_iface_block "To_Kharej" "IPv4 GRE Tunnel (Iran side)"

  # SIT + IPv6
  show_iface_block "6to4_To_KH" "IPv6-in-IPv4 SIT Tunnel (Iran side)"
  echo -e "${BOLD}Expected IPv6 endpoints${NC}"
  echo "  Iran   : $V6_IRAN/64"
  echo "  Kharej : $V6_KHAREJ/64"
  echo

  # GRE over IPv6
  show_iface_block "GRE6Tun_To_KH" "GRE over IPv6 (Iran side, carries IPv4 172.20.20.0/30)"

  echo -e "${BOLD}Quick checks${NC}"
  echo "  IPv4 GRE test : ping -c 3 172.20.20.2"
  echo "  SIT test      : ping6 -c 3 $V6_KHAREJ"
  echo "  GRE6 test     : ping -c 3 172.20.20.2"
  echo

  echo -e "${BOLD}Tunnels summary (raw)${NC}"
  echo "  ip tunnel show:"
  ip tunnel show 2>/dev/null || true
  echo
  echo "  ip -6 tunnel show:"
  ip -6 tunnel show 2>/dev/null || true
  echo
  echo "  ip -d link show (filtered gre/sit):"
  ip -d link show 2>/dev/null | awk '
    /: To_Kharej:|: To_IR:|: 6to4_To_KH:|: 6to4_To_IR:|: GRE6Tun_To_KH:|: GRE6Tun_To_IR:|mode gre|mode sit|mode ip6gre/ {print}
  ' || true
  echo

  echo -e "${BOLD}NAT/Forwarding${NC}"
  echo "  net.ipv4.ip_forward = $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo N/A)"
  echo "  iptables -t nat (relevant lines):"
  iptables -t nat -S 2>/dev/null | grep -E 'PREROUTING|POSTROUTING|DNAT|MASQUERADE' || true
  echo
}

show_info() {
  echo -e "${CYAN}GRE Tunnel Wizard${NC}"
  echo "Created by: Hamed Jafari"
  echo "Configures:"
  echo "  1) GRE (IPv4) between Iran and Kharej via SSH"
  echo "  2) IPv6: SIT over IPv4 + GRE over IPv6 (ip6gre) using fde8:b030:25cf::/64"
}

main_menu() {
  print_banner
  echo "1) Configure GRE (IPv4)"
  echo "2) Configure IPv6 (SIT + GRE-over-IPv6)"
  echo "3) Settings / Status (show active tunnels)"
  echo "4) Info"
  echo "0) Exit"
  echo
  read -r -p "Select: " choice
  case "$choice" in
    1) configure_gre_ipv4; pause ;;
    2) configure_ipv6_sit_and_ip6gre; pause ;;
    3) show_settings_status; pause ;;
    4) show_info; pause ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}"; pause ;;
  esac
}

need_root
ensure_local_deps
while true; do
  main_menu
done
