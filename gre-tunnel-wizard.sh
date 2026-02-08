#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (IPv4) - Normal Servers + AWS EC2
# Created by: Hamed Jafari (refined)
# Version: 1.6
#
# Features:
# - Builds GRE link 172.20.20.0/30:
#     Iran(local) 172.20.20.1  <-->  Kharej(remote) 172.20.20.2
# - AWS-aware:
#     Remote GRE "local" must be EC2 PRIVATE IPv4 (not public)
#     Remote reachable for SSH = EC2 PUBLIC IPv4
# - Optional traffic forwarding (real traffic pass):
#     * Enables ip_forward
#     * Adds NAT MASQUERADE rules (safe, scoped)
# - Prompts cleanly (no duplicate password prompts)
#
# Local requirements:
#   bash, ip, sysctl, ssh, nc, timeout, base64, ping, iptables
#   sshpass optional (only if you use SSH password)
# ==========================================================

SCRIPT_VERSION="1.6"

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
      printf "\r%-74s %s" "$msg" "${frames:i%4:1}"
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
  printf "\r%-74s ✓\n" "$msg"
}
spinner_stop_fail() {
  local msg="$1"
  if [[ -n "${SPINNER_PID:-}" ]]; then
    kill "$SPINNER_PID" >/dev/null 2>&1 || true
    wait "$SPINNER_PID" >/dev/null 2>&1 || true
    SPINNER_PID=""
  fi
  printf "\r%-74s ✗\n" "$msg"
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

detect_local_ipv4() {
  local ip=""
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
  if [[ -z "${ip:-}" ]]; then
    ip="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1 || true)"
  fi
  echo "${ip:-}"
}

detect_default_iface() {
  # interface used for default route
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

is_bool() { [[ "${1:-}" == "true" || "${1:-}" == "false" ]]; }

# ---------- deps ----------
ensure_local_deps() {
  command_exists ip       || die "'ip' is missing (iproute2)."
  command_exists sysctl   || die "'sysctl' is missing."
  command_exists ssh      || die "'ssh' is missing."
  command_exists ping     || die "'ping' is missing."
  command_exists nc       || die "'nc' is missing."
  command_exists timeout  || die "'timeout' is missing."
  command_exists base64   || die "'base64' is missing."
  command_exists iptables || die "'iptables' is missing."
  command_exists modprobe || warn "'modprobe' not found. Kernel module load might fail."
  if ! command_exists sshpass; then
    warn "'sshpass' not found. SSH password auth won't work (SSH key auth is fine)."
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
  command_exists sshpass || die "sshpass not installed but SSH password was provided."
  timeout 240 sshpass -p "$pass" ssh -p "$port" \
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
  timeout 240 ssh -p "$port" \
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

# ---------- Remote payload runner (base64 + sudo -i) ----------
run_remote_payload_b64_capture() {
  local host="$1" port="$2" user="$3" ssh_pass="$4" sudo_pass="$5" payload="$6"
  local tmp; tmp="$(mktemp)"

  local payload_b64
  payload_b64="$(printf "%s" "$payload" | base64 -w0)"

  local remote_script
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

  if sudo -n true >/dev/null 2>&1; then
    sudo -i bash "$PAY"
    exit 0
  fi

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

  local remote_cmd
  remote_cmd="PAYLOAD_B64=$(printf "%q" "$payload_b64") SUDO_PASS=$(printf "%q" "${sudo_pass:-}") bash -lc $(printf "%q" "$remote_script")"

  if [[ -n "${ssh_pass:-}" ]]; then
    if ! ssh_run_password "$host" "$port" "$user" "$ssh_pass" "$remote_cmd" >"$tmp" 2>&1; then
      echo "$tmp"
      return 1
    fi
  else
    if ! ssh_run_key "$host" "$port" "$user" "$remote_cmd" >"$tmp" 2>&1; then
      echo "$tmp"
      return 1
    fi
  fi

  echo "$tmp"
}

# ---------- iptables helper ----------
iptables_add_once() {
  # usage: iptables_add_once <table> <rule...>
  local table="$1"; shift
  iptables -t "$table" -C "$@" >/dev/null 2>&1 && return 0
  iptables -t "$table" -A "$@"
}

del_tunnel_if_exists() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}

# ---------- Globals ----------
IRAN_IP=""
KHAREJ_PUBLIC_IP=""
KHAREJ_PRIVATE_IP=""
KHAREJ_GRE_LOCAL_IP=""     # remote GRE "local" parameter
SSH_PORT="22"
SSH_USER="root"
SSH_PASS=""
SUDO_PASS=""               # only if needed
DEBUG="false"
IS_AWS="false"
ENABLE_TRAFFIC="false"     # enable forwarding/NAT

LOCAL_WAN_IF=""
REMOTE_WAN_IF=""

# ---------- Input ----------
prompt_inputs() {
  local detected use_auto

  detected="$(detect_local_ipv4)"
  echo
  echo "Auto-detected Iran IPv4 (local src): ${detected:-N/A}"
  read -r -p "Use this Iran IPv4? (true/false) [true]: " use_auto
  use_auto="${use_auto:-true}"
  is_bool "$use_auto" || die "Only 'true' or 'false' allowed."

  if [[ "$use_auto" == "true" ]]; then
    [[ -n "$detected" ]] || die "Auto-detection failed. Set false to enter Iran IP manually."
    IRAN_IP="$detected"
  else
    while true; do
      read -r -p "Enter Iran PUBLIC IPv4: " IRAN_IP
      is_valid_ipv4 "$IRAN_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  fi

  read -r -p "Is Kharej server on AWS EC2 (Public IP + Private IP)? (true/false) [false]: " IS_AWS
  IS_AWS="${IS_AWS:-false}"
  is_bool "$IS_AWS" || die "Only 'true' or 'false' allowed."

  while true; do
    read -r -p "Enter Kharej PUBLIC IPv4 (reachable for SSH): " KHAREJ_PUBLIC_IP
    is_valid_ipv4 "$KHAREJ_PUBLIC_IP" && break
    echo -e "${RED}Invalid IP format.${NC}"
  done

  if [[ "$IS_AWS" == "true" ]]; then
    echo
    echo "AWS needs BOTH IPs (from EC2 console):"
    echo "  - Public IPv4  : $KHAREJ_PUBLIC_IP"
    echo "  - Private IPv4 : (example: 172.26.14.230)"
    while true; do
      read -r -p "Enter Kharej PRIVATE IPv4 (EC2 console): " KHAREJ_PRIVATE_IP
      is_valid_ipv4 "$KHAREJ_PRIVATE_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
    KHAREJ_GRE_LOCAL_IP="$KHAREJ_PRIVATE_IP"
  else
    KHAREJ_PRIVATE_IP=""
    KHAREJ_GRE_LOCAL_IP="$KHAREJ_PUBLIC_IP"
  fi

  read -r -p "SSH port [22]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-22}"

  read -r -p "SSH user [root]: " SSH_USER
  SSH_USER="${SSH_USER:-root}"

  read -r -s -p "SSH password (leave empty if using SSH key): " SSH_PASS
  echo

  read -r -p "Enable traffic forwarding/NAT after link is up? (true/false) [false]: " ENABLE_TRAFFIC
  ENABLE_TRAFFIC="${ENABLE_TRAFFIC:-false}"
  is_bool "$ENABLE_TRAFFIC" || die "Only 'true' or 'false' allowed."

  read -r -p "Debug logs on failure? (true/false) [false]: " DEBUG
  DEBUG="${DEBUG:-false}"
  is_bool "$DEBUG" || die "Only 'true' or 'false' allowed."

  LOCAL_WAN_IF="$(detect_default_iface || true)"

  echo
  echo "Summary:"
  echo "  Iran public IPv4      : $IRAN_IP"
  echo "  Kharej public IPv4    : $KHAREJ_PUBLIC_IP"
  echo "  Kharej private IPv4   : ${KHAREJ_PRIVATE_IP:-N/A}"
  echo "  Kharej GRE local IP   : $KHAREJ_GRE_LOCAL_IP"
  echo "  SSH                   : $SSH_USER@$KHAREJ_PUBLIC_IP:$SSH_PORT"
  echo "  AWS mode              : $IS_AWS"
  echo "  Enable traffic/NAT    : $ENABLE_TRAFFIC"
  echo "  Local WAN iface       : ${LOCAL_WAN_IF:-unknown}"
  echo
}

preflight_ssh() {
  spinner_start "Checking TCP connectivity to Kharej:$SSH_PORT"
  if ! check_tcp_port "$KHAREJ_PUBLIC_IP" "$SSH_PORT"; then
    spinner_stop_fail "Checking TCP connectivity to Kharej:$SSH_PORT"
    die "Port $SSH_PORT is not reachable."
  fi
  spinner_stop_ok "TCP reachable"

  spinner_start "Trusting SSH host key (no prompts)"
  if ! ssh_trust_hostkey "$KHAREJ_PUBLIC_IP" "$SSH_PORT"; then
    spinner_stop_fail "Trusting SSH host key (no prompts)"
    die "Cannot pre-trust host key."
  fi
  spinner_stop_ok "Host key trusted"

  spinner_start "Checking SSH login (non-interactive)"
  if ! ssh_login_check "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS"; then
    spinner_stop_fail "Checking SSH login (non-interactive)"
    die "SSH login failed."
  fi
  spinner_stop_ok "SSH login OK"

  if [[ "$SSH_USER" == "root" ]]; then
    SUDO_PASS=""
    ok "Remote user is root (no sudo needed)"
    return 0
  fi

  # IMPORTANT: Do not ask twice.
  # If SSH password is provided, reuse it for sudo (common setup).
  if [[ -n "${SSH_PASS:-}" ]]; then
    SUDO_PASS="$SSH_PASS"
    ok "Remote: sudo password will reuse SSH password (single prompt)"
    return 0
  fi

  # If using SSH key, ask sudo password once.
  read -r -s -p "Sudo password (one-time): " SUDO_PASS
  echo
  [[ -n "${SUDO_PASS:-}" ]] || die "Sudo password is required for non-root user."
}

# ---------- Remote side ----------
remote_setup_gre_payload() {
  cat <<'EOF'
set -euo pipefail

modprobe ip_gre 2>/dev/null || true

# rp_filter kills asymmetric/encapped flows a lot (AWS especially)
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
# try common nic names
sysctl -w net.ipv4.conf.ens5.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth0.rp_filter=0 >/dev/null 2>&1 || true

ip link show To_IR >/dev/null 2>&1 && ip tunnel del To_IR >/dev/null 2>&1 || true

ip tunnel add To_IR mode gre remote <IRAN_IP> local <KHAREJ_GRE_LOCAL_IP> ttl 255
ip addr add 172.20.20.2/30 dev To_IR
ip link set To_IR mtu 1436
ip link set To_IR up

echo "REMOTE_OK"
ip -d link show To_IR
ip -4 addr show dev To_IR
EOF
}

remote_enable_traffic_payload() {
  cat <<'EOF'
set -euo pipefail

# Enable forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Detect WAN interface (default route)
WAN_IF="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
[ -n "$WAN_IF" ] || WAN_IF="$(ip -o link show | awk -F': ' 'NR==1{print $2}')"

# Allow forwarding between GRE and WAN
iptables -C FORWARD -i To_IR -o "$WAN_IF" -j ACCEPT >/dev/null 2>&1 || iptables -A FORWARD -i To_IR -o "$WAN_IF" -j ACCEPT
iptables -C FORWARD -i "$WAN_IF" -o To_IR -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || iptables -A FORWARD -i "$WAN_IF" -o To_IR -m state --state RELATED,ESTABLISHED -j ACCEPT

# NAT (masquerade) only for traffic leaving WAN that came from tunnel subnet
iptables -t nat -C POSTROUTING -s 172.20.20.0/30 -o "$WAN_IF" -j MASQUERADE >/dev/null 2>&1 || iptables -t nat -A POSTROUTING -s 172.20.20.0/30 -o "$WAN_IF" -j MASQUERADE

echo "REMOTE_TRAFFIC_OK WAN_IF=$WAN_IF"
EOF
}

configure_remote() {
  spinner_start "Configuring GRE on Kharej (remote)"
  local payload out_file out

  payload="$(remote_setup_gre_payload)"
  payload="${payload//<IRAN_IP>/$IRAN_IP}"
  payload="${payload//<KHAREJ_GRE_LOCAL_IP>/$KHAREJ_GRE_LOCAL_IP}"

  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Configuring GRE on Kharej (remote)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then
      echo -e "${RED}Remote output (debug):${NC}" >&2
      cat "$out_file" >&2
    fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote GRE configuration failed."
  fi

  out="$(cat "$out_file" 2>/dev/null || true)"
  rm -f "$out_file" >/dev/null 2>&1 || true
  spinner_stop_ok "Remote GRE configured"

  if [[ "$DEBUG" == "true" ]]; then
    echo -e "${CYAN}Remote output (debug):${NC}"
    echo "$out"
  fi
}

enable_remote_traffic() {
  spinner_start "Enabling forwarding/NAT on Kharej (remote)"
  local payload out_file

  payload="$(remote_enable_traffic_payload)"

  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Enabling forwarding/NAT on Kharej (remote)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then
      echo -e "${RED}Remote output (debug):${NC}" >&2
      cat "$out_file" >&2
    fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote traffic/NAT configuration failed."
  fi

  REMOTE_WAN_IF="$(tr -d '\r' <"$out_file" | grep -oE 'WAN_IF=[^ ]+' | cut -d= -f2 | tail -n1 || true)"
  if [[ "$DEBUG" == "true" ]]; then
    echo -e "${CYAN}Remote traffic output (debug):${NC}"
    cat "$out_file" || true
  fi
  rm -f "$out_file" >/dev/null 2>&1 || true
  spinner_stop_ok "Remote forwarding/NAT enabled"
}

# ---------- Local side ----------
configure_local() {
  spinner_start "Configuring GRE on Iran (local)"
  modprobe ip_gre 2>/dev/null || true

  # safer defaults
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

  del_tunnel_if_exists "To_Kharej"
  ip tunnel add To_Kharej mode gre remote "$KHAREJ_PUBLIC_IP" local "$IRAN_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up
  spinner_stop_ok "Local GRE configured"
}

enable_local_traffic() {
  spinner_start "Enabling forwarding/NAT on Iran (local)"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  LOCAL_WAN_IF="${LOCAL_WAN_IF:-$(detect_default_iface || true)}"
  [[ -n "${LOCAL_WAN_IF:-}" ]] || warn "Could not detect local WAN iface. NAT rules may need manual adjustment."

  # Allow forwarding between LAN/WAN and GRE (generic accept + established)
  iptables -C FORWARD -o To_Kharej -j ACCEPT >/dev/null 2>&1 || iptables -A FORWARD -o To_Kharej -j ACCEPT
  iptables -C FORWARD -i To_Kharej -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || iptables -A FORWARD -i To_Kharej -m state --state RELATED,ESTABLISHED -j ACCEPT

  # NAT only outbound via GRE (this is the usual "send traffic to Kharej")
  iptables -t nat -C POSTROUTING -o To_Kharej -j MASQUERADE >/dev/null 2>&1 || iptables -t nat -A POSTROUTING -o To_Kharej -j MASQUERADE

  spinner_stop_ok "Local forwarding/NAT enabled"
}

test_link() {
  echo
  info "Testing GRE link (ICMP over tunnel)..."

  spinner_start "Ping remote tunnel IP (172.20.20.2)"
  if ping -c 5 -W 2 172.20.20.2 >/dev/null 2>&1; then
    spinner_stop_ok "Tunnel ping OK"
    ok "GRE link is UP (172.20.20.1 <-> 172.20.20.2)."
  else
    spinner_stop_fail "Tunnel ping FAILED"
    warn "GRE interface is configured, but ICMP did not pass."

    echo
    echo "Most common AWS blockers:"
    echo "  1) Security Group / NACL must allow GRE (Protocol 47) inbound & outbound."
    echo "  2) EC2 'local' in ip tunnel must be PRIVATE IPv4 (you provided: $KHAREJ_PRIVATE_IP)."
    echo "  3) rp_filter must be 0 (script sets it)."
    echo
    echo "Quick checks:"
    echo "  Local:  ip -d link show To_Kharej"
    echo "  Local:  tcpdump -ni ${LOCAL_WAN_IF:-<wan>} proto 47"
    echo "  Remote: tcpdump -ni ${REMOTE_WAN_IF:-<nic>} proto 47"
    echo "  Remote: tcpdump -ni To_IR icmp"
  fi
}

show_status() {
  echo
  echo -e "${CYAN}${BOLD}=== Status (Local) ===${NC}"
  echo "Version: ${SCRIPT_VERSION}"
  echo "Iran public IPv4    : ${IRAN_IP:-N/A}"
  echo "Kharej public IPv4  : ${KHAREJ_PUBLIC_IP:-N/A}"
  echo "Kharej private IPv4 : ${KHAREJ_PRIVATE_IP:-N/A}"
  echo "Kharej GRE local IP : ${KHAREJ_GRE_LOCAL_IP:-N/A}"
  echo "AWS mode            : ${IS_AWS:-N/A}"
  echo

  echo -e "${BOLD}Local GRE interface:${NC}"
  if ip link show To_Kharej >/dev/null 2>&1; then
    ip -d link show To_Kharej || true
    ip -4 addr show dev To_Kharej || true
  else
    echo "  To_Kharej: MISSING"
  fi
  echo

  echo -e "${BOLD}Local tunnels:${NC}"
  ip tunnel show 2>/dev/null || true
  echo

  echo -e "${BOLD}iptables (local) nat/filter snapshot:${NC}"
  iptables -t nat -S 2>/dev/null || true
  iptables -S 2>/dev/null || true
  echo
}

cleanup_local() {
  spinner_start "Cleaning local GRE + rules (best-effort)"
  del_tunnel_if_exists "To_Kharej"
  # We won't try to delete iptables rules blindly (dangerous).
  spinner_stop_ok "Local GRE removed (iptables left untouched)"
}

cleanup_remote() {
  spinner_start "Cleaning remote GRE (best-effort)"
  local payload out_file
  payload=$(
    cat <<'EOF'
set -euo pipefail
ip link show To_IR >/dev/null 2>&1 && ip tunnel del To_IR >/dev/null 2>&1 || true
echo "REMOTE_CLEAN_OK"
EOF
  )
  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Cleaning remote GRE (best-effort)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote cleanup failed."
  fi
  rm -f "$out_file" >/dev/null 2>&1 || true
  spinner_stop_ok "Remote GRE removed"
}

full_setup() {
  info "--- Iran Server (Local) Configuration ---"
  prompt_inputs
  preflight_ssh

  echo
  ok "Using Kharej GRE local IP: $KHAREJ_GRE_LOCAL_IP"
  if [[ "$IS_AWS" == "true" ]]; then
    ok "AWS mode: remote GRE local=PRIVATE, remote reachable via PUBLIC"
  else
    ok "Normal mode: remote GRE local=PUBLIC"
  fi
  echo

  configure_remote
  configure_local
  test_link

  if [[ "$ENABLE_TRAFFIC" == "true" ]]; then
    echo
    info "Enabling traffic forwarding/NAT (so traffic really passes)..."
    enable_remote_traffic
    enable_local_traffic

    echo
    ok "Traffic/NAT enabled."
    if [[ "$IS_AWS" == "true" ]]; then
      warn "AWS REQUIRED: Disable 'Source/Destination Check' on this EC2 instance (otherwise routing/NAT breaks)."
      warn "AWS REQUIRED: SecurityGroup/NACL must allow GRE (Protocol 47) IN/OUT."
    fi
  fi

  echo
  ok "Done."
}

main_menu() {
  print_banner
  echo "1) Full setup (GRE link + optional traffic/NAT)"
  echo "2) Status (Local)"
  echo "3) Cleanup (GRE only)"
  echo "4) Info / AWS checklist"
  echo "0) Exit"
  echo
  read -r -p "Select: " choice
  case "$choice" in
    1) full_setup; pause ;;
    2) show_status; pause ;;
    3)
      info "--- Cleanup ---"
      # Needs current connection info; re-prompt minimal:
      prompt_inputs
      preflight_ssh
      cleanup_remote
      cleanup_local
      pause
      ;;
    4)
      echo
      echo "AWS checklist (must be correct):"
      echo "  1) You entered EC2 PRIVATE IPv4 correctly (for remote GRE local)."
      echo "  2) Security Group + NACL allow:"
      echo "       - Protocol 47 (GRE) inbound + outbound"
      echo "       - ICMP (for ping test) optional but helpful"
      echo "       - SSH inbound (port ${SSH_PORT})"
      echo "  3) If you want traffic routing/NAT through EC2:"
      echo "       - Disable Source/Destination Check on the instance"
      echo "       - Keep ip_forward=1 and NAT rules enabled"
      echo
      pause
      ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}"; pause ;;
  esac
}

need_root
ensure_local_deps
while true; do
  main_menu
done
