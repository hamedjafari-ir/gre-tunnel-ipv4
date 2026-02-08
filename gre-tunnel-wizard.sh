#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (IPv4) - Normal Servers + AWS EC2
# Created by: Hamed Jafari (refined)
# Version: 1.7
#
# Features:
# - GRE link setup Iran (local) <-> Kharej (remote via SSH)
# - AWS mode supported:
#     * remote "local" for GRE = PRIVATE IPv4 (not Public)
#     * remote reachable via PUBLIC IPv4 (SSH)
# - Optional traffic forwarding/NAT (gateway mode) after link is up
# - Better remote execution: no forced TTY, single password logic
# - Idempotent: uses ip addr replace + deletes existing tunnels
#
# NOTE:
# - GRE uses IP protocol 47. On AWS you MUST allow it in SG + NACL.
# - If forwarding traffic through EC2, disable Source/Dest Check on the instance.
# ==========================================================

SCRIPT_VERSION="1.7"

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; CYAN="\033[0;36m"; NC="\033[0m"; BOLD="\033[1m"

die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root. Example: sudo ./gre-tunnel-wizard.sh"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# ---------- Banner ----------
print_banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  cat <<'EOF'
████████╗██╗   ██╗██████╗ ███╗   ██╗███╗   ██╗███████╗██╗
╚══██╔══╝██║   ██║██╔══██╗████╗  ██║████╗  ██║██╔════╝██║
   ██║   ██║   ██║██████╔╝██╔██╗ ██║██╔██╗ ██║█████╗  ██║
   ██║   ██║   ██║██╔══██╗██║╚██╗██║██║╚██╗██║██╔══╝  ██║
   ██║   ╚██████╔╝██║  ██║██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
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
  ip route show default 2>/dev/null | awk '{print $5}' | head -n1
}

# ---------- deps ----------
ensure_local_deps() {
  command_exists ip       || die "'ip' is missing (iproute2)."
  command_exists sysctl   || die "'sysctl' is missing."
  command_exists ssh      || die "'ssh' is missing."
  command_exists ping     || die "'ping' is missing."
  command_exists nc       || die "'nc' is missing."
  command_exists timeout  || die "'timeout' is missing."
  command_exists base64   || die "'base64' is missing."
  command_exists iptables || warn "'iptables' missing. NAT mode will fail without it."
  command_exists modprobe || warn "'modprobe' not found. Kernel module load might fail on some systems."
  if ! command_exists sshpass; then
    warn "'sshpass' not found. SSH password auth won't work (SSH key auth is fine)."
  fi
}

# ---------- SSH helpers ----------
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
  command_exists sshpass || die "sshpass not installed but SSH password was provided."
  timeout 180 sshpass -p "$pass" ssh -p "$port" \
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

remote_exec_capture() {
  # returns path to tmp file containing stdout+stderr; nonzero exit propagates via return code
  local host="$1" port="$2" user="$3" ssh_pass="$4" cmd="$5"
  local tmp; tmp="$(mktemp)"
  if [[ -n "${ssh_pass:-}" ]]; then
    ssh_run_password "$host" "$port" "$user" "$ssh_pass" "$cmd" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  else
    ssh_run_key "$host" "$port" "$user" "$cmd" >"$tmp" 2>&1 || { echo "$tmp"; return 1; }
  fi
  echo "$tmp"
}

run_remote_payload_b64_capture() {
  # Runs payload as root on remote (root user OR sudo). Returns tmp logfile path.
  local host="$1" port="$2" user="$3" ssh_pass="$4" sudo_pass="$5" payload="$6"
  local tmp; tmp="$(mktemp)"

  local payload_b64 remote_script remote_cmd
  payload_b64="$(printf "%s" "$payload" | base64 -w0)"

  remote_script="$(cat <<'RS'
set -euo pipefail
PAYLOAD_B64="$PAYLOAD_B64"
SUDO_PASS="${SUDO_PASS:-}"
PAY="/tmp/gre_payload_$$.sh"
cleanup(){ rm -f "$PAY" >/dev/null 2>&1 || true; }
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
IRAN_PUBLIC_IP=""
KHAREJ_PUBLIC_IP=""
KHAREJ_PRIVATE_IP=""
IS_AWS="false"

SSH_PORT="22"
SSH_USER="root"
SSH_PASS=""
SUDO_PASS=""      # only needed if SSH_USER != root and remote needs sudo
DEBUG="false"

# Tunnel inner IPs (can be private, independent from AWS VPC range)
TUN_SUBNET="172.20.20.0/30"
IRAN_TUN_IP="172.20.20.1/30"
KHAREJ_TUN_IP="172.20.20.2/30"

# Remote GRE "local" param:
# - normal: same as Kharej PUBLIC
# - AWS: Kharej PRIVATE
KHAREJ_GRE_LOCAL_IP=""

# NAT options
ENABLE_NAT="false"
LOCAL_WAN_IFACE=""

prompt_inputs() {
  local detected use_auto

  detected="$(detect_local_ipv4)"
  echo
  echo "Auto-detected Iran IPv4 (local src): ${detected:-N/A}"
  read -r -p "Use this Iran IPv4? (true/false) [true]: " use_auto
  use_auto="${use_auto:-true}"

  if [[ "$use_auto" == "true" ]]; then
    [[ -n "$detected" ]] || die "Auto-detection failed. Rerun and set false to enter Iran IP manually."
    IRAN_PUBLIC_IP="$detected"
  elif [[ "$use_auto" == "false" ]]; then
    while true; do
      read -r -p "Enter Iran IPv4 (public): " IRAN_PUBLIC_IP
      is_valid_ipv4 "$IRAN_PUBLIC_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  else
    die "Only 'true' or 'false' allowed."
  fi

  read -r -p "Is Kharej server on AWS EC2 (Public IP + Private IP)? (true/false) [false]: " IS_AWS
  IS_AWS="${IS_AWS:-false}"
  [[ "$IS_AWS" == "true" || "$IS_AWS" == "false" ]] || die "Only 'true' or 'false' allowed."

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
    read -r -p "Enter Kharej PRIVATE IPv4 (EC2 console) [auto-detect if empty]: " KHAREJ_PRIVATE_IP
    if [[ -n "${KHAREJ_PRIVATE_IP:-}" ]]; then
      is_valid_ipv4 "$KHAREJ_PRIVATE_IP" || die "Invalid private IPv4 format."
    fi
  else
    KHAREJ_PRIVATE_IP=""
  fi

  read -r -p "SSH port [22]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-22}"

  read -r -p "SSH user [root]: " SSH_USER
  SSH_USER="${SSH_USER:-root}"

  read -r -s -p "SSH password (leave empty if using SSH key): " SSH_PASS
  echo

  read -r -p "Enable traffic forwarding/NAT after link is up? (true/false) [false]: " ENABLE_NAT
  ENABLE_NAT="${ENABLE_NAT:-false}"
  [[ "$ENABLE_NAT" == "true" || "$ENABLE_NAT" == "false" ]] || die "Only 'true' or 'false' allowed."

  if [[ "$ENABLE_NAT" == "true" ]]; then
    LOCAL_WAN_IFACE="$(detect_default_iface || true)"
    read -r -p "Local WAN interface (Iran, for MASQUERADE) [${LOCAL_WAN_IFACE:-eth0}]: " tmpif
    LOCAL_WAN_IFACE="${tmpif:-${LOCAL_WAN_IFACE:-eth0}}"
  fi

  read -r -p "Debug logs on failure? (true/false) [false]: " DEBUG
  DEBUG="${DEBUG:-false}"
  [[ "$DEBUG" == "true" || "$DEBUG" == "false" ]] || die "Only 'true' or 'false' allowed."

  echo
  echo "Summary:"
  echo "  Iran public IPv4     : $IRAN_PUBLIC_IP"
  echo "  Kharej public IPv4   : $KHAREJ_PUBLIC_IP"
  echo "  Kharej private IPv4  : ${KHAREJ_PRIVATE_IP:-N/A}"
  echo "  AWS mode             : $IS_AWS"
  echo "  SSH                  : $SSH_USER@$KHAREJ_PUBLIC_IP:$SSH_PORT"
  echo "  Tunnel subnet        : $TUN_SUBNET ($IRAN_TUN_IP <-> $KHAREJ_TUN_IP)"
  echo "  Enable traffic/NAT   : $ENABLE_NAT"
  if [[ "$ENABLE_NAT" == "true" ]]; then
    echo "  Local WAN iface      : $LOCAL_WAN_IFACE"
  fi
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
    ok "Remote user is root (no sudo password needed)"
    return 0
  fi

  # If user provided SSH password, we can reuse it for sudo (single prompt behavior)
  if [[ -n "${SSH_PASS:-}" ]]; then
    SUDO_PASS="$SSH_PASS"
    ok "Remote: sudo password will reuse SSH password (single prompt)"
  else
    read -r -s -p "Sudo password (one-time): " SUDO_PASS
    echo
    [[ -n "${SUDO_PASS:-}" ]] || die "Sudo password is required for non-root user."
  fi
}

ensure_aws_private_ip() {
  if [[ "$IS_AWS" != "true" ]]; then
    KHAREJ_GRE_LOCAL_IP="$KHAREJ_PUBLIC_IP"
    return 0
  fi

  if [[ -n "${KHAREJ_PRIVATE_IP:-}" ]]; then
    KHAREJ_GRE_LOCAL_IP="$KHAREJ_PRIVATE_IP"
    return 0
  fi

  # Auto-detect private IP without sudo (ip route get doesn't require root)
  spinner_start "Detecting AWS private IPv4 on remote (no sudo)"
  local cmd out_file ip
  cmd="ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if (\$i==\"src\") {print \$(i+1); exit}}'"
  if ! out_file="$(remote_exec_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$cmd")"; then
    spinner_stop_fail "Detecting AWS private IPv4 on remote (no sudo)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Could not detect remote private IPv4 automatically. Please enter it from EC2 console."
  fi

  ip="$(tr -d '\r' <"$out_file" | tail -n1 | tr -d '[:space:]')"
  rm -f "$out_file" >/dev/null 2>&1 || true

  is_valid_ipv4 "$ip" || {
    spinner_stop_fail "Detecting AWS private IPv4 on remote (no sudo)"
    die "Remote private IPv4 detection returned invalid value: '$ip'"
  }

  KHAREJ_PRIVATE_IP="$ip"
  KHAREJ_GRE_LOCAL_IP="$KHAREJ_PRIVATE_IP"
  spinner_stop_ok "AWS private IPv4 detected: $KHAREJ_PRIVATE_IP"
}

configure_remote_gre() {
  spinner_start "Configuring GRE on Kharej (remote)"
  local payload out_file

  payload=$(
    cat <<'EOF'
set -euo pipefail

echo "REMOTE_OK"

modprobe ip_gre 2>/dev/null || true

# rp_filter can drop GRE/encapsulated traffic (especially with NAT/public/private mix)
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.ens5.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth0.rp_filter=0 >/dev/null 2>&1 || true

# cleanup old tunnel if exists
ip link show To_IR >/dev/null 2>&1 && ip tunnel del To_IR >/dev/null 2>&1 || true

# create GRE
ip tunnel add To_IR mode gre remote <IRAN_PUBLIC_IP> local <KHAREJ_GRE_LOCAL_IP> ttl 255
ip link set To_IR mtu 1436

# set inner ip (idempotent)
ip addr replace <KHAREJ_TUN_IP> dev To_IR
ip link set To_IR up

# show for debug
ip -d link show To_IR
ip -4 addr show dev To_IR
EOF
  )

  payload="${payload//<IRAN_PUBLIC_IP>/$IRAN_PUBLIC_IP}"
  payload="${payload//<KHAREJ_GRE_LOCAL_IP>/$KHAREJ_GRE_LOCAL_IP}"
  payload="${payload//<KHAREJ_TUN_IP>/$KHAREJ_TUN_IP}"

  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Configuring GRE on Kharej (remote)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then
      echo -e "${RED}Remote output (debug):${NC}" >&2
      cat "$out_file" >&2
    fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote GRE configuration failed."
  fi

  spinner_stop_ok "Remote GRE configured"
  if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then
    echo -e "${CYAN}Remote output (debug):${NC}"
    cat "$out_file" || true
  fi
  rm -f "$out_file" >/dev/null 2>&1 || true
}

configure_local_gre() {
  spinner_start "Configuring GRE on Iran (local)"

  modprobe ip_gre 2>/dev/null || true

  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

  del_tunnel_if_exists "To_Kharej"

  ip tunnel add To_Kharej mode gre remote "$KHAREJ_PUBLIC_IP" local "$IRAN_PUBLIC_IP" ttl 255
  ip link set To_Kharej mtu 1436
  ip addr replace "$IRAN_TUN_IP" dev To_Kharej
  ip link set To_Kharej up

  spinner_stop_ok "Local GRE configured"
}

test_link() {
  echo
  info "Testing GRE link (ICMP over tunnel)..."
  spinner_start "Ping remote tunnel IP (${KHAREJ_TUN_IP%/*})"
  if ping -c 5 -W 2 "${KHAREJ_TUN_IP%/*}" >/dev/null 2>&1; then
    spinner_stop_ok "Tunnel ping OK"
    ok "GRE link is UP (${IRAN_TUN_IP%/*} <-> ${KHAREJ_TUN_IP%/*})."
  else
    spinner_stop_fail "Tunnel ping FAILED"
    warn "GRE interface is configured, but ICMP did not pass."
    echo
    echo "AWS checklist (most common misses):"
    echo "  1) Security Group: allow GRE (IP protocol 47) IN/OUT (at least from Iran public IP)"
    echo "  2) NACL: allow protocol 47 IN/OUT"
    echo "  3) Instance: disable Source/Destination Check (if you forward traffic through it)"
    echo "  4) Remote GRE 'local' MUST be EC2 PRIVATE IPv4 (you used: $KHAREJ_GRE_LOCAL_IP)"
    echo
  fi
}

apply_nat_local_iran() {
  command_exists iptables || die "iptables not installed; cannot enable NAT."
  spinner_start "Applying NAT/forwarding rules on Iran (local)"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Your existing rules (kept), but idempotent:
  add_iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination "${IRAN_TUN_IP%/*}"
  add_iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination "${KHAREJ_TUN_IP%/*}"
  add_iptables_rule_once -t nat -A POSTROUTING -o "$LOCAL_WAN_IFACE" -j MASQUERADE

  spinner_stop_ok "Iran NAT/forwarding configured"
}

apply_nat_remote_kharej_gateway() {
  # Optional: make Kharej (AWS/normal) act as egress for tunnel traffic
  spinner_start "Applying NAT/forwarding rules on Kharej (remote gateway)"
  local payload out_file

  payload=$(
    cat <<'EOF'
set -euo pipefail

# enable forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# find default iface on remote
WAN_IF="$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)"
WAN_IF="${WAN_IF:-eth0}"

# NAT traffic coming from tunnel out to internet
iptables -t nat -C POSTROUTING -s <TUN_SUBNET> -o "$WAN_IF" -j MASQUERADE >/dev/null 2>&1 || \
iptables -t nat -A POSTROUTING -s <TUN_SUBNET> -o "$WAN_IF" -j MASQUERADE

echo "Remote WAN iface: $WAN_IF"
iptables -t nat -S | tail -n 20 || true
EOF
  )
  payload="${payload//<TUN_SUBNET>/${TUN_SUBNET}}"

  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Applying NAT/forwarding rules on Kharej (remote gateway)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote NAT configuration failed."
  fi

  spinner_stop_ok "Remote NAT/forwarding configured"
  if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then
    echo -e "${CYAN}Remote output (debug):${NC}"
    cat "$out_file" || true
  fi
  rm -f "$out_file" >/dev/null 2>&1 || true
}

full_setup() {
  info "--- Iran Server (Local) Configuration ---"
  prompt_inputs
  preflight_ssh
  ensure_aws_private_ip

  echo
  ok "Using Kharej GRE local IP: $KHAREJ_GRE_LOCAL_IP"
  if [[ "$IS_AWS" == "true" ]]; then
    ok "AWS mode: remote GRE local=PRIVATE, remote reachable via PUBLIC"
  else
    ok "Normal mode: remote GRE local=PUBLIC"
  fi
  echo

  configure_remote_gre
  configure_local_gre
  test_link

  if [[ "$ENABLE_NAT" == "true" ]]; then
    echo
    warn "You enabled NAT/forwarding. On AWS, also disable Source/Dest Check on the instance."
    apply_nat_local_iran

    # Optional: Ask to also NAT on remote (gateway)
    local gw
    read -r -p "Also configure Kharej as NAT gateway for tunnel traffic? (true/false) [false]: " gw
    gw="${gw:-false}"
    if [[ "$gw" == "true" ]]; then
      apply_nat_remote_kharej_gateway
    fi
  fi

  echo
  ok "Done."
}

status_local() {
  echo
  echo -e "${CYAN}${BOLD}=== Status (Local) ===${NC}"
  echo "Version: ${SCRIPT_VERSION}"
  echo "Iran public IPv4    : ${IRAN_PUBLIC_IP:-N/A}"
  echo "Kharej public IPv4  : ${KHAREJ_PUBLIC_IP:-N/A}"
  echo "Kharej private IPv4 : ${KHAREJ_PRIVATE_IP:-N/A}"
  echo "Kharej GRE local IP : ${KHAREJ_GRE_LOCAL_IP:-N/A}"
  echo "Tunnel subnet       : ${TUN_SUBNET}"
  echo

  echo -e "${BOLD}Local GRE interface (To_Kharej):${NC}"
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

  echo -e "${BOLD}Local ip_forward / rp_filter:${NC}"
  echo "  ip_forward: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo N/A)"
  echo "  rp_filter all: $(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo N/A)"
  echo
}

cleanup_gre_only() {
  spinner_start "Removing local GRE tunnel (To_Kharej)"
  del_tunnel_if_exists "To_Kharej"
  spinner_stop_ok "Local GRE removed"

  spinner_start "Removing remote GRE tunnel (To_IR)"
  local payload out_file
  payload=$(
    cat <<'EOF'
set -euo pipefail
ip link show To_IR >/dev/null 2>&1 && ip tunnel del To_IR >/dev/null 2>&1 || true
echo "OK"
EOF
  )
  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Removing remote GRE tunnel (To_IR)"
    if [[ -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote cleanup failed."
  fi
  rm -f "$out_file" >/dev/null 2>&1 || true
  spinner_stop_ok "Remote GRE removed"
}

aws_checklist() {
  echo
  echo -e "${CYAN}${BOLD}AWS Checklist (must-do)${NC}"
  echo
  echo "1) Security Group (Instance):"
  echo "   - Inbound: SSH (22) from your IP"
  echo "   - Inbound: GRE (Protocol 47) from Iran public IP (${IRAN_PUBLIC_IP:-YOUR_IRAN_IP})"
  echo "   - Outbound: allow all OR at least GRE + needed traffic"
  echo
  echo "2) NACL (Subnet):"
  echo "   - Allow inbound/outbound protocol 47"
  echo
  echo "3) Disable Source/Destination Check:"
  echo "   - EC2 Console -> Instance -> Networking -> Change source/dest check -> Disable"
  echo "   - Required if you forward traffic through the instance."
  echo
  echo "4) GRE endpoints:"
  echo "   - Remote 'local' must be EC2 PRIVATE IPv4"
  echo "   - Remote reachable via EC2 PUBLIC IPv4 (SSH)"
  echo
  echo "5) If ping works but forwarding doesn't:"
  echo "   - Check ip_forward on the forwarding host"
  echo "   - Check iptables NAT rules on the gateway side"
  echo
}

main_menu() {
  print_banner
  echo "1) Full setup (GRE link + optional traffic/NAT)"
  echo "2) Status (local)"
  echo "3) Cleanup (GRE only)"
  echo "4) Info / AWS checklist"
  echo "0) Exit"
  echo
  read -r -p "Select: " choice
  case "$choice" in
    1) full_setup; pause ;;
    2) status_local; pause ;;
    3) cleanup_gre_only; pause ;;
    4) aws_checklist; pause ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}"; pause ;;
  esac
}

need_root
ensure_local_deps
while true; do
  main_menu
done
