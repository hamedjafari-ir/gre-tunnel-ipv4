#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (IPv4) - Normal Servers + AWS EC2
# Created by: Hamed Jafari
# Version: 1.6
#
# Modes:
# 1) GRE link only (ping test)
# 2) GRE + traffic forwarding (NAT/DNAT)  [like your working rules]
#
# AWS notes (important):
# - On EC2, GRE "local" must be the instance PRIVATE IPv4 (not Public).
# - For traffic forwarding through EC2, often you must DISABLE Source/Dest Check.
# - Security Group / NACL must allow GRE (Protocol 47) inbound/outbound as needed.
# - rp_filter can drop asymmetric traffic; script disables it on both ends.
# ==========================================================

SCRIPT_VERSION="1.6"

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
      printf "\r%-72s %s" "$msg" "${frames:i%4:1}"
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
  printf "\r%-72s ✓\n" "$msg"
}
spinner_stop_fail() {
  local msg="$1"
  if [[ -n "${SPINNER_PID:-}" ]]; then
    kill "$SPINNER_PID" >/dev/null 2>&1 || true
    wait "$SPINNER_PID" >/dev/null 2>&1 || true
    SPINNER_PID=""
  fi
  printf "\r%-72s ✗\n" "$msg"
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

# ---------- deps ----------
ensure_local_deps() {
  command_exists ip       || die "'ip' is missing (iproute2)."
  command_exists sysctl   || die "'sysctl' is missing."
  command_exists ssh      || die "'ssh' is missing."
  command_exists ping     || die "'ping' is missing."
  command_exists nc       || die "'nc' is missing."
  command_exists timeout  || die "'timeout' is missing."
  command_exists base64   || die "'base64' is missing."
  command_exists iptables || die "'iptables' is missing (needed for traffic mode)."
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

run_remote_payload_b64_capture() {
  local host="$1" port="$2" user="$3" ssh_pass="$4" sudo_pass="$5" payload="$6"
  local tmp; tmp="$(mktemp)"
  local payload_b64; payload_b64="$(printf "%s" "$payload" | base64 -w0)"

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
      echo "$tmp"; return 1
    fi
  else
    if ! ssh_run_key "$host" "$port" "$user" "$remote_cmd" >"$tmp" 2>&1; then
      echo "$tmp"; return 1
    fi
  fi

  echo "$tmp"
}

# ---------- idempotent helpers ----------
del_tunnel_if_exists() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}
iptables_rule_once() {
  # usage: iptables_rule_once -t nat -A PREROUTING ...
  iptables -C "$@" >/dev/null 2>&1 && return 0
  iptables "$@"
}

# ---------- Globals ----------
IRAN_LOCAL_IP=""
KHAREJ_PUBLIC_IP=""     # reachable from Iran for outer GRE + SSH
KHAREJ_PRIVATE_IP=""    # EC2 private (needed for remote "local" param)
KHAREJ_GRE_LOCAL_IP=""  # what we pass as "local" on Kharej side (AWS=>private, else=>public)

SSH_PORT="22"
SSH_USER="root"
SSH_PASS=""
SUDO_PASS=""
SUDO_SAME_AS_SSH="true"

DEBUG="false"
IS_AWS="false"

# ---------- Input ----------
prompt_inputs() {
  local detected use_auto

  detected="$(detect_local_ipv4)"
  echo
  echo "Auto-detected Iran IPv4 (local src): ${detected:-N/A}"
  read -r -p "Use this Iran IPv4? (true/false) [true]: " use_auto
  use_auto="${use_auto:-true}"

  if [[ "$use_auto" == "true" ]]; then
    [[ -n "$detected" ]] || die "Auto-detection failed. Rerun and set false to enter Iran IP manually."
    IRAN_LOCAL_IP="$detected"
  elif [[ "$use_auto" == "false" ]]; then
    while true; do
      read -r -p "Enter Iran IPv4 (local): " IRAN_LOCAL_IP
      is_valid_ipv4 "$IRAN_LOCAL_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  else
    die "Only 'true' or 'false' allowed."
  fi

  read -r -p "Is Kharej server on AWS EC2 (Public IP + Private IP)? (true/false) [false]: " IS_AWS
  IS_AWS="${IS_AWS:-false}"
  [[ "$IS_AWS" == "true" || "$IS_AWS" == "false" ]] || die "Only 'true' or 'false' allowed."

  while true; do
    read -r -p "Enter Kharej PUBLIC IPv4 (reachable for SSH / outer GRE): " KHAREJ_PUBLIC_IP
    is_valid_ipv4 "$KHAREJ_PUBLIC_IP" && break
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
  echo "  Iran local IPv4    : $IRAN_LOCAL_IP"
  echo "  Kharej public IPv4 : $KHAREJ_PUBLIC_IP"
  echo "  Kharej on AWS      : $IS_AWS"
  echo "  SSH                : $SSH_USER@$KHAREJ_PUBLIC_IP:$SSH_PORT"
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

  # Ask sudo password only once, optionally reuse SSH password
  read -r -p "Use SSH password also as sudo password? (true/false) [true]: " SUDO_SAME_AS_SSH
  SUDO_SAME_AS_SSH="${SUDO_SAME_AS_SSH:-true}"
  [[ "$SUDO_SAME_AS_SSH" == "true" || "$SUDO_SAME_AS_SSH" == "false" ]] || die "Only 'true' or 'false' allowed."

  if [[ "$SUDO_SAME_AS_SSH" == "true" ]]; then
    [[ -n "${SSH_PASS:-}" ]] || die "SSH password is empty (key auth). Can't reuse it for sudo. Choose false and enter sudo password."
    SUDO_PASS="$SSH_PASS"
    ok "Remote: sudo password set from SSH password"
  else
    read -r -s -p "Sudo password (one-time): " SUDO_PASS
    echo
    [[ -n "${SUDO_PASS:-}" ]] || die "Sudo password is required for non-root user."
  fi
}

# ---------- AWS private IP detection ----------
detect_remote_private_ip_if_needed() {
  if [[ "$IS_AWS" != "true" ]]; then
    KHAREJ_PRIVATE_IP=""
    KHAREJ_GRE_LOCAL_IP="$KHAREJ_PUBLIC_IP"
    ok "Kharej local IP for GRE set to PUBLIC IP: $KHAREJ_GRE_LOCAL_IP"
    return 0
  fi

  spinner_start "Detecting AWS Private IPv4 on remote (IMDS / ip route)"
  local payload out_file out ip

  payload=$(
    cat <<'EOF'
set -euo pipefail

# Try IMDSv2 first
get_imds_token() {
  command -v curl >/dev/null 2>&1 || return 1
  curl -sS -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || return 1
}

get_imds_local_ipv4() {
  command -v curl >/dev/null 2>&1 || return 1
  local token=""
  token="$(get_imds_token 2>/dev/null || true)"
  if [[ -n "$token" ]]; then
    curl -sS -m 2 -H "X-aws-ec2-metadata-token: $token" \
      "http://169.254.169.254/latest/meta-data/local-ipv4" || return 1
  fi
  return 1
}

ip_from_imds="$(get_imds_local_ipv4 2>/dev/null || true)"
if [[ -n "${ip_from_imds:-}" ]]; then
  echo "$ip_from_imds"
  exit 0
fi

# Fallback: ip route get
ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
EOF
  )

  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Detecting AWS Private IPv4 on remote (IMDS / ip route)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    warn "Auto-detect failed."
    out_file=""
  fi

  if [[ -n "${out_file:-}" && -f "$out_file" ]]; then
    out="$(tr -d '\r' <"$out_file" | tail -n 20)"
    rm -f "$out_file" >/dev/null 2>&1 || true
    ip="$(echo "$out" | tail -n1 | tr -d '[:space:]')"
  else
    ip=""
  fi

  if ! is_valid_ipv4 "${ip:-}"; then
    spinner_stop_fail "Detecting AWS Private IPv4 on remote (IMDS / ip route)"
    warn "Could not reliably detect AWS Private IPv4 automatically."

    while true; do
      read -r -p "Enter Kharej PRIVATE IPv4 (from AWS console, e.g. 172.x.x.x): " KHAREJ_PRIVATE_IP
      is_valid_ipv4 "$KHAREJ_PRIVATE_IP" && break
      echo -e "${RED}Invalid IP format.${NC}"
    done
  else
    KHAREJ_PRIVATE_IP="$ip"
    spinner_stop_ok "AWS private IPv4 detected: $KHAREJ_PRIVATE_IP"
  fi

  KHAREJ_GRE_LOCAL_IP="$KHAREJ_PRIVATE_IP"
  ok "Kharej local IP for GRE set to PRIVATE IP: $KHAREJ_GRE_LOCAL_IP"
}

# ---------- GRE config ----------
remote_prepare_kernel() {
  local payload out_file
  payload=$(
    cat <<'EOF'
set -euo pipefail

# Load GRE module if possible (ignore if built-in)
modprobe ip_gre 2>/dev/null || true

# rp_filter off (prevents asymmetric drop)
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.ens5.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth0.rp_filter=0 >/dev/null 2>&1 || true

true
EOF
  )
  out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")" || {
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote kernel prep failed."
  }
  rm -f "$out_file" >/dev/null 2>&1 || true
}

configure_remote_gre() {
  spinner_start "Configuring GRE on Kharej (remote)"
  local payload out_file

  payload=$(
    cat <<'EOF'
set -euo pipefail

ip link show To_IR >/dev/null 2>&1 && ip tunnel del To_IR >/dev/null 2>&1 || true

ip tunnel add To_IR mode gre remote <IRAN_LOCAL_IP> local <KHAREJ_GRE_LOCAL_IP> ttl 255
ip addr add 172.20.20.2/30 dev To_IR
ip link set To_IR mtu 1436
ip link set To_IR up

ip -d link show To_IR
ip -4 addr show dev To_IR
EOF
  )
  payload="${payload//<IRAN_LOCAL_IP>/$IRAN_LOCAL_IP}"
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

  # rp_filter off locally too
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

  del_tunnel_if_exists "To_Kharej"
  ip tunnel add To_Kharej mode gre remote "$KHAREJ_PUBLIC_IP" local "$IRAN_LOCAL_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up
  spinner_stop_ok "Local GRE configured"
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
    warn "GRE is configured, but ICMP didn't pass."
    echo
    echo "If this is AWS and you see GRE packets arriving but no replies:"
    echo "  1) Ensure Kharej GRE local IP is PRIVATE IPv4 (this script uses: $KHAREJ_GRE_LOCAL_IP)"
    echo "  2) Ensure SG/NACL allow Protocol 47 (GRE)"
    echo "  3) rp_filter is disabled by script; verify:"
    echo "       sysctl net.ipv4.conf.all.rp_filter"
    echo "  4) Run tcpdump:"
    echo "       Local : tcpdump -ni <public-if> proto 47"
    echo "       Remote: tcpdump -ni <nic> proto 47"
    echo "       Remote: tcpdump -ni To_IR icmp"
  fi
}

# ---------- Traffic mode (NAT/DNAT) ----------
enable_forwarding_and_nat_local() {
  spinner_start "Enabling IPv4 forwarding + NAT rules (local)"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Your rules (idempotent)
  iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.20.20.1
  iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination 172.20.20.2
  iptables_rule_once -t nat -A POSTROUTING -j MASQUERADE

  spinner_stop_ok "Local forwarding/NAT configured"
}

enable_forwarding_remote_if_needed() {
  # optional: for some scenarios you want forwarding on remote too
  spinner_start "Enabling IPv4 forwarding on remote (Kharej)"
  local payload out_file
  payload=$(
    cat <<'EOF'
set -euo pipefail
sysctl -w net.ipv4.ip_forward=1 >/dev/null
true
EOF
  )
  if ! out_file="$(run_remote_payload_b64_capture "$KHAREJ_PUBLIC_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$SUDO_PASS" "$payload")"; then
    spinner_stop_fail "Enabling IPv4 forwarding on remote (Kharej)"
    if [[ "$DEBUG" == "true" && -f "$out_file" ]]; then cat "$out_file" >&2; fi
    rm -f "$out_file" >/dev/null 2>&1 || true
    die "Remote forwarding enable failed."
  fi
  rm -f "$out_file" >/dev/null 2>&1 || true
  spinner_stop_ok "Remote forwarding enabled"
}

# ---------- Status ----------
show_status() {
  echo
  echo -e "${CYAN}${BOLD}=== Status (Local) ===${NC}"
  echo "Version             : ${SCRIPT_VERSION}"
  echo "Iran local IPv4      : ${IRAN_LOCAL_IP:-N/A}"
  echo "Kharej public IPv4   : ${KHAREJ_PUBLIC_IP:-N/A}"
  echo "Kharej private IPv4  : ${KHAREJ_PRIVATE_IP:-N/A}"
  echo "Kharej GRE local IP  : ${KHAREJ_GRE_LOCAL_IP:-N/A}"
  echo "AWS mode             : ${IS_AWS:-N/A}"
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

  echo -e "${BOLD}sysctl (local):${NC}"
  echo "  ip_forward : $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo N/A)"
  echo "  rp_filter  : all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo N/A), default=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo N/A)"
  echo

  echo -e "${BOLD}iptables nat (local):${NC}"
  iptables -t nat -S 2>/dev/null || true
  echo
}

# ---------- Main actions ----------
configure_gre_link_only() {
  info "--- Iran Server (Local) Configuration ---"
  prompt_inputs
  preflight_ssh
  detect_remote_private_ip_if_needed

  echo
  ok "Using Kharej GRE local IP: $KHAREJ_GRE_LOCAL_IP"
  if [[ "$IS_AWS" == "true" ]]; then
    ok "AWS mode: remote GRE local=PRIVATE, remote reachable via PUBLIC"
    warn "If you want traffic forwarding later: disable Source/Dest Check for the EC2 instance."
  else
    ok "Normal mode: remote GRE local=PUBLIC"
  fi
  echo

  remote_prepare_kernel
  configure_remote_gre
  configure_local_gre
  test_link
}

configure_gre_with_traffic() {
  configure_gre_link_only
  echo
  info "Enabling traffic forwarding mode..."
  enable_forwarding_and_nat_local
  enable_forwarding_remote_if_needed

  echo
  ok "Traffic mode enabled."
  if [[ "$IS_AWS" == "true" ]]; then
    warn "AWS reminder: for forwarding real traffic through EC2, disable Source/Dest Check on the instance."
    warn "Also ensure SG/NACL allow GRE (proto 47) and your desired forwarded ports."
  fi
}

main_menu() {
  print_banner
  echo "1) Configure GRE Link only (IPv4)  [PING TEST]"
  echo "2) Configure GRE + Traffic Forwarding (NAT/DNAT)"
  echo "3) Status (Local)"
  echo "4) Info"
  echo "0) Exit"
  echo
  read -r -p "Select: " choice
  case "$choice" in
    1) configure_gre_link_only; pause ;;
    2) configure_gre_with_traffic; pause ;;
    3) show_status; pause ;;
    4)
      echo
      echo "Info:"
      echo "- AWS: remote GRE 'local' must be PRIVATE IPv4"
      echo "- AWS traffic: likely needs Source/Dest Check disabled"
      echo "- rp_filter is disabled by this script on both ends"
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
