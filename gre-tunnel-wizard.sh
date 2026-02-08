#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# GRE Tunnel Wizard (GRE over IPv4)
# Created by: Hamed Jafari
# ==========================================================

# ---------- Colors ----------
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
NC="\033[0m"

# ---------- Helpers ----------
die() { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root (sudo). Example: sudo ./gre-tunnel-wizard.sh"
  fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

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

progress_8s() {
  local frames=("-" "\\" "|" "/")
  local i=0
  local p=0
  local step=5
  local sleep_s=0.4  # 20 steps * 0.4 = 8 seconds
  while (( p <= 100 )); do
    printf "\rConfiguring remote server... %3d%% %s" "$p" "${frames[i]}"
    i=$(( (i + 1) % 4 ))
    p=$(( p + step ))
    sleep "$sleep_s"
  done
  printf "\rConfiguring remote server... 100%% ✓\n"
}

pause() { read -r -p "Press Enter to continue... " _; }

# ---------- Dependency auto-install ----------
ensure_apt_pkg() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    return 0
  fi
  info "Installing dependency: $pkg"
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y "$pkg" >/dev/null 2>&1 || die "Failed to install $pkg. Install it manually and retry."
}

ensure_deps() {
  # Best effort auto install on Debian/Ubuntu
  if command_exists apt-get && command_exists dpkg; then
    ensure_apt_pkg "iproute2"
    ensure_apt_pkg "iptables"
    ensure_apt_pkg "openssh-client"
    ensure_apt_pkg "sshpass"
    ensure_apt_pkg "iputils-ping"
  else
    warn "Auto-install is only implemented for Debian/Ubuntu (apt)."
    warn "Make sure these exist: ip, iptables, ssh, sshpass, ping"
    command_exists ip || die "'ip' is missing."
    command_exists iptables || die "'iptables' is missing."
    command_exists ssh || die "'ssh' is missing."
    command_exists sshpass || die "'sshpass' is missing."
    command_exists ping || die "'ping' is missing."
  fi
}

# ---------- Remote execution (hidden output) ----------
run_remote_hidden() {
  local host="$1" port="$2" user="$3" pass="$4" cmd="$5"

  # No output to the user
  sshpass -p "$pass" ssh \
    -p "$port" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=10 \
    "$user@$host" \
    "bash -lc '$cmd'" >/dev/null 2>&1
}

# ---------- Idempotent local helpers ----------
del_tunnel_if_exists() {
  local name="$1"
  ip link show "$name" >/dev/null 2>&1 && ip tunnel del "$name" >/dev/null 2>&1 || true
}

iptables_rule_exists() {
  # usage: iptables_rule_exists -t nat -A PREROUTING ...
  iptables -C "$@" >/dev/null 2>&1
}

add_iptables_rule_once() {
  # args: table/chain/rule params after -t ...
  if iptables -C "$@" >/dev/null 2>&1; then
    return 0
  fi
  iptables "$@"
}

# ---------- Menu Actions ----------
configure_from_iran() {
  info "--- Iran Server (Local) Configuration ---"

  local detected
  detected="$(detect_ipv4)"
  [[ -n "$detected" ]] || warn "Could not auto-detect IPv4. You may need to enter it manually."

  echo
  echo "Auto-detected Iran IPv4: ${detected:-N/A}"
  read -r -p "Is this the correct Iran server IPv4? (true/false) [true]: " is_auto
  is_auto="${is_auto:-true}"

  local IRAN_IP=""
  if [[ "$is_auto" == "true" ]]; then
    [[ -n "$detected" ]] || die "Auto-detection failed. Rerun and set false to enter Iran IP manually."
    IRAN_IP="$detected"
  elif [[ "$is_auto" == "false" ]]; then
    while true; do
      read -r -p "Enter Iran IPv4: " IRAN_IP
      if is_valid_ipv4 "$IRAN_IP"; then break; fi
      echo -e "${RED}Invalid IP format.${NC} Please enter a valid IPv4 (e.g., 203.0.113.10)."
    done
  else
    die "Only 'true' or 'false' is allowed."
  fi

  echo
  local KHAREJ_IP=""
  while true; do
    read -r -p "Enter Kharej server IPv4 (IP Kharej): " KHAREJ_IP
    if is_valid_ipv4 "$KHAREJ_IP"; then break; fi
    echo -e "${RED}Invalid IP format.${NC} Please enter a valid IPv4 (e.g., 198.51.100.20)."
  done

  local SSH_PORT SSH_USER SSH_PASS
  read -r -p "SSH port for Kharej [22]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-22}"

  read -r -p "SSH user for Kharej [root]: " SSH_USER
  SSH_USER="${SSH_USER:-root}"

  read -r -s -p "SSH password for ${SSH_USER}@${KHAREJ_IP}: " SSH_PASS
  echo

  echo
  echo "Summary:"
  echo "  Iran IPv4  : $IRAN_IP"
  echo "  Kharej IPv4: $KHAREJ_IP"
  echo "  SSH        : $SSH_USER@$KHAREJ_IP:$SSH_PORT"
  echo

  # ---------------- Remote config (Kharej) ----------------
  # Run with sudo if needed; also make it re-runnable (delete existing tunnel first)
  local remote_cmd
  remote_cmd=$(
    cat <<'EOF'
set -euo pipefail

# Elevate if not root (works if user has sudo rights)
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

# Clean existing tunnel (best-effort)
$SUDO ip link show To_IR >/dev/null 2>&1 && $SUDO ip tunnel del To_IR >/dev/null 2>&1 || true

$SUDO ip tunnel add To_IR mode gre remote <IP_IRAN> local <IP_KHAREJ> ttl 255
$SUDO ip addr add 172.20.20.2/30 dev To_IR
$SUDO ip link set To_IR mtu 1436
$SUDO ip link set To_IR up
EOF
  )
  remote_cmd="${remote_cmd//<IP_IRAN>/$IRAN_IP}"
  remote_cmd="${remote_cmd//<IP_KHAREJ>/$KHAREJ_IP}"

  progress_8s
  run_remote_hidden "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_cmd" \
    || die "Remote configuration failed. Check SSH credentials, firewall, and sudo/root access on Kharej."

  ok "Kharej server configured."
  echo

  # ---------------- Local config (Iran) ----------------
  info "Configuring Iran server now..."

  del_tunnel_if_exists "To_Kharej"

  ip tunnel add To_Kharej mode gre remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up

  ok "Iran GRE interface configured."
  echo

  # ---------------- Forwarding & NAT (Iran) ----------------
  info "Enabling forwarding and applying iptables rules..."

  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Your exact rules, but added idempotently (won't duplicate on re-run)
  add_iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.20.20.1
  add_iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination 172.20.20.2
  add_iptables_rule_once -t nat -A POSTROUTING -j MASQUERADE

  ok "Forwarding rules applied."
  echo

  # ---------------- Test ----------------
  info "Testing tunnel (ping 172.20.20.2 from Iran)..."
  if ping -c 3 -W 2 172.20.20.2 >/dev/null 2>&1; then
    ok "END: Tunnel created successfully."
  else
    warn "END (with warning): Tunnel interface is up, but ping failed."
    echo "Check routing, firewall, and whether GRE (protocol 47) is allowed."
  fi
}

show_info() {
  echo -e "${CYAN}GRE Tunnel Wizard${NC}"
  echo "Created by: Hamed Jafari"
  echo
  echo "This script configures a GRE tunnel between Iran and Kharej servers."
  echo "Menus and comments are in English as requested."
}

main_menu() {
  clear
  echo "=============================================="
  echo " GRE Tunnel Wizard (GRE over IPv4)"
  echo " Created by: Hamed Jafari"
  echo "=============================================="
  echo
  echo "1) Configure tunnel from Iran server (local) + remote Kharej config via SSH"
  echo "2) Info"
  echo "0) Exit"
  echo

  read -r -p "Select an option: " choice
  case "$choice" in
    1) configure_from_iran; pause ;;
    2) show_info; pause ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}"; pause ;;
  esac
}

# ---------- Entry ----------
need_root
ensure_deps
while true; do
  main_menu
done
