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
NC="\033[0m"

die() { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo). Example: sudo ./gre-tunnel-wizard.sh"
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
  local i=0 p=0 step=5 sleep_s=0.4
  while (( p <= 100 )); do
    printf "\rConfiguring remote server... %3d%% %s" "$p" "${frames[i]}"
    i=$(( (i + 1) % 4 ))
    p=$(( p + step ))
    sleep "$sleep_s"
  done
  printf "\rConfiguring remote server... 100%% ✓\n"
}

pause() { read -r -p "Press Enter to continue... " _; }

# ---------------- Local deps (Iran server) ----------------
APT_UPDATED=0
apt_update_once() {
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    apt-get update -y >/dev/null 2>&1 || true
    APT_UPDATED=1
  fi
}

ensure_local_deps() {
  # We do NOT force sshpass anymore. We'll use it if present, otherwise plain ssh.
  if command_exists apt-get; then
    info "Checking local dependencies..."
    apt_update_once
    apt-get install -y iproute2 iptables openssh-client iputils-ping >/dev/null 2>&1 || true
    ok "Local dependencies ready."
  else
    command_exists ip || die "'ip' is missing."
    command_exists iptables || die "'iptables' is missing."
    command_exists ssh || die "'ssh' is missing."
    command_exists ping || die "'ping' is missing."
  fi
}

# ---------------- SSH runner (sshpass optional) ----------------
# If sshpass exists, run fully non-interactive.
# If not, run plain ssh and user will enter password manually (no install required).
run_remote() {
  local host="$1" port="$2" user="$3" pass="$4" cmd="$5" debug="${6:-false}"
  local tmp
  tmp="$(mktemp)"

  if command_exists sshpass; then
    sshpass -p "$pass" ssh \
      -p "$port" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o ConnectTimeout=10 \
      "$user@$host" \
      "bash -lc '$cmd'" >"$tmp" 2>&1 || {
        if [[ "$debug" == "true" ]]; then
          echo -e "${RED}Remote output (debug):${NC}"
          cat "$tmp" >&2
        fi
        rm -f "$tmp"
        return 1
      }
  else
    warn "sshpass not found. Using normal SSH (you may be prompted for password)."
    ssh \
      -p "$port" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o ConnectTimeout=10 \
      "$user@$host" \
      "bash -lc '$cmd'" >"$tmp" 2>&1 || {
        if [[ "$debug" == "true" ]]; then
          echo -e "${RED}Remote output (debug):${NC}"
          cat "$tmp" >&2
        fi
        rm -f "$tmp"
        return 1
      }
  fi

  rm -f "$tmp"
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

  read -r -s -p "SSH password (press Enter if using SSH key): " SSH_PASS
  echo

  read -r -p "Enable debug logs if remote fails? (true/false) [false]: " DEBUG
  DEBUG="${DEBUG:-false}"

  echo
  echo "Summary:"
  echo "  Iran IPv4  : $IRAN_IP"
  echo "  Kharej IPv4: $KHAREJ_IP"
  echo "  SSH        : $SSH_USER@$KHAREJ_IP:$SSH_PORT"
  echo

  # ---------- Remote preflight + config ----------
  # - Ensure ip is available (install iproute2 if apt exists)
  # - Ensure we run as root or via sudo
  # - Make it re-runnable (delete existing To_IR first)
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

  progress_8s
  if ! run_remote "$KHAREJ_IP" "$SSH_PORT" "$SSH_USER" "$SSH_PASS" "$remote_cmd" "$DEBUG"; then
    die "Remote configuration failed. Try debug=true, or use root / passwordless sudo on Kharej."
  fi
  ok "Kharej server configured."
  echo

  # ---------- Local (Iran) config ----------
  info "Configuring Iran server now..."

  del_tunnel_if_exists "To_Kharej"
  ip tunnel add To_Kharej mode gre remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255
  ip addr add 172.20.20.1/30 dev To_Kharej
  ip link set To_Kharej mtu 1436
  ip link set To_Kharej up

  ok "Iran GRE interface configured."
  echo

  # ---------- Forwarding & NAT (Iran) ----------
  info "Enabling forwarding and applying iptables rules..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Your exact rules, idempotent:
  add_iptables_rule_once -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.20.20.1
  add_iptables_rule_once -t nat -A PREROUTING -j DNAT --to-destination 172.20.20.2
  add_iptables_rule_once -t nat -A POSTROUTING -j MASQUERADE

  ok "Forwarding rules applied."
  echo

  # ---------- Test ----------
  info "Testing tunnel (ping 172.20.20.2 from Iran)..."
  if ping -c 3 -W 2 172.20.20.2 >/dev/null 2>&1; then
    ok "END: Tunnel created successfully."
  else
    warn "END (with warning): Tunnel is up, but ping failed."
    echo "Check firewall/provider: GRE protocol 47 must be allowed."
  fi
}

show_info() {
  echo -e "${CYAN}GRE Tunnel Wizard${NC}"
  echo "Created by: Hamed Jafari"
}

main_menu() {
  clear
  echo "=============================="
  echo " GRE Tunnel Wizard (IPv4)"
  echo " Created by: Hamed Jafari"
  echo "=============================="
  echo
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
