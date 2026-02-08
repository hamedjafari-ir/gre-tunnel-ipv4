# GRE Tunnel Wizard (IPv4)
**Created by Hamed Jafari**

---

## Language
- [English](#english)
- [فارسی](#persian)

---

<a id="english"></a>
# English

Interactive Bash wizard to configure a GRE (IPv4) tunnel between an **Iran server** and a **Kharej server** via SSH.

## Quick Install (One Command)

Run this on the Iran server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hamedjafari-ir/gre-tunnel-ipv4/main/gre-tunnel-wizard.sh)
```

If `sshpass` is not installed:

```bash
sudo apt-get update && sudo apt-get install -y sshpass
```

## What the script does

- Detects Iran public IPv4 automatically
- Asks for Kharej server IP
- Connects to Kharej via SSH
- Configures GRE tunnel on both servers
- Enables IP forwarding
- Applies NAT rules
- Tests the tunnel connectivity

## Requirements

- Ubuntu / Debian based system
- Root or sudo access
- SSH access to Kharej server
- GRE protocol (47) must be allowed by provider/firewall

---

<a id="persian"></a>
# فارسی

اسکریپت Bash برای راه‌اندازی خودکار تونل GRE (IPv4) بین **سرور ایران** و **سرور خارج** از طریق SSH.

## نصب سریع (با یک دستور)

این دستور را روی سرور ایران اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hamedjafari-ir/gre-tunnel-ipv4/main/gre-tunnel-wizard.sh)
```

اگر پکیج `sshpass` نصب نیست:

```bash
sudo apt-get update && sudo apt-get install -y sshpass
```

## کارهایی که اسکریپت انجام می‌دهد

- تشخیص خودکار IP ورژن 4 سرور ایران
- دریافت IP سرور خارج از کاربر
- اتصال SSH به سرور خارج
- تنظیم کامل تونل GRE در هر دو سرور
- فعال‌سازی IP Forward
- اعمال تنظیمات NAT
- تست اتصال تونل

## پیش‌نیازها

- سیستم Ubuntu یا Debian
- دسترسی root یا sudo
- دسترسی SSH به سرور خارج
- باز بودن پروتکل GRE (شماره 47) در فایروال یا ارائه‌دهنده سرور

---

**GRE Tunnel Wizard**  
GRE over IPv4  
Made with care by Hamed Jafari
