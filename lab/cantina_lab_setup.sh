#!/bin/bash
# cantina-lab multi-service stack setup (OSCP enum practice target)
# Runs inside CT 100 (10.10.10.50). Enumeration surface only — intentional weak configs.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[*] Configuring multi-service lab on $(hostname) $(hostname -I)"

# ── SSH already default :22 ──────────────────────────────────────────
systemctl enable --now ssh || systemctl enable --now sshd || true

# ── Nginx multi-port HTTP 80 / 8000 / 8080 / 8888 ─────────────────────
mkdir -p /var/www/html /etc/nginx/sites-enabled
cat >/var/www/html/index.html <<'HTML'
<html><body><h1>cantina-lab</h1><p>OSCP-style multi-service enum target</p></body></html>
HTML
cat >/etc/nginx/sites-available/cantina-multi <<'NGX'
server { listen 80 default_server; listen [::]:80 default_server; root /var/www/html; index index.html; server_name _; }
server { listen 8000; root /var/www/html; index index.html; server_name _; location / { try_files $uri $uri/ =404; } add_header X-Powered-By "cantina-lab-nginx-8000"; }
server { listen 8080; root /var/www/html; index index.html; server_name _; location / { try_files $uri $uri/ =404; } add_header Server "Apache-looking-proxy"; }
server { listen 8888; root /var/www/html; index index.html; server_name _; location /api { return 200 '{"status":"ok","service":"fake-api"}'; add_header Content-Type application/json; } }
NGX
ln -sfn /etc/nginx/sites-available/cantina-multi /etc/nginx/sites-enabled/cantina-multi
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx && systemctl reload nginx || systemctl restart nginx

# ── vsftpd :21 ───────────────────────────────────────────────────────
if [ -f /etc/vsftpd.conf ]; then
  sed -i 's/^#\?anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd.conf
  sed -i 's/^#\?local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
  sed -i 's/^#\?write_enable=.*/write_enable=NO/' /etc/vsftpd.conf
  grep -q '^listen=' /etc/vsftpd.conf || echo 'listen=YES' >>/etc/vsftpd.conf
  sed -i 's/^listen_ipv6=.*/listen_ipv6=NO/' /etc/vsftpd.conf || true
  mkdir -p /srv/ftp/pub
  echo "welcome to cantina-lab ftp" >/srv/ftp/pub/readme.txt
  chown -R ftp:ftp /srv/ftp 2>/dev/null || true
  systemctl enable --now vsftpd || true
fi

# ── Samba :139/445 ───────────────────────────────────────────────────
if command -v smbd >/dev/null; then
  cat >/etc/samba/smb.conf <<'SMB'
[global]
   workgroup = CANTINA
   server string = cantina-lab SMB
   map to guest = Bad User
   dns proxy = no
   log file = /var/log/samba/log.%m
   max log size = 50
[public]
   path = /srv/samba/public
   browsable = yes
   read only = yes
   guest ok = yes
SMB
  mkdir -p /srv/samba/public
  echo "public share for enum practice" >/srv/samba/public/note.txt
  systemctl enable --now smbd nmbd || systemctl enable --now smb nmb || true
fi

# ── MariaDB :3306 ────────────────────────────────────────────────────
if command -v mariadbd >/dev/null || command -v mysqld >/dev/null; then
  systemctl enable --now mariadb || systemctl enable --now mysql || true
  # bind all interfaces so remote enum sees the port (lab only)
  if [ -d /etc/mysql/mariadb.conf.d ]; then
    cat >/etc/mysql/mariadb.conf.d/99-cantina-lab.cnf <<'CNF'
[mysqld]
bind-address = 0.0.0.0
skip-networking = 0
CNF
    systemctl restart mariadb || systemctl restart mysql || true
  fi
fi

# ── PostgreSQL :5432 ─────────────────────────────────────────────────
if command -v psql >/dev/null; then
  systemctl enable --now postgresql || true
  # listen on all
  conf=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)
  hba=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)
  if [ -n "$conf" ]; then
    sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$conf"
  fi
  if [ -n "$hba" ]; then
    grep -q 'cantina-lab' "$hba" || echo "host all all 0.0.0.0/0 scram-sha-256 # cantina-lab" >>"$hba"
  fi
  systemctl restart postgresql || true
fi

# ── Redis :6379 ──────────────────────────────────────────────────────
if command -v redis-server >/dev/null; then
  sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf 2>/dev/null || true
  sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf 2>/dev/null || true
  systemctl enable --now redis-server || systemctl enable --now redis || true
  systemctl restart redis-server 2>/dev/null || systemctl restart redis 2>/dev/null || true
fi

# ── SNMP :161/udp ────────────────────────────────────────────────────
if [ -f /etc/snmp/snmpd.conf ]; then
  cat >/etc/snmp/snmpd.conf <<'SNMP'
agentAddress udp:161
rocommunity public default
sysLocation  "cantina-lab"
sysContact   lab@cantina.local
SNMP
  systemctl enable --now snmpd || true
fi

# ── rsync daemon :873 ────────────────────────────────────────────────
cat >/etc/rsyncd.conf <<'RSYNC'
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsync.lock
log file = /var/log/rsync.log
[lab]
  path = /srv/rsync
  comment = cantina lab rsync
  read only = true
  list = yes
RSYNC
mkdir -p /srv/rsync
echo "rsync module" >/srv/rsync/readme.txt
systemctl enable --now rsync 2>/dev/null || true
# if no unit, start detached
if ! ss -lntp | grep -q ':873'; then
  rsync --daemon || true
fi

# ── dnsmasq DNS :53 ──────────────────────────────────────────────────
if command -v dnsmasq >/dev/null; then
  cat >/etc/dnsmasq.d/cantina-lab.conf <<'DNS'
port=53
domain=cantina.lab
address=/target.cantina.lab/10.10.10.50
log-queries
DNS
  # disable systemd-resolved conflict if present
  systemctl disable --now systemd-resolved 2>/dev/null || true
  systemctl enable --now dnsmasq || true
fi

# ── Telnet via inetd :23 ─────────────────────────────────────────────
if [ -f /etc/inetd.conf ]; then
  sed -i 's/^#\?telnet/#telnet/' /etc/inetd.conf || true
  grep -q '^telnet' /etc/inetd.conf || echo 'telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/telnetd' >>/etc/inetd.conf
  systemctl enable --now inetutils-inetd 2>/dev/null || systemctl enable --now openbsd-inetd 2>/dev/null || true
fi

# ── Extra obscure HTTP-ish listeners (python) ────────────────────────
mkdir -p /opt/cantina-lab
cat >/opt/cantina-lab/extra_ports.py <<'PY'
#!/usr/bin/env python3
"""Bind several uncommon ports with distinctive banners for enum practice."""
import socket
import threading
import time

# port -> (proto_hint, banner_bytes)
PORTS = {
    2121: b"220 cantina-lab Fake FTP alternate\r\n",
    2323: b"cantina-lab telnet-alt\r\nlogin: ",
    4444: b"HTTP/1.0 200 OK\r\nServer: cantina-obscure/0.1\r\nContent-Length: 12\r\n\r\nhello-obscure",
    5000: b"HTTP/1.0 200 OK\r\nServer: Werkzeug-like\r\nContent-Type: text/plain\r\n\r\nflask-dev-style",
    5601: b"HTTP/1.0 200 OK\r\nServer: kibana-fake\r\n\r\nkibana-ish",
    6378: b"+PONG\r\n",  # redis-alt
    7001: b"HTTP/1.0 200 OK\r\nServer: WebLogic-looking\r\n\r\n",
    8443: b"HTTP/1.0 200 OK\r\nServer: https-alt-plain\r\n\r\nplain-8443",
    9200: b'{"name":"cantina-lab","cluster_name":"fake-es","tagline":"You Know, for Search"}\n',
    11211: b"ERROR unknown command\r\n",  # memcached-ish
    27017: b"",  # bare accept for mongo port presence
}

def serve(port, banner):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"skip {port}: {e}")
        return
    s.listen(5)
    print(f"listening {port}")
    while True:
        try:
            c, _ = s.accept()
            if banner:
                try:
                    c.sendall(banner)
                except Exception:
                    pass
            time.sleep(0.05)
            c.close()
        except Exception:
            time.sleep(0.1)

for p, b in PORTS.items():
    t = threading.Thread(target=serve, args=(p, b), daemon=True)
    t.start()
print(f"extra_ports up: {sorted(PORTS)}")
while True:
    time.sleep(3600)
PY
chmod +x /opt/cantina-lab/extra_ports.py
cat >/etc/systemd/system/cantina-extra-ports.service <<'UNIT'
[Unit]
Description=Cantina lab obscure port banners
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/cantina-lab/extra_ports.py
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now cantina-extra-ports.service

# ── Juice Shop on :3000 if node available (optional, non-fatal) ───────
if command -v npm >/dev/null && [ ! -d /opt/juice-shop ]; then
  echo "[*] Installing OWASP Juice Shop (may take a while)..."
  cd /opt
  # Prefer dockerless clone if network allows
  if curl -fsSL -o /tmp/juice.tgz "https://github.com/juice-shop/juice-shop/releases/download/v17.1.1/juice-shop-17.1.1_node20_linux_x64.tgz" 2>/dev/null; then
    mkdir -p /opt/juice-shop && tar -xzf /tmp/juice.tgz -C /opt/juice-shop --strip-components=1
    cat >/etc/systemd/system/juice-shop.service <<'UNIT'
[Unit]
Description=OWASP Juice Shop
After=network.target
[Service]
WorkingDirectory=/opt/juice-shop
ExecStart=/usr/bin/npm start
Environment=PORT=3000
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now juice-shop.service || true
  else
    echo "[!] Juice Shop download failed; skipping (other services still up)"
  fi
fi

# ── Inventory ────────────────────────────────────────────────────────
sleep 2
echo "===== LISTENERS ====="
ss -lntu | head -80 || netstat -lntu | head -80
echo "===== DONE cantina-lab ====="
hostname -I
