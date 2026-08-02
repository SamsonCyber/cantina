# Cantina lab target (CT 100)

Example multi-service OSCP-style enum surface for scoring cantina deep mode.
Hostnames and IPs below are placeholders. Point them at your own lab.

| Field | Value |
|-------|--------|
| Proxmox | lab-hypervisor (`10.10.10.10`) |
| CT | 100 `cantina-lab` |
| IP | `10.10.10.50` |
| Disk | 12G on local-zfs |
| RAM | 2G |

## What is listening

Common: SSH, FTP (anon), Telnet, HTTP multi-port, SMB, MySQL, Postgres, Redis, rsync, DNS, Juice Shop `:3000`.

Obscure / fake banners (via `cantina-extra-ports`): 2121, 2323, 4444, 5000, 5601, 6378, 7001, 8443, 9200, 11211, 27017.

UDP: DNS 53, NetBIOS 137, SNMP 161 (`public`).

Ground truth: `cantina_lab_expected.json`.

## Recreate / repair services

```bash
# from lab-hypervisor
pct push 206 /path/to/cantina_lab_setup.sh /tmp/cantina_lab_setup.sh
pct exec 206 -- bash /tmp/cantina_lab_setup.sh
```

## Live deep run (from Kali)

Enumeration only. Short tools can run while deep continues.

```bash
# deploy tools once
scp cantina.py cantina_score.py cantina_live_bench.py findings.py tui.py report.py jedi.nse kali@KALI:~/cantina-tools/
scp -r lab kali@KALI:~/cantina-tools/

# background deep (sudo if you want UDP 137/161)
sudo python3 ~/cantina-tools/cantina.py 10.10.10.50 -t deep --background \
  -o ~/cantina-live/10.10.10.50 -j --rate 4

# poll progress (does not block short tools)
python3 ~/cantina-tools/cantina.py --status -o ~/cantina-live/10.10.10.50

# score vs ground truth (any time; re-run after complete for final)
python3 ~/cantina-tools/cantina_live_bench.py \
  -o ~/cantina-live/10.10.10.50 \
  --expected ~/cantina-tools/lab/cantina_lab_expected.json
```

## OSCP scope

- Enum orchestration only: port/service discovery, version, script banners, service-specific recon tools.
- No exploit payloads, no password spray campaigns, no shell delivery.
- `deep` + `--background` is the long job; `quick` / jarjar / jawa stay short-running in the foreground.

## Decision branches (v1.3)

Recon is **probe → decide → run**:

| Service | Light (always if open) | Heavy (conditional) |
|---------|------------------------|---------------------|
| HTTP | curl probe, whatweb | ferox/nikto only if real app (not tiny fake banners); wpscan if WP |
| SMB | smbclient null | enum4linux/smbmap if null works |
| FTP | nmap ftp scripts | anon list/write only if anon allowed |
| Redis | PING | INFO only on PONG; never redis-brute |
| SNMP | public/private probe | walk only if community valid; never snmp-brute |
| VNC | vnc-info | no auto hydra/vnc-brute |

Audit trail: `recon/decision_log.jsonl` and `cantina.json` → `decisions`.

## Metrics that matter

| Metric | Meaning |
|--------|---------|
| `lab_recall_tcp` | fraction of expected TCP ports found |
| `lab_recall_obscure` | fraction of obscure tier ports found |
| `lab_recall_udp` | fraction of expected UDP ports found (needs root) |
| `lab_weighted_coverage` | weighted hit rate (obscure ports count more) |
| `composite` | blend of completeness + weighted coverage + obscure recall |
