# Cantina

![Cantina - OSCP-legal network recon orchestrator](banner.jpg)

```
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣀⣸⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠴⠾⠿⠿⠿⠛⠋⠁⠀⣠⣴⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣄⣀⣀⣀⣀⣀⣤⣤⣴⠶⠛⢋⣡⣴⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣬⣉⣉⣉⣉⡟⣁⠀⠀⠈⠙⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⡀⠛⠀⠀⠀⠀⣿⣿⠋⠉⠙⢿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⣀⣴⣿⣇⠀⠀⠀⣸⣿⣿⡿⠀⠀⠀⠀⠀⠀C A N T I N A
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡴⠟⠛⣁⠤⠂⠀⠀⠀⠀⠀Network Recon v1.3.3
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠛⠛⣉⣡⠤⠒⠋⠁⢀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⠬⣉⣉⣉⣉⣠⠤⠤⠤⠴⠒⠚⠉⠁⠀⠀⠀⣤⣾⣿⣿⣿⣶⣄⡀⠀⠀"You'll never find a more
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣦⣤⣤⣤⣤⣤⣤⣤⣤⣴⣶⣶⣦⡀⠀⠈⠙⢿⣿⠋⠛⣿⣿⣦⡀ wretched hive of scans
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠿⠛⠉⠉⠉⠉⠉⠛⠿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⢿⣿⣿⣿ and enumery."
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠟⠁⢀⣠⣤⣤⣤⣄⡀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠉⠉
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⣴⣿⣿⣿⣿⣿⠟⠀⢀⡀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠇⠀⠀⢹⣿⣿⣿⣿⣿⣤⣴⣿⣿⡄⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⣿⣦⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⠻
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⡿⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡀⠸⣿⡿⢿⣿⣿⣿⣿⣿⣄⠀⠈⠁⠀⠀⢀⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⣠⣤⣶
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣧⠀⠙⠀⢰⣿⣿⣿⣿⣿⣿⡷⠀⠀⠀⠀⣼⣿⣿⣿⣿⡟⠁⠀⠀⣠⡀⠀⢻⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣷⡀⠀⠘⠛⠿⠿⠿⠛⠉⠀⠀⠀⢀⣾⣿⣿⣿⣿⠏⠀⠀⢀⣴⣿⣷⣤⣼⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⡏⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣷⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⠋
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠘⠛⠛⣹⣿⣿⣿⠟⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢠⣶⣿⣿⡿⠟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠈⠻⠿⠛⠉⠀⠀⠀⠀⠀
⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠛⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀
```

*(Same art as the CLI banner in `cantina.py` - see [`assets/banner.txt`](assets/banner.txt).)*

**Cantina** is an OSCP-legal network recon orchestrator. Port discovery, service enum, and plugin dispatch. No exploitation. No credential spray auto-run.

---

## What it does

1. Scans targets (`quick` / `full` / `udp` / `vuln` / `recon` / `all` / `deep`)
2. Classifies open services
3. Runs **enum-only plugins** for matching services (HTTP, SMB, FTP, SNMP, SSH, and the rest)
4. Writes per-port artifacts, `_commands.log` audit, optional HTML/JSON

## Requirements

- Python 3.10+
- Kali (or similar) tools when available: `nmap`, and service tools plugins call when present
- Soft deps only: missing tools are skipped, not fatal

## Quick start

```bash
# list plugins (no scan)
python cantina.py --list-plugins

# single host
python cantina.py 10.10.10.5 -t quick

# full enum with known ports (skip rediscovery)
python cantina.py 10.10.10.5 -t recon \
  --force-services tcp/80/http tcp/445/smb tcp/22/ssh \
  -o ./out -j

# multi-target concurrent
python cantina.py -T hosts.txt -t all --max-workers 3 --timeout 90
```

Quiet CLI (no banner): `python cantina.py TARGET -q`

## Plugins

Drop a module under `plugins/` (or `--plugins-dir`):

```python
PLUGIN = {
    "name": "my_enum",
    "services": ["ftp"],
    "ports": [21],
    "enabled": True,
    "replaces_builtin": True,
    "description": "FTP enum (enum only)",
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return signals.get("svc_type") == "ftp" or int(signals.get("port") or 0) == 21

def run(ctx):
    art = ctx.port_dir / "plugin_my_enum.txt"
    art.write_text(f"enum note for {ctx.target}:{ctx.port}\n")
    return {"ok": True, "artifact": str(art)}
```

`replaces_builtin: True` skips the old monorepo branch for that service so you do not double-run.

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

## Legal

Enumeration only. Authorized targets and own lab / OSCP exam scope only. You are responsible for scope.

## Layout

```
cantina.py          CLI + orchestrator (includes banner)
cantina_plugins.py  discover / select / run
plugins/            service enum plugins
assets/banner.txt   same art as CLI banner
banner.jpg          README hero image
tests/              unit tests (stubbed tools)
lab/                optional multi-service lab ground truth
fixtures/           nmap parse fixtures
```
