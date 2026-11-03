#!/usr/bin/env python3
"""
HomeSIEM - lightweight network monitor for networks YOU own.
Runs on Windows / Linux / macOS / Raspberry Pi. Needs Python 3.7+.
Optional: `pip install scapy` for live packet inspection (needs admin/root + Npcap on Windows).

  python siem.py                 # dashboard on http://127.0.0.1:8080
  python siem.py --host 0.0.0.0  # reachable from other devices on your LAN
"""
import argparse, collections, ipaddress, json, os, platform, re, secrets, socket
import sqlite3, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, DNSQR
    SCAPY = True
except Exception:
    SCAPY = False

OS = platform.system()
HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "siem.db")
TOKEN_PATH = os.path.join(HERE, ".token")
BLOCKLIST = os.path.join(HERE, "blocklist.txt")   # one bad domain per line
WORKERS = 20                                       # devices probed at once
SCAN_EVERY = 60                                    # seconds between sweeps
KEEP_ALERTS = 5000                                 # log rotation
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 554, 1883, 3389, 5900, 8080]

lock = threading.RLock()
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.executescript("""
CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT, name TEXT,
  first_seen REAL, last_seen REAL, online INT, blocked INT DEFAULT 0, trusted INT DEFAULT 0,
  ports TEXT DEFAULT '', rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL,
  sev TEXT, kind TEXT, msg TEXT);
""")

# ---------------------------------------------------------------- alerts
_cool = {}
def alert(sev, kind, msg, key=None, cooldown=60):
    k = (kind, key or msg)
    now = time.time()
    if now - _cool.get(k, 0) < cooldown:
        return
    _cool[k] = now
    with lock:
        db.execute("INSERT INTO alerts(ts,sev,kind,msg) VALUES(?,?,?,?)", (now, sev, kind, msg))
        db.execute("DELETE FROM alerts WHERE id <= (SELECT MAX(id) FROM alerts) - ?", (KEEP_ALERTS,))
        db.commit()
    print(f"[{sev.upper()}] {kind}: {msg}")

# ---------------------------------------------------------------- discovery
def local_net():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1)); ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip, ipaddress.ip_network(ip + "/24", strict=False)   # assumes /24 (typical home LAN)

def ping(ip):
    if OS == "Windows": cmd = ["ping", "-n", "1", "-w", "500", ip]
    elif OS == "Darwin": cmd = ["ping", "-c", "1", "-W", "500", ip]
    else: cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except Exception:
        pass

def arp_table():
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return {}
    res = {}
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\D+?((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})", line)
        if not m:
            continue
        ip = m.group(1)
        mac = ":".join(p.zfill(2) for p in re.split(r"[:-]", m.group(2).lower()))
        if mac.startswith(("ff:ff", "01:00:5e")) or ip.endswith(".255") or ip.startswith("224."):
            continue
        res[ip] = mac
    return res

def resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def port_scan(ip):
    def probe(p):
        s = socket.socket(); s.settimeout(0.5)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        finally:
            s.close()
    with ThreadPoolExecutor(WORKERS) as ex:
        return [p for p in ex.map(probe, COMMON_PORTS) if p]

scan_state = {"running": False, "last": 0, "subnet": ""}

def scan_once():
    if scan_state["running"]:
        return
    scan_state["running"] = True
    try:
        me, net = local_net()
        scan_state["subnet"] = str(net)
        with ThreadPoolExecutor(WORKERS) as ex:           # 20 devices at a time
            list(ex.map(ping, [str(h) for h in net.hosts()]))
        table = arp_table()
        now = time.time()
        with lock:
            db.execute("UPDATE devices SET online=0")
            for ip, mac in table.items():
                if ipaddress.ip_address(ip) not in net:
                    continue
                row = db.execute("SELECT mac,name FROM devices WHERE mac=?", (mac,)).fetchone()
                if row is None:
                    name = resolve(ip)
                    db.execute("INSERT INTO devices(mac,ip,name,first_seen,last_seen,online) VALUES(?,?,?,?,?,1)",
                               (mac, ip, name, now, now))
                    alert("warn", "new-device", f"New device {ip} ({mac}) {name}", key=mac, cooldown=3600)
                else:
                    db.execute("UPDATE devices SET ip=?,last_seen=?,online=1 WHERE mac=?", (ip, now, mac))
            db.commit()
        scan_state["last"] = now
    finally:
        scan_state["running"] = False

def scan_loop():
    while True:
        try: scan_once()
        except Exception as e: print("scan error:", e)
        time.sleep(SCAN_EVERY)

# ---------------------------------------------------------------- packet analysis
traffic = collections.defaultdict(lambda: [0, 0])      # ip -> [rx, tx] since last flush
ports_seen = collections.defaultdict(dict)            # src ip -> {(dst,port): ts}
arp_map = {}
history = collections.deque(maxlen=120)               # bytes/sec for sparkline
totals = {"pkts": 0, "bytes": 0}
bad_domains = set()
if os.path.exists(BLOCKLIST):
    bad_domains = {l.strip().lower() for l in open(BLOCKLIST) if l.strip() and not l.startswith("#")}

def on_packet(p):
    totals["pkts"] += 1
    n = len(p); totals["bytes"] += n
    if p.haslayer(ARP) and p[ARP].op == 2:
        ip, mac = p[ARP].psrc, p[ARP].hwsrc.lower()
        if arp_map.get(ip, mac) != mac:
            alert("high", "arp-spoof", f"{ip} changed MAC {arp_map[ip]} -> {mac} (possible ARP spoofing)", key=ip)
        arp_map[ip] = mac
        return
    if not p.haslayer(IP):
        return
    src, dst = p[IP].src, p[IP].dst
    traffic[src][1] += n; traffic[dst][0] += n
    if p.haslayer(TCP) and p[TCP].flags & 0x02 and not p[TCP].flags & 0x10:      # SYN only
        now = time.time(); seen = ports_seen[src]
        seen[(dst, p[TCP].dport)] = now
        for k in [k for k, t in seen.items() if now - t > 10]:
            del seen[k]
        if len(seen) > 25:
            alert("high", "port-scan", f"{src} touched {len(seen)} host:port pairs in 10s (port scan?)", key=src)
    if p.haslayer(UDP) and p.haslayer(DNSQR):
        q = p[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
        if any(q == d or q.endswith("." + d) for d in bad_domains):
            alert("high", "bad-dns", f"{src} looked up blocklisted domain {q}", key=src + q)

def flush_loop():
    last = 0
    while True:
        time.sleep(5)
        with lock:
            for ip, (rx, tx) in list(traffic.items()):
                db.execute("UPDATE devices SET rx=rx+?, tx=tx+? WHERE ip=?", (rx, tx, ip))
                if tx > 50_000_000:   # >50 MB upload in 5 s
                    alert("warn", "high-upload", f"{ip} sent {tx//1_000_000} MB in 5s", key=ip)
            traffic.clear(); db.commit()
        history.append((totals["bytes"] - last) // 5); last = totals["bytes"]

def sniff_loop():
    try:
        sniff(filter="ip or arp", prn=on_packet, store=False)
    except Exception as e:
        alert("warn", "sniffer", f"Packet capture stopped: {e}. Run as admin/root.", cooldown=3600)

# ---------------------------------------------------------------- access control
def run_hook(action, mac, ip):
    hook = os.path.join(HERE, "router_hook.sh" if OS != "Windows" else "router_hook.bat")
    if os.path.exists(hook):
        subprocess.run([hook, action, mac, ip], timeout=30)       # plug your router API in here

def set_block(mac, block):
    with lock:
        row = db.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
        if not row:
            return False
        ip = row[0]
        db.execute("UPDATE devices SET blocked=? WHERE mac=?", (int(block), mac)); db.commit()
    try:
        if OS == "Linux":       # effective when this machine is the gateway (Pi hotspot/router)
            flag = "-I" if block else "-D"
            for chain in ("FORWARD", "INPUT"):
                subprocess.run(["iptables", flag, chain, "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                               capture_output=True)
        elif OS == "Windows":   # blocks the device from reaching THIS PC
            name = "HomeSIEM-" + mac
            cmd = (["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                    "action=block", f"remoteip={ip}"] if block else
                   ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            subprocess.run(cmd, capture_output=True)
        run_hook("block" if block else "unblock", mac, ip)
    except Exception as e:
        print("block error:", e)
    alert("info", "access", f"{'Blocked' if block else 'Unblocked'} {mac} ({ip})", key=mac + str(block), cooldown=0)
    return True

# ---------------------------------------------------------------- web
def get_token():
    if os.path.exists(TOKEN_PATH):
        return open(TOKEN_PATH).read().strip()
    t = secrets.token_urlsafe(16); open(TOKEN_PATH, "w").write(t); return t
TOKEN = get_token()

def state():
    with lock:
        cols = ["mac", "ip", "name", "first_seen", "last_seen", "online", "blocked", "trusted", "ports", "rx", "tx"]
        devs = [dict(zip(cols, r)) for r in db.execute(
            "SELECT " + ",".join(cols) + " FROM devices ORDER BY online DESC, ip")]
        al = [dict(zip(["id", "ts", "sev", "kind", "msg"], r)) for r in db.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 100")]
    return {"devices": devs, "alerts": al, "history": list(history), "pkts": totals["pkts"],
            "sniffer": SCAPY, "scanning": scan_state["running"], "subnet": scan_state["subnet"],
            "os": OS}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/api/state":
            return self.send(200, json.dumps(state()))
        if self.path == "/":
            return self.send(200, open(os.path.join(HERE, "dashboard.html"), "rb").read(), "text/html; charset=utf-8")
        self.send(404, "{}")
    def do_POST(self):
        if self.headers.get("X-Token") != TOKEN:
            return self.send(403, '{"error":"bad token"}')
        n = int(self.headers.get("Content-Length") or 0)
        d = json.loads(self.rfile.read(n) or b"{}")
        mac = str(d.get("mac", "")).lower()
        if self.path == "/api/scan":
            threading.Thread(target=scan_once, daemon=True).start()
        elif self.path == "/api/block":   set_block(mac, True)
        elif self.path == "/api/unblock": set_block(mac, False)
        elif self.path == "/api/trust":
            with lock:
                db.execute("UPDATE devices SET trusted=1-trusted WHERE mac=?", (mac,)); db.commit()
        elif self.path == "/api/ports":
            def job():
                with lock: r = db.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
                if r:
                    ps = port_scan(r[0])
                    with lock:
                        db.execute("UPDATE devices SET ports=? WHERE mac=?", (",".join(map(str, ps)), mac)); db.commit()
            threading.Thread(target=job, daemon=True).start()
        else:
            return self.send(404, "{}")
        self.send(200, '{"ok":true}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=flush_loop, daemon=True).start()
    if SCAPY:
        threading.Thread(target=sniff_loop, daemon=True).start()
    else:
        print("scapy not installed: device scanning works, live packet inspection is off (pip install scapy)")
    print(f"Dashboard: http://{a.host}:{a.port}   Control token: {TOKEN}")
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()

if __name__ == "__main__":
    main()
