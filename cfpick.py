#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF-Pick · Cloudflare 入口优选测速台

本地服务 + 浏览器界面。打包成单文件 exe，双击即用。

测速原理：
    连接候选 IP/域名 → 用你的 SNI 做 TLS 握手 → 发一个普通 HTTP 请求
    → 读首字节。CF 按 SNI 找到你的 zone 并回源，所以耗时里包含了
      「你 → CF 边缘」+「CF 边缘 → 你的源站」两段，比只 ping 边缘更真实。
"""

import csv
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP = "CF-Pick"
VERSION = "1.0.1"
DEFAULT_SNI = "cdn.example.com"
DEFAULT_PORT = 443
PORTS = list(range(5390, 5406))

USABLE_CODES_HINT = "200/400/404 = 路径已通（源站拒绝普通请求属正常）"

# Cloudflare 官方边缘网段（IPv4 15 段 + IPv6 7 段）
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CF_NETS = [ipaddress.ip_network(n) for n in CF_RANGES]


def is_cf_ip(ip: str) -> bool:
    """只认 CF 官方网段。非 CF 地址即使返回 200/404 也不是有效入口。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CF_NETS if net.version == addr.version)


# --------------------------------------------------------------------------
# 路径
# --------------------------------------------------------------------------
def base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def res_dir() -> str:
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def data_dir() -> str:
    """配置写 exe 同级目录；不可写时退回 LOCALAPPDATA。"""
    d = base_dir()
    try:
        probe = os.path.join(d, ".write_test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("1")
        os.remove(probe)
        return d
    except Exception:
        alt = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP)
        os.makedirs(alt, exist_ok=True)
        return alt


DATA = data_dir()
CFG_FILE = os.path.join(DATA, "CF-Pick.config.json")
CAND_FILE = os.path.join(DATA, "CF-Pick.candidates.txt")
LOG_FILE = os.path.join(DATA, "CF-Pick.log")


def log(msg: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg + "\n")
    except Exception:
        pass


def fatal(msg: str) -> None:
    log("FATAL " + msg)
    splash_close()
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, msg, APP, 0x10)
    except Exception:
        pass


# --------------------------------------------------------------------------
# 启动体验：splash 画面 + 单实例互斥
# --------------------------------------------------------------------------
def splash_text(msg: str) -> None:
    """更新启动画面底部的提示文字（仅在打包后存在 pyi_splash）。"""
    try:
        import pyi_splash  # type: ignore
        pyi_splash.update_text(msg)
    except Exception:
        pass


def splash_close() -> None:
    try:
        import pyi_splash  # type: ignore
        pyi_splash.close()
    except Exception:
        pass


MUTEX_NAME = "CF-Pick-SingleInstance"
_mutex_handle = None


def is_first_instance() -> bool:
    """用命名互斥体判断是否已有实例。第二个实例会立刻知道，不必等端口探测。"""
    global _mutex_handle
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        _mutex_handle = k32.CreateMutexW(None, False, MUTEX_NAME)
        return k32.GetLastError() != 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return True  # 非 Windows 或调用失败：不拦，照常启动


# --------------------------------------------------------------------------
# 配置 / 候选
# --------------------------------------------------------------------------
DEFAULT_CFG = {
    "sni": DEFAULT_SNI,
    "port": DEFAULT_PORT,
    "tries": 2,
    "concurrency": 32,
    "family": "auto",
    "max_ips": 2,
}


def load_cfg() -> dict:
    cfg = dict(DEFAULT_CFG)
    try:
        with open(CFG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update({k: v for k, v in data.items() if k in DEFAULT_CFG})
    except Exception:
        pass
    return cfg


def save_cfg(cfg: dict) -> None:
    try:
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump({k: cfg.get(k, DEFAULT_CFG[k]) for k in DEFAULT_CFG}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def default_candidates() -> list:
    for path in (os.path.join(res_dir(), "cf-domains.txt"), os.path.join(base_dir(), "cf-domains.txt")):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                items = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
            if items:
                return items
        except Exception:
            continue
    return []


def load_candidates() -> list:
    try:
        with open(CAND_FILE, "r", encoding="utf-8", errors="ignore") as f:
            items = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        if items:
            return items
    except Exception:
        pass
    items = default_candidates()
    save_candidates(items)
    return items


def save_candidates(items: list) -> None:
    try:
        with open(CAND_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(items) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------
# 测速
# --------------------------------------------------------------------------
def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx


CTX = _ssl_ctx()
AF = {"auto": socket.AF_UNSPEC, "v4": socket.AF_INET, "v6": socket.AF_INET6}

REQ_TMPL = (
    "GET / HTTP/1.1\r\n"
    "Host: {sni}\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
    "Accept: */*\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Connection: close\r\n\r\n"
)


def classify(code: int) -> str:
    if code == 403:
        return "被CF拦截"
    if code in (502, 503, 504) or 520 <= code <= 527 or code == 530:
        return "回源异常"
    if 100 <= code <= 499:
        return "可用"
    return "可用"


def probe(ip: str, fam: int, sni: str, port: int, timeout: float = 6.0):
    """返回 (毫秒 | None, 状态码或负值, 错误文本)"""
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if fam == socket.AF_INET6:
            sock.connect((ip, port, 0, 0))
        else:
            sock.connect((ip, port))
        ssock = CTX.wrap_socket(sock, server_hostname=sni)
        sock = ssock
        ssock.settimeout(timeout)
        ssock.sendall(REQ_TMPL.format(sni=sni).encode())
        buf = ssock.recv(160)
        ms = (time.perf_counter() - t0) * 1000.0
        if not buf:
            return None, -1, "空响应"
        head = buf.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
        m = re.search(r"\b(\d{3})\b", head)
        return ms, (int(m.group(1)) if m else 0), ""
    except (socket.timeout, TimeoutError):
        return None, -1, "超时"
    except ssl.SSLError:
        return None, -2, "握手失败"
    except OSError:
        return None, -3, "不通"
    except Exception:
        return None, -4, "不通"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def resolve(cand: str, port: int, family: str) -> list:
    out = []
    try:
        infos = socket.getaddrinfo(cand, port, AF.get(family, socket.AF_UNSPEC), socket.SOCK_STREAM)
    except Exception:
        return out
    seen = set()
    for fam, _t, _p, _c, sa in infos:
        if fam not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = sa[0]
        if (fam, ip) in seen:
            continue
        seen.add((fam, ip))
        out.append((fam, ip))
    out.sort(key=lambda x: 0 if x[0] == socket.AF_INET6 else 1)  # v6 优先
    return out


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.results = []
        self.running = False
        self.done = 0
        self.total = 0
        self.t0 = 0.0
        self.stop = threading.Event()
        self.cfg = dict(DEFAULT_CFG)
        self.phase = "idle"
        self.finished = ""

    def reset(self, cfg):
        self.results = []
        self.done = 0
        self.total = 0
        self.t0 = time.time()
        self.stop = threading.Event()
        self.cfg = cfg
        self.phase = "resolve"
        self.finished = ""
        self.running = True


STATE = State()


def _resolve_all(items, cfg):
    jobs = []
    per_fam_cap = max(1, int(cfg.get("max_ips", 2)))
    with ThreadPoolExecutor(max_workers=min(64, max(8, cfg["concurrency"] * 2))) as ex:
        futs = {ex.submit(resolve, it, cfg["port"], cfg["family"]): it for it in items}
        for fut in as_completed(futs):
            if STATE.stop.is_set():
                break
            cand = futs[fut]
            try:
                addrs = fut.result()
            except Exception:
                addrs = []
            if not addrs:
                with STATE.lock:
                    STATE.results.append({
                        "domain": cand, "family": "v4" if cfg["family"] == "v4" else "v6",
                        "ip": "-", "ms": None, "status": "解析失败", "code": 0,
                        "ok": 0, "tries": cfg["tries"], "usable": False,
                    })
            else:
                cf_addrs = [(f, ip) for f, ip in addrs if is_cf_ip(ip)]
                if not cf_addrs:
                    with STATE.lock:
                        STATE.results.append({
                            "domain": cand,
                            "family": "v6" if addrs[0][0] == socket.AF_INET6 else "v4",
                            "ip": addrs[0][1], "ms": None, "status": "非CF节点", "code": 0,
                            "ok": 0, "tries": cfg["tries"], "usable": False,
                        })
                for fam in (socket.AF_INET6, socket.AF_INET):
                    picked = [a for a in cf_addrs if a[0] == fam][:per_fam_cap]
                    for f, ip in picked:
                        jobs.append((cand, f, ip))
            with STATE.lock:
                STATE.done += 1
    return jobs


def _run_jobs(jobs, cfg):
    tries = cfg["tries"]
    sni, port = cfg["sni"], cfg["port"]
    try:
        with ThreadPoolExecutor(max_workers=cfg["concurrency"]) as ex:
            futs = {}
            for job in jobs:
                if STATE.stop.is_set():
                    break
                futs[ex.submit(_one_entry, job, tries, sni, port)] = job
            for fut in as_completed(futs):
                try:
                    entry = fut.result()
                except Exception as e:
                    log("probe error: %r" % (e,))
                    continue
                with STATE.lock:
                    STATE.results.append(entry)
                    STATE.done += 1
                if STATE.stop.is_set():
                    for f in futs:
                        f.cancel()
                    break
    finally:
        with STATE.lock:
            STATE.running = False
            STATE.phase = "idle"
            STATE.finished = time.strftime("%H:%M:%S")


def _one_entry(job, tries, sni, port):
    cand, fam, ip = job
    fam_name = "v6" if fam == socket.AF_INET6 else "v4"
    lat, codes, err = [], [], ""
    for _ in range(tries):
        if STATE.stop.is_set():
            break
        ms, code, e = probe(ip, fam, sni, port)
        if ms is not None:
            lat.append(ms)
            codes.append(code)
        else:
            err = e
    if lat:
        ms = int(round(sum(lat) / len(lat)))
        code = codes[-1]
        status = classify(code)
        return {"domain": cand, "family": fam_name, "ip": ip, "ms": ms, "status": status,
                "code": code, "ok": len(lat), "tries": tries, "usable": status == "可用"}
    return {"domain": cand, "family": fam_name, "ip": ip, "ms": None, "status": err or "不通",
            "code": 0, "ok": 0, "tries": tries, "usable": False}


def start_run(cfg) -> dict:
    with STATE.lock:
        if STATE.running:
            return {"error": "正在测试中，请先停止"}
        STATE.reset(cfg)
        items = load_candidates()
        STATE.total = len(items)
    if not items:
        with STATE.lock:
            STATE.running = False
        return {"error": "候选列表为空"}

    def work():
        try:
            jobs = _resolve_all(items, cfg)
            if not jobs:
                with STATE.lock:
                    STATE.running = False
                    STATE.phase = "idle"
                return
            with STATE.lock:
                STATE.total = len(jobs)
                STATE.done = 0
                STATE.phase = "probe"
            _run_jobs(jobs, cfg)
        except Exception:
            log("runner crash:\n" + traceback.format_exc())
            with STATE.lock:
                STATE.running = False
                STATE.phase = "idle"

    threading.Thread(target=work, daemon=True).start()
    return {"total": len(items), "running": True}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
UI_HTML = ""


def load_ui() -> str:
    global UI_HTML
    for p in (os.path.join(res_dir(), "ui.html"), os.path.join(base_dir(), "ui.html")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                UI_HTML = f.read()
                return UI_HTML
        except Exception:
            continue
    UI_HTML = "<h1>ui.html 缺失</h1>"
    return UI_HTML


def snapshot(include_results=True) -> dict:
    with STATE.lock:
        res = list(STATE.results)
        return {
            "running": STATE.running,
            "done": STATE.done,
            "total": STATE.total,
            "phase": STATE.phase,
            "elapsed": round(time.time() - STATE.t0, 1) if STATE.t0 else 0,
            "finished": STATE.finished,
            "results": res if include_results else [],
        }


def csv_bytes() -> bytes:
    with STATE.lock:
        res = list(STATE.results)
    res.sort(key=lambda r: (0, r["ms"]) if r["usable"] else (1, 0))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["排名", "入口", "地址族", "解析IP", "延迟(ms)", "成功次数", "状态"])
    rank = 0
    for r in res:
        if r["usable"]:
            rank += 1
            w.writerow([rank, r["domain"], r["family"].upper(), r["ip"], r["ms"], "%d/%d" % (r["ok"], r["tries"]), r["status"]])
        else:
            w.writerow(["-", r["domain"], r["family"].upper(), r["ip"], "-", "0/%d" % r["tries"], r["status"]])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = APP + "/" + VERSION

    def log_message(self, fmt, *args):
        pass

    # ---- helpers ----
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    # ---- routes ----
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p in ("/", "/index.html"):
            return self._send(200, UI_HTML or load_ui(), "text/html; charset=utf-8")
        if p == "/api/ping":
            return self._send(200, "ok", "text/plain")
        if p == "/api/init":
            snap = snapshot()
            return self._json({
                "config": load_cfg(),
                "candidates": load_candidates(),
                "version": VERSION,
                **snap,
            })
        if p == "/api/progress":
            qs = u.query
            since = 0
            m = re.search(r"since=(\d+)", qs)
            if m:
                since = int(m.group(1))
            with STATE.lock:
                total_res = len(STATE.results)
                entries = STATE.results[since:] if since <= total_res else []
                data = {
                    "running": STATE.running,
                    "done": STATE.done,
                    "total": STATE.total,
                    "phase": STATE.phase,
                    "elapsed": round(time.time() - STATE.t0, 1) if STATE.t0 else 0,
                    "since": since + len(entries),
                    "entries": entries,
                }
            return self._json(data)
        if p == "/api/export.csv":
            return self._send(200, csv_bytes(), "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="cf-pick-result.csv"'})
        if p == "/api/shutdown":
            self._send(200, "bye", "text/plain")
            threading.Timer(0.35, lambda: os._exit(0)).start()
            return
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        p = urlparse(self.path).path
        body = self._body()
        if p == "/api/run":
            cfg = load_cfg()
            try:
                cfg["sni"] = str(body.get("sni") or DEFAULT_SNI).strip()
                cfg["port"] = max(1, min(65535, int(body.get("port") or DEFAULT_PORT)))
                cfg["tries"] = max(1, min(10, int(body.get("tries") or 2)))
                cfg["concurrency"] = max(4, min(64, int(body.get("concurrency") or 32)))
                cfg["family"] = body.get("family") if body.get("family") in ("auto", "v4", "v6") else "auto"
            except Exception:
                return self._json({"error": "参数不合法"})
            if not cfg["sni"]:
                return self._json({"error": "SNI / Host 不能为空"})
            save_cfg(cfg)
            return self._json(start_run(cfg))
        if p == "/api/stop":
            STATE.stop.set()
            return self._json({"stopped": True})
        if p == "/api/candidates":
            text = str(body.get("text") or "")
            items, seen = [], set()
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if s.lower() in seen:
                    continue
                seen.add(s.lower())
                items.append(s)
            save_candidates(items)
            return self._json({"count": len(items)})
        self._json({"error": "unknown"})

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def open_ui(port: int) -> None:
    """打开浏览器界面。CF_PICK_NO_BROWSER=1 时不打开（自动化测试用）。"""
    if os.environ.get("CF_PICK_NO_BROWSER") == "1":
        return
    try:
        webbrowser.open("http://127.0.0.1:%d/" % port)
    except Exception:
        pass


def close_splash_then_open(port: int) -> None:
    """先撤掉启动图，再开浏览器，避免浏览器窗口被启动图挡一下。"""
    splash_close()
    threading.Timer(0.4, lambda: open_ui(port)).start()


def already_running(port: int) -> bool:
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:%d/api/ping" % port, timeout=0.45) as r:
            return r.read().strip() == b"ok"
    except Exception:
        return False


def main():
    t0 = time.time()
    first = is_first_instance()

    if not first:
        # 已有实例在跑：等它把端口监听起来，然后把浏览器指过去，自己退出。
        splash_text("已有一个测速台在运行，正在打开…")
        deadline = t0 + 25
        while time.time() < deadline:
            for p in PORTS:
                if already_running(p):
                    log("second instance -> reuse 127.0.0.1:%d" % p)
                    splash_close()
                    open_ui(p)
                    return
            time.sleep(0.25)
        log("second instance: 未找到已在运行的实例，改为自行启动")

    splash_text("正在载入界面…")
    load_ui()

    srv = None
    for p in PORTS:
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            srv.daemon_threads = True
            port = p
            break
        except OSError:
            continue
    if srv is None:
        fatal("端口 %d-%d 全部被占用，无法启动。" % (PORTS[0], PORTS[-1]))
        return

    log("listening on 127.0.0.1:%d  data=%s  启动耗时 %.2fs" % (port, DATA, time.time() - t0))
    splash_text("正在打开界面…")
    close_splash_then_open(port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        fatal("启动失败：\n\n" + traceback.format_exc()[-1200:])
