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

import ctypes
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
VERSION = "1.0.6"
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
    "auto_open": True,
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


# --------------------------------------------------------------------------
# 「页面还开着吗」的痕迹：靠网页的心跳判断，避免重复开标签页
# --------------------------------------------------------------------------
PAGE_FILE = os.path.join(DATA, "page.alive")
PAGE = {"last": 0.0, "saved": 0.0}


def page_touch() -> None:
    """网页每 2.5 秒心跳一次，这里只记时间戳（写盘做节流）。"""
    now = time.time()
    PAGE["last"] = now
    if now - PAGE["saved"] > 20:
        PAGE["saved"] = now
        try:
            with open(PAGE_FILE, "w", encoding="utf-8") as f:
                f.write("%.0f" % now)
        except Exception:
            pass


def page_recall() -> float:
    """上一次运行期间，最后有页面在线的时间（跨进程保留，用来判断值不值得等心跳）。"""
    try:
        with open(PAGE_FILE, "r", encoding="utf-8") as f:
            return float(f.read().strip() or 0)
    except Exception:
        return 0.0


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
            # 带 page=1 的是网页心跳；不带的是「还有实例在跑吗」的端口探测
            if "page=1" in (u.query or ""):
                page_touch()
            return self._send(200, "ok", "text/plain")
        if p == "/api/beat":
            page_touch()
            return self._json({"ok": True})
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
            tray_remove()
            threading.Timer(0.35, lambda: os._exit(0)).start()
            return
        if p == "/api/exit":
            # 弹原生对话框让用户选：最小化到托盘 / 彻底退出
            mode = ask_exit_mode()
            self._json({"mode": mode})
            if mode == "minimize":
                log("exit -> minimize to tray")
                tray_balloon("已最小化到系统托盘。双击图标打开界面，右键可彻底退出。")
            else:
                log("exit -> quit")
                tray_remove()
                threading.Timer(0.4, lambda: os._exit(0)).start()
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
        if p == "/api/shutdown":
            self._json({"mode": "exit"})
            tray_remove()
            threading.Timer(0.35, lambda: os._exit(0)).start()
            return
        if p == "/api/exit":
            mode = ask_exit_mode()
            self._json({"mode": mode})
            if mode == "minimize":
                log("exit -> minimize to tray")
                tray_balloon("已最小化到系统托盘。双击图标打开界面，右键可彻底退出。")
            else:
                log("exit -> quit")
                tray_remove()
                threading.Timer(0.4, lambda: os._exit(0)).start()
            return
        self._json({"error": "unknown"})

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")


# --------------------------------------------------------------------------
# 运行状态小窗 + 系统托盘（纯 ctypes 调 Win32，不引入任何 GUI 依赖）
#
# 为什么不做成纯托盘：Win11 默认把新图标塞进「隐藏的图标」折叠区，
# 用户看不到；所以给一个真实存在的小窗口（任务栏上能看到），
# 关掉时再问「最小化到托盘」还是「彻底退出」。
# --------------------------------------------------------------------------
HAS_SHELL = sys.platform == "win32"
WM_TRAY = 0x0400 + 1          # WM_APP + 1
ID_OPEN, ID_QUIT = 101, 102
MENU_OPEN, MENU_SHOW, MENU_EXIT = 1001, 1003, 1002
_SHELL = {"hwnd": None, "ready": False, "port": None}
_KEEP = []                    # 保住 WNDPROC 回调与字体句柄，防止被 GC

if HAS_SHELL:
    import ctypes
    from ctypes import wintypes

    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class _NID(ctypes.Structure):
        """NOTIFYICONDATAW"""
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("hWnd", wintypes.HWND),
            ("uID", wintypes.UINT),
            ("uFlags", wintypes.UINT),
            ("uCallbackMessage", wintypes.UINT),
            ("hIcon", wintypes.HICON),
            ("szTip", wintypes.WCHAR * 128),
            ("dwState", wintypes.DWORD),
            ("dwStateMask", wintypes.DWORD),
            ("szInfo", wintypes.WCHAR * 256),
            ("uVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * 64),
            ("dwInfoFlags", wintypes.DWORD),
            ("guidItem", _GUID),
            ("hBalloonIcon", wintypes.HICON),
        ]

    class _PAINTSTRUCT(ctypes.Structure):
        _fields_ = [("hdc", wintypes.HDC), ("fErase", wintypes.BOOL),
                    ("rcPaint", wintypes.RECT), ("fRestore", wintypes.BOOL),
                    ("fIncUpdate", wintypes.BOOL), ("rgbReserved", ctypes.c_byte * 32)]

    class _WNDCLASS(ctypes.Structure):
        _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", ctypes.c_void_p),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                    ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

    _WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND,
                                  wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    _u = ctypes.windll.user32
    _g = ctypes.windll.gdi32
    _k = ctypes.windll.kernel32
    _s = ctypes.windll.shell32

    # 64 位下必须显式声明签名，否则句柄会被截断成 32 位
    _k.GetModuleHandleW.restype = wintypes.HMODULE
    _k.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _u.RegisterClassW.argtypes = [ctypes.POINTER(_WNDCLASS)]
    _u.CreateWindowExW.restype = wintypes.HWND
    _u.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                   wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    _u.DefWindowProcW.restype = ctypes.c_ssize_t
    _u.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                  wintypes.WPARAM, wintypes.LPARAM]
    _u.SendMessageW.restype = ctypes.c_ssize_t
    _u.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                wintypes.WPARAM, wintypes.LPARAM]
    _u.LoadCursorW.restype = wintypes.HANDLE
    _u.LoadIconW.restype = wintypes.HICON
    _u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _u.CreatePopupMenu.restype = wintypes.HMENU
    _u.TrackPopupMenu.restype = ctypes.c_int
    _u.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
    _u.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
    _u.DestroyMenu.argtypes = [wintypes.HMENU]
    _u.SetForegroundWindow.argtypes = [wintypes.HWND]
    _u.DestroyWindow.argtypes = [wintypes.HWND]
    _u.PostQuitMessage.argtypes = [ctypes.c_int]
    _u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, wintypes.UINT]
    _u.GetDC.restype = wintypes.HDC
    _u.GetDC.argtypes = [wintypes.HWND]
    _u.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _g.GetDeviceCaps.restype = ctypes.c_int
    _g.GetDeviceCaps.argtypes = [wintypes.HDC, ctypes.c_int]
    _u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                wintypes.WPARAM, wintypes.LPARAM]
    _u.BeginPaint.restype = wintypes.HDC
    _u.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(_PAINTSTRUCT)]
    _u.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(_PAINTSTRUCT)]
    _u.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _u.DrawTextW.argtypes = [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int,
                             ctypes.POINTER(wintypes.RECT), wintypes.UINT]
    _u.FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HBRUSH]
    _g.SetTextColor.argtypes = [wintypes.HDC, wintypes.DWORD]
    _g.SetTextColor.restype = wintypes.DWORD
    _g.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
    _g.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    _g.SelectObject.restype = wintypes.HGDIOBJ
    _g.CreateFontW.restype = wintypes.HANDLE
    _g.CreateSolidBrush.restype = wintypes.HBRUSH
    _g.CreateSolidBrush.argtypes = [wintypes.DWORD]
    _g.CreatePen.restype = ctypes.c_void_p
    _g.CreatePen.argtypes = [ctypes.c_int, ctypes.c_int, wintypes.DWORD]
    _g.RoundRect.argtypes = [wintypes.HDC] + [ctypes.c_int] * 6
    _g.MoveToEx.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _g.LineTo.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    _g.DeleteObject.argtypes = [ctypes.c_void_p]
    _u.InvalidateRect.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL]
    _u.SetTimer.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.UINT, ctypes.c_void_p]
    _s.ExtractIconW.restype = wintypes.HICON
    _s.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(_NID)]
    _s.Shell_NotifyIconW.restype = wintypes.BOOL


def dpi_aware() -> None:
    """启动图撤掉之后再开 DPI 感知，免得小窗被位图拉伸、字发糊。"""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _dpi_scale() -> float:
    try:
        hdc = _u.GetDC(None)
        dpi = _g.GetDeviceCaps(hdc, 88)     # LOGPIXELSX
        _u.ReleaseDC(None, hdc)
        return max(1.0, dpi / 96.0)
    except Exception:
        return 1.0


def _make_font(size_px: int, weight: int = 400) -> int:
    """Microsoft YaHei UI；拿不到就交给系统默认。"""
    try:
        h = ctypes.windll.gdi32.CreateFontW(
            -size_px, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, "Microsoft YaHei UI")
        if h:
            _KEEP.append(h)
            return h
    except Exception:
        pass
    return 0


def _tray_icon():
    try:
        h = ctypes.windll.shell32.ExtractIconW(None, sys.executable, 0)
        if h:
            return h
    except Exception:
        pass
    try:
        return ctypes.windll.user32.LoadIconW(None, 32512)  # IDI_APPLICATION
    except Exception:
        return None


def _nid(flags: int) -> "_NID":
    nid = _NID()
    nid.cbSize = ctypes.sizeof(_NID)
    nid.hWnd = _SHELL["hwnd"]
    nid.uID = 1
    nid.uFlags = flags
    return nid


def tray_balloon(text: str, title: str = "CF-Pick") -> None:
    if not HAS_SHELL or not _SHELL["hwnd"]:
        return
    try:
        nid = _nid(0x10)  # NIF_INFO
        nid.szInfo = text
        nid.szInfoTitle = title
        nid.dwInfoFlags = 0x1  # NIIF_INFO
        ctypes.windll.shell32.Shell_NotifyIconW(1, ctypes.byref(nid))
    except Exception:
        pass


def tray_remove() -> None:
    if not HAS_SHELL or not _SHELL["hwnd"]:
        return
    try:
        nid = _nid(0)
        ctypes.windll.shell32.Shell_NotifyIconW(2, ctypes.byref(nid))
    except Exception:
        pass


def quit_now() -> None:
    """彻底退出：撤图标 → 结束进程。"""
    tray_remove()
    threading.Timer(0.2, lambda: os._exit(0)).start()


_ASK = {"result": None}
ID_MIN, ID_BYE = 201, 202


def _ask_paint(hwnd) -> None:
    ps = _PAINTSTRUCT()
    hdc = _u.BeginPaint(hwnd, ctypes.byref(ps))
    try:
        rc = wintypes.RECT()
        _u.GetClientRect(hwnd, ctypes.byref(rc))
        _u.FillRect(hdc, ctypes.byref(rc), _SHELL["brush"])
        _g.SetBkMode(hdc, 1)
        S = _SHELL.get("scale") or 1.0

        _g.SelectObject(hdc, _SHELL.get("f_ask_title") or 0)
        _g.SetTextColor(hdc, 0x00F4ECE8)
        r1 = wintypes.RECT(int(22 * S), int(16 * S), rc.right - int(22 * S), int(48 * S))
        _u.DrawTextW(hdc, "测速台还在后台运行", -1, ctypes.byref(r1), 0x0020 | 0x0004)

        _g.SelectObject(hdc, _SHELL.get("f_ask_body") or 0)
        _g.SetTextColor(hdc, 0x00B8A49A)
        r2 = wintypes.RECT(int(22 * S), int(50 * S), rc.right - int(22 * S), int(108 * S))
        _u.DrawTextW(hdc, "关掉浏览器标签页不会退出程序。\n"
                          "是要它留在后台继续待命，还是顺手把进程也结束？",
                     -1, ctypes.byref(r2), 0x0010)
    finally:
        _u.EndPaint(hwnd, ctypes.byref(ps))


def _ask_proc(hwnd, msg, wparam, lparam):
    try:
        if msg == 0x000F:                        # WM_PAINT
            _ask_paint(hwnd)
            return 0
        if msg == 0x0111:                        # WM_COMMAND
            cid = wparam & 0xFFFF
            if cid == ID_MIN:
                _ASK["result"] = "minimize"
                _u.DestroyWindow(hwnd)
                return 0
            if cid == ID_BYE:
                _ASK["result"] = "exit"
                _u.DestroyWindow(hwnd)
                return 0
        if msg == 0x0010:                        # WM_CLOSE：点 X 按「留在后台」处理，不杀进程
            _ASK["result"] = "minimize"
            _u.DestroyWindow(hwnd)
            return 0
        if msg == 0x0002:                        # WM_DESTROY
            _u.PostQuitMessage(0)
            return 0
    except Exception:
        pass
    return _u.DefWindowProcW(hwnd, msg, wparam, lparam)


def ask_exit_mode() -> str:
    """自绘对话框：最小化到托盘 / 彻底退出。返回 minimize 或 exit。"""
    if not HAS_SHELL:
        return "exit"
    _ASK["result"] = None
    k = ctypes.windll.kernel32
    hinst = k.GetModuleHandleW(None)
    S = _SHELL.get("scale") or _dpi_scale()

    proc = _WNDPROC(_ask_proc)
    _KEEP.append(proc)
    wc = _WNDCLASS()
    wc.lpfnWndProc = ctypes.cast(proc, ctypes.c_void_p)
    wc.hInstance = hinst
    wc.hbrBackground = _SHELL.get("brush")
    wc.hCursor = _u.LoadCursorW(None, 32512)
    wc.lpszClassName = "CFPickAskWnd"
    _u.RegisterClassW(ctypes.byref(wc))

    w, h = int(430 * S), int(200 * S)
    sw, sh = _u.GetSystemMetrics(0), _u.GetSystemMetrics(1)
    hwnd = _u.CreateWindowExW(0x00000008, "CFPickAskWnd", "CF-Pick · 退出",
                              0x00C80000,   # CAPTION | SYSMENU
                              int((sw - w) / 2), int((sh - h) / 2), w, h,
                              None, None, hinst, None)
    if not hwnd:
        return "exit"

    _SHELL.setdefault("f_ask_title", _make_font(int(19 * S), 600))
    _SHELL.setdefault("f_ask_body", _make_font(int(14 * S), 400))
    f_btn = _make_font(int(14 * S), 400)

    def btn(text, x, cw, cid):
        hs = int(38 * S)
        bh = _u.CreateWindowExW(0, "BUTTON", text, 0x50000000,
                                int(x * S), int(122 * S), int(cw * S), hs,
                                hwnd, ctypes.c_void_p(cid), hinst, None)
        if bh and f_btn:
            _u.SendMessageW(bh, 0x0030, f_btn, 1)

    btn("最小化到托盘", 22, 128, ID_MIN)
    btn("彻底退出", 164, 104, ID_BYE)

    _u.ShowWindow(hwnd, 5)
    _u.SetForegroundWindow(hwnd)

    msg = wintypes.MSG()
    while _u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        _u.TranslateMessage(ctypes.byref(msg))
        _u.DispatchMessageW(ctypes.byref(msg))
    return _ASK["result"] or "minimize"


def _show_window(show: bool = True) -> None:
    hwnd = _SHELL["hwnd"]
    if not hwnd:
        return
    try:
        ctypes.windll.user32.ShowWindow(hwnd, 5 if show else 0)  # SW_SHOW / SW_HIDE
        if show:
            ctypes.windll.user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def _on_close(hwnd) -> None:
    """用户关窗：问一下是最小化到托盘还是彻底退出。"""
    mode = ask_exit_mode()
    if mode == "minimize":
        log("window close -> minimize to tray")
        _show_window(False)
        tray_balloon("已最小化到系统托盘。双击图标打开界面，右键可彻底退出。")
    else:
        log("window close -> quit")
        quit_now()


def _tray_popup(hwnd) -> None:
    u = ctypes.windll.user32
    hmenu = u.CreatePopupMenu()
    u.AppendMenuW(hmenu, 0x0, MENU_OPEN, "打开测速台")
    u.AppendMenuW(hmenu, 0x0, MENU_SHOW, "显示状态窗口")
    u.AppendMenuW(hmenu, 0x800, 0, None)  # MF_SEPARATOR
    u.AppendMenuW(hmenu, 0x0, MENU_EXIT, "彻底退出")
    pt = wintypes.POINT()
    u.GetCursorPos(ctypes.byref(pt))
    u.SetForegroundWindow(hwnd)
    cmd = u.TrackPopupMenu(hmenu, 0x0100 | 0x0002, pt.x, pt.y, 0, hwnd, None)
    u.PostMessageW(hwnd, 0, 0, 0)
    u.DestroyMenu(hmenu)
    if cmd == MENU_OPEN:
        open_ui(_SHELL["port"])
        _show_window(True)
    elif cmd == MENU_SHOW:
        _show_window(True)
    elif cmd == MENU_EXIT:
        quit_now()


_AO = {"v": True, "t": 0.0}


def auto_open_setting() -> bool:
    """开关读得比较频繁，缓存 1 秒，免得每次都去碰文件。"""
    now = time.time()
    if now - _AO["t"] > 1.0:
        _AO["v"] = bool(load_cfg().get("auto_open", True))
        _AO["t"] = now
    return _AO["v"]


def set_auto_open(on: bool) -> bool:
    cfg = load_cfg()
    cfg["auto_open"] = bool(on)
    save_cfg(cfg)
    _AO["v"] = bool(on)
    _AO["t"] = time.time()
    log("auto_open -> %s" % ("on" if on else "off"))
    return _AO["v"]


def _check_hit(x: int, y: int) -> bool:
    """点击是否落在勾选行上。"""
    S = _SHELL.get("scale") or 1.0
    return (int(14 * S) <= x <= int(320 * S)) and (int(102 * S) <= y <= int(130 * S))


def _draw_checkbox(hdc, x: int, y: int, S: float, on: bool) -> None:
    box = int(15 * S)
    l, t, r, b = x, y, x + box, y + box
    if on:
        fill, edge = 0x00EED322, 0x00EED322          # #22d3ee
    else:
        fill, edge = 0x00120D0A, 0x00504A45          # 深底 + 暗边
    br = _g.CreateSolidBrush(fill)
    pen = _g.CreatePen(0, max(1, int(S)), edge)
    try:
        _g.SelectObject(hdc, br)
        _g.SelectObject(hdc, pen)
        _g.RoundRect(hdc, l, t, r, b, int(9 * S), int(9 * S))
    finally:
        _g.DeleteObject(br)
        _g.DeleteObject(pen)
    if on:                                            # 打勾
        pen2 = _g.CreatePen(0, max(2, int(2 * S)), 0x00120F0B)
        try:
            _g.SelectObject(hdc, pen2)
            _g.MoveToEx(hdc, l + int(4 * S), t + int(8 * S), None)
            _g.LineTo(hdc, l + int(7 * S), t + int(11 * S))
            _g.LineTo(hdc, l + int(12 * S), t + int(4 * S))
        finally:
            _g.DeleteObject(pen2)


def _paint(hwnd) -> None:
    """自绘文字，避免 STATIC 控件在深色背景上留下白块。"""
    ps = _PAINTSTRUCT()
    hdc = _u.BeginPaint(hwnd, ctypes.byref(ps))
    try:
        rc = wintypes.RECT()
        _u.GetClientRect(hwnd, ctypes.byref(rc))
        _u.FillRect(hdc, ctypes.byref(rc), _SHELL["brush"])
        _g.SetBkMode(hdc, 1)  # TRANSPARENT

        _g.SelectObject(hdc, _SHELL.get("f_big") or 0)
        _g.SetTextColor(hdc, 0x00F4ECE8)          # RGB(232,236,244)
        S = _SHELL.get("scale") or 1.0
        r1 = wintypes.RECT(int(20 * S), int(8 * S), rc.right - int(20 * S), int(46 * S))
        _u.DrawTextW(hdc, "● 本地服务运行中 · 端口 %d" % (_SHELL["port"] or 0),
                     -1, ctypes.byref(r1), 0x0020 | 0x0004)  # SINGLELINE | VCenter

        on = auto_open_setting()
        _SHELL["ao_shown"] = on

        _g.SelectObject(hdc, _SHELL.get("f_mid") or 0)
        _g.SetTextColor(hdc, 0x00B8A49A)          # RGB(154,164,184)
        r2 = wintypes.RECT(int(20 * S), int(46 * S), rc.right - int(20 * S), int(100 * S))
        desc = ("启动时自动打开浏览器界面，关掉标签页不影响后台运行。\n"
                "关闭本窗口可选择「最小化到托盘」或「彻底退出」。") if on else \
               ("已关闭自动打开：点下方「打开界面」进入测速台。\n"
                "关闭本窗口可选择「最小化到托盘」或「彻底退出」。")
        _u.DrawTextW(hdc, desc, -1, ctypes.byref(r2), 0x0010)          # WORDBREAK

        # 勾选行：[✓] 启动 exe 时自动打开界面
        _draw_checkbox(hdc, int(20 * S), int(106 * S), S, on)
        r3 = wintypes.RECT(int(42 * S), int(103 * S), rc.right - int(20 * S), int(127 * S))
        _g.SetTextColor(hdc, 0x00C0AC9F)
        _u.DrawTextW(hdc, "启动 exe 时自动打开界面", -1,
                     ctypes.byref(r3), 0x0020 | 0x0004)
    finally:
        _u.EndPaint(hwnd, ctypes.byref(ps))


def _shell_proc(hwnd, msg, wparam, lparam):
    try:
        if msg == WM_TRAY:
            event = lparam & 0xFFFF
            if event in (0x0205, 0x0204):        # 右键抬起 / 按下
                _tray_popup(hwnd)
            elif event in (0x0202, 0x0203):      # 左键单击 / 双击
                open_ui(_SHELL["port"])
                _show_window(True)
            return 0
        if msg == 0x0010:                        # WM_CLOSE
            _on_close(hwnd)
            return 0
        if msg == 0x0111:                        # WM_COMMAND
            cid = wparam & 0xFFFF
            if cid == ID_OPEN:
                open_ui(_SHELL["port"])
                return 0
            if cid == ID_QUIT:
                _on_close(hwnd)
                return 0
        if msg == 0x0201:                        # WM_LBUTTONDOWN：点勾选行
            x = lparam & 0xFFFF
            y = (lparam >> 16) & 0xFFFF
            if _check_hit(x, y):
                set_auto_open(not auto_open_setting())
                _u.InvalidateRect(hwnd, None, True)
                return 0
        if msg == 0x0113:                        # WM_TIMER：网页那边改了开关也跟着刷新
            if auto_open_setting() != _SHELL.get("ao_shown"):
                _u.InvalidateRect(hwnd, None, True)
            return 0
        if msg == 0x000F:                        # WM_PAINT
            _paint(hwnd)
            return 0
        if msg == 0x0138:                        # WM_CTLCOLORSTATIC
            hdc = wparam
            ctypes.windll.gdi32.SetTextColor(hdc, 0x00F4ECE8)   # RGB(232,236,244)
            ctypes.windll.gdi32.SetBkMode(hdc, 1)               # TRANSPARENT
            return _SHELL.get("brush") or 0
        if msg == 0x0002:                        # WM_DESTROY
            ctypes.windll.user32.PostQuitMessage(0)
            return 0
    except Exception:
        pass
    return _u.DefWindowProcW(hwnd, msg, wparam, lparam)


def _build_window(port: int):
    u = _u
    k = ctypes.windll.kernel32
    hinst = k.GetModuleHandleW(None)

    proc = _WNDPROC(_shell_proc)
    _KEEP.append(proc)

    wc = _WNDCLASS()
    wc.lpfnWndProc = ctypes.cast(proc, ctypes.c_void_p)
    wc.hInstance = hinst
    brush = ctypes.windll.gdi32.CreateSolidBrush(0x00180E0B)   # RGB(11,14,24)
    _SHELL["brush"] = brush
    _KEEP.append(brush)
    wc.hbrBackground = brush
    wc.hCursor = u.LoadCursorW(None, 32512)  # IDC_ARROW
    wc.lpszClassName = "CFPickStatusWnd"
    u.RegisterClassW(ctypes.byref(wc))

    S = _dpi_scale()

    def sc(v):
        return int(round(v * S))

    width, height = sc(480), sc(212)
    sw = u.GetSystemMetrics(0)
    sh = u.GetSystemMetrics(1)
    x = int((sw - width) / 2)
    y = int((sh - height) / 2) - 40

    hwnd = u.CreateWindowExW(
        0, "CFPickStatusWnd", "CF-Pick · 测速台运行中",
        0x00CA0000,  # WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
        x, y, width, height, None, None, hinst, None)
    if not hwnd:
        return None

    try:  # 深色标题栏，和界面风格一致
        on = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(on), ctypes.sizeof(on))
    except Exception:
        pass

    f_big = _make_font(sc(20), 600)
    f_mid = _make_font(sc(15), 400)
    f_btn = _make_font(sc(15), 400)
    _SHELL["f_big"], _SHELL["f_mid"] = f_big, f_mid

    def child(cls, text, style, cx, cy, cw, ch, cid, font):
        h = u.CreateWindowExW(0, cls, text, 0x40000000 | 0x10000000 | style,
                              cx, cy, cw, ch, hwnd, ctypes.c_void_p(cid), hinst, None)
        if h and font:
            u.SendMessageW(h, 0x0030, font, 1)   # WM_SETFONT
        return h

    child("BUTTON", "打开界面", 0x00000000, sc(92), sc(136), sc(140), sc(34), ID_OPEN, f_btn)
    child("BUTTON", "退出", 0x00000000, sc(248), sc(136), sc(140), sc(34), ID_QUIT, f_btn)
    _SHELL["scale"] = S

    _SHELL["hwnd"] = hwnd

    nid = _nid(0x1 | 0x2 | 0x4)  # MESSAGE | ICON | TIP
    nid.uCallbackMessage = WM_TRAY
    nid.hIcon = _tray_icon()
    nid.szTip = "CF-Pick · 测速台运行中（端口 %d）" % port
    ctypes.windll.shell32.Shell_NotifyIconW(0, ctypes.byref(nid))

    u.ShowWindow(hwnd, 5)
    u.UpdateWindow(hwnd)
    u.SetTimer(hwnd, 1, 2000, None)
    for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE（新/旧编号）
        try:
            on = ctypes.c_int(1)
            hr = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(on), ctypes.sizeof(on))
            log("dark title bar attr=%d hr=%s" % (attr, hr))
            if hr == 0:
                _u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0004 | 0x0020)
                break
        except Exception:
            pass
    return hwnd


def _shell_loop(port: int) -> None:
    if not _build_window(port):
        return
    _SHELL["ready"] = True
    msg = wintypes.MSG()
    while _u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        _u.TranslateMessage(ctypes.byref(msg))
        _u.DispatchMessageW(ctypes.byref(msg))


def shell_start(port: int) -> bool:
    """起状态窗口 + 托盘图标，返回是否成功。"""
    if not HAS_SHELL or os.environ.get("CF_PICK_NO_SHELL") == "1":
        return False
    _SHELL["port"] = port
    threading.Thread(target=_shell_loop, args=(port,), daemon=True).start()
    for _ in range(30):
        if _SHELL["ready"]:
            return True
        time.sleep(0.05)
    return False


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
PAGE_TITLE = "CF 入口优选"       # 与 ui.html 的 <title> 对应，用来找已开着的浏览器窗口


def find_page_window():
    """找开着测速台页面的浏览器窗口（只管可见窗口）。"""
    if os.name != "nt":
        return None
    try:
        import ctypes
        u32 = ctypes.windll.user32
        hits = []

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def cb(hwnd, _lp):
            if not u32.IsWindowVisible(hwnd):
                return True
            n = u32.GetWindowTextLengthW(hwnd)
            if n > 0:
                buf = ctypes.create_unicode_buffer(n + 1)
                u32.GetWindowTextW(hwnd, buf, n + 1)
                if PAGE_TITLE in buf.value:
                    hits.append(hwnd)
            return True

        u32.EnumWindows(cb, None)
        return hits[0] if hits else None
    except Exception:
        return None


def focus_window(hwnd) -> None:
    """把窗口拽到前台（SetForegroundWindow 受前台锁限制，先置顶再取消）。"""
    try:
        import ctypes
        u32 = ctypes.windll.user32
        u32.ShowWindow(hwnd, 9)                                   # SW_RESTORE
        u32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0001 | 0x0002)    # TOPMOST
        u32.SetWindowPos(hwnd, -2, 0, 0, 0, 0, 0x0001 | 0x0002)    # NOTOPMOST
        u32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def focus_existing_page() -> bool:
    """已有页面窗口就切到前台，返回是否复用。"""
    hwnd = find_page_window()
    if not hwnd:
        return False
    focus_window(hwnd)
    log("reuse existing page window")
    return True


def open_tab(port: int) -> None:
    if os.environ.get("CF_PICK_NO_BROWSER") == "1":
        return
    try:
        webbrowser.open("http://127.0.0.1:%d/" % port)
    except Exception:
        pass


def open_ui(port: int) -> bool:
    """状态小窗 / 托盘按钮用：能复用就复用，否则开一个新标签页。"""
    if os.environ.get("CF_PICK_NO_BROWSER") == "1":
        return False
    if focus_existing_page():
        return True
    open_tab(port)
    return False


def startup_open(port: int) -> None:
    """启动时决定要不要开浏览器。

    优先顺序：
      1) 配置里关了「自动打开界面」→ 什么都不做，等用户点状态小窗的按钮
      2) 已有可见的页面窗口 → 切到前台（不再开新标签页）
      3) 没有可见窗口，但上次运行时页面在线过 → 等它的心跳（最多 4 秒），有就不开新页
      4) 以上都不成立 → 打开浏览器
    """
    if os.environ.get("CF_PICK_NO_BROWSER") == "1":
        return
    if not load_cfg().get("auto_open", True):
        log("auto_open=off，不自动打开界面")
        return
    if focus_existing_page():
        return
    if time.time() - page_recall() < 12 * 3600:
        t0 = time.time()
        while time.time() - t0 < 4.0:
            if PAGE["last"] >= t0:          # 老页面自己心跳上来了
                log("page already open (heartbeat) -> no new tab")
                return
            time.sleep(0.2)
    open_tab(port)


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
    splash_close()
    dpi_aware()
    log("status window + tray: %s" % ("on" if shell_start(port) else "off"))
    threading.Timer(0.35, lambda: startup_open(port)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        fatal("启动失败：\n\n" + traceback.format_exc()[-1200:])
