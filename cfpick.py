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
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP = "CF-Pick"
VERSION = "1.1.2"
DEFAULT_SNI = ""                       # 首次使用留空，由使用者自己填 CDN 域名
LEGACY_SNI = "cdn.example.com"         # 老版本写进配置的示例值，读到当空处理
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

# 光看上面 15 段会把 CF 自有 AS 的地址误判成「非 CF」：
# AS209242（Cloudflare London）、AS395747、AS202623 登记在 RIPE 的段基本都不在官方列表里，
# 官方列表只是「代理域名会解析到的那 15 段」，不是「CF 的全部地址」。
# 所以再按 cf-asn.txt 里 CF 自有 AS 的登记段补一层，命中的标上 AS 号，仍然照测。
_OWN_INDEX = None          # {首字节: [(net, asn), ...]}
_OWN_WIDE = []             # 比 /8 还宽的段（理论上没有，防御性留着）


def _build_own_index():
    idx, wide = {}, []
    try:
        groups = asn_groups()
    except Exception:
        groups = []
    for g in groups:
        asn = g["asn"]
        for s in g["prefixes"]:
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            if net.prefixlen < 8:
                wide.append((net, asn))
            else:
                idx.setdefault(int(str(net.network_address).split(".")[0]), []).append((net, asn))
    return idx, wide


def _own_index():
    global _OWN_INDEX
    if _OWN_INDEX is None:
        _OWN_INDEX = _build_own_index()
    return _OWN_INDEX


def cf_source(ip: str):
    """'' = 官方公布段；'AS209242' 之类 = CF 自有 AS 的登记段；None = 不是 CF 地址"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in CF_NETS:
        if net.version == addr.version and addr in net:
            return ""
    if addr.version != 4:
        return None
    idx, wide = _own_index()
    for net, asn in wide:
        if addr in net:
            return asn
    for net, asn in idx.get(addr.packed[0], ()):
        if addr in net:
            return asn
    return None


def is_cf_ip(ip: str) -> bool:
    """官方 15 段 + CF 自有 AS 段都算 CF。真正的非 CF 地址即使返回 200/404 也不是有效入口。"""
    return cf_source(ip) is not None


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
#
# 双击后前 1~2 秒是 PyInstaller 解压阶段，只有一张静态图（splash.png）能看；
# Python 一起来就换成下面自绘的启动窗（见「启动画面」一节），尺寸和静态图
# 完全一致，所以换窗那一刻看不出跳变，之后进度条和文案才开始动。
# --------------------------------------------------------------------------
def _pyi_splash_close() -> None:
    """撤掉 PyInstaller 的静态启动图（非打包运行时没有这个模块）。"""
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
    "theme": "dark",        # dark / light / cb（色盲友好）
    "skip_env_check": False,  # 只对「系统代理 / 代理进程」这类软提示生效，TUN 永远拦
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
    # 老版本把示例域名当默认值存进了配置：一律清空，让输入框回到空白
    if str(cfg.get("sni") or "").strip().lower() == LEGACY_SNI:
        cfg["sni"] = ""
        save_cfg(cfg)          # 顺手把磁盘上的旧值也抹掉，别让配置文件里留着假域名
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
    return []          # 文件不存在 / 空：要测什么由使用者自己粘贴或点「导入」


def save_candidates(items: list) -> None:
    try:
        with open(CAND_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(items) + ("\n" if items else ""))
    except Exception:
        pass


# 一个数据目录只做一次的「旧候选迁移」标记
CAND_MARK = os.path.join(DATA, "candidates.migrated")


def candidates_boot_init() -> None:
    """老版本第一次启动会自动把内置域名库写进候选文件，升级上来的用户会平白多出
    整份内置清单从没选过的候选。这里只在「这个数据目录第一次跑新版」时清一次，并落一个
    标记文件；之后用户自己点「导入 → 优选域名库」写进去的同名清单必须原样保留。

    早期实现把这套判断塞在 load_candidates() 里，等于每次开测都拿当前内容和内置
    清单比对，一旦相等就把文件清空 —— 于是用户导入优选域名库后一按「开始测速」就
    必现「候选列表为空」。迁移必须只发生一次，且绝不能发生在读路径上。
    """
    try:
        if os.path.exists(CAND_MARK):
            return
        if os.path.exists(CAND_FILE):
            try:
                with open(CAND_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    items = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
                if items and items == default_candidates():
                    save_candidates([])
                    log("candidates: dropped built-in library inherited from old version")
            except Exception:
                pass
        with open(CAND_MARK, "w", encoding="utf-8") as f:
            f.write("1")
    except Exception:
        pass


# --------------------------------------------------------------------------
# 候选库：界面「导入」里的几套清单（优选域名 / CF 官方网段 / CF 各 AS 网段）
# --------------------------------------------------------------------------
def _res_lines(name: str) -> list:
    for d in (res_dir(), base_dir()):
        try:
            with open(os.path.join(d, name), "r", encoding="utf-8", errors="ignore") as f:
                return [ln.strip() for ln in f]
        except Exception:
            continue
    return []


# 只留在判定表里、不当预置库的 AS。
# 这两个 AS 的网段全球都有 BGP 路由，但 443 上压根没有 HTTP 服务：
# 实测 AS395747 0/40、AS202623 0/30 全超时，做成预置库只会让人白扫一遍。
# 留在 cf-asn.txt 里是为了判定时还能认出「这是 CF 的机器，只是不通」，
# 而不是误报成「非CF节点」。
NO_PRESET = {"AS395747", "AS202623"}


def asn_groups() -> list:
    """读 cf-asn.txt：`[AS13335] 名称` 起一段，后面每行一个 IPv4 前缀"""
    groups, cur = [], None
    for ln in _res_lines("cf-asn.txt"):
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("["):
            head, _, tail = ln.partition("]")
            cur = {"asn": head.strip("[] ").strip(),
                   "name": tail.lstrip("| ").split("|")[0].strip(), "prefixes": []}
            groups.append(cur)
        elif cur is not None:
            cur["prefixes"].append(ln)
    return [g for g in groups if g["prefixes"]]


def _sprinkle(prefixes, want: int) -> list:
    """撒点：每轮每个网段取一个地址，不够就再轮一轮（同库每次结果一致）"""
    nets = []
    for s in prefixes:
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    if not nets:
        return []
    want = max(1, int(want))
    out, seen = [], set()
    i = 0
    while len(out) < want and i < want * 6:
        net = nets[i % len(nets)]
        k = i // len(nets)
        total = net.num_addresses
        if total <= 1:
            off = 0
        elif total == 2:
            off = k % 2
        else:
            off = 1 + (zlib.crc32(("%s#%d" % (net, k)).encode()) % (total - 2))
        ip = str(net.network_address + off)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
        i += 1
    return out


def preset_list() -> list:
    """导入菜单：每项自带现成的候选条目，前端点一下直接追加"""
    presets = [{
        "id": "domains",
        "name": "优选域名库",
        "note": "内置在用的 CF 优选域名，直接测",
        "items": default_candidates(),
    }]
    presets.append({
        "id": "cf_official",
        "name": "CF 官方 IP 段",
        "note": "官方公布的 %d 个边缘网段，每段撒点" % len(CF_RANGES),
        "items": _sprinkle(CF_RANGES, 66),
    })
    for g in asn_groups():
        if g["asn"] in NO_PRESET:
            continue
        want = {"AS13335": 150, "AS209242": 60}.get(g["asn"], 30)
        items = _sprinkle(g["prefixes"], want)
        presets.append({
            "id": g["asn"].lower(),
            "name": "%s 网段" % g["asn"],
            "note": "%s · %d 个 IPv4 段" % (g["name"] or "Cloudflare", len(g["prefixes"])),
            "items": items,
        })
    for p in presets:
        p["count"] = len(p["items"])
    return presets


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
                cf_addrs = []
                for f, ip in addrs:
                    src = cf_source(ip)
                    if src is not None:
                        cf_addrs.append((f, ip, src))
                if not cf_addrs:
                    with STATE.lock:
                        STATE.results.append({
                            "domain": cand,
                            "family": "v6" if addrs[0][0] == socket.AF_INET6 else "v4",
                            "ip": addrs[0][1], "ms": None, "status": "非CF节点", "code": 0,
                            "ok": 0, "tries": cfg["tries"], "usable": False, "asn": "",
                        })
                for fam in (socket.AF_INET6, socket.AF_INET):
                    picked = [a for a in cf_addrs if a[0] == fam][:per_fam_cap]
                    for f, ip, src in picked:
                        jobs.append((cand, f, ip, src))
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
    cand, fam, ip, src = job
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
                "code": code, "ok": len(lat), "tries": tries, "usable": status == "可用",
                "asn": src or ""}
    return {"domain": cand, "family": fam_name, "ip": ip, "ms": None, "status": err or "不通",
            "code": 0, "ok": 0, "tries": tries, "usable": False, "asn": src or ""}


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
        return {"error": "候选列表是空的，先点「导入」或粘贴几行入口"}

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
# 网络环境检测：开着 VPN / 代理时，测出来的是「到代理」的距离，不是真实链路
# --------------------------------------------------------------------------

# 只认用户态代理客户端的进程名片段。带 service / helper 的常驻服务（例如
# clash-verge-service.exe）在代理没开时也在跑，必须排除，否则天天误报。
_PROXY_PROC_HINTS = ("clash", "mihomo", "v2ray", "xray", "sing-box", "singbox",
                     "shadowsocks", "sslocal", "ss-local", "trojan", "nekoray",
                     "nekobox", "hiddify", "netch", "proxifier", "qv2ray", "v2raya")
_PROXY_PROC_SKIP = ("service", "-svc", "helper", "updater", "installer", "uninst")

# 网卡名 / 描述关键词，只在网卡处于「已连接」时才算数
_PROXY_IF_HINTS = ("tap-windows", "wintun", "wireguard", "openvpn", "tun",
                   "clash", "mihomo", "sing-box", "v2ray", "tailscale",
                   "zerotier", "vpn", "pptp", "l2tp", "sstp", "easyconnect")


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


# 只声明到 OperStatus，后面的字段用不到；前面的偏移必须和系统结构一致
_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.c_void_p),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Mtu", ctypes.c_ulong),
    ("IfType", ctypes.c_ulong),
    ("OperStatus", ctypes.c_uint),
]


def _ie_proxy_state() -> dict:
    """当前用户的系统代理设置（Edge / Chrome 默认都走这里）。"""
    out = {"enable": False, "server": "", "pac": ""}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            try:
                out["enable"] = bool(winreg.QueryValueEx(k, "ProxyEnable")[0])
            except OSError:
                pass
            try:
                out["server"] = str(winreg.QueryValueEx(k, "ProxyServer")[0] or "")
            except OSError:
                pass
            try:
                out["pac"] = str(winreg.QueryValueEx(k, "AutoConfigURL")[0] or "")
            except OSError:
                pass
    except Exception:
        pass
    return out


def _winhttp_proxy() -> str:
    """WinHTTP 自己的代理配置（netsh winhttp set proxy 设的那份）。"""
    try:
        class _INFO(ctypes.Structure):
            _fields_ = [("dwAccessType", ctypes.c_ulong),
                        ("lpszProxy", ctypes.c_wchar_p),
                        ("lpszProxyBypass", ctypes.c_wchar_p)]

        info = _INFO()
        fn = ctypes.windll.winhttp.WinHttpGetDefaultProxyConfiguration
        fn.argtypes = [ctypes.POINTER(_INFO)]
        fn.restype = ctypes.c_int
        if fn(ctypes.byref(info)) and info.dwAccessType == 3:      # NAMED_PROXY
            return str(info.lpszProxy or "")
    except Exception:
        pass
    return ""


def _tunnel_adapters() -> list:
    """已连接的虚拟网卡 / 隧道网卡（TUN 模式、WireGuard、系统 VPN 都会留下一个）。"""
    hits = []
    try:
        fn = ctypes.windll.iphlpapi.GetAdaptersAddresses
        fn.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        fn.restype = ctypes.c_ulong
        size = ctypes.c_ulong(16 * 1024)
        buf = ctypes.create_string_buffer(size.value)
        flags = 0x0002 | 0x0004 | 0x0008        # 跳过 anycast / multicast / dns
        rc = fn(0, flags, None, buf, ctypes.byref(size))
        if rc == 111:                            # ERROR_BUFFER_OVERFLOW
            buf = ctypes.create_string_buffer(size.value)
            rc = fn(0, flags, None, buf, ctypes.byref(size))
        if rc != 0:
            return hits
        node = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        while node:
            a = node.contents
            if a.OperStatus == 1:                # IfOperStatusUp
                name = " ".join(x for x in (a.FriendlyName, a.Description) if x)
                low = name.lower()
                if a.IfType in (23, 131) or any(k in low for k in _PROXY_IF_HINTS):
                    label = (a.FriendlyName or a.Description or "").strip()
                    if label and "loopback" not in low and "pseudo" not in low:
                        if label not in hits:
                            hits.append(label)
            node = a.Next
    except Exception:
        pass
    return hits


def _proxy_processes() -> list:
    """正在运行的代理客户端进程。"""
    names = []
    try:
        k = ctypes.windll.kernel32
        k.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        k.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
        k.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        snap = k.CreateToolhelp32Snapshot(2, 0)          # TH32CS_SNAPPROCESS
        if not snap or snap == ctypes.c_void_p(-1).value:
            return names
        try:
            pe = _PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(pe)
            ok = k.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                exe = pe.szExeFile
                low = exe.lower()
                stem = low[:-4] if low.endswith(".exe") else low
                if any(h in stem for h in _PROXY_PROC_HINTS) and \
                        not any(s in stem for s in _PROXY_PROC_SKIP):
                    if exe not in names:
                        names.append(exe)
                ok = k.Process32NextW(snap, ctypes.byref(pe))
        finally:
            k.CloseHandle(snap)
    except Exception:
        pass
    return names


def env_check() -> dict:
    """测速前的环境体检。

    分两档，只有真正会改路径的才拦：

    * hard —— TUN / 虚拟网卡。流量在路由层被抓进隧道，测出来是「到代理」的延迟，
      必须关掉才能测，绕不过去（后端也会拦，直接调接口同样不行）。
    * soft —— 系统代理 / PAC / WinHTTP / 代理进程。本工具用裸 socket 直连候选 IP，
      这几样只是给浏览器之类「愿意遵守的软件」用的，不会改变它走的路，数据依然有效。
      常年挂着 v2rayN / Clash 的人被它们挡住完全没道理，所以只提示一次，
      界面上给「仍要测速」和「以后不再提示」两个出口。
    """
    hard, soft = [], []
    ie = _ie_proxy_state()
    if ie.get("enable") and ie.get("server"):
        soft.append({"kind": "system_proxy", "label": "系统代理已开启：" + ie["server"]})
    if ie.get("pac"):
        soft.append({"kind": "pac", "label": "已配置 PAC 自动代理：" + ie["pac"]})
    wh = _winhttp_proxy()
    if wh:
        soft.append({"kind": "winhttp", "label": "WinHTTP 代理：" + wh})
    for a in _tunnel_adapters():
        hard.append({"kind": "adapter", "label": "虚拟网卡 / 隧道：" + a})
    for p in _proxy_processes():
        soft.append({"kind": "process", "label": "代理程序在运行：" + p})
    try:
        skip = bool(load_cfg().get("skip_env_check"))
    except Exception:
        skip = False
    return {"blocked": bool(hard), "hard": hard, "soft": soft,
            "items": hard + soft, "skip": skip}


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


# ---- 界面「最小化 / 恢复」状态 -------------------------------------------------
# 网页点「退出 → 最小化到托盘」后，页面只在最上层盖一层遮罩、DOM 全部保留。
# 托盘双击 / 小窗「打开界面」/ 再双击一次 exe，都会把 reopen 计数 +1；
# 页面心跳读到计数变了就把遮罩撤掉，测速台原样回来（不刷新、不丢已测出的结果）。
_UI = {"minimized": False, "reopen": 0}
_UI_LOCK = threading.Lock()


def ui_minimize() -> None:
    with _UI_LOCK:
        _UI["minimized"] = True


def ui_reopen() -> None:
    with _UI_LOCK:
        _UI["minimized"] = False
        _UI["reopen"] += 1


def ui_state() -> dict:
    with _UI_LOCK:
        return dict(_UI)


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
            return self._json({"ok": True, "ui": ui_state()})
        if p == "/api/check-env":
            return self._json(env_check())
        if p == "/api/init":
            snap = snapshot()
            port = self.server.server_address[1]
            return self._json({
                "config": load_cfg(),
                # 页面右上角要显示「本地服务正在哪个端口上」，退出弹窗里也要报这个端口
                "port": port,
                "endpoint": "127.0.0.1:%d" % port,
                # 候选入口每次打开都是空白，要测什么由使用者自己导入或粘贴
                "candidates": [],
                "version": VERSION,
                # 内嵌窗口（无边框）才需要页面画标题栏和缩放热区
                "embed": bool(_APP.get("embed")),
                **snap,
            })
        if p == "/api/presets":
            # 候选库（域名库 / 官方网段 / 各 AS 网段），条目现成算好随列表一起给
            return self._json({"presets": preset_list()})
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
            quit_now()
            return
        if p == "/api/exit":
            # GET 兜底（界面走 POST 带 mode，不会弹系统框）；这里还是让用户选一次
            mode = ask_exit_mode()
            self._json({"mode": mode})
            if mode == "minimize":
                log("exit -> minimize to tray")
                go_tray()
            elif mode == "exit":
                log("exit -> quit")
                quit_now()
            return
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        p = urlparse(self.path).path
        body = self._body()
        if p == "/api/run":
            cfg = load_cfg()
            probe = env_check()
            ignore = bool(body.get("ignore_env")) or bool(cfg.get("skip_env_check"))
            # TUN 会真的改路径，任何时候都拦；系统代理这类软提示只挡第一次（除非用户点了「仍要测速」）
            if probe["blocked"] or (probe["soft"] and not ignore):
                log("run blocked: proxy in use -> " +
                    "; ".join(i["label"] for i in probe["items"]))
                return self._json({"error": "检测到 VPN / 代理正在运行，请先关闭再测速",
                                   "blocked": True,
                                   "items": probe["items"],
                                   "hard": probe["hard"],
                                   "soft": probe["soft"]})
            try:
                cfg["sni"] = str(body.get("sni") or "").strip()
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
        if p == "/api/reopen":
            # 第二次双击 exe 时，由第二个进程调这里，让已跑着的实例把界面叫回来
            ui_reopen()
            app_show()
            log("reopen requested by second instance")
            return self._json({"ok": True, "ui": ui_state()})
        if p == "/api/stop":
            STATE.stop.set()
            return self._json({"stopped": True})
        if p == "/api/theme":
            th = str(body.get("theme") or "")
            if th not in ("dark", "light", "cb"):
                return self._json({"error": "未知主题"})
            cfg = load_cfg()
            cfg["theme"] = th
            save_cfg(cfg)
            return self._json({"theme": th})
        if p == "/api/env-skip":
            # 勾了「以后不再提示」：软提示（系统代理 / 代理进程）以后直接放行
            cfg = load_cfg()
            cfg["skip_env_check"] = bool(body.get("on"))
            save_cfg(cfg)
            return self._json({"skip": cfg["skip_env_check"]})
        if p == "/api/win":
            # 自绘标题栏用：最小化 / 最大化 / 拖动 / 拉边框
            act = str(body.get("action") or "")
            if act == "min":
                win_minimize()
            elif act == "max":
                return self._json({"maxed": win_toggle_max(), "embed": bool(_APP.get("embed"))})
            elif act == "drag":
                win_drag()
            elif act == "resize":
                win_resize(str(body.get("dir") or ""))
            return self._json({"ok": True, "maxed": _WIN["maxed"], "embed": bool(_APP.get("embed"))})
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
            quit_now()
            return
        if p == "/api/exit":
            mode = str(body.get("mode") or "")
            if mode not in ("minimize", "exit"):
                mode = ask_exit_mode()
            self._json({"mode": mode})
            if mode == "minimize":
                log("exit -> minimize to tray")
                go_tray()
            elif mode == "exit":
                log("exit -> quit")
                quit_now()
            else:
                log("exit -> cancelled")
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

    # 自绘按钮要自己判断悬停 / 点击，这几支也得有签名
    _u.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    _u.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    _u.SetCursor.argtypes = [wintypes.HANDLE]
    _u.SetCursor.restype = wintypes.HANDLE
    _u.TrackMouseEvent.argtypes = [ctypes.c_void_p]
    _u.AdjustWindowRectEx.argtypes = [ctypes.POINTER(wintypes.RECT), wintypes.DWORD,
                                      wintypes.BOOL, wintypes.DWORD]


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


# --------------------------------------------------------------------------
# 启动画面：自绘「正在启动」窗口（Steam 更新窗那种观感）
#
# 打包后前 1~2 秒是 PyInstaller 解压阶段，只有一张静态图可看（splash.png）。
# 这个窗口的尺寸、竖向渐变底、logo 与文字位置和静态图逐像素对齐，
# Python 一起来就接管：静态图撤掉 → 同一个位置开始走进度、跑流光。
# 分层窗口（per-pixel alpha）让圆角和字都干净，退出时按帧淡出，和主界面无缝接上。
# --------------------------------------------------------------------------
SPL_W, SPL_H, SPL_R = 600, 262, 16      # 逻辑尺寸（1x），和 splash.png 一致
SPL_TICK = 40                           # 刷新间隔 ms
SPL_WM_PING = 0x0400 + 21               # 进度 / 文案变了
SPL_WM_BYE = 0x0400 + 22                # 淡出并销毁

_SPL_BG_TOP = (17, 22, 36)
_SPL_BG_BOT = (8, 11, 19)
_SPL_TRACK = (32, 40, 56)
_SPL_CYAN = (34, 211, 238)
_SPL_INDIGO = (129, 140, 248)
_SPL_VIOLET = (167, 139, 250)


class _SIZEW(ctypes.Structure):
    _fields_ = [("cx", ctypes.c_long), ("cy", ctypes.c_long)]


class _PTW(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class _BLENDFN(ctypes.Structure):
    _fields_ = [("BlendOp", ctypes.c_ubyte), ("BlendFlags", ctypes.c_ubyte),
                ("SourceConstantAlpha", ctypes.c_ubyte), ("AlphaFormat", ctypes.c_ubyte)]


class _BMIH(ctypes.Structure):
    _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_uint16),
                ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", ctypes.c_uint32),
                ("biClrImportant", ctypes.c_uint32)]


_SPL = {"hwnd": None, "memdc": None, "bits": None, "scrdc": None,
        "w": 0, "h": 0, "x": 0, "y": 0, "S": 1.0,
        "bg": None, "buf": None, "corner": None, "f": {},
        "cur": 0.04, "target": 0.04, "text": "正在启动…", "tag": "",
        "alpha": 255, "ready": False, "closing": False, "fade_t": 0.0,
        "t0": time.time()}

if HAS_SHELL:
    _u.UpdateLayeredWindow.restype = wintypes.BOOL
    _u.UpdateLayeredWindow.argtypes = [
        wintypes.HWND, wintypes.HDC, ctypes.POINTER(_PTW), ctypes.POINTER(_SIZEW),
        wintypes.HDC, ctypes.POINTER(_PTW), wintypes.DWORD,
        ctypes.POINTER(_BLENDFN), wintypes.DWORD]
    _u.KillTimer.argtypes = [wintypes.HWND, ctypes.c_void_p]
    _g.CreateCompatibleDC.restype = wintypes.HDC
    _g.CreateCompatibleDC.argtypes = [wintypes.HDC]
    _g.CreateDIBSection.restype = wintypes.HBITMAP
    _g.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT,
                                    ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE,
                                    wintypes.DWORD]
    _g.Ellipse.argtypes = [wintypes.HDC] + [ctypes.c_int] * 4
    _g.Ellipse.restype = wintypes.BOOL


def _spl_bg(w: int, h: int) -> bytearray:
    """竖向渐变底：比纯色更像一块屏幕，也顺手把卡片边缘勾出来。"""
    buf = bytearray(w * h * 4)
    t0, t1 = _SPL_BG_TOP, _SPL_BG_BOT
    for y in range(h):
        k = y / max(1, h - 1)
        row = bytes((
            int(t1[2] + (t0[2] - t1[2]) * (1 - k)),
            int(t1[1] + (t0[1] - t1[1]) * (1 - k)),
            int(t1[0] + (t0[0] - t1[0]) * (1 - k)), 0)) * w
        buf[y * w * 4:(y + 1) * w * 4] = row
    return buf


def _spl_corners(w: int, h: int, r: int) -> list:
    """四个圆角的 alpha 覆盖表（3x3 超采样），画一次用到底。"""
    out = []
    for ox, oy, sx, sy in ((0, 0, 1, 1), (w - r, 0, -1, 1), (0, h - r, 1, -1), (w - r, h - r, -1, -1)):
        cov = bytearray(r * r)
        for j in range(r):
            for i in range(r):
                # 像素在「角内」的那一半才需要算，其余是实心
                px = i + 0.5 if sx > 0 else r - i - 0.5
                py = j + 0.5 if sy > 0 else r - j - 0.5
                if px >= r or py >= r:
                    cov[j * r + i] = 255
                    continue
                acc = 0
                for sj in (0.17, 0.5, 0.83):
                    for si in (0.17, 0.5, 0.83):
                        dx, dy = px + si - 0.5 - r, py + sj - 0.5 - r
                        if dx * dx + dy * dy <= (r - 0.5) ** 2:
                            acc += 1
                cov[j * r + i] = int(255 * acc / 9.0)
        out.append((ox, oy, r, cov))
    return out


def _spl_lerp(a, b, u: float):
    return (a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u, a[2] + (b[2] - a[2]) * u)


def _spl_bar(buf: bytearray, w: int, S: float, prog: float, now: float) -> None:
    """进度条：底槽 + 渐变填充 + 一道循环流光（Steam 更新条的那个味道）。"""
    x0, x1 = int(34 * S), int(566 * S)
    y0 = int(152 * S)
    bh = max(4, int(5 * S))
    r = bh / 2.0
    fill = x0 + int((x1 - x0) * max(0.0, min(1.0, prog)))
    span = max(1, x1 - x0)
    # 流光位置：从左往右扫，扫完从头来
    head = ((now * 0.36) % 1.30 - 0.15) * span
    for x in range(x0, x1):
        ci = ((x - x0) / span)
        if ci < 0.55:
            c = _spl_lerp(_SPL_CYAN, _SPL_INDIGO, ci / 0.55)
        else:
            c = _spl_lerp(_SPL_INDIGO, _SPL_VIOLET, (ci - 0.55) / 0.45)
        # 流光：离光头越近越亮
        d = (x - x0 - head) / (span * 0.09)
        k = 0.0 if abs(d) > 3.2 else 0.55 * (2.718281828 ** (-d * d))
        c = (c[0] + (255 - c[0]) * k, c[1] + (255 - c[1]) * k, c[2] + (255 - c[2]) * k)
        base = c if x < fill else _SPL_TRACK
        for y in range(y0, y0 + bh):
            cov = 1.0
            if x - x0 < r:                       # 左端半月
                dx = x0 + r - (x + 0.5)
                dy = (y + 0.5) - (y0 + r)
                if dx > 0:
                    dd = (dx * dx + dy * dy) ** 0.5
                    cov = max(0.0, min(1.0, r - dd + 0.5))
            elif x1 - 1 - x < r:                 # 右端半月
                dx = (x + 0.5) - (x1 - r)
                dy = (y + 0.5) - (y0 + r)
                if dx > 0:
                    dd = (dx * dx + dy * dy) ** 0.5
                    cov = max(0.0, min(1.0, r - dd + 0.5))
            i = (y * w + x) * 4
            if cov >= 0.995:
                buf[i], buf[i + 1], buf[i + 2] = int(base[2]), int(base[1]), int(base[0])
            elif cov > 0:
                for ch in range(3):
                    bgv = buf[i + ch]
                    buf[i + ch] = int(bgv + ((base[2 - ch]) - bgv) * cov)


def _spl_alpha(buf: bytearray, w: int, h: int) -> None:
    buf[3::4] = b"\xff" * (w * h)                 # 内部实心
    for ox, oy, r, cov in _SPL["corner"]:
        for j in range(r):
            row = (oy + j) * w
            for i in range(r):
                a = cov[j * r + i]
                if a != 255:
                    buf[(row + ox + i) * 4 + 3] = a


def _spl_text(S: float) -> None:
    """文字与 logo 走 GDI（真轮廓抗锯齿），像素缓冲只管底和进度条。"""
    hdc = _SPL["memdc"]
    f = _SPL["f"]
    _g.SetBkMode(hdc, 1)
    # logo：外圈用粗笔 + 深色填充，就成了圆环；中间补一个实心点
    ring_br = _g.CreateSolidBrush(0x00120B08)          # RGB(8,11,18)，比底略深
    ring_pen = _g.CreatePen(0, max(2, int(3.8 * S)), 0x00F4ECE8)
    _g.SelectObject(hdc, ring_br)
    _g.SelectObject(hdc, ring_pen)
    cx, cy, r = int(56 * S), int(76 * S), int(21 * S)
    _g.Ellipse(hdc, cx - r, cy - r, cx + r, cy + r)
    dot_br = _g.CreateSolidBrush(0x00F4ECE8)
    _g.SelectObject(hdc, dot_br)
    dr = max(2, int(5.5 * S))
    _g.Ellipse(hdc, cx - dr, cy - dr, cx + dr, cy + dr)
    _g.DeleteObject(ring_br)
    _g.DeleteObject(ring_pen)
    _g.DeleteObject(dot_br)

    def txt(font, color, x, y, x2, y2, s, flags=0x0020 | 0x0004):
        _g.SelectObject(hdc, f.get(font) or 0)
        _g.SetTextColor(hdc, color)
        rc = wintypes.RECT(x, y, x2, y2)
        _u.DrawTextW(hdc, s, -1, ctypes.byref(rc), flags)

    txt("title", 0x00FBF5F2, int(96 * S), int(40 * S), int(430 * S), int(74 * S), "CF-Pick")
    txt("sub", 0x00AF998E, int(97 * S), int(80 * S), int(520 * S), int(108 * S),
        "Cloudflare 入口优选测速台")
    txt("ver", 0x00706A5E, int(430 * S), int(24 * S), int(566 * S), int(46 * S),
        "v" + VERSION, 0x0002 | 0x0020 | 0x0004)
    txt("phase", 0x00B0A398, int(34 * S), int(168 * S), int(470 * S), int(192 * S), _SPL["text"])
    txt("pct", 0x00F9E867, int(470 * S), int(168 * S), int(566 * S), int(192 * S),
        "%d%%" % int(round(_SPL["cur"] * 100)), 0x0002 | 0x0020 | 0x0004)
    txt("tip", 0x00705A4E, int(34 * S), int(202 * S), int(566 * S), int(224 * S),
        _SPL["tag"] or "本地并发测速 · 结果只留在本机", 0x0020 | 0x0004)


def _spl_paint() -> None:
    st = _SPL
    if not st["hwnd"] or not st["bits"]:
        return
    w, h, S = st["w"], st["h"], st["S"]
    buf = st["buf"]
    buf[:] = st["bg"]
    _spl_bar(buf, w, S, st["cur"], time.time())
    ctypes.memmove(st["bits"], bytes(buf), w * h * 4)
    try:
        _spl_text(S)                       # GDI 画进同一块 DIB
    except Exception:
        pass
    buf[:] = ctypes.string_at(st["bits"], w * h * 4)   # 取回 GDI 画好的字
    _spl_alpha(buf, w, h)
    ctypes.memmove(st["bits"], bytes(buf), w * h * 4)

    size = _SIZEW(w, h)
    src = _PTW(0, 0)
    dst = _PTW(st["x"], st["y"])
    a = max(0, min(255, int(st["alpha"])))
    blend = _BLENDFN(0, 0, a, 1)           # AC_SRC_OVER + AC_SRC_ALPHA
    _u.UpdateLayeredWindow(st["hwnd"], st["scrdc"], ctypes.byref(dst),
                           ctypes.byref(size), st["memdc"], ctypes.byref(src),
                           0, ctypes.byref(blend), 2)


def _spl_create() -> bool:
    S = _dpi_scale()
    w, h = int(SPL_W * S), int(SPL_H * S)
    sw, sh = _u.GetSystemMetrics(0), _u.GetSystemMetrics(1)
    x, y = max(0, (sw - w) // 2), max(0, (sh - h) // 2)

    proc = _WNDPROC(_spl_proc)
    _KEEP.append(proc)
    wc = _WNDCLASS()
    wc.lpfnWndProc = ctypes.cast(proc, ctypes.c_void_p)
    wc.hInstance = _k.GetModuleHandleW(None)
    wc.hCursor = _u.LoadCursorW(None, 32512)
    wc.lpszClassName = "CFPickSplash"
    _u.RegisterClassW(ctypes.byref(wc))

    hwnd = _u.CreateWindowExW(
        0x00080000 | 0x00000080 | 0x00000008 | 0x08000000,   # LAYERED|TOOLWINDOW|TOPMOST|NOACTIVATE
        "CFPickSplash", "", 0x80000000,                        # WS_POPUP
        x, y, w, h, None, None, _k.GetModuleHandleW(None), None)
    if not hwnd:
        return False

    scrdc = _u.GetDC(None)
    memdc = _g.CreateCompatibleDC(scrdc)
    bmi = _BMIH()
    bmi.biSize, bmi.biWidth, bmi.biHeight = ctypes.sizeof(_BMIH), w, -h
    bmi.biPlanes, bmi.biBitCount, bmi.biCompression = 1, 32, 0
    bits = ctypes.c_void_p()
    hbmp = _g.CreateDIBSection(memdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
    if not hbmp or not bits.value:
        return False
    _g.SelectObject(memdc, hbmp)

    _SPL.update(hwnd=hwnd, memdc=memdc, bits=bits, scrdc=scrdc, w=w, h=h, x=x, y=y, S=S,
                bg=_spl_bg(w, h), buf=bytearray(w * h * 4),
                corner=_spl_corners(w, h, max(3, int(SPL_R * S))),
                f={"title": _make_font(int(25 * S), 600), "sub": _make_font(int(13 * S), 400),
                   "ver": _make_font(int(12 * S), 400), "phase": _make_font(int(13 * S), 400),
                   "pct": _make_font(int(13 * S), 600), "tip": _make_font(int(11 * S), 400)})
    _u.ShowWindow(hwnd, 4)                  # SW_SHOWNOACTIVATE
    _u.SetTimer(hwnd, 1, SPL_TICK, None)
    _spl_paint()
    return True


def _spl_proc(hwnd, msg, wparam, lparam):
    try:
        if msg == 0x0113:                          # WM_TIMER
            st = _SPL
            if st["closing"]:
                t = (time.time() - st["fade_t"]) / 0.34
                st["alpha"] = int(255 * max(0.0, 1.0 - t))
                if t >= 1.0:
                    _u.KillTimer(hwnd, 1)
                    _u.DestroyWindow(hwnd)
                    return 0
                _spl_paint()
                return 0
            gap = st["target"] - st["cur"]
            if abs(gap) > 0.0015:
                st["cur"] += gap * 0.16
            elif gap:
                st["cur"] = st["target"]
            _spl_paint()
            return 0
        if msg == SPL_WM_PING:
            _spl_paint()
            return 0
        if msg == SPL_WM_BYE:
            st = _SPL
            if not st["closing"]:
                st["cur"] = 1.0
                st["closing"] = True
                st["fade_t"] = time.time()
                _spl_paint()
            return 0
        if msg == 0x0002:                          # WM_DESTROY
            _u.PostQuitMessage(0)
            return 0
    except Exception:
        pass
    return _u.DefWindowProcW(hwnd, msg, wparam, lparam)


def _spl_loop() -> None:
    try:
        ok = _spl_create()
    except Exception:
        log("splash failed: " + traceback.format_exc()[-300:])
        ok = False
    _SPL["ready"] = True                       # 起不来也别拖住主流程
    if not ok:
        return
    msg = wintypes.MSG()
    while _u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        _u.TranslateMessage(ctypes.byref(msg))
        _u.DispatchMessageW(ctypes.byref(msg))
    _SPL["hwnd"] = None


def splash_boot() -> None:
    """尽早调用：先把 DPI 感知打开，再起自绘启动窗，最后撤掉静态图。"""
    if not HAS_SHELL or os.environ.get("CF_PICK_NO_SPLASH") == "1":
        _pyi_splash_close()
        return
    dpi_aware()
    threading.Thread(target=_spl_loop, name="cfpick-splash", daemon=True).start()
    for _ in range(80):
        if _SPL["ready"]:
            break
        time.sleep(0.01)
    _pyi_splash_close()


def splash_progress(pct: float, text: str = "", tag: str = "") -> None:
    """推进度 / 换文案。主线程随时可调，实际重绘在启动窗自己的消息循环里。"""
    try:
        _SPL["target"] = max(0.0, min(1.0, float(pct)))
    except Exception:
        pass
    if text:
        _SPL["text"] = text
    if tag:
        _SPL["tag"] = tag
    hwnd = _SPL["hwnd"]
    if hwnd and not _SPL["closing"]:
        _u.PostMessageW(hwnd, SPL_WM_PING, 0, 0)


def splash_close() -> None:
    """淡出并销毁启动窗（主界面已经画好了再叫它）。"""
    _pyi_splash_close()
    hwnd = _SPL["hwnd"]
    if not hwnd or _SPL["closing"]:
        return
    _SPL["target"] = 1.0
    _u.PostMessageW(hwnd, SPL_WM_BYE, 0, 0)


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


_SRV = {"srv": None, "port": None}


def release_port() -> None:
    """把本地服务的监听端口关掉，让「正在退出并释放端口」这句话名副其实。"""
    srv = _SRV.get("srv")
    _SRV["srv"] = None
    if srv is None:
        return
    try:
        srv.shutdown()
    except Exception:
        pass
    try:
        srv.server_close()
        log("released 127.0.0.1:%s" % _SRV.get("port"))
    except Exception:
        pass


def quit_now() -> None:
    """彻底退出：停测速 → 关服务、释放端口 → 撤图标 → 结束进程。"""
    try:
        STATE.stop.set()
    except Exception:
        pass
    release_port()
    tray_remove()
    threading.Timer(0.25, lambda: os._exit(0)).start()


def go_tray() -> None:
    """收进托盘：进程和端口都留着，随时能叫回来。"""
    ui_minimize()
    app_hide()
    tray_balloon("已收进系统托盘。双击图标打开界面，右键可彻底退出。")


_ASK = {"result": None, "hot": "", "press": ""}
ID_MIN, ID_BYE = 201, 202

if HAS_SHELL:
    class _TRACKMOUSEEVENT(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("hwndTrack", wintypes.HWND), ("dwHoverTime", wintypes.DWORD)]

# 关闭确认框的版式（逻辑 px，运行时按 DPI 缩放）。
# 和界面同一套配色：深底 + 青色主按钮 + 红色危险按钮，不用系统灰按钮。
_ASKBOX = {
    "w": 470, "h": 218,
    "bye": (24, 152, 116, 38),      # 彻底退出（危险）
    "min": (152, 152, 158, 38),     # 最小化到托盘（主按钮）
}
_ASK_TXT = {
    "title": "要把测速台留在后台吗？",
    "b1": "「最小化到托盘」保留后台进程，本地服务继续占用 127.0.0.1:%d；",
    "b2": "「彻底退出」立即停下测速、关闭服务并释放这个端口。",
    "bye": "彻底退出",
    "min": "最小化到托盘",
    "tip": "按 Esc 或点右上角 × 取消",
}


def _ask_btn_rect(key: str, S: float):
    x, y, w, h = _ASKBOX[key]
    return int(x * S), int(y * S), int((x + w) * S), int((y + h) * S)


def _ask_hit(x: int, y: int, S: float) -> str:
    for key in ("bye", "min"):
        l, t, r, b = _ask_btn_rect(key, S)
        if l <= x <= r and t <= y <= b:
            return key
    return ""


def _ask_draw_btn(hdc, key: str, S: float) -> None:
    """一个圆角按钮：主按钮填青色，危险按钮只描红边（悬停时垫一层暗红）。"""
    l, t, r, b = _ask_btn_rect(key, S)
    hot = _ASK["hot"] == key
    press = _ASK["press"] == key
    if press:
        t += max(1, int(1 * S))
        b += max(1, int(1 * S))
    rad = int(10 * S)
    if key == "min":
        fill = 0x00F0DC46 if hot else 0x00EED322          # 亮青 / 青
        edge, txt = fill, 0x00140F02                      # 深色字
    else:
        fill = 0x00141228 if hot else None                # 暗红（BGR）
        edge, txt = (0x007171F8, 0x00A5A5FC) if not hot else (0x007171F8, 0x00C4C4FF)
    br = _g.CreateSolidBrush(fill) if fill is not None else _g.CreateSolidBrush(0x00180E0B)
    pen = _g.CreatePen(0, max(1, int(S)), edge)
    try:
        _g.SelectObject(hdc, br)
        _g.SelectObject(hdc, pen)
        _g.RoundRect(hdc, l, t, r, b, rad, rad)
    finally:
        _g.DeleteObject(br)
        _g.DeleteObject(pen)
    _g.SelectObject(hdc, _SHELL.get("f_ask_btn") or 0)
    _g.SetTextColor(hdc, txt)
    rr = wintypes.RECT(l, t, r, b)
    _u.DrawTextW(hdc, _ASK_TXT[key], -1, ctypes.byref(rr), 0x0001 | 0x0004 | 0x0020)


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
        _g.SetTextColor(hdc, 0x00FBF5F2)                     # RGB(242,245,251)
        r1 = wintypes.RECT(int(24 * S), int(20 * S), rc.right - int(24 * S), int(50 * S))
        _u.DrawTextW(hdc, _ASK_TXT["title"], -1, ctypes.byref(r1), 0x0020 | 0x0004)

        _g.SelectObject(hdc, _SHELL.get("f_ask_body") or 0)
        _g.SetTextColor(hdc, 0x00AF998E)                     # RGB(142,153,175)
        port = _SHELL.get("port") or 0
        body = (_ASK_TXT["b1"] % port) + "\n" + _ASK_TXT["b2"]
        r2 = wintypes.RECT(int(24 * S), int(54 * S), rc.right - int(24 * S), int(124 * S))
        _u.DrawTextW(hdc, body, -1, ctypes.byref(r2), 0x0010)

        _ask_draw_btn(hdc, "bye", S)
        _ask_draw_btn(hdc, "min", S)

        _g.SelectObject(hdc, _SHELL.get("f_ask_tip") or 0)
        _g.SetTextColor(hdc, 0x00605A4E)                     # RGB(78,90,96)
        r3 = wintypes.RECT(int(24 * S), int(196 * S), rc.right - int(24 * S), rc.bottom)
        _u.DrawTextW(hdc, _ASK_TXT["tip"], -1, ctypes.byref(r3), 0x0020 | 0x0004)
    finally:
        _u.EndPaint(hwnd, ctypes.byref(ps))


def _ask_proc(hwnd, msg, wparam, lparam):
    try:
        S = _SHELL.get("scale") or 1.0
        if msg == 0x000F:                                    # WM_PAINT
            _ask_paint(hwnd)
            return 0
        if msg == 0x0020:                                    # WM_SETCURSOR
            pt = wintypes.POINT()
            if _u.GetCursorPos(ctypes.byref(pt)) and _u.ScreenToClient(hwnd, ctypes.byref(pt)):
                cid = "hand" if _ask_hit(pt.x, pt.y, S) else "arrow"
                _u.SetCursor(_u.LoadCursorW(None, 32649 if cid == "hand" else 32512))
                return 1
        if msg == 0x0200:                                    # WM_MOUSEMOVE
            x = ctypes.c_short(lparam & 0xFFFF).value
            y = ctypes.c_short((lparam >> 16) & 0xFFFF).value
            hot = _ask_hit(x, y, S)
            if hot != _ASK["hot"]:
                _ASK["hot"] = hot
                _u.InvalidateRect(hwnd, None, False)
            tm = _TRACKMOUSEEVENT(ctypes.sizeof(_TRACKMOUSEEVENT), 0x00000002, hwnd, 0)
            _u.TrackMouseEvent(ctypes.byref(tm))
            return 0
        if msg == 0x02A3:                                    # WM_MOUSELEAVE
            if _ASK["hot"]:
                _ASK["hot"] = ""
                _u.InvalidateRect(hwnd, None, False)
            return 0
        if msg == 0x0201:                                    # WM_LBUTTONDOWN
            x = ctypes.c_short(lparam & 0xFFFF).value
            y = ctypes.c_short((lparam >> 16) & 0xFFFF).value
            _ASK["press"] = _ask_hit(x, y, S)
            if _ASK["press"]:
                _u.InvalidateRect(hwnd, None, False)
            return 0
        if msg == 0x0202:                                    # WM_LBUTTONUP
            x = ctypes.c_short(lparam & 0xFFFF).value
            y = ctypes.c_short((lparam >> 16) & 0xFFFF).value
            hit = _ask_hit(x, y, S)
            pressed, _ASK["press"] = _ASK["press"], ""
            _u.InvalidateRect(hwnd, None, False)
            if pressed and pressed == hit:
                _ASK["result"] = "exit" if hit == "bye" else "minimize"
                _u.DestroyWindow(hwnd)
            return 0
        if msg == 0x0100 and wparam == 0x1B:                 # WM_KEYDOWN VK_ESCAPE
            _ASK["result"] = "cancel"
            _u.DestroyWindow(hwnd)
            return 0
        if msg == 0x0010:                                    # WM_CLOSE：点 × 算取消，窗口留着
            _ASK["result"] = "cancel"
            _u.DestroyWindow(hwnd)
            return 0
        if msg == 0x0002:                                    # WM_DESTROY
            _u.PostQuitMessage(0)
            return 0
    except Exception:
        pass
    return _u.DefWindowProcW(hwnd, msg, wparam, lparam)


def ask_exit_mode() -> str:
    """自绘确认框（浏览器模式的兜底路径）。返回 minimize / exit / cancel。"""
    if not HAS_SHELL:
        return "exit"
    _ASK.update(result=None, hot="", press="")
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

    # 传进去的是「客户区」尺寸：带标题栏的窗口要再加一圈边框，否则按钮会被切掉
    style = 0x00C80000                       # CAPTION | SYSMENU
    box = wintypes.RECT(0, 0, int(_ASKBOX["w"] * S), int(_ASKBOX["h"] * S))
    _u.AdjustWindowRectEx(ctypes.byref(box), style, False, 0x00000008)
    w, h = box.right - box.left, box.bottom - box.top

    wa = wintypes.RECT()
    if not _u.SystemParametersInfoW(0x0030, 0, ctypes.byref(wa), 0):
        wa = wintypes.RECT(0, 0, _u.GetSystemMetrics(0), _u.GetSystemMetrics(1))
    x = wa.left + max(0, ((wa.right - wa.left) - w) // 2)
    y = wa.top + max(0, ((wa.bottom - wa.top) - h) // 2)

    hwnd = _u.CreateWindowExW(0x00000008, "CFPickAskWnd", "CF-Pick · 关闭确认",
                              style, x, y, w, h, None, None, hinst, None)
    if not hwnd:
        return "exit"

    try:  # 深色标题栏 + 程序图标，和主界面一致
        for attr in (20, 19):
            on = ctypes.c_int(1)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(on), ctypes.sizeof(on)) == 0:
                break
        icon = _tray_icon()
        if icon:
            _u.SendMessageW(hwnd, 0x0080, 0, icon)
            _u.SendMessageW(hwnd, 0x0080, 1, icon)
    except Exception:
        pass

    _SHELL.setdefault("f_ask_title", _make_font(int(17 * S), 600))
    _SHELL.setdefault("f_ask_body", _make_font(int(13 * S), 400))
    _SHELL.setdefault("f_ask_btn", _make_font(int(13 * S), 400))
    _SHELL.setdefault("f_ask_tip", _make_font(int(11 * S), 400))

    _u.ShowWindow(hwnd, 5)
    _u.SetForegroundWindow(hwnd)

    msg = wintypes.MSG()
    while _u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        _u.TranslateMessage(ctypes.byref(msg))
        _u.DispatchMessageW(ctypes.byref(msg))
    return _ASK["result"] or "cancel"


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
    """状态小窗被关：问一下是收进托盘还是彻底退出。"""
    mode = ask_exit_mode()
    if mode == "minimize":
        log("window close -> minimize to tray")
        _show_window(False)
        go_tray()
    elif mode == "exit":
        log("window close -> quit")
        _APP["quitting"] = True
        quit_now()
    else:
        log("window close -> cancelled")


def _tray_popup(hwnd) -> None:
    u = ctypes.windll.user32
    hmenu = u.CreatePopupMenu()
    u.AppendMenuW(hmenu, 0x0, MENU_OPEN, "打开测速台")
    if not _APP["win"]:                   # 内嵌窗口就是界面本身，不再需要额外的状态窗
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
        bring_ui(_SHELL["port"])
    elif cmd == MENU_SHOW:
        _show_window(True)
    elif cmd == MENU_EXIT:
        _APP["quitting"] = True
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
                bring_ui(_SHELL["port"])
            return 0
        if msg == 0x0010:                        # WM_CLOSE
            _on_close(hwnd)
            return 0
        if msg == 0x0111:                        # WM_COMMAND
            cid = wparam & 0xFFFF
            if cid == ID_OPEN:
                bring_ui(_SHELL["port"])
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
    # 客户区尺寸传进去只是内容的大小，标题栏和边框要另加，否则底部按钮会被切
    st = 0x00CA0000      # WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
    box = wintypes.RECT(0, 0, width, height)
    u.AdjustWindowRectEx(ctypes.byref(box), st, False, 0)
    width, height = box.right - box.left, box.bottom - box.top
    sw = u.GetSystemMetrics(0)
    sh = u.GetSystemMetrics(1)
    x = int((sw - width) / 2)
    y = int((sh - height) / 2) - 40

    hwnd = u.CreateWindowExW(
        0, "CFPickStatusWnd", "CF-Pick · 测速台运行中",
        st, x, y, width, height, None, None, hinst, None)
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

    if _APP["embed"]:
        # 内嵌窗口本身就是界面：这个窗口只当托盘宿主用，不显示，免得任务栏多一个
        log("status window: hidden (embedded mode)")
    else:
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
# 内嵌窗口（Edge WebView2）
#
# 双击 exe 直接出现一个自己的窗口，标题栏是程序名、任务栏是程序图标，
# 不再借 Chrome / Edge 的 --app 壳。渲染还是 Edge 内核（WebView2 运行时，
# Win10/11 默认自带），页面本身照旧由本地 HTTP 服务提供，前端一行不用改。
#
# 拿不到 WebView2 时自动退回浏览器模式，功能不少。
# --------------------------------------------------------------------------
_WV = {"mod": None, "tried": False}
_APP = {"win": None, "quitting": False, "embed": False}
WV2_GUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"


def _webview2_runtime() -> bool:
    """查 Edge WebView2 运行时在不在（比硬启动一次试错快得多）。"""
    try:
        import winreg
    except Exception:
        return False
    for hive, path in (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\\" + WV2_GUID),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\\" + WV2_GUID),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\EdgeUpdate\Clients\\" + WV2_GUID),
    ):
        try:
            with winreg.OpenKey(hive, path) as k:
                pv = str(winreg.QueryValueEx(k, "pv")[0]).strip()
            if pv and pv != "0.0.0.0":
                return True
        except Exception:
            continue
    return False


def has_webview() -> bool:
    """能不能用内嵌窗口。

    CF_PICK_BROWSER=1 → 强制回到浏览器模式
    CF_PICK_NO_BROWSER=1 → 完全不开界面（CI 冒烟测试用）
    """
    if not HAS_SHELL:
        return False
    if os.environ.get("CF_PICK_BROWSER") == "1":
        return False
    if os.environ.get("CF_PICK_NO_BROWSER") == "1":
        return False
    if not _WV["tried"]:
        _WV["tried"] = True
        try:
            if not _webview2_runtime():
                log("WebView2 运行时未安装 -> 浏览器模式")
            else:
                import webview
                _WV["mod"] = webview
                log("WebView2 就绪 -> 内嵌窗口模式")
        except Exception:
            log("pywebview 不可用 -> 浏览器模式: " + traceback.format_exc()[-300:])
            _WV["mod"] = None
    return _WV["mod"] is not None


def app_hwnd():
    """内嵌窗口的 Win32 句柄（隐藏时也要能找到，所以不过滤可见性）。"""
    if os.name != "nt" or not _APP["win"]:
        return None
    try:
        u32 = ctypes.windll.user32
        hits = []

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def cb(hwnd, _lp):
            n = u32.GetWindowTextLengthW(hwnd)
            if n > 0:
                buf = ctypes.create_unicode_buffer(n + 1)
                u32.GetWindowTextW(hwnd, buf, n + 1)
                if buf.value.startswith(PAGE_TITLE):
                    hits.append(hwnd)
            return True

        u32.EnumWindows(cb, None)
        return hits[0] if hits else None
    except Exception:
        return None


def app_show() -> bool:
    """把内嵌窗口叫回来（托盘双击 / 再双击 exe / 小窗按钮都走这里）。"""
    w = _APP["win"]
    if not w:
        return False
    try:
        w.show()
        try:
            w.restore()                      # 之前是最小化状态的话先还原
        except Exception:
            pass
        hwnd = app_hwnd()
        if hwnd:
            focus_window(hwnd)
        try:                                  # 页面若盖着「已最小化」遮罩，顺手撤掉
            w.evaluate_js("if(typeof restoreUI==='function') restoreUI();")
        except Exception:
            pass
        return True
    except Exception:
        log("app_show failed: " + traceback.format_exc()[-300:])
        return False


def app_hide() -> None:
    w = _APP["win"]
    if not w:
        return
    try:
        w.hide()
    except Exception:
        log("app_hide failed: " + traceback.format_exc()[-200:])


# --------------------------------------------------------------------------
# 自绘标题栏：窗口是无边框的，拖动 / 缩放 / 最大化都要自己接
# --------------------------------------------------------------------------
_SWP_NOZORDER = 0x0004
_SWP_NOMOVE = 0x0002
_SWP_NOSIZE = 0x0001
_MIN_W, _MIN_H = 960, 620
_WIN = {"maxed": False, "restore": None, "moving": False, "resizing": False}


def _work_area():
    """当前显示器工作区（不含任务栏）。"""
    u32 = ctypes.windll.user32
    rc = wintypes.RECT()
    if u32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rc), 0):
        return rc.left, rc.top, rc.right, rc.bottom
    return 0, 0, u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)


def win_drag() -> None:
    """按住页头拖窗口。

    无边框窗口拿不到系统的移动循环（发 WM_NCLBUTTONDOWN/HTCAPTION 在这套窗体上不起作用），
    所以自己跟鼠标走。最大化状态下先按光标比例还原，再接着拖——和系统行为一致。
    """
    hwnd = app_hwnd()
    if not hwnd or _WIN["resizing"] or _WIN["moving"]:
        return
    _WIN["moving"] = True

    def run():
        u32 = ctypes.windll.user32
        try:
            pt = wintypes.POINT()
            u32.GetCursorPos(ctypes.byref(pt))
            if _WIN["maxed"]:                     # 从最大化状态拖出来：先还原到对应位置
                r = _WIN["restore"] or (0, 0, 1400, 900)
                wl, wt, wr, wb = _work_area()
                nh = r[3] if r[3] > 200 else 900
                nw = r[2] if r[2] > 300 else 1400
                ratio = (pt.x - wl) / max(1, wr - wl)
                nl = int(pt.x - nw * ratio)
                nt = max(wt, pt.y - 20)
                _WIN["maxed"] = False
                u32.SetWindowPos(hwnd, None, nl, nt, nw, nh, _SWP_NOZORDER)
            rc = wintypes.RECT()
            u32.GetWindowRect(hwnd, ctypes.byref(rc))
            ox, oy = pt.x, pt.y
            l, t = rc.left, rc.top
            while u32.GetAsyncKeyState(0x01) & 0x8000:
                u32.GetCursorPos(ctypes.byref(pt))
                u32.SetWindowPos(hwnd, None, l + (pt.x - ox), t + (pt.y - oy), 0, 0,
                                 _SWP_NOZORDER | _SWP_NOSIZE)
                time.sleep(0.012)
            u32.GetCursorPos(ctypes.byref(pt))
            wl, wt, _wr, _wb = _work_area()
            if pt.y <= wt + 3:                    # 拖到屏幕顶 = 最大化，和系统一样
                win_toggle_max()
        except Exception:
            pass
        finally:
            _WIN["moving"] = False

    threading.Thread(target=run, daemon=True).start()


def win_resize(direction: str) -> None:
    """按住窗口边 / 角拉大小：无边框窗口没有原生缩放边框，自己跟一遍鼠标。"""
    hwnd = app_hwnd()
    if not hwnd or _WIN["maxed"] or _WIN["resizing"]:
        return
    d = "".join(ch for ch in str(direction or "").lower() if ch in "nsew")
    if not d or d in ("ns", "sn", "ew", "we"):
        return
    _WIN["resizing"] = True

    def run():
        u32 = ctypes.windll.user32
        try:
            r = wintypes.RECT()
            pt = wintypes.POINT()
            u32.GetWindowRect(hwnd, ctypes.byref(r))
            u32.GetCursorPos(ctypes.byref(pt))
            ox, oy = pt.x, pt.y
            l, t, rr, b = r.left, r.top, r.right, r.bottom
            while u32.GetAsyncKeyState(0x01) & 0x8000:
                u32.GetCursorPos(ctypes.byref(pt))
                dx, dy = pt.x - ox, pt.y - oy
                nl, nt, nr, nb = l, t, rr, b
                if "w" in d:
                    nl = min(l + dx, rr - _MIN_W)
                if "e" in d:
                    nr = max(rr + dx, l + _MIN_W)
                if "n" in d:
                    nt = min(t + dy, b - _MIN_H)
                if "s" in d:
                    nb = max(b + dy, t + _MIN_H)
                u32.SetWindowPos(hwnd, None, nl, nt, nr - nl, nb - nt, _SWP_NOZORDER)
                time.sleep(0.012)
        except Exception:
            pass
        finally:
            _WIN["resizing"] = False

    threading.Thread(target=run, daemon=True).start()


def win_toggle_max() -> bool:
    """最大化 / 还原：无边框窗口不靠系统的 zoom，自己记原位置再铺满工作区。"""
    hwnd = app_hwnd()
    if not hwnd:
        return False
    u32 = ctypes.windll.user32
    if _WIN["maxed"]:
        l, t, w, h = _WIN["restore"] or (0, 0, 1400, 900)
        _WIN["maxed"] = False
        u32.SetWindowPos(hwnd, None, l, t, w, h, _SWP_NOZORDER)
        return False
    r = wintypes.RECT()
    u32.GetWindowRect(hwnd, ctypes.byref(r))
    _WIN["restore"] = (r.left, r.top, r.right - r.left, r.bottom - r.top)
    wl, wt, wr, wb = _work_area()
    _WIN["maxed"] = True
    u32.SetWindowPos(hwnd, None, wl, wt, wr - wl, wb - wt, _SWP_NOZORDER)
    return True


def win_minimize() -> None:
    hwnd = app_hwnd()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 6)      # SW_MINIMIZE



def _app_closing():
    """点窗口右上角 X：收进托盘，不结束进程。"""
    if _APP["quitting"]:
        return True
    log("app window close -> hide to tray")
    app_hide()
    ui_minimize()
    tray_balloon("测速台已收进系统托盘。双击图标打开，右键可彻底退出。")
    return False                              # 返回 False = 取消关闭


def _app_loaded():
    # 主界面已经画出来了：启动窗走完最后一段进度，停半拍再淡出，
    # 让页面先把第一帧画完，中间不会闪一下空窗口
    splash_progress(1.0, "准备就绪")
    threading.Timer(0.30, splash_close).start()
    threading.Thread(target=_dress_app_window, daemon=True).start()


def _dress_app_window() -> None:
    """窗口出来后补三件事：夹进工作区、深色标题栏、程序图标（WinForms 默认是占位图标）。"""
    hwnd = app_hwnd()
    if not hwnd:
        return
    try:
        # pywebview 是按整块屏幕居中的，遇到任务栏不在「隐藏」状态时底边会压上去
        u32 = ctypes.windll.user32
        r, wa = wintypes.RECT(), wintypes.RECT()
        u32.GetWindowRect(hwnd, ctypes.byref(r))
        if u32.SystemParametersInfoW(0x0030, 0, ctypes.byref(wa), 0):
            dx = dy = 0
            if r.bottom > wa.bottom:
                dy = wa.bottom - r.bottom
            if r.right > wa.right:
                dx = wa.right - r.right
            if r.top + dy < wa.top:
                dy = wa.top - r.top
            if r.left + dx < wa.left:
                dx = wa.left - r.left
            if dx or dy:
                u32.SetWindowPos(hwnd, None, r.left + dx, r.top + dy, 0, 0, 0x0001 | 0x0004)
    except Exception:
        pass
    try:
        icon = _tray_icon()
        if icon:
            user32 = ctypes.windll.user32
            user32.SendMessageW(hwnd, 0x0080, 0, icon)      # WM_SETICON ICON_SMALL
            user32.SendMessageW(hwnd, 0x0080, 1, icon)      # WM_SETICON ICON_BIG
    except Exception:
        pass
    try:
        # 无边框窗口没有系统标题栏了：靠 DWM 把四角切圆（Win11），Win10 上不生效也不影响
        corner = ctypes.c_int(2)                            # DWMWCP_ROUND
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 33, ctypes.byref(corner), ctypes.sizeof(corner))   # DWMWA_WINDOW_CORNER_PREFERENCE
    except Exception:
        pass


def _app_size() -> tuple:
    """窗口尺寸按「可用工作区」来（扣掉任务栏），小本子上也不会超出屏幕。"""
    try:
        u = ctypes.windll.user32
        rc = wintypes.RECT()
        if u.SystemParametersInfoW(0x0030, 0, ctypes.byref(rc), 0):   # SPI_GETWORKAREA
            sw, sh = rc.right - rc.left, rc.bottom - rc.top
        else:
            sw, sh = u.GetSystemMetrics(0), u.GetSystemMetrics(1)
        s = _dpi_scale()
        # 无边框窗口：传进去的就是整窗尺寸，不用再给标题栏留余量
        w = int(min(1240, sw / s - 60))
        h = int(min(900, sh / s - 30))
        return max(960, w), max(620, h)
    except Exception:
        return 1240, 860


def embed_start(port: int) -> bool:
    """开内嵌窗口并进入 GUI 循环（阻塞到窗口真关闭）。失败返回 False。"""
    wv = _WV["mod"]
    if not wv:
        return False
    w_px, h_px = _app_size()
    theme = str(load_cfg().get("theme") or "dark")
    bg = "#EEF2F9" if theme == "light" else "#080C14"
    try:
        w = wv.create_window(
            PAGE_TITLE + " · 测速台",
            "http://127.0.0.1:%d/" % port,
            width=w_px, height=h_px, min_size=(960, 620),
            frameless=True, easy_drag=False,      # 标题栏自己画：右上角那组按钮在页面里
            background_color=bg,
        )
        _APP["win"] = w
        w.events.closing += _app_closing
        w.events.loaded += _app_loaded
        log("embedded window created")
        splash_progress(0.88, "正在渲染界面…")
        wv.start(debug=False)
    except Exception:
        log("内嵌窗口启动失败 -> 浏览器模式: " + traceback.format_exc()[-800:])
        _APP["win"] = None
        return False
    log("embedded window destroyed -> exit")
    os._exit(0)
    return True


def bring_ui(port: int) -> None:
    """统一入口：内嵌窗口优先，其次旧浏览器窗口，最后才开新标签。"""
    open_ui(port)
    if not _APP["embed"]:
        _show_window(True)                    # 浏览器模式下状态小窗才有意义


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
    """状态小窗 / 托盘按钮 / 再次双击 exe 都走这里。

    先发「恢复界面」信号：页面若正停在「已最小化到托盘」的遮罩上，
    心跳读到就立刻撤掉遮罩，测速台原样回来（不刷新、已测结果还在）。
    """
    ui_reopen()
    if os.environ.get("CF_PICK_NO_BROWSER") == "1":
        return False
    if app_show():                        # 内嵌窗口模式：直接叫回自己的窗口
        return True
    if _APP["win"]:                       # 有窗口但这会儿叫不起来，别再开浏览器
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


def notify_reopen(port: int) -> bool:
    """跨进程叫回界面。

    _UI 是进程内状态，第二个进程自己改没用；必须让已经在跑的那个实例
    （托盘图标、状态小窗都挂在那里）把 reopen 计数 +1，页面才会撤掉遮罩。
    """
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:%d/api/reopen" % port,
                                     data=b"{}", method="POST")
        with urllib.request.urlopen(req, timeout=1.2) as r:
            return r.status == 200
    except Exception:
        return False


def main():
    t0 = time.time()
    first = is_first_instance()

    splash_boot()                      # 自绘启动窗接手静态图，从这里开始有进度可看
    splash_progress(0.10, "正在检查运行环境…")

    if not first:
        # 已有实例在跑：等它把端口监听起来，然后把已有的界面叫回来，自己退出。
        splash_progress(0.45, "已有一个测速台在运行，正在把界面叫回来…")
        deadline = t0 + 25
        while time.time() < deadline:
            for p in PORTS:
                if already_running(p):
                    log("second instance -> reuse 127.0.0.1:%d" % p)
                    notify_reopen(p)      # 先让老实例放行界面（它才有 _UI 和托盘）
                    open_ui(p)            # 再把已有窗口提到前台
                    splash_progress(1.0, "已切回正在运行的测速台")
                    time.sleep(0.15)
                    splash_close()
                    return
            time.sleep(0.25)
        log("second instance: 未找到已在运行的实例，改为自行启动")

    splash_progress(0.28, "正在载入界面…")
    candidates_boot_init()             # 只在本次数据目录第一次启动时做旧候选迁移
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
    _SRV.update(srv=srv, port=port)

    log("listening on 127.0.0.1:%d  data=%s  启动耗时 %.2fs" % (port, DATA, time.time() - t0))
    splash_progress(0.48, "本地服务已就绪 · 127.0.0.1:%d" % port)

    embed = has_webview()
    _APP["embed"] = embed
    splash_progress(0.62, "正在准备窗口…" if embed else "正在打开浏览器…")

    log("status window + tray: %s" % ("on" if shell_start(port) else "off"))

    # 本地服务挪到后台线程：主线程要留给内嵌窗口（WebView2 的 GUI 循环必须在主线程）
    threading.Thread(target=srv.serve_forever, name="cfpick-http", daemon=True).start()

    if embed and embed_start(port):
        return                                    # 窗口关闭后 embed_start 自己退出进程

    # 内嵌窗口起不来（缺运行时 / 初始化失败）：退回原来的「浏览器 + 状态小窗」
    if embed:
        _APP["embed"] = False
        _APP["win"] = None
        log("回退到浏览器模式")
        _show_window(True)
    splash_progress(0.92, "正在打开界面…")
    threading.Timer(0.35, lambda: startup_open(port)).start()
    threading.Timer(1.4, splash_close).start()
    try:
        threading.Event().wait()                  # 主线程挂住，服务在后台线程跑
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        fatal("启动失败：\n\n" + traceback.format_exc()[-1200:])
