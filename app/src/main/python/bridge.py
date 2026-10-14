# -*- coding: utf-8 -*-
"""Android 端 PLC 配置桥接层（Route A）。

复用 mdp_client 协议栈，把 PC 版 twincat2_login.py 的 Api 逻辑搬到手机端，
通过 addJavascriptInterface 供 app.html 的 JS 调用。所有方法都返回 JSON 字符串。
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mdp_client  # noqa: E402

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

try:
    from java.net import NetworkInterface, Inet4Address
    from java.util import Collections
    _HAS_JAVA_NET = True
except Exception:
    NetworkInterface = None
    Inet4Address = None
    Collections = None
    _HAS_JAVA_NET = False

USER = "Administrator"
PASS = "1"


def _to_iso8601(dt_local, bias="+08:00"):
    dt_local = (dt_local or "").strip()
    if "T" not in dt_local:
        return None
    d, tpart = dt_local.split("T", 1)
    parts = tpart.split(":")
    if len(parts) == 2:
        tpart = tpart + ":00"
    if "." not in tpart:
        tpart = tpart + ".000"
    return "{0}T{1}{2}".format(d, tpart, bias)


def is_valid_target(s):
    s = s.strip()
    if not s:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s):
        return all(0 <= int(p) <= 255 for p in s.split("."))
    return bool(re.match(r"^[a-zA-Z0-9\-\.]+$", s))


# ---------------------------------------------------------------------------
# 最近连接历史（持久化到 App 私有目录）
# ---------------------------------------------------------------------------
# 桌面预览时 Java 侧不会调用 set_data_dir，则回退到脚本所在目录。
_DATA_DIR = None  # 由 Java 侧经 set_data_dir() 注入（App 私有 files 目录）
_HISTORY_FILE = "history.json"
_MAX_HISTORY = 5


def set_data_dir(path):
    global _DATA_DIR
    _DATA_DIR = path


def _history_path():
    base = _DATA_DIR if _DATA_DIR else os.path.dirname(os.path.abspath(__file__))
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        pass
    return os.path.join(base, _HISTORY_FILE)


def _load_history():
    try:
        with open(_history_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            # 兼容旧版纯字符串历史
            out = []
            for h in data:
                if isinstance(h, dict) and h.get("ip"):
                    out.append(h)
                elif isinstance(h, str) and h:
                    out.append({"ip": h, "ts": 0})
            return out
    except Exception:
        pass
    return []


def _save_history(data):
    path = _history_path()
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 网段扫描（Android 适配版）
# ---------------------------------------------------------------------------
# 与 PC 版不同：Android 没有 ipconfig / 不支持 ICMP ping，因此
#   1) 获取本机网段：用 java.net.NetworkInterface 取 IPv4 地址 + 子网前缀长度 → CIDR
#   2) 在线判定：并行 TCP 端口探测（80/443/48898 ADS 等），命中端口即视为在线
# 纯端口探测可能漏掉「无任何开放端口」的设备，但对发现 PLC（必备 48898 ADS）足够。
_SCAN_PORTS = [
    (48898, "ADS"),
    (80, "Web"),
    (443, "HTTPS"),
    (502, "Modbus"),
    (22, "SSH"),
    (8080, "HTTP-alt"),
]


_KIND_WIFI = ("wlan", "ap", "wifi")
_KIND_ETH = ("eth", "usb", "rndis")
_KIND_CELL = ("rmnet", "ccmni", "pdp", "ppp", "clat")


def _iface_kind(name):
    n = (name or "").lower()
    if n.startswith(_KIND_WIFI) or "wifi" in n:
        return "wifi"
    if n.startswith(_KIND_ETH):
        return "eth"
    if n.startswith(_KIND_CELL):
        return "cell"
    if n.startswith(("tun", "tap")):
        return "vpn"
    return "other"


def get_subnets():
    """枚举本机所有非回环、已启用网卡的 IPv4 网段（含蜂窝），返回 (subs, debug)。

    注意：不再按网卡名跳过蜂窝/拨号口 —— 否则手机只连蜂窝时列表会全空，
    表现为“无法选择网卡 / 请先选择网段”。现在一律列出，由 UI 标注网络类型。
    """
    subs, dbg = [], []
    if not _HAS_JAVA_NET or NetworkInterface is None:
        return subs, "java 网络接口不可用（Chaquopy java.net 导入失败）"
    try:
        enums = NetworkInterface.getNetworkInterfaces()
        if enums is None:
            return subs, "getNetworkInterfaces() 返回空"
        ifaces = Collections.list(enums) if Collections is not None else list(enums)
    except Exception as e:
        return subs, "枚举网络接口失败：{}".format(e)
    for iface in ifaces:
        try:
            name = iface.getName() or "?"
            up = bool(iface.isUp())
            loop = bool(iface.isLoopback())
        except Exception:
            continue
        try:
            addrs = iface.getInterfaceAddresses() or []
        except Exception:
            addrs = []
        for ia in addrs:
            try:
                addr = ia.getAddress()
                ip = addr.getHostAddress()
                is4 = isinstance(addr, Inet4Address)
                prefix = int(ia.getNetworkPrefixLength())
            except Exception as e:
                dbg.append("{},?（{}）".format(name, e))
                continue
            dbg.append("{} {} /{} {}{}{}".format(
                name, ip, prefix, "v4" if is4 else "v6",
                " up" if up else " down", " loop" if loop else ""))
            if not is4 or not ip or ip.startswith("127.") or ":" in ip:
                continue
            if loop or not up:
                continue
            if prefix <= 0 or prefix > 32:
                continue
            try:
                net = ipaddress.ip_network("{}/{}".format(ip, prefix), strict=False)
                subs.append({"iface": name, "ip": ip, "net": str(net),
                             "count": max(0, net.num_addresses - 2),
                             "kind": _iface_kind(name)})
            except Exception:
                continue
    # 同一网段多别名去重
    seen, uniq = set(), []
    for s in subs:
        if s["net"] in seen:
            continue
        seen.add(s["net"])
        uniq.append(s)
    return uniq, " | ".join(dbg)


def _tcp_open(ip, port, timeout=0.3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_subnet(net_cidr):
    """对给定 CIDR 并行 TCP 端口探测，返回在线设备 [{"ip","tags"}]（按 IP 升序）。"""
    net = ipaddress.ip_network(net_cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]

    def probe(ip):
        tags = []
        for port, tag in _SCAN_PORTS:
            if _tcp_open(ip, port, 0.3):
                tags.append(tag)
        return {"ip": ip, "tags": tags}

    results = []
    with ThreadPoolExecutor(max_workers=120) as ex:
        results = list(ex.map(probe, hosts))
    online = [r for r in results if r["tags"]]
    online.sort(key=lambda d: int(ipaddress.ip_address(d["ip"])))
    return online


class Api:
    def __init__(self):
        self.client = None
        self.nic_mods = []
        self.nic_data = []
        self.time_mod = None
        self.last_time = None
        self.history = _load_history()  # 最近连接历史，持久化到 App 私有目录
        self.ams_net_id = None  # 设备 AMS NetId（ADS 读取），供界面显示

    def connect(self, ip, user=None, pw=None):
        if not is_valid_target(ip):
            return {"ok": False, "msg": "IP 地址 / 主机名格式不正确"}
        user = user or USER
        pw = pw if pw else PASS
        try:
            c = mdp_client.MdpClient(ip, user, pw)
            nics = c.read_all_nic()
            t = c.read_time()
            if not nics and not t:
                return {"ok": False, "msg": "未读取到任何模块参数（设备可能不支持）"}
            self.client = c
            self.nic_mods = c.nic_modules()
            self.nic_data = nics
            self.time_mod = c.find_module(mdp_client.TYPE_TIME)
            self.last_time = t
            self.add_history(ip)
            try:
                self.ams_net_id = c.read_ams_net_id()
            except Exception:
                self.ams_net_id = None
            return {"ok": True, "nics": nics, "time": t, "ams_net_id": self.ams_net_id}
        except Exception as e:
            return {"ok": False, "msg": "连接失败：{}".format(e)}

    def refresh(self):
        if not self.client:
            return {"ok": False, "msg": "未连接"}
        try:
            nics = self.client.read_all_nic()
            t = self.client.read_time()
            self.last_time = t
            self.nic_data = nics
            return {"ok": True, "nics": nics, "time": t, "ams_net_id": self.ams_net_id}
        except Exception as e:
            return {"ok": False, "msg": "刷新失败：{}".format(e)}

    def current_time(self):
        if not self.client or self.time_mod is None:
            return {"ok": False, "text_datetime": None}
        try:
            t = self.client.read_time(self.time_mod, with_timezones=False)
            return {"ok": True, "text_datetime": t.get("text_datetime")}
        except Exception:
            return {"ok": False, "text_datetime": None}

    def apply_time(self, sntp_server, sntp_refresh, timezone, dt_local=None):
        if not self.client:
            return {"ok": False, "msg": "未连接"}
        try:
            # 来自 WebView 桥接时，JS 数字可能是 Integer/Double/None，统一规整为 int
            if sntp_refresh is not None:
                sntp_refresh = _as_int(sntp_refresh)
            if timezone is not None:
                timezone = _as_int(timezone)
            text_dt = None
            if dt_local:
                bias = "+08:00"
                if self.last_time and self.last_time.get("text_datetime"):
                    m = re.search(r"([+-]\d{2}:\d{2})", self.last_time["text_datetime"])
                    if m:
                        bias = m.group(1)
                text_dt = self._to_iso8601(dt_local, bias)
                if not text_dt:
                    return {"ok": False, "msg": "系统日期时间格式不正确"}
            codes = self.client.write_time(
                self.time_mod,
                sntp_server=sntp_server or None,
                sntp_refresh=sntp_refresh,
                timezone=timezone,
                text_datetime=text_dt,
            )
            if all(code == 0 for code in codes):
                return {"ok": True, "msg": "系统时间设置已写入设备"}
            return {"ok": False, "msg": "写入返回错误码：{}".format(codes)}
        except Exception as e:
            return {"ok": False, "msg": "写入失败：{}".format(e)}

    def apply_nic(self, idx, ip, subnet, gateway, dhcp):
        if not self.client:
            return {"ok": False, "msg": "未连接"}
        # 自愈：异常时序下模块列表可能为空，按需重读，避免“无效的网卡索引”
        if not self.nic_mods:
            try:
                self.nic_mods = self.client.nic_modules()
                self.nic_data = self.client.read_all_nic()
            except Exception:
                pass
        idx = _as_int(idx)
        if idx is None or idx < 0 or idx >= len(self.nic_mods):
            return {"ok": False,
                    "msg": "无效的网卡索引（idx={0}, 可用网卡数={1}）".format(idx, len(self.nic_mods))}
        name = ""
        if 0 <= idx < len(self.nic_data):
            name = self.nic_data[idx].get("name", "")
        if name.strip().upper().endswith("X2"):
            return {"ok": False,
                    "msg": "X2 网口为当前连接网口，禁止修改（仅 X1 网口可修改）"}
        mod = self.nic_mods[idx]
        if dhcp:
            codes = self.client.write_nic(mod, dhcp=True)
            if not all(code == 0 for code in codes):
                return {"ok": False, "msg": "DHCP 写入返回错误码：{}".format(codes)}
            return self._renew_and_report(mod, "已启用 DHCP（静态地址将被忽略）")
        code = self.client.write_nic_service(mod, ip or "", subnet or "", gateway or "")
        if code != 0:
            return {"ok": False, "msg": "IP 写入返回错误码：0x{:08X}".format(code & 0xFFFFFFFF)}
        return self._renew_and_report(mod, "静态 IP 已写入")

    def _renew_and_report(self, mod, base_msg):
        try:
            rc = self.client.write_nic_renew(mod)
        except Exception as e:
            return {"ok": True,
                    "msg": base_msg + "，但网卡释放/续订调用异常（{}），可能仍需重启才能生效".format(e)}
        if rc == 0:
            return {"ok": True,
                    "msg": base_msg + "，并已执行网卡释放/续订，新设置已立即生效（无需断电重启）"}
        return {"ok": True,
                "msg": base_msg + "，但网卡释放/续订返回 0x{:08X}，可能仍需重启才能生效".format(rc & 0xFFFFFFFF)}

    def disconnect(self):
        self.client = None
        self.nic_mods = []
        self.time_mod = None
        return {"ok": True}

    def add_history(self, ip):
        ip = (ip or "").strip()
        if not ip:
            return self.history
        self.history = [h for h in self.history
                        if (h.get("ip") if isinstance(h, dict) else h) != ip]
        self.history.insert(0, {"ip": ip, "ts": int(time.time())})
        self.history = self.history[:_MAX_HISTORY]
        _save_history(self.history)
        return self.history

    def get_history(self):
        return self.history

    def del_history(self, ip):
        ip = (ip or "").strip()
        self.history = [h for h in self.history
                        if (h.get("ip") if isinstance(h, dict) else h) != ip]
        _save_history(self.history)
        return self.history

    def clear_history(self):
        self.history = []
        _save_history(self.history)
        return self.history

    def scan_subnets(self):
        try:
            subs, dbg = get_subnets()
            return {"ok": True, "subnets": subs, "debug": dbg}
        except Exception as e:
            return {"ok": False, "msg": "获取网段失败：" + str(e)}

    def scan(self, net_cidr):
        try:
            if not net_cidr or "/" not in net_cidr:
                return {"ok": False, "msg": "请选择有效的网段（CIDR）"}
            net = ipaddress.ip_network(net_cidr, strict=False)
            n = net.num_addresses
            if n - 2 > 2048:
                return {"ok": False,
                        "msg": "网段过大（约 {} 个地址），请选择更小的网段".format(n - 2)}
            online = scan_subnet(net_cidr)
            return {"ok": True, "net": str(net), "online": online}
        except Exception as e:
            return {"ok": False, "msg": "扫描失败：" + str(e)}


_api = None


def get_api():
    global _api
    if _api is None:
        _api = Api()
    return _api


def _j(obj):
    return json.dumps(obj, separators=(',', ':'))


def _wrap(fn):
    try:
        return _j(fn())
    except Exception as e:
        return _j({"ok": False, "msg": "Python 异常：" + str(e)})


def _as_int(v, default=None):
    """把来自 WebView 桥接的各种形态（int/float/str/None/NaN）统一转成 int。

    WebView 经 Java 桥接传来的数字可能是 Java int/Double，也可能在极端情况下是
    Chaquopy 代理对象；这里逐一兜底，转不出就返回 default，避免 int() 抛错。"""
    if v is None:
        return default
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, float):
        if v != v:  # NaN
            return default
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return default
        try:
            return int(s)
        except ValueError:
            return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def get_last():
    h = get_api().history
    return h[0].get("ip") if h and isinstance(h[0], dict) else ""


def get_history():
    return _j(get_api().get_history())


def del_history(ip):
    return _j(get_api().del_history(ip))


def clear_history():
    return _j(get_api().clear_history())


def connect(ip):
    return _wrap(lambda: get_api().connect(ip))


def refresh():
    return _wrap(get_api().refresh)


def current_time():
    return _wrap(get_api().current_time)


def apply_nic(idx, ip, subnet, gateway, dhcp):
    return _wrap(lambda: get_api().apply_nic(idx, ip, subnet, gateway, dhcp))


def apply_time(sntp_server, sntp_refresh, timezone, dt_local):
    return _wrap(lambda: get_api().apply_time(sntp_server, sntp_refresh, timezone, dt_local))


def disconnect():
    return _wrap(get_api().disconnect)


def scan_subnets():
    return _wrap(get_api().scan_subnets)


def scan(net):
    return _wrap(lambda: get_api().scan(net))
