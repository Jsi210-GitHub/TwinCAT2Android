"""Beckhoff Device Manager MDP client (NTLM, via /MdpWebService/MdpWebService.dll).

Reverse-engineered from the device's DeviceManager JS. Reads/writes NIC (IP
settings) and TIME (system time / SNTP / timezone) module parameters without
exposing the original web console UI.

Design notes
------------
* Python 3.13+ removed MD4 from hashlib, which breaks NTLM. md4_patch.py injects
  a pure-Python MD4 so ntlm_auth works.
* We use a *persistent* http.client connection with a single NTLM handshake
  (type-1 -> 401 type-2 -> type-3), then reuse the connection for every MDP call
  by replaying the type-3 token. This avoids the per-request re-handshake that
  the WinCE web service throttles / rejects.
* Only stdlib + ntlm_auth are required (no requests / requests_ntlm).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import md4_patch  # noqa: E402  (patches hashlib for NTLM)

import base64
import struct
import re
import http.client  # noqa: E402
from ntlm_auth.ntlm import NtlmContext  # noqa: E402

MDP_NS = "urn:beckhoff.com:service:cxconfig:1"
READ_IG = 0xF080
WRITE_IG = 0xF081

TYPE_NIC = 2
TYPE_TIME = 3
TYPE_CONNECTIVITY = 8   # Device Manager「Connectivity」模块：暴露本机 AMS NetId + TwinCAT 路由表
TYPE_DISPLAY = 19


def mdp_offset(index, sub, flags=0):
    return ((index & 0xFFFF) << 16) | ((flags & 0xFF) << 8) | (sub & 0xFF)


def cstr(b):
    if b is None:
        return ""
    z = b.find(b"\x00")
    if z >= 0:
        b = b[:z]
    return b.decode("latin-1", "replace").strip()


def cstr_to_buf(s, size):
    buf = s.encode("latin-1", "replace")[:size]
    return buf + b"\x00" * (size - len(buf))


class NtlmTransport:
    """Per-call NTLM-authenticated HTTP transport.

    The WinCE web service re-challenges after the first authenticated request on a
    connection, so we perform a *fresh* 3-step handshake (GET / with type-1 ->
    401 type-2 -> POST with type-3) for every single MDP call. Each call is a
    self-contained connection.
    """

    def __init__(self, host, port=80, user="Administrator", pw="1", domain="", timeout=30):
        self.host, self.port = host, port
        self.user, self.pw, self.domain = user, pw, domain
        self.timeout = timeout

    def post(self, path, body, headers):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            ctx = NtlmContext(self.user, self.pw, self.domain)
            t1 = ctx.step()
            conn.request("GET", "/",
                         headers={"Authorization": "NTLM " + base64.b64encode(t1).decode()})
            r = conn.getresponse()
            r.read()
            ch = r.getheader("WWW-Authenticate")
            if not ch or " " not in ch:
                raise RuntimeError("NTLM handshake: no challenge (status %d)" % r.status)
            t2 = base64.b64decode(ch.split()[1])
            t3 = ctx.step(t2)
            h = dict(headers)
            h["Authorization"] = "NTLM " + base64.b64encode(t3).decode()
            conn.request("POST", path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read()
            return r.status, data
        finally:
            try:
                conn.close()
            except Exception:
                pass


class MdpClient:
    def __init__(self, host, user="Administrator", pw="1", timeout=30):
        self.host = host
        self.base_path = "/MdpWebService/MdpWebService.dll"
        self.tr = NtlmTransport(host, 80, user, pw, "", timeout)
        self._mods = None

    # --- low level SOAP -----------------------------------------------------
    def _soap(self, pairs):
        body = "".join(f"<{k}>{v}</{k}>" for k, v in pairs)
        xml = ('<?xml version="1.0" encoding="utf-8"?>'
               '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" '
               'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
               f'<u:ReadWrite xmlns:u="{MDP_NS}">{body}</u:ReadWrite>'
               '</s:Body></s:Envelope>')
        h = {"Content-Type": "text/xml; charset=utf-8",
             "SOAPAction": f'"{MDP_NS}#ReadWrite"'}
        status, data = self.tr.post(self.base_path, xml.encode("utf-8"), h)
        if status != 200:
            raise RuntimeError("MDP HTTP %d: %s" % (status, data[:200]))
        m = re.search(r"<ppRdData[^>]*>(.*?)</ppRdData>", data.decode("utf-8", "replace"), re.S)
        if not m:
            raise RuntimeError("no ppRdData in response: " + data.decode("utf-8", "replace")[:300])
        return base64.b64decode(m.group(1))

    # --- read ---------------------------------------------------------------
    def read(self, items):
        if not items:
            return []
        n = len(items)
        pwr = b"".join(struct.pack('<III', 0, off & 0xFFFFFFFF, size) for off, size in items)
        cb = sum(size for _, size in items) + n * 8
        res = self._soap([("netId", ""), ("nPort", 0), ("indexGroup", READ_IG),
                          ("indexOffset", n), ("cbRdLen", cb),
                          ("pwrData", base64.b64encode(pwr).decode())])
        hdrs = [struct.unpack_from('<iI', res, i * 8) for i in range(n)]
        out, pos = [], n * 8
        for rcode, actual in hdrs:
            if rcode == 0 and 0 <= actual <= 65535:
                out.append(res[pos:pos + actual]); pos += actual
            else:
                out.append(None)
        return out

    # --- write --------------------------------------------------------------
    def write(self, writes):
        """writes: list of (offset, data_bytes). Returns list of return codes (int).

        NOTE: this WinCE device's ReadWrite only accepts ONE parameter per write
        call (a multi-parameter write returns HTTP 500), so we issue one SOAP
        call per parameter.
        """
        if not writes:
            return []
        codes = []
        for off, d in writes:
            n = 1
            pwr = struct.pack('<III', 0, off & 0xFFFFFFFF, len(d)) + d
            res = self._soap([("netId", ""), ("nPort", 0), ("indexGroup", WRITE_IG),
                              ("indexOffset", n), ("cbRdLen", n * 4),
                              ("pwrData", base64.b64encode(pwr).decode())])
            (code,) = struct.unpack_from('<i', res, 0)
            codes.append(code)
        return codes

    # --- module discovery ---------------------------------------------------
    def modules(self):
        if self._mods is not None:
            return self._mods
        off = mdp_offset(0xF020, 0, 1)
        data = self.read([(off, 1024)])[0]
        if not data or len(data) < 2:
            return []
        (mc,) = struct.unpack_from('<b', data, 0)
        mods, p = [], 2
        for _ in range(mc):
            pid, ptype = struct.unpack_from('<hh', data, p); p += 4
            nn = ("0" if pid < 16 else "") + format(pid, 'x') + "0"
            mods.append({"pos": pid, "type": ptype,
                         "props": int("0x8" + nn, 16), "func": int("0xB" + nn, 16)})
        self._mods = mods
        return mods

    def find_module(self, mtype):
        for m in self.modules():
            if m["type"] == mtype:
                return m
        return None

    # --- NIC (IP settings) --------------------------------------------------
    def read_nic(self, mod=None):
        if mod is None:
            mod = self.find_module(TYPE_NIC)
        if mod is None:
            return None
        P = mod["props"]
        items = [
            ("name",    mdp_offset(P + 0, 3), 128),
            ("mac",     mdp_offset(P + 1, 1), 128),
            ("ipv4",    mdp_offset(P + 1, 2), 128),
            ("subnet",  mdp_offset(P + 1, 3), 128),
            ("dhcp",    mdp_offset(P + 1, 4), 1),
            ("gateway", mdp_offset(P + 1, 5), 128),
            ("dns",     mdp_offset(P + 1, 6), 128),
        ]
        raw = self.read([(it[1], it[2]) for it in items])
        out = {}
        for (nm, _, _), r in zip(items, raw):
            if nm == "dhcp":
                out[nm] = (r[0] != 0) if r else None
            else:
                out[nm] = cstr(r)
        out["_pos"] = mod["pos"]
        return out

    def write_nic(self, mod, ip=None, subnet=None, gateway=None, dhcp=None):
        if mod is None:
            mod = self.find_module(TYPE_NIC)
        P = mod["props"]
        writes = []
        if ip is not None:
            writes.append((mdp_offset(P + 1, 2), cstr_to_buf(ip, 128)))
        if subnet is not None:
            writes.append((mdp_offset(P + 1, 3), cstr_to_buf(subnet, 128)))
        if gateway is not None:
            writes.append((mdp_offset(P + 1, 5), cstr_to_buf(gateway, 128)))
        if dhcp is not None:
            writes.append((mdp_offset(P + 1, 4), bytes([1 if dhcp else 0])))
        return self.write(writes)

    def nic_modules(self):
        return [m for m in self.modules() if m["type"] == TYPE_NIC]

    def read_all_nic(self):
        return [self.read_nic(m) for m in self.nic_modules()]

    # --- Connectivity (Router / AMS NetId) ----------------------------------
    def read_ams_net_id(self, mod=None):
        """读取设备本机 AMS NetId（Device Manager「Connectivity」页的 AMS Net Id 一栏）。

        位于 CONNECTIVITY 模块（type=8）的 property 块：mdp_offset(P+1, 4)。
        该值即设备真实 AMS 地址（如 10.10.24.27.1.1），与连接 IP 无关。
        读不到返回 None。
        """
        if mod is None:
            mod = self.find_module(TYPE_CONNECTIVITY)
        if mod is None:
            return None
        P = mod["props"]
        r = self.read([(mdp_offset(P + 1, 4), 128)])[0]
        if not r:
            return None
        s = cstr(r)
        return s or None

    def write_nic_service(self, mod, ip, subnet, gateway):
        """Set NIC IPv4/Subnet/Gateway via the Set_IpAndSubnet ServiceTransfer.

        Direct property writes of the IP strings are rejected by this device
        (0xeca60106); the proper path is the module's function (ServiceTransfer)
        object. Function address = func_base + 1.
        """
        func_addr = mod["func"] + 1
        ip_b = ip.encode("latin-1", "replace")
        subnet_b = subnet.encode("latin-1", "replace")
        gw_b = gateway.encode("latin-1", "replace")
        params_size = 4 * 4 + len(ip_b) + len(subnet_b) + len(gw_b)
        block = struct.pack('<I', params_size)      # cb
        block += struct.pack('<I', len(ip_b))        # cchIp
        block += struct.pack('<I', len(subnet_b))    # cchSubnet
        block += struct.pack('<I', len(gw_b))        # cchGateway
        block += ip_b + subnet_b + gw_b
        pwr = struct.pack('<III', 0, mdp_offset(func_addr, 1, 0), params_size) + block
        res = self._soap([("netId", ""), ("nPort", 0), ("indexGroup", WRITE_IG),
                          ("indexOffset", 1), ("cbRdLen", 4),
                          ("pwrData", base64.b64encode(pwr).decode())])
        (code,) = struct.unpack_from('<i', res, 0)
        return code

    def write_nic_renew(self, mod):
        """Release/Renew the NIC IP (NIC_Function_IP_Release_Renew ServiceTransfer).

        On WinCE the original web console calls this *after* a successful static-IP
        write (Set_IpAndSubnet) or a successful DHCP toggle, so the new address takes
        effect immediately instead of waiting for a power cycle.

        Reverse-engineered mapping (communication__moduleList.js /
        pages__page_Hardware_Nic.js):
          * address  = func base + 0   (= mod["func"])
          * subIndex = 1
          * single parameter: UNSIGNED8 DummyByte = 1
            (its value is getServiceTransferParameterSize(...), which is 1 for one
            UNSIGNED8 param)
        """
        func_addr = mod["func"]  # base + 0
        data = struct.pack('<B', 1)  # DummyByte (UNSIGNED8) = 1, per JS RenewIP()
        pwr = struct.pack('<III', 0, mdp_offset(func_addr, 1, 0), len(data)) + data
        res = self._soap([("netId", ""), ("nPort", 0), ("indexGroup", WRITE_IG),
                          ("indexOffset", 1), ("cbRdLen", 4),
                          ("pwrData", base64.b64encode(pwr).decode())])
        (code,) = struct.unpack_from('<i', res, 0)
        return code

    # --- TIME (system time / SNTP / timezone) -------------------------------
    def read_time(self, mod=None, with_timezones=True):
        if mod is None:
            mod = self.find_module(TYPE_TIME)
        if mod is None:
            return None
        P = mod["props"]
        items = [
            ("sntp_server",   mdp_offset(P + 1, 1), 128),
            ("sntp_refresh",  mdp_offset(P + 1, 2), 4),
            ("seconds",       mdp_offset(P + 1, 3), 4),
            ("text_datetime", mdp_offset(P + 1, 4), 128),
            ("timezone",      mdp_offset(P + 1, 5), 2),
            ("sntp_offset",   mdp_offset(P + 1, 6), 4),
            ("tz1_len",       mdp_offset(P + 2, 0), 2),
            ("tz2_len",       mdp_offset(P + 3, 0), 2),
        ]
        raw = self.read([(it[1], it[2]) for it in items])
        out = {}
        for (nm, _, _), r in zip(items, raw):
            if r is None:
                out[nm] = None
            elif nm in ("sntp_refresh", "seconds", "sntp_offset"):
                (v,) = struct.unpack_from('<i', r + b"\x00\x00\x00\x00", 0)
                out[nm] = v
            elif nm in ("timezone", "tz1_len", "tz2_len"):
                (v,) = struct.unpack_from('<H', r + b"\x00\x00", 0)
                out[nm] = v
            else:
                out[nm] = cstr(r)

        if with_timezones:
            tz = []
            n1 = out.get("tz1_len") or 0
            n2 = out.get("tz2_len") or 0
            if n1:
                arr = self.read([(mdp_offset(P + 2, i), 80) for i in range(1, n1 + 1)])
                tz += [cstr(r) for r in arr]
            if n2:
                arr = self.read([(mdp_offset(P + 3, i), 80) for i in range(1, n2 + 1)])
                tz += [cstr(r) for r in arr]
            out["timezones"] = tz
        out["_pos"] = mod["pos"]
        return out

    def write_time(self, mod, sntp_server=None, sntp_refresh=None,
                   timezone=None, seconds=None, sntp_offset=None,
                   text_datetime=None):
        if mod is None:
            mod = self.find_module(TYPE_TIME)
        P = mod["props"]
        writes = []
        if sntp_server is not None:
            writes.append((mdp_offset(P + 1, 1), cstr_to_buf(sntp_server, 128)))
        if sntp_refresh is not None:
            writes.append((mdp_offset(P + 1, 2), struct.pack('<i', int(sntp_refresh))))
        if timezone is not None:
            writes.append((mdp_offset(P + 1, 5), struct.pack('<H', int(timezone))))
        if seconds is not None:
            writes.append((mdp_offset(P + 1, 3), struct.pack('<i', int(seconds))))
        if sntp_offset is not None:
            writes.append((mdp_offset(P + 1, 6), struct.pack('<i', int(sntp_offset))))
        # 设置设备时钟走「文本日期时间」(sub4)，与原网页保存本地时间一致
        if text_datetime is not None:
            writes.append((mdp_offset(P + 1, 4), cstr_to_buf(text_datetime, 128)))
        return self.write(writes)


if __name__ == "__main__":
    import json
    c = MdpClient("10.10.8.165")
    print("MODULES:")
    for m in c.modules():
        print("  ", m)
    nic = c.read_nic()
    print("NIC:", json.dumps(nic, ensure_ascii=False))
    t = c.read_time()
    print("TIME:", {k: v for k, v in t.items() if k != "timezones"})
    print("TIMEZONES count:", len(t.get("timezones", [])), "first 5:", t.get("timezones", [])[:5])
