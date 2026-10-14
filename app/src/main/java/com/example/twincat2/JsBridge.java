package com.example.twincat2;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * WebView <-> Python 桥接层（Route A）。
 *
 * app.html 里的 JS 通过 window.Android.xxx(...) 调用本类方法；本类再把调用
 * 转发给 Python 模块 bridge。所有方法都返回 JSON 字符串。
 *
 * 关键：参数一律用「确定类型」声明（int / boolean / String / Integer），
 * 不要声明成 Object。声明成 Object 时，WebView 会把 JS 数字按 Double 甚至
 * Chaquopy 代理对象传过来，Python 端 int() 直接抛错 → 表现为“无效的网卡索引”。
 */
public class JsBridge {

    private final MainActivity activity;

    public JsBridge(MainActivity activity) {
        this.activity = activity;
        // 把 App 私有 files 目录传给 Python，用于持久化「最近连接」历史（跨 App 重启保留）。
        try {
            Python py = Python.getInstance();
            py.getModule("bridge").callAttr("set_data_dir", activity.getFilesDir().getAbsolutePath());
        } catch (Exception ignore) {
            // Python 尚未启动或 bridge 模块缺失：历史将回退到脚本目录，不影响其他功能。
        }
    }

    /** 统一把异常包成桥接层可识别的 JSON 错误，避免 JS 侧 JSON.parse 抛错。 */
    private String err(Exception e) {
        String m = e != null && e.getMessage() != null ? e.getMessage() : "unknown";
        // 转义双引号，保证仍是合法 JSON
        m = m.replace("\"", "'");
        return "{\"ok\":false,\"msg\":\"桥接调用失败：" + m + "\"}";
    }

    private PyObject bridgeModule() {
        // Python 已在 MainActivity.onCreate 的主线程启动；这里直接取单例。
        Python py = Python.getInstance();
        return py.getModule("bridge");
    }

    @android.webkit.JavascriptInterface
    public String get_last() {
        try {
            return bridgeModule().callAttr("get_last").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String get_history() {
        try {
            return bridgeModule().callAttr("get_history").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String del_history(String ip) {
        try {
            return bridgeModule().callAttr("del_history", ip).toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String clear_history() {
        try {
            return bridgeModule().callAttr("clear_history").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String connect(String ip) {
        try {
            return bridgeModule().callAttr("connect", ip).toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String refresh() {
        try {
            return bridgeModule().callAttr("refresh").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String current_time() {
        try {
            return bridgeModule().callAttr("current_time").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    /**
     * idx 用 int、dhcp 用 boolean：让 WebView 直接把 JS 数字/布尔转成确定类型，
     * 避免走 Object 时 Double/代理对象导致 Python int() 报错（“无效的网卡索引”）。
     */
    @android.webkit.JavascriptInterface
    public String apply_nic(int idx, String ip, String subnet, String gateway, boolean dhcp) {
        try {
            return bridgeModule()
                    .callAttr("apply_nic", idx, ip, subnet, gateway, dhcp)
                    .toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    /**
     * sntpServer / dtLocal 是字符串；sntpRefresh / timezone 可为空（JS 传 null），
     * 用 Integer（可空）接收，交给 Python 端 _as_int 规整。
     */
    @android.webkit.JavascriptInterface
    public String apply_time(String sntpServer, Integer sntpRefresh, Integer timezone, String dtLocal) {
        try {
            return bridgeModule()
                    .callAttr("apply_time", sntpServer, sntpRefresh, timezone, dtLocal)
                    .toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    @android.webkit.JavascriptInterface
    public String disconnect() {
        try {
            return bridgeModule().callAttr("disconnect").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    /**
     * 枚举手机本机非回环、已启用网卡的 IPv4 网段。
     * 优先用纯 Java（java.net.NetworkInterface，最可靠），失败再回退 Python 实现。
     * 返回 {"ok":true,"subnets":[{iface,ip,net,count,kind}],"debug":"..."}
     */
    @android.webkit.JavascriptInterface
    public String scan_subnets() {
        try {
            String j = scanSubnetsJava();
            if (j != null) return j;
        } catch (Exception e) {
            // Java 枚举异常时回退到 Python 实现
        }
        try {
            return bridgeModule().callAttr("scan_subnets").toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    /** 纯 Java 枚举网卡：不跳过任何非回环网卡（含蜂窝），由 UI 标注类型。 */
    private String scanSubnetsJava() throws Exception {
        JSONArray arr = new JSONArray();
        StringBuilder dbg = new StringBuilder();
        LinkedHashMap<String, JSONObject> uniq = new LinkedHashMap<String, JSONObject>();
        Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
        if (en == null) dbg.append("getNetworkInterfaces()=null");
        while (en != null && en.hasMoreElements()) {
            NetworkInterface ni = en.nextElement();
            if (ni == null) continue;
            String nm = ni.getName() == null ? "?" : ni.getName();
            boolean up, loop;
            try { up = ni.isUp(); } catch (Exception e) { up = false; }
            try { loop = ni.isLoopback(); } catch (Exception e) { loop = false; }
            List<InterfaceAddress> addrs = ni.getInterfaceAddresses();
            if (addrs == null) { dbg.append(nm).append(": getInterfaceAddresses()=null | "); continue; }
            for (InterfaceAddress ia : addrs) {
                if (ia == null) continue;
                InetAddress a = ia.getAddress();
                if (a == null) continue;
                String ip = a.getHostAddress();
                int pfx = ia.getNetworkPrefixLength();
                boolean v4 = a instanceof Inet4Address;
                if (dbg.length() > 0) dbg.append(" | ");
                dbg.append(nm).append(" ").append(ip).append(" /").append(pfx)
                   .append(v4 ? " v4" : " v6")
                   .append(up ? " up" : " down")
                   .append(loop ? " loop" : "");
                if (!v4 || ip == null || ip.startsWith("127.") || ip.indexOf(':') >= 0) continue;
                if (loop || !up) continue;
                if (pfx <= 0 || pfx > 32) continue;
                byte[] raw = a.getAddress();
                long v = 0;
                for (int i = 0; i < 4 && i < raw.length; i++) {
                    v = (v << 8) | (raw[i] & 0xFF);
                }
                long mask = (0xFFFFFFFFL << (32 - pfx)) & 0xFFFFFFFFL;
                long netv = v & mask;
                String net = ((netv >> 24) & 0xFF) + "." + ((netv >> 16) & 0xFF) + "."
                           + ((netv >> 8) & 0xFF) + "." + (netv & 0xFF) + "/" + pfx;
                long hostCount = (1L << (32 - pfx)) - 2;
                if (hostCount < 0) hostCount = 0;
                if (uniq.containsKey(net)) continue;
                JSONObject o = new JSONObject();
                o.put("iface", nm);
                o.put("ip", ip);
                o.put("net", net);
                o.put("count", hostCount);
                o.put("kind", kindOf(nm));
                uniq.put(net, o);
            }
        }
        for (JSONObject o : uniq.values()) arr.put(o);
        JSONObject ret = new JSONObject();
        ret.put("ok", true);
        ret.put("subnets", arr);
        ret.put("debug", dbg.toString());
        return ret.toString();
    }

    private static String kindOf(String nm) {
        String n = nm == null ? "" : nm.toLowerCase();
        if (n.startsWith("wlan") || n.startsWith("ap") || n.contains("wifi")) return "wifi";
        if (n.startsWith("eth") || n.startsWith("usb") || n.startsWith("rndis")) return "eth";
        if (n.startsWith("rmnet") || n.startsWith("ccmni") || n.startsWith("pdp")
                || n.startsWith("ppp") || n.startsWith("clat")) return "cell";
        if (n.startsWith("tun") || n.startsWith("tap")) return "vpn";
        return "other";
    }

    /** 对给定 CIDR 做 TCP 端口探测，返回在线设备列表（Android 无 ICMP，以端口命中判定在线）。 */
    @android.webkit.JavascriptInterface
    public String scan(String net) {
        try {
            return bridgeModule().callAttr("scan", net).toString();
        } catch (Exception e) {
            return err(e);
        }
    }
}
