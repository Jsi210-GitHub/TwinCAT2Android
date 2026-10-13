package com.example.twincat2;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;

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

    /** 枚举手机本机 IPv4 网段（基于 java.net.NetworkInterface，无 ipconfig）。 */
    @android.webkit.JavascriptInterface
    public String scan_subnets() {
        try {
            return bridgeModule().callAttr("scan_subnets").toString();
        } catch (Exception e) {
            return err(e);
        }
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
