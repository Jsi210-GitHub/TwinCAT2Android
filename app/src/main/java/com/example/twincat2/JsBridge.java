package com.example.twincat2;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;

/**
 * WebView <-> Python 桥接层（Route A）。
 *
 * app.html 里的 JS 通过 window.Android.xxx(...) 调用本类方法；本类再把调用
 * 转发给 assets/app.html 同级协议层（Python 模块 bridge）。所有方法都返回
 * JSON 字符串，与 PC 版 twincat2_login 的约定一致。
 *
 * 注意线程：@JavascriptInterface 方法运行在 WebView 内部线程（非 App 主线程），
 * 因此这里做阻塞式网络 I/O（Python mdp_client）不会触发主线程 ANR；app.html 又用
 * setTimeout(...,30) 先让「正在连接…」遮罩渲染出来，再发起阻塞调用，体验更顺。
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
     * JS 侧入参：idx(Number) / ip / subnet / gateway(String) / dhcp(Boolean)。
     * 用 Object 接收，交给 Chaquopy 自动转成 Python 的 int / str / bool / None。
     */
    @android.webkit.JavascriptInterface
    public String apply_nic(Object idx, Object ip, Object subnet, Object gateway, Object dhcp) {
        try {
            return bridgeModule()
                    .callAttr("apply_nic", idx, ip, subnet, gateway, dhcp)
                    .toString();
        } catch (Exception e) {
            return err(e);
        }
    }

    /**
     * JS 侧入参：sntpServer(String) / sntpRefresh(Number|null) /
     *              timezone(Number|null) / dtLocal(String|null)。
     */
    @android.webkit.JavascriptInterface
    public String apply_time(Object sntpServer, Object sntpRefresh, Object timezone, Object dtLocal) {
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
}
