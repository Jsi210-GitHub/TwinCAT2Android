package com.example.twincat2;

import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

public class MainActivity extends AppCompatActivity {

    private WebView webview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 隐藏系统 ActionBar，让自定义界面占满整屏（app.html 自带顶栏）
        if (getSupportActionBar() != null) getSupportActionBar().hide();

        // 尽早启动 Python 运行时：必须在有 Looper 的线程（主线程）调用一次。
        // 已启动会抛异常，忽略即可（与旧 test_mdp 版行为一致）。
        try {
            Python.start(new AndroidPlatform(this));
        } catch (Exception ignore) {
            // Python 已启动
        }

        webview = findViewById(R.id.webview);
        // 拦截页面内导航，避免跳转被丢到外部浏览器
        webview.setWebViewClient(new WebViewClient());

        webview.getSettings().setJavaScriptEnabled(true);
        webview.getSettings().setDomStorageEnabled(true);

        // 注入桥接对象：JS 通过 window.Android 调用 Python 协议层
        webview.addJavascriptInterface(new JsBridge(this), "Android");

        // 加载本地自定义双面板界面（IP 设置 + 系统时间）
        webview.loadUrl("file:///android_asset/app.html");
    }

    @Override
    public void onBackPressed() {
        if (webview != null && webview.canGoBack()) {
            webview.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
