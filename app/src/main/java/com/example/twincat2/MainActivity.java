package com.example.twincat2;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

public class MainActivity extends AppCompatActivity {

    private EditText ipEdit;
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ipEdit = findViewById(R.id.ip);
        logView = findViewById(R.id.log);
        Button btn = findViewById(R.id.connect);

        // 预填一个常用地址，方便测试
        ipEdit.setText("10.10.8.165");

        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String ip = ipEdit.getText().toString().trim();
                if (ip.isEmpty()) {
                    Toast.makeText(MainActivity.this, "请输入 PLC IP", Toast.LENGTH_SHORT).show();
                    return;
                }
                logView.setText("连接中…\n");
                // 网络操作放子线程，避免阻塞 UI
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        // 首次调用启动 Python 运行时（已启动会抛异常，忽略即可）
                        try {
                            Python.start(new AndroidPlatform(MainActivity.this));
                        } catch (Exception ignore) {
                            // already started
                        }
                        try {
                            Python py = Python.getInstance();
                            PyObject module = py.getModule("test_mdp");
                            PyObject result = module.callAttr("run_test", ip);
                            final String out = result.toString();
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    logView.setText(out);
                                }
                            });
                        } catch (final Exception e) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    logView.setText("Python 启动/调用失败:\n" + e);
                                }
                            });
                        }
                    }
                }).start();
            }
        });
    }
}
