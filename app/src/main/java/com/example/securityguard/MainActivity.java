package com.example.securityguard;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

/**
 * 示例Activity
 *
 * 展示如何在Activity中使用安全验证功能
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    // 你的应用的预期签名哈希
    private static final String EXPECTED_SIGNATURE =
            "YOUR_APP_SIGNATURE_HASH_HERE";

    private TextView statusTextView;
    private TextView resultTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 初始化视图
        statusTextView = findViewById(R.id.statusTextView);
        resultTextView = findViewById(R.id.resultTextView);

        Button checkButton = findViewById(R.id.checkButton);
        Button reportButton = findViewById(R.id.reportButton);
        Button signatureButton = findViewById(R.id.signatureButton);

        // 设置按钮点击事件
        checkButton.setOnClickListener(v -> performSecurityCheck());
        reportButton.setOnClickListener(v -> getSecurityReport());
        signatureButton.setOnClickListener(v -> getCurrentSignature());
    }

    /**
     * 执行安全检查
     */
    private void performSecurityCheck() {
        Log.i(TAG, "Performing security check...");

        SecurityGuard.SecurityCheckResult result =
                SecurityGuard.performFullSecurityCheck(this, EXPECTED_SIGNATURE);

        // 更新状态显示
        StringBuilder statusBuilder = new StringBuilder();
        statusBuilder.append("安全检查结果: ").append(result.isSecure ? "安全" : "不安全").append("\n\n");
        statusBuilder.append("签名验证: ").append(result.signatureValid ? "通过" : "失败").append("\n");
        statusBuilder.append("Xposed检测: ").append(result.xposedDetected ? "检测到" : "未检测到").append("\n");
        statusBuilder.append("Xposed应用: ").append(result.xposedPackagesDetected ? "检测到" : "未检测到").append("\n");
        statusBuilder.append("调试模式: ").append(result.debugMode ? "是" : "否").append("\n");
        statusBuilder.append("模拟器: ").append(result.emulatorDetected ? "是" : "否").append("\n");

        statusTextView.setText(statusBuilder.toString());

        // 显示Toast提示
        if (result.isSecure) {
            Toast.makeText(this, "安全检查通过", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "警告：检测到安全风险！", Toast.LENGTH_LONG).show();
        }
    }

    /**
     * 获取安全报告
     */
    private void getSecurityReport() {
        Log.i(TAG, "Getting security report...");

        String report = SecurityGuard.getSecurityReport(this);
        resultTextView.setText(report);
    }

    /**
     * 获取当前应用签名
     * 用于调试时获取实际签名哈希值
     */
    private void getCurrentSignature() {
        Log.i(TAG, "Getting current signature...");

        String signature = SecurityGuard.getSignature(this);

        StringBuilder info = new StringBuilder();
        info.append("当前应用签名哈希:\n\n");
        info.append(signature).append("\n\n");
        info.append("请将此签名添加到EXPECTED_SIGNATURE常量中");
        info.append("\n以启用签名验证功能");

        resultTextView.setText(info.toString());

        Log.i(TAG, "Current signature: " + signature);
        Toast.makeText(this, "签名已获取，请查看日志", Toast.LENGTH_SHORT).show();
    }

    /**
     * 在执行关键操作前验证
     * 示例：支付、数据传输等敏感操作
     */
    private void performCriticalOperation() {
        // 执行快速安全检查
        boolean isSecure = SecurityGuard.verifySignature(this, EXPECTED_SIGNATURE)
                && !SecurityGuard.detectXposed();

        if (!isSecure) {
            Toast.makeText(this, "安全验证失败，无法执行此操作", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Security verification failed for critical operation");
            return;
        }

        // 执行关键操作
        Log.i(TAG, "Executing critical operation...");
        Toast.makeText(this, "操作执行成功", Toast.LENGTH_SHORT).show();
    }
}