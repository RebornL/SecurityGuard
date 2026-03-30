package com.example.securityguard;

import android.app.Application;
import android.content.Context;
import android.util.Log;

/**
 * Application示例类
 *
 * 展示如何在Application中集成安全验证功能
 */
public class SecurityApplication extends Application {

    private static final String TAG = "SecurityApplication";

    // 你的应用的预期签名哈希（SHA-256）
    // 请在正式发布时替换为你的实际签名哈希
    // 可以通过SecurityGuard.getSignature(context)获取当前签名
    private static final String EXPECTED_SIGNATURE =
            "YOUR_APP_SIGNATURE_HASH_HERE";  // 例如: "a1b2c3d4e5f6..."

    private boolean securityPassed = false;

    @Override
    public void onCreate() {
        super.onCreate();

        Log.i(TAG, "Application starting, performing security check...");

        // 执行安全检查
        performSecurityCheck();

        if (!securityPassed) {
            Log.e(TAG, "Security check failed!");
            handleSecurityFailure();
        } else {
            Log.i(TAG, "Security check passed, application is secure");
            initializeApp();
        }
    }

    /**
     * 执行安全检查
     */
    private void performSecurityCheck() {
        try {
            // 方式1: 使用完整安全检查（推荐）
            securityPassed = SecurityGuard.performSecurityCheck(this, EXPECTED_SIGNATURE);

            // 方式2: 使用详细安全检查
            // SecurityGuard.SecurityCheckResult result =
            //     SecurityGuard.performFullSecurityCheck(this, EXPECTED_SIGNATURE);
            // securityPassed = result.isSecure;
            // Log.i(TAG, "Security check result: " + result.toString());

            // 方式3: 分步检查（用于调试）
            // stepByStepCheck();

        } catch (Exception e) {
            Log.e(TAG, "Security check exception", e);
            securityPassed = false;
        }
    }

    /**
     * 分步检查（用于调试和学习）
     */
    private void stepByStepCheck() {
        Log.i(TAG, "=== Step-by-step Security Check ===");

        // 1. 签名验证
        String currentSignature = SecurityGuard.getSignature(this);
        Log.i(TAG, "Current signature: " + currentSignature);
        boolean signatureValid = SecurityGuard.verifySignature(this, EXPECTED_SIGNATURE);
        Log.i(TAG, "Signature valid: " + signatureValid);

        // 2. Xposed检测
        boolean xposedDetected = SecurityGuard.detectXposed();
        Log.i(TAG, "Xposed detected: " + xposedDetected);

        // 3. 获取详细检测结果
        DetectionResult detectionResult = SecurityGuard.getDetectionResult();
        Log.i(TAG, "Detection result: " + detectionResult.toString());

        // 4. 检测已安装的Xposed应用
        boolean xposedPackages = SecurityGuard.detectXposedPackages(this);
        Log.i(TAG, "Xposed packages detected: " + xposedPackages);

        // 5. 获取完整安全报告
        String report = SecurityGuard.getSecurityReport(this);
        Log.i(TAG, "Security report:\n" + report);

        // 6. 调试模式检查
        boolean debugMode = SecurityGuard.isDebugMode(this);
        Log.i(TAG, "Debug mode: " + debugMode);

        // 7. 模拟器检测
        boolean isEmulator = SecurityGuard.isEmulator();
        Log.i(TAG, "Running in emulator: " + isEmulator);

        // 综合判断
        securityPassed = signatureValid && !xposedDetected && !xposedPackages && !debugMode;
        Log.i(TAG, "=== Security check result: " + (securityPassed ? "PASS" : "FAIL") + " ===");
    }

    /**
     * 处理安全检查失败
     */
    private void handleSecurityFailure() {
        // 根据安全策略，可以选择不同的处理方式：

        // 方式1: 直接退出应用（最严格）
        // System.exit(0);

        // 方式2: 显示警告并限制功能（推荐）
        showSecurityWarning();

        // 方式3: 记录日志并继续运行（用于调试）
        // Log.w(TAG, "Running in potentially unsafe environment");

        // 方式4: 上报安全事件
        // reportSecurityEvent();
    }

    /**
     * 显示安全警告
     */
    private void showSecurityWarning() {
        // 在实际应用中，这里可以启动一个Activity或显示对话框
        // 通知用户应用环境不安全
        Log.w(TAG, "WARNING: Application running in unsafe environment!");
    }

    /**
     * 初始化应用（安全检查通过后）
     */
    private void initializeApp() {
        Log.i(TAG, "Initializing application components...");

        // 这里可以初始化应用的核心功能
        // 例如：初始化网络请求、加载配置等
    }

    /**
     * 获取安全状态
     * @return 安全检查是否通过
     */
    public boolean isSecurityPassed() {
        return securityPassed;
    }

    /**
     * 在关键操作前再次验证安全状态
     * @return 是否安全
     */
    public boolean verifyBeforeCriticalOperation() {
        // 在关键操作前再次检查
        return SecurityGuard.performSecurityCheck(this, EXPECTED_SIGNATURE);
    }
}