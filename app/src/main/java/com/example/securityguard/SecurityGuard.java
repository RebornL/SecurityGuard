package com.example.securityguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.util.Log;

/**
 * SecurityGuard - 安全验证工具类
 *
 * 提供Native层的签名验证和反Xposed检测功能
 *
 * 使用方法:
 * 1. 在Application初始化时调用初始化方法
 * 2. 在关键操作前调用安全检查方法
 * 3. 处理检测结果
 */
public class SecurityGuard {
    private static final String TAG = "SecurityGuard";

    static {
        // 加载Native库
        System.loadLibrary("securityguard");
    }

    // Native方法声明

    /**
     * 获取应用签名
     * @param context 应用Context
     * @return 签名字符串（SHA-256哈希）
     */
    private static native String nativeGetSignature(Context context);

    /**
     * 验证应用签名
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 签名是否匹配
     */
    private static native boolean nativeVerifySignature(Context context, String expectedSignature);

    /**
     * 检测Xposed框架
     * @return 是否检测到Xposed
     */
    private static native boolean nativeDetectXposed();

    /**
     * 获取详细检测结果
     * @return 检测结果对象
     */
    private static native DetectionResult nativeGetDetectionResult();

    /**
     * 执行完整安全检查
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 安全检查是否通过
     */
    private static native boolean nativePerformSecurityCheck(Context context, String expectedSignature);

    /**
     * 获取安全报告
     * @param context 应用Context
     * @return 安全报告字符串
     */
    private static native String nativeGetSecurityReport(Context context);

    /**
     * 检测已安装的Xposed相关应用
     * @param context 应用Context
     * @return 是否检测到Xposed相关应用
     */
    private static native boolean nativeDetectXposedPackages(Context context);

    // ==================== 安全签名验证（绕过PM Hook） ====================

    /**
     * 直接从APK文件获取签名（不经过PackageManager）
     * 这个方法不会被Xposed的PM绕过选项影响
     * @return 签名字符串（SHA-256哈希）
     */
    private static native String nativeGetSignatureDirect();

    /**
     * 安全验证签名（同时使用两种方式，检测PM Hook）
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 验证结果对象
     */
    private static native SignatureVerificationResult nativeVerifySignatureSecure(
            Context context, String expectedSignature);

    /**
     * 检测PackageManager是否被Hook
     * @param context 应用Context
     * @return 是否检测到Hook
     */
    private static native boolean nativeDetectPmHook(Context context);

    /**
     * 获取APK路径
     * @return APK文件路径
     */
    private static native String nativeGetApkPath();

    // ==================== 公共API ====================

    /**
     * 获取当前应用签名的SHA-256哈希值
     *
     * @param context 应用Context
     * @return 签名哈希字符串，如果获取失败返回null
     */
    public static String getSignature(Context context) {
        if (context == null) {
            Log.e(TAG, "Context is null");
            return null;
        }
        try {
            return nativeGetSignature(context);
        } catch (Exception e) {
            Log.e(TAG, "Failed to get signature", e);
            return null;
        }
    }

    /**
     * 验证应用签名是否匹配
     *
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希（SHA-256，小写）
     * @return 签名是否匹配
     */
    public static boolean verifySignature(Context context, String expectedSignature) {
        if (context == null || expectedSignature == null || expectedSignature.isEmpty()) {
            Log.e(TAG, "Invalid parameters for signature verification");
            return false;
        }
        try {
            return nativeVerifySignature(context, expectedSignature.toLowerCase().trim());
        } catch (Exception e) {
            Log.e(TAG, "Signature verification failed", e);
            return false;
        }
    }

    /**
     * 检测设备上是否存在Xposed框架
     *
     * @return 是否检测到Xposed
     */
    public static boolean detectXposed() {
        try {
            return nativeDetectXposed();
        } catch (Exception e) {
            Log.e(TAG, "Xposed detection failed", e);
            return false;
        }
    }

    /**
     * 获取详细的Xposed检测结果
     *
     * @return 检测结果对象
     */
    public static DetectionResult getDetectionResult() {
        try {
            return nativeGetDetectionResult();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get detection result", e);
            return new DetectionResult();
        }
    }

    /**
     * 执行完整的安全检查
     * 包括签名验证和Xposed检测
     *
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 安全检查是否通过
     */
    public static boolean performSecurityCheck(Context context, String expectedSignature) {
        if (context == null || expectedSignature == null || expectedSignature.isEmpty()) {
            Log.e(TAG, "Invalid parameters for security check");
            return false;
        }
        try {
            return nativePerformSecurityCheck(context, expectedSignature.toLowerCase().trim());
        } catch (Exception e) {
            Log.e(TAG, "Security check failed", e);
            return false;
        }
    }

    /**
     * 获取完整的安全报告
     *
     * @param context 应用Context
     * @return 安全报告字符串
     */
    public static String getSecurityReport(Context context) {
        if (context == null) {
            return "Error: Context is null";
        }
        try {
            return nativeGetSecurityReport(context);
        } catch (Exception e) {
            Log.e(TAG, "Failed to get security report", e);
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 检测是否安装了Xposed相关应用
     *
     * @param context 应用Context
     * @return 是否检测到Xposed相关应用
     */
    public static boolean detectXposedPackages(Context context) {
        if (context == null) {
            return false;
        }
        try {
            return nativeDetectXposedPackages(context);
        } catch (Exception e) {
            Log.e(TAG, "Failed to detect Xposed packages", e);
            return false;
        }
    }

    // ==================== 辅助方法 ====================

    // ==================== 安全签名验证API（绕过PM Hook） ====================

    /**
     * 直接从APK文件获取签名（不经过PackageManager）
     *
     * 这个方法不会被Xposed的PackageManager绕过选项影响，
     * 因为它直接在Native层解析APK文件，不经过Java层的PackageManager。
     *
     * @return 签名哈希字符串，如果获取失败返回null
     */
    public static String getSignatureDirect() {
        try {
            return nativeGetSignatureDirect();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get signature directly from APK", e);
            return null;
        }
    }

    /**
     * 安全验证签名（推荐使用此方法）
     *
     * 同时使用两种方式获取签名并比较：
     * 1. 直接解析APK文件（不经过Java层，无法被Hook）
     * 2. 通过PackageManager获取（可能被Xposed Hook）
     *
     * 如果两者不一致，说明PackageManager可能被Hook篡改。
     * 只信任直接解析APK的结果。
     *
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 验证结果对象
     */
    public static SignatureVerificationResult verifySignatureSecure(
            Context context, String expectedSignature) {
        if (context == null || expectedSignature == null || expectedSignature.isEmpty()) {
            Log.e(TAG, "Invalid parameters for secure signature verification");
            return new SignatureVerificationResult();
        }
        try {
            return nativeVerifySignatureSecure(context, expectedSignature.toLowerCase().trim());
        } catch (Exception e) {
            Log.e(TAG, "Secure signature verification failed", e);
            return new SignatureVerificationResult();
        }
    }

    /**
     * 检测PackageManager是否被Hook
     *
     * 通过比较直接解析APK和通过PackageManager获取的签名是否一致，
     * 判断PackageManager是否可能被Xposed Hook篡改。
     *
     * @param context 应用Context
     * @return 是否检测到可能的Hook
     */
    public static boolean detectPmHook(Context context) {
        if (context == null) {
            return false;
        }
        try {
            return nativeDetectPmHook(context);
        } catch (Exception e) {
            Log.e(TAG, "Failed to detect PM hook", e);
            return false;
        }
    }

    /**
     * 获取当前应用的APK路径
     *
     * @return APK文件路径
     */
    public static String getApkPath() {
        try {
            return nativeGetApkPath();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get APK path", e);
            return null;
        }
    }

    /**
     * 执行最安全的签名验证（强烈推荐）
     *
     * 使用直接解析APK的方式验证签名，完全不依赖PackageManager，
     * 因此不会被Xposed的PM绕过选项影响。
     *
     * @param expectedSignature 预期的签名哈希
     * @return 签名是否匹配
     */
    public static boolean verifySignatureBypassPmHook(String expectedSignature) {
        if (expectedSignature == null || expectedSignature.isEmpty()) {
            Log.e(TAG, "Expected signature is null or empty");
            return false;
        }
        try {
            String directSignature = getSignatureDirect();
            if (directSignature == null || directSignature.isEmpty()) {
                Log.e(TAG, "Failed to get signature directly from APK");
                return false;
            }
            String expectedLower = expectedSignature.toLowerCase().trim();
            String directLower = directSignature.toLowerCase();
            return expectedLower.equals(directLower);
        } catch (Exception e) {
            Log.e(TAG, "Bypass PM hook verification failed", e);
            return false;
        }
    }

    /**
     * 执行终极安全检查（最严格的安全验证）
     *
     * 包含所有检测项，并使用安全的签名验证方式：
     * - 直接解析APK签名验证（绕过PM Hook）
     * - PackageManager Hook检测
     * - Xposed框架检测
     * - 调试模式检测
     * - 模拟器检测
     *
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 终极安全检查结果
     */
    public static UltimateSecurityResult performUltimateSecurityCheck(
            Context context, String expectedSignature) {
        UltimateSecurityResult result = new UltimateSecurityResult();

        // 安全签名验证
        SignatureVerificationResult sigResult = verifySignatureSecure(context, expectedSignature);
        result.signatureResult = sigResult;
        result.signatureValid = sigResult.isValid();
        result.pmHookDetected = sigResult.possibleHookDetected;

        // Xposed检测
        result.xposedDetected = detectXposed();
        result.xposedPackagesDetected = detectXposedPackages(context);
        result.detectionResult = getDetectionResult();

        // 其他检测
        result.debugMode = isDebugMode(context);
        result.emulatorDetected = isEmulator();

        // 综合判断（只信任直接解析APK的签名结果）
        result.isSecure = result.signatureValid
                && !result.pmHookDetected
                && !result.xposedDetected
                && !result.xposedPackagesDetected
                && !result.debugMode
                && !result.emulatorDetected;

        return result;
    }

    /**
     * 终极安全检查结果类
     */
    public static class UltimateSecurityResult {
        public SignatureVerificationResult signatureResult;
        public boolean signatureValid;
        public boolean pmHookDetected;
        public boolean xposedDetected;
        public boolean xposedPackagesDetected;
        public boolean debugMode;
        public boolean emulatorDetected;
        public boolean isSecure;
        public DetectionResult detectionResult;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("UltimateSecurityResult {\n");
            sb.append("  signatureValid: ").append(signatureValid).append("\n");
            sb.append("  pmHookDetected: ").append(pmHookDetected).append("\n");
            sb.append("  xposedDetected: ").append(xposedDetected).append("\n");
            sb.append("  xposedPackagesDetected: ").append(xposedPackagesDetected).append("\n");
            sb.append("  debugMode: ").append(debugMode).append("\n");
            sb.append("  emulatorDetected: ").append(emulatorDetected).append("\n");
            sb.append("  isSecure: ").append(isSecure).append("\n");
            sb.append("  signatureResult:\n").append(signatureResult).append("\n");
            sb.append("}");
            return sb.toString();
        }
    }

    // ==================== 其他辅助方法 ====================

    /**
     * 检查应用是否运行在调试模式下
     *
     * @param context 应用Context
     * @return 是否处于调试模式
     */
    public static boolean isDebugMode(Context context) {
        if (context == null) {
            return false;
        }
        try {
            return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Exception e) {
            Log.e(TAG, "Failed to check debug mode", e);
            return false;
        }
    }

    /**
     * 检查是否运行在模拟器中
     *
     * @return 是否运行在模拟器中
     */
    public static boolean isEmulator() {
        try {
            // 检查设备信息
            return Build.FINGERPRINT.startsWith("generic")
                    || Build.FINGERPRINT.startsWith("unknown")
                    || Build.MODEL.contains("google_sdk")
                    || Build.MODEL.contains("Emulator")
                    || Build.MODEL.contains("Android SDK built for x86")
                    || Build.MANUFACTURER.contains("Genymotion")
                    || Build.BRAND.startsWith("generic")
                    || Build.DEVICE.startsWith("generic")
                    || "google_sdk".equals(Build.PRODUCT)
                    || Build.HARDWARE.contains("goldfish")
                    || Build.HARDWARE.contains("ranchu")
                    || Build.PRODUCT.contains("sdk")
                    || Build.PRODUCT.contains("emulator")
                    || Build.PRODUCT.contains("simulator");
        } catch (Exception e) {
            Log.e(TAG, "Failed to check emulator", e);
            return false;
        }
    }

    /**
     * 执行全面的安全检查（包括额外检查）
     *
     * @param context 应用Context
     * @param expectedSignature 预期的签名哈希
     * @return 安全检查结果
     */
    public static SecurityCheckResult performFullSecurityCheck(Context context, String expectedSignature) {
        SecurityCheckResult result = new SecurityCheckResult();

        // 基础安全检查
        result.signatureValid = verifySignature(context, expectedSignature);
        result.xposedDetected = detectXposed();
        result.xposedPackagesDetected = detectXposedPackages(context);

        // 额外检查
        result.debugMode = isDebugMode(context);
        result.emulatorDetected = isEmulator();

        // 综合判断
        result.isSecure = result.signatureValid
                && !result.xposedDetected
                && !result.xposedPackagesDetected
                && !result.debugMode
                && !result.emulatorDetected;

        return result;
    }

    /**
     * 安全检查结果类
     */
    public static class SecurityCheckResult {
        public boolean signatureValid;
        public boolean xposedDetected;
        public boolean xposedPackagesDetected;
        public boolean debugMode;
        public boolean emulatorDetected;
        public boolean isSecure;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("SecurityCheckResult {\n");
            sb.append("  signatureValid: ").append(signatureValid).append("\n");
            sb.append("  xposedDetected: ").append(xposedDetected).append("\n");
            sb.append("  xposedPackagesDetected: ").append(xposedPackagesDetected).append("\n");
            sb.append("  debugMode: ").append(debugMode).append("\n");
            sb.append("  emulatorDetected: ").append(emulatorDetected).append("\n");
            sb.append("  isSecure: ").append(isSecure).append("\n");
            sb.append("}");
            return sb.toString();
        }
    }
}