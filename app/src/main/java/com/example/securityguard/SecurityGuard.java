package com.example.securityguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import java.security.MessageDigest;

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
     * 直接从APK文件获取签名（带Context参数，推荐使用）
     * @param context 应用Context
     * @return 签名字符串（SHA-256哈希）
     */
    private static native String nativeGetSignatureDirectWithContext(Context context);

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

    /**
     * 执行Native层安全检查（推荐使用）
     * 明确返回C++获取的签名值和检查状态
     * @param context 应用Context
     * @return Native安全检查结果
     */
    private static native NativeSecurityCheckResult nativePerformNativeSecurityCheck(Context context);

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
     * 注意：此方法可能因SELinux权限限制而失败，建议使用getSignatureDirect(Context)
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
     * 直接从APK文件获取签名（推荐使用此方法）
     *
     * 通过Context获取APK路径，更可靠。
     * 这个方法不会被Xposed的PackageManager绕过选项影响。
     *
     * @param context 应用Context
     * @return 签名哈希字符串，如果获取失败返回null
     */
    public static String getSignatureDirect(Context context) {
        if (context == null) {
            Log.e(TAG, "Context is null, falling back to no-context method");
            return getSignatureDirect();
        }
        try {
            String signature = nativeGetSignatureDirectWithContext(context);
            if (signature == null || signature.isEmpty()) {
                // 回退到无Context版本
                Log.w(TAG, "nativeGetSignatureDirectWithContext failed, trying fallback");
                return getSignatureDirect();
            }
            return signature;
        } catch (Exception e) {
            Log.e(TAG, "Failed to get signature directly from APK with context", e);
            // 回退到无Context版本
            return getSignatureDirect();
        }
    }

    /**
     * 执行Native层安全检查（强烈推荐使用）
     *
     * 在C++ Native层执行完整的安全检查，明确返回：
     * 1. C++ Native层获取的真实签名值
     * 2. Java层获取的签名值（对比用）
     * 3. 签名一致性检测结果
     * 4. PackageManager Hook检测结果
     * 5. Xposed框架检测结果
     *
     * @param context 应用Context
     * @return Native安全检查结果，包含所有检测详情
     */
    public static NativeSecurityCheckResult performNativeSecurityCheck(Context context) {
        if (context == null) {
            Log.e(TAG, "Context is null for native security check");
            NativeSecurityCheckResult result = new NativeSecurityCheckResult();
            result.errorMessage = "Context is null";
            return result;
        }
        try {
            return nativePerformNativeSecurityCheck(context);
        } catch (Exception e) {
            Log.e(TAG, "Native security check failed", e);
            NativeSecurityCheckResult result = new NativeSecurityCheckResult();
            result.errorMessage = "Exception: " + e.getMessage();
            return result;
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

    // ==================== 纯Java层签名获取（确保被Xposed Hook） ====================

    /**
     * 【重要】纯Java层获取签名 - 确保能被Xposed Hook
     *
     * 这个方法完全在Java层调用PackageManager，不经过Native JNI，
     * 因此可以确保被Xposed签名绕过模块Hook，返回篡改后的签名值。
     *
     * 使用场景：用于检测是否存在签名篡改Hook
     * 对比此方法返回的签名与getSignatureDirect()返回的真实签名，
     * 如果不一致，说明PackageManager被Hook篡改了签名。
     *
     * @param context 应用Context
     * @return 签名哈希字符串（可能被Xposed篡改），失败返回null
     */
    public static String getSignatureFromJava(Context context) {
        if (context == null) {
            Log.e(TAG, "Context is null");
            return null;
        }
        try {
            PackageManager pm = context.getPackageManager();
            String packageName = context.getPackageName();

            // 使用GET_SIGNATURES标志获取签名
            // 这个调用会被Xposed签名绕过模块Hook
            PackageInfo packageInfo = pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
            );

            if (packageInfo.signatures == null || packageInfo.signatures.length == 0) {
                Log.e(TAG, "No signatures found from PackageManager");
                return null;
            }

            // 获取第一个签名并计算SHA-256哈希
            Signature signature = packageInfo.signatures[0];
            byte[] signatureBytes = signature.toByteArray();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(signatureBytes);

            // 转换为十六进制字符串
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }

            String hash = sb.toString();
            Log.i(TAG, "Java-layer signature hash: " + hash);
            return hash;

        } catch (Exception e) {
            Log.e(TAG, "Failed to get signature from Java layer", e);
            return null;
        }
    }

    /**
     * 【重要】完整的签名对比检测
     *
     * 同时获取三种签名并对比：
     * 1. Java层PackageManager签名（会被Xposed Hook篡改）
     * 2. Native JNI层PackageManager签名（可能被部分Hook）
     * 3. Native直接解析APK签名（真实签名，不会被篡改）
     *
     * @param context 应用Context
     * @return 签名对比结果
     */
    public static SignatureComparisonResult compareSignatures(Context context) {
        SignatureComparisonResult result = new SignatureComparisonResult();

        // 1. 纯Java层获取签名（确保被Xposed Hook）
        result.javaSignature = getSignatureFromJava(context);
        Log.i(TAG, "Java signature: " + result.javaSignature);

        // 2. Native JNI层获取签名（通过PackageManager）
        result.nativePmSignature = getSignature(context);
        Log.i(TAG, "Native PM signature: " + result.nativePmSignature);

        // 3. Native直接解析APK获取真实签名
        result.realSignature = getSignatureDirect();
        Log.i(TAG, "Real APK signature: " + result.realSignature);

        // 检测Hook情况
        result.analyzeResults();

        return result;
    }

    /**
     * 签名对比结果类
     */
    public static class SignatureComparisonResult {
        // 纯Java层获取的签名（会被Xposed Hook）
        public String javaSignature;

        // Native JNI层获取的签名（可能被部分Hook）
        public String nativePmSignature;

        // Native直接解析APK的真实签名（不会被篡改）
        public String realSignature;

        // 分析结果
        public boolean javaHooked;       // Java层是否被Hook
        public boolean nativeHooked;     // Native JNI层是否被Hook
        public boolean signatureTampered; // 签名是否被篡改
        public String analysisReport;

        public SignatureComparisonResult() {
            javaSignature = "";
            nativePmSignature = "";
            realSignature = "";
            javaHooked = false;
            nativeHooked = false;
            signatureTampered = false;
            analysisReport = "";
        }

        /**
         * 分析检测结果
         */
        public void analyzeResults() {
            StringBuilder report = new StringBuilder();
            report.append("=== Signature Comparison Analysis ===\n");

            // 检查真实签名是否获取成功
            if (realSignature == null || realSignature.isEmpty()) {
                report.append("ERROR: Failed to get real signature from APK\n");
                analysisReport = report.toString();
                return;
            }

            // 对比Java签名与真实签名
            boolean javaMatchesReal = signaturesEqual(javaSignature, realSignature);
            report.append("Java vs Real: ").append(javaMatchesReal ? "MATCH" : "MISMATCH").append("\n");

            if (!javaMatchesReal && javaSignature != null && !javaSignature.isEmpty()) {
                javaHooked = true;
                report.append("  -> Java layer signature was HOOKED!\n");
                report.append("  -> Java returned: ").append(javaSignature).append("\n");
                report.append("  -> Real signature: ").append(realSignature).append("\n");
            }

            // 对比Native PM签名与真实签名
            boolean nativeMatchesReal = signaturesEqual(nativePmSignature, realSignature);
            report.append("Native PM vs Real: ").append(nativeMatchesReal ? "MATCH" : "MISMATCH").append("\n");

            if (!nativeMatchesReal && nativePmSignature != null && !nativePmSignature.isEmpty()) {
                nativeHooked = true;
                report.append("  -> Native JNI signature was HOOKED!\n");
            }

            // 综合判断
            signatureTampered = javaHooked || nativeHooked;

            if (signatureTampered) {
                report.append("\nWARNING: Signature tampering detected!\n");
                report.append("The application's signature verification may be bypassed.\n");
            } else {
                report.append("\nOK: No signature tampering detected.\n");
            }

            analysisReport = report.toString();
        }

        private boolean signaturesEqual(String sig1, String sig2) {
            if (sig1 == null || sig2 == null) return false;
            return sig1.toLowerCase().trim().equals(sig2.toLowerCase().trim());
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("SignatureComparisonResult {\n");
            sb.append("  javaSignature: ").append(javaSignature).append("\n");
            sb.append("  nativePmSignature: ").append(nativePmSignature).append("\n");
            sb.append("  realSignature: ").append(realSignature).append("\n");
            sb.append("  javaHooked: ").append(javaHooked).append("\n");
            sb.append("  nativeHooked: ").append(nativeHooked).append("\n");
            sb.append("  signatureTampered: ").append(signatureTampered).append("\n");
            sb.append("  analysisReport:\n").append(analysisReport).append("\n");
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