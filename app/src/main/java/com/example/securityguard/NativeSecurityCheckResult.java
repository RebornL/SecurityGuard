package com.example.securityguard;

/**
 * Native层安全检查结果类
 *
 * 明确返回C++ Native层获取的签名值和检查状态
 */
public class NativeSecurityCheckResult {

    // ==================== 签名信息 ====================

    /**
     * C++ Native层直接解析APK获取的签名值（真实签名，不可被篡改）
     */
    public String nativeSignature;

    /**
     * APK文件路径
     */
    public String apkPath;

    /**
     * Native层签名是否获取成功
     */
    public boolean nativeSignatureSuccess;

    // ==================== Java层签名信息（对比用） ====================

    /**
     * Java层通过PackageManager获取的签名值（可能被Xposed篡改）
     */
    public String javaSignature;

    /**
     * Java层签名是否获取成功
     */
    public boolean javaSignatureSuccess;

    // ==================== 检测结果 ====================

    /**
     * 两个签名是否一致
     * 如果不一致，说明PackageManager可能被Hook
     */
    public boolean signaturesMatch;

    /**
     * 是否检测到PackageManager Hook
     */
    public boolean pmHookDetected;

    /**
     * 是否检测到Xposed框架
     */
    public boolean xposedDetected;

    // ==================== 综合状态 ====================

    /**
     * 安全检查是否通过
     */
    public boolean isSecure;

    /**
     * 错误信息
     */
    public String errorMessage;

    /**
     * 详细报告
     */
    public String detailReport;

    /**
     * 默认构造函数
     */
    public NativeSecurityCheckResult() {
        nativeSignature = "";
        apkPath = "";
        nativeSignatureSuccess = false;
        javaSignature = "";
        javaSignatureSuccess = false;
        signaturesMatch = false;
        pmHookDetected = false;
        xposedDetected = false;
        isSecure = false;
        errorMessage = "";
        detailReport = "";
    }

    /**
     * 全参数构造函数（JNI调用）
     */
    public NativeSecurityCheckResult(String nativeSignature, String apkPath,
                                     boolean nativeSignatureSuccess,
                                     String javaSignature, boolean javaSignatureSuccess,
                                     boolean signaturesMatch, boolean pmHookDetected,
                                     boolean xposedDetected, boolean isSecure,
                                     String errorMessage, String detailReport) {
        this.nativeSignature = nativeSignature;
        this.apkPath = apkPath;
        this.nativeSignatureSuccess = nativeSignatureSuccess;
        this.javaSignature = javaSignature;
        this.javaSignatureSuccess = javaSignatureSuccess;
        this.signaturesMatch = signaturesMatch;
        this.pmHookDetected = pmHookDetected;
        this.xposedDetected = xposedDetected;
        this.isSecure = isSecure;
        this.errorMessage = errorMessage;
        this.detailReport = detailReport;
    }

    /**
     * 获取状态描述
     */
    public String getStatusDescription() {
        if (isSecure) {
            return "安全：Native层检查通过";
        } else if (!nativeSignatureSuccess) {
            return "错误：Native层签名获取失败";
        } else if (pmHookDetected) {
            return "警告：检测到PackageManager Hook";
        } else if (xposedDetected) {
            return "警告：检测到Xposed框架";
        } else {
            return "警告：安全检查未通过";
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Native Security Check Result ===\n\n");

        sb.append("【C++ Native层签名】\n");
        sb.append("  APK路径: ").append(apkPath).append("\n");
        sb.append("  签名值: ").append(nativeSignature).append("\n");
        sb.append("  获取状态: ").append(nativeSignatureSuccess ? "成功" : "失败").append("\n\n");

        sb.append("【Java层签名（对比用）】\n");
        sb.append("  签名值: ").append(javaSignature).append("\n");
        sb.append("  获取状态: ").append(javaSignatureSuccess ? "成功" : "失败").append("\n\n");

        sb.append("【检测结果】\n");
        sb.append("  签名一致性: ").append(signaturesMatch ? "一致" : "不一致").append("\n");
        sb.append("  PM Hook检测: ").append(pmHookDetected ? "检测到" : "未检测到").append("\n");
        sb.append("  Xposed检测: ").append(xposedDetected ? "检测到" : "未检测到").append("\n\n");

        sb.append("【综合状态】\n");
        sb.append("  安全状态: ").append(isSecure ? "安全" : "不安全").append("\n");
        sb.append("  状态描述: ").append(getStatusDescription()).append("\n");

        if (!errorMessage.isEmpty()) {
            sb.append("  错误信息: ").append(errorMessage).append("\n");
        }

        if (!detailReport.isEmpty()) {
            sb.append("\n【详细报告】\n");
            sb.append(detailReport).append("\n");
        }

        return sb.toString();
    }
}