package com.example.securityguard;

/**
 * 签名验证结果类（安全验证模式）
 *
 * 包含直接解析APK和通过PackageManager两种方式的验证结果
 * 用于检测PackageManager是否被Xposed Hook
 */
public class SignatureVerificationResult {

    // 直接解析APK文件获取的签名（不经过Java层，无法被Hook）
    public String apkDirectSignature;

    // 通过PackageManager获取的签名（可能被Xposed Hook篡改）
    public String pmSignature;

    // 两个签名是否一致（如果不一致说明PM可能被Hook）
    public boolean signaturesMatch;

    // APK直接解析的签名是否匹配预期签名
    public boolean apkSignatureValid;

    // PackageManager获取的签名是否匹配预期签名
    public boolean pmSignatureValid;

    // 是否检测到可能的PackageManager Hook
    public boolean possibleHookDetected;

    // 错误信息
    public String errorMessage;

    /**
     * 默认构造函数
     */
    public SignatureVerificationResult() {
        apkDirectSignature = "";
        pmSignature = "";
        signaturesMatch = false;
        apkSignatureValid = false;
        pmSignatureValid = false;
        possibleHookDetected = false;
        errorMessage = "";
    }

    /**
     * 全参数构造函数（JNI调用）
     */
    public SignatureVerificationResult(String apkDirectSignature, String pmSignature,
                                       boolean signaturesMatch, boolean apkSignatureValid,
                                       boolean pmSignatureValid, boolean possibleHookDetected,
                                       String errorMessage) {
        this.apkDirectSignature = apkDirectSignature;
        this.pmSignature = pmSignature;
        this.signaturesMatch = signaturesMatch;
        this.apkSignatureValid = apkSignatureValid;
        this.pmSignatureValid = pmSignatureValid;
        this.possibleHookDetected = possibleHookDetected;
        this.errorMessage = errorMessage;
    }

    /**
     * 判断验证是否通过
     * 只信任APK直接解析的结果（因为它不经过可能被Hook的Java层）
     *
     * @return 验证是否通过
     */
    public boolean isValid() {
        // 只使用APK直接解析的结果进行判断
        // 即使PM被Hook返回了错误的签名，APK直接解析的结果才是真实的
        return apkSignatureValid;
    }

    /**
     * 判断是否存在安全风险
     *
     * @return 是否存在风险
     */
    public boolean hasRisk() {
        // 如果检测到PM Hook，说明存在安全风险
        return possibleHookDetected || !apkSignatureValid;
    }

    /**
     * 获取安全状态描述
     *
     * @return 状态描述
     */
    public String getStatusDescription() {
        if (possibleHookDetected) {
            return "警告：检测到PackageManager可能被Hook篡改！";
        }

        if (apkSignatureValid) {
            if (!signaturesMatch) {
                return "警告：签名来源不一致，可能存在安全风险";
            }
            return "安全：签名验证通过";
        }

        return "危险：签名验证失败";
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SignatureVerificationResult {\n");
        sb.append("  apkDirectSignature: ").append(apkDirectSignature).append("\n");
        sb.append("  pmSignature: ").append(pmSignature).append("\n");
        sb.append("  signaturesMatch: ").append(signaturesMatch).append("\n");
        sb.append("  apkSignatureValid: ").append(apkSignatureValid).append("\n");
        sb.append("  pmSignatureValid: ").append(pmSignatureValid).append("\n");
        sb.append("  possibleHookDetected: ").append(possibleHookDetected).append("\n");
        sb.append("  errorMessage: ").append(errorMessage).append("\n");
        sb.append("  status: ").append(getStatusDescription()).append("\n");
        sb.append("}");
        return sb.toString();
    }
}