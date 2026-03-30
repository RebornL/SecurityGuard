package com.example.securityguard;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 签名验证辅助类
 *
 * 处理不同Android版本的签名API差异
 * Android P (API 28) 及以上使用新的签名API
 */
public class SignatureHelper {

    private static final String TAG = "SignatureHelper";

    /**
     * 获取应用签名的SHA-256哈希
     * 兼容所有Android版本
     *
     * @param context 应用Context
     * @return 签名哈希字符串
     */
    public static String getSignatureHash(Context context) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // Android P及以上使用新API
                return getSignatureHashApi28(context);
            } else {
                // Android P以下使用旧API
                return getSignatureHashLegacy(context);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get signature hash", e);
            return null;
        }
    }

    /**
     * Android P及以上的签名获取方法
     */
    private static String getSignatureHashApi28(Context context) throws Exception {
        PackageManager pm = context.getPackageManager();
        String packageName = context.getPackageName();

        // 使用GET_SIGNING_CERTIFICATES标志
        PackageInfo packageInfo = pm.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
        );

        if (packageInfo.signingInfo == null) {
            Log.e(TAG, "No signingInfo found");
            return null;
        }

        // 获取签名证书
        Signature[] signatures = packageInfo.signingInfo.getApkContentsSigners();
        if (signatures == null || signatures.length == 0) {
            Log.e(TAG, "No signatures found in signingInfo");
            return null;
        }

        return computeSignatureHash(signatures[0]);
    }

    /**
     * Android P以下的签名获取方法
     */
    private static String getSignatureHashLegacy(Context context) throws Exception {
        PackageManager pm = context.getPackageManager();
        String packageName = context.getPackageName();

        PackageInfo packageInfo = pm.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNATURES
        );

        if (packageInfo.signatures == null || packageInfo.signatures.length == 0) {
            Log.e(TAG, "No signatures found");
            return null;
        }

        return computeSignatureHash(packageInfo.signatures[0]);
    }

    /**
     * 计算签名的SHA-256哈希
     */
    private static String computeSignatureHash(Signature signature) throws Exception {
        byte[] signatureBytes = signature.toByteArray();

        // 解析证书
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(signatureBytes)
        );

        // 计算公钥的SHA-256哈希
        byte[] publicKeyBytes = cert.getPublicKey().getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(publicKeyBytes);

        // 转换为十六进制字符串
        return bytesToHex(hashBytes);
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 验证签名是否匹配
     *
     * @param context 应用Context
     * @param expectedHash 预期的签名哈希
     * @return 是否匹配
     */
    public static boolean verifySignature(Context context, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) {
            Log.e(TAG, "Expected hash is null or empty");
            return false;
        }

        String currentHash = getSignatureHash(context);
        if (currentHash == null) {
            Log.e(TAG, "Failed to get current signature hash");
            return false;
        }

        // 规范化比较
        String expected = expectedHash.toLowerCase().trim();
        String current = currentHash.toLowerCase().trim();

        boolean result = expected.equals(current);
        if (!result) {
            Log.w(TAG, "Signature mismatch: expected=" + expected + ", current=" + current);
        }

        return result;
    }
}