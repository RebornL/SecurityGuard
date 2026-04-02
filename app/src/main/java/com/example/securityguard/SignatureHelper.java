package com.example.securityguard;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * 签名验证辅助类
 *
 * 提供多种签名获取方式：
 * 1. 通过PackageManager获取（可能被Xposed Hook）
 * 2. 直接从APK文件解析V2/V3签名（不会被Hook）
 * 3. 签名对比验证机制
 */
public class SignatureHelper {

    private static final String TAG = "SignatureHelper";

    // APK Signing Block Magic: "APK Sig Block 42"
    private static final byte[] APK_SIG_BLOCK_MAGIC = {
            0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
            0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
    };

    // V2签名块ID
    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
    // V3签名块ID
    private static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;

    // ==================== 纯Java层直接解析APK签名（不会被Xposed Hook） ====================

    /**
     * 直接从APK文件获取签名（纯Java实现，绕过PackageManager）
     *
     * 这个方法不会被Xposed的PackageManager Hook影响，
     * 因为它直接读取APK文件并解析V2/V3签名块。
     *
     * @param context 应用Context
     * @return 签名哈希字符串，如果获取失败返回null
     */
    public static String getSignatureDirectFromApk(Context context) {
        String apkPath = getApkPath(context);
        if (apkPath == null || apkPath.isEmpty()) {
            Log.e(TAG, "Failed to get APK path");
            return null;
        }
        return getSignatureDirectFromApkPath(apkPath);
    }

    /**
     * 直接从指定APK文件路径获取签名
     *
     * @param apkPath APK文件路径
     * @return 签名哈希字符串，如果获取失败返回null
     */
    public static String getSignatureDirectFromApkPath(String apkPath) {
        if (apkPath == null || apkPath.isEmpty()) {
            Log.e(TAG, "APK path is null or empty");
            return null;
        }

        File apkFile = new File(apkPath);
        if (!apkFile.exists()) {
            Log.e(TAG, "APK file not found: " + apkPath);
            return null;
        }

        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(apkFile, "r");

            // Step 1: 查找ZIP End of Central Directory (EOCD)
            long eocdOffset = findEocd(raf);
            if (eocdOffset < 0) {
                Log.e(TAG, "Failed to find EOCD in APK");
                return null;
            }
            Log.d(TAG, "EOCD found at offset: " + eocdOffset);

            // Step 2: 获取Central Directory偏移
            raf.seek(eocdOffset + 16);
            long cdOffset = readUInt32(raf);
            Log.d(TAG, "Central Directory offset: " + cdOffset);

            // Step 3: 检查APK Signing Block (V2/V3)
            if (cdOffset < 32) {
                Log.e(TAG, "No APK Signing Block (APK may only have V1 signature)");
                return null;
            }

            // Step 4: 验证APK Signing Block Magic
            long magicOffset = cdOffset - 16;
            raf.seek(magicOffset);
            byte[] magic = new byte[16];
            raf.readFully(magic);

            if (!Arrays.equals(magic, APK_SIG_BLOCK_MAGIC)) {
                Log.e(TAG, "APK Signing Block magic mismatch - no V2/V3 signature");
                return null;
            }
            Log.d(TAG, "Found APK Signing Block");

            // Step 5: 读取Block Size (uint64, 8字节)
            // APK Signing Block格式：
            // [blockSize1(8)] [signing data] [blockSize2(8)] [magic(16)]
            //                                     ↑               ↑
            //                              cdOffset-24       cdOffset-16
            
            long blockSizeOffset = cdOffset - 24;
            raf.seek(blockSizeOffset);
            long blockSize = readUInt64(raf);
            Log.d(TAG, "APK Signing Block size: " + blockSize);

            if (blockSize == 0 || blockSize > cdOffset) {
                Log.e(TAG, "Invalid block size");
                return null;
            }

            // Step 6: 解析Key-Value Pairs查找签名块
            // APK Signing Block结构：
            // [blockSize1(8)] [signing data] [blockSize2(8)] [magic(16)]
            //       ↑              ↑              ↑             ↑
            //  cdOffset-bs-8   cdOffset-bs    cdOffset-24    cdOffset-16
            // 
            // blockSize = signing data + blockSize2(8) + magic(16) = signing data + 24
            // 
            // signing data 内部格式：
            // repeated ID-value pairs:
            //     uint64: pair_size (excluding this field)
            //     uint32: ID
            //     (pair_size - 4) bytes: value
            
            long blockStart = cdOffset - blockSize - 8;
            raf.seek(blockStart);
            
            // 读取并验证blockSize1（应该等于blockSize）
            long blockSize1 = readUInt64(raf);
            if (blockSize1 != blockSize) {
                Log.e(TAG, String.format("Block size mismatch: size1=%d, size2=%d", blockSize1, blockSize));
                return null;
            }
            Log.d(TAG, "BlockSize verified: " + blockSize + ", pairs start at: " + raf.getFilePointer());
            
            // 现在文件指针位于 signing data (key-value pairs) 的起始位置
            // signing data 结束于 blockSize2 的位置 (cdOffset - 24)
            
            byte[] signatureData = null;
            long endOfPairs = cdOffset - 24;

            while (raf.getFilePointer() + 12 <= endOfPairs) {  // 8 (size) + 4 (id) minimum
                // pair size 是 uint64
                long pairSize = readUInt64(raf);
                if (pairSize < 4 || pairSize > Integer.MAX_VALUE) {
                    Log.w(TAG, "Invalid pair size: " + pairSize);
                    break;
                }

                // pair ID 是 uint32
                long pairIdLong = readUInt32(raf);
                int pairId = (int) pairIdLong;

                long pairStart = raf.getFilePointer() - 12;
                Log.d(TAG, String.format("Pair ID: 0x%08x, size: %d at pos: %d", pairId, pairSize, pairStart));

                // 检查是否是V2或V3签名块
                if (pairId == APK_SIGNATURE_SCHEME_V2_BLOCK_ID ||
                    pairId == APK_SIGNATURE_SCHEME_V3_BLOCK_ID) {

                    int dataSize = (int) pairSize - 4;
                    if (raf.getFilePointer() + dataSize > endOfPairs) {
                        Log.e(TAG, "Signature data exceeds block boundary");
                        return null;
                    }
                    signatureData = new byte[dataSize];
                    raf.readFully(signatureData);
                    Log.i(TAG, String.format("Found signature block (ID: 0x%08x), size: %d", pairId, dataSize));
                    break;
                } else {
                    // 跳过此pair的数据部分
                    int skipSize = (int) pairSize - 4;
                    raf.skipBytes(skipSize);
                    Log.d(TAG, String.format("Skipped pair 0x%08x, %d bytes", pairId, skipSize));
                }
            }

            if (signatureData == null) {
                Log.e(TAG, "No V2/V3 signature block found in APK");
                return null;
            }

            // Step 7: 从签名块提取证书
            byte[] certificate = extractCertificateFromV2Block(signatureData);
            if (certificate == null) {
                Log.e(TAG, "Failed to extract certificate from signature block");
                return null;
            }

            // Step 8: 计算证书的SHA-256哈希
            String hash = computeSha256Hash(certificate);
            Log.i(TAG, "Direct APK signature hash: " + hash);
            return hash;

        } catch (Exception e) {
            Log.e(TAG, "Error parsing APK signature: " + e.getMessage(), e);
            return null;
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 从V2/V3签名块提取证书
     */
    private static byte[] extractCertificateFromV2Block(byte[] block) {
        try {
            int pos = 0;

            // signers数组大小
            int signersSize = readUInt32(block, pos);
            pos += 4;
            Log.d(TAG, "Signers size: " + signersSize);

            if (pos + 4 > block.length) return null;

            // 第一个signer的大小
            int signerSize = readUInt32(block, pos);
            pos += 4;
            Log.d(TAG, "Signer size: " + signerSize);

            if (pos + 4 > block.length) return null;

            // signedData大小
            int signedDataSize = readUInt32(block, pos);
            pos += 4;
            Log.d(TAG, "SignedData size: " + signedDataSize);

            if (pos + 4 > block.length) return null;

            // digests数组大小
            int digestsSize = readUInt32(block, pos);
            pos += 4 + digestsSize;
            Log.d(TAG, "Digests size: " + digestsSize);

            if (pos + 4 > block.length) return null;

            // certificates数组大小
            int certsSize = readUInt32(block, pos);
            pos += 4;
            Log.d(TAG, "Certificates array size: " + certsSize);

            if (pos + 4 > block.length) return null;

            // 第一个certificate大小
            int certSize = readUInt32(block, pos);
            pos += 4;
            Log.d(TAG, "Certificate size: " + certSize);

            if (pos + certSize > block.length) {
                Log.e(TAG, "Certificate data exceeds block size");
                return null;
            }

            // 提取证书数据
            byte[] certificate = new byte[certSize];
            System.arraycopy(block, pos, certificate, 0, certSize);
            return certificate;

        } catch (Exception e) {
            Log.e(TAG, "Error extracting certificate: " + e.getMessage());
            return null;
        }
    }

    /**
     * 查找ZIP End of Central Directory
     */
    private static long findEocd(RandomAccessFile raf) throws Exception {
        long fileSize = raf.length();

        // EOCD最小22字节，最大可以有65535字节的注释
        long searchStart = fileSize > 65557 ? fileSize - 65557 : 0;

        // 从后向前搜索EOCD签名: 0x06054b50
        byte[] buffer = new byte[4];
        for (long i = fileSize - 22; i >= searchStart && i > 0; i--) {
            raf.seek(i);
            raf.readFully(buffer);

            if (buffer[0] == 0x50 && buffer[1] == 0x4b &&
                buffer[2] == 0x05 && buffer[3] == 0x06) {
                return i;
            }
        }

        return -1;
    }

    /**
     * 读取小端序uint32
     */
    private static long readUInt32(RandomAccessFile raf) throws Exception {
        byte[] bytes = new byte[4];
        raf.readFully(bytes);
        return readUInt32(bytes, 0);
    }

    /**
     * 读取小端序uint64
     */
    private static long readUInt64(RandomAccessFile raf) throws Exception {
        byte[] bytes = new byte[8];
        raf.readFully(bytes);
        return readUInt64(bytes, 0);
    }

    /**
     * 从字节数组读取小端序uint64
     */
    private static long readUInt64(byte[] data, int offset) {
        return (data[offset] & 0xffL) |
               ((data[offset + 1] & 0xffL) << 8) |
               ((data[offset + 2] & 0xffL) << 16) |
               ((data[offset + 3] & 0xffL) << 24) |
               ((data[offset + 4] & 0xffL) << 32) |
               ((data[offset + 5] & 0xffL) << 40) |
               ((data[offset + 6] & 0xffL) << 48) |
               ((data[offset + 7] & 0xffL) << 56);
    }

    /**
     * 从字节数组读取小端序uint32
     */
    private static int readUInt32(byte[] data, int offset) {
        return (data[offset] & 0xff) |
               ((data[offset + 1] & 0xff) << 8) |
               ((data[offset + 2] & 0xff) << 16) |
               ((data[offset + 3] & 0xff) << 24);
    }

    /**
     * 计算SHA-256哈希
     */
    private static String computeSha256Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        return bytesToHex(hash);
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
     * 获取APK路径
     */
    public static String getApkPath(Context context) {
        if (context == null) return null;
        try {
            return context.getApplicationInfo().sourceDir;
        } catch (Exception e) {
            Log.e(TAG, "Failed to get APK path: " + e.getMessage());
            return null;
        }
    }

    // ==================== 通过PackageManager获取签名（可能被Xposed Hook） ====================

    /**
     * 获取应用签名的SHA-256哈希（通过PackageManager）
     * 注意：此方法可能被Xposed Hook篡改
     *
     * @param context 应用Context
     * @return 签名哈希字符串
     */
    public static String getSignatureHash(Context context) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return getSignatureHashApi28(context);
            } else {
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

        PackageInfo packageInfo = pm.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
        );

        if (packageInfo.signingInfo == null) {
            Log.e(TAG, "No signingInfo found");
            return null;
        }

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

        return bytesToHex(hashBytes);
    }

    // ==================== 签名验证和对比 ====================

    /**
     * 验证签名是否匹配（使用安全方式）
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

        // 使用直接解析APK的方式获取签名
        String currentHash = getSignatureDirectFromApk(context);
        if (currentHash == null) {
            Log.e(TAG, "Failed to get current signature hash");
            return false;
        }

        String expected = expectedHash.toLowerCase().trim();
        String current = currentHash.toLowerCase().trim();

        boolean result = expected.equals(current);
        if (!result) {
            Log.w(TAG, "Signature mismatch: expected=" + expected + ", current=" + current);
        }

        return result;
    }

    /**
     * 签名对比结果
     */
    public static class SignatureComparisonResult {
        // 直接从APK解析的真实签名（不会被Hook）
        public String realSignature;

        // 通过PackageManager获取的签名（可能被Hook）
        public String pmSignature;

        // 两者是否一致
        public boolean signaturesMatch;

        // 是否检测到可能的Hook
        public boolean hookDetected;

        // 分析报告
        public String analysisReport;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== Signature Comparison Result ===\n");
            sb.append("Real Signature (from APK): ").append(realSignature).append("\n");
            sb.append("PM Signature (may be hooked): ").append(pmSignature).append("\n");
            sb.append("Signatures Match: ").append(signaturesMatch ? "YES" : "NO").append("\n");
            sb.append("Hook Detected: ").append(hookDetected ? "YES" : "NO").append("\n");
            if (analysisReport != null) {
                sb.append("\n").append(analysisReport);
            }
            return sb.toString();
        }
    }

    /**
     * 执行签名对比检测
     *
     * 同时使用两种方式获取签名并比较，检测PackageManager是否被Hook
     *
     * @param context 应用Context
     * @return 签名对比结果
     */
    public static SignatureComparisonResult compareSignatures(Context context) {
        SignatureComparisonResult result = new SignatureComparisonResult();

        // 1. 直接从APK解析获取真实签名（不会被Hook）
        result.realSignature = getSignatureDirectFromApk(context);
        Log.i(TAG, "Real signature (from APK): " + result.realSignature);

        // 2. 通过PackageManager获取签名（可能被Hook）
        result.pmSignature = getSignatureHash(context);
        Log.i(TAG, "PM signature: " + result.pmSignature);

        // 3. 对比签名
        if (result.realSignature != null && result.pmSignature != null) {
            String real = result.realSignature.toLowerCase().trim();
            String pm = result.pmSignature.toLowerCase().trim();
            result.signaturesMatch = real.equals(pm);
            result.hookDetected = !result.signaturesMatch;

            if (result.hookDetected) {
                result.analysisReport = "WARNING: PackageManager may be hooked!\n" +
                        "The signature returned by PackageManager differs from the real APK signature.\n" +
                        "This indicates possible Xposed signature bypass.";
                Log.w(TAG, "PackageManager Hook detected! Signatures don't match.");
            } else {
                result.analysisReport = "OK: Signatures match. No PackageManager hook detected.";
            }
        } else {
            result.signaturesMatch = false;
            result.hookDetected = false;
            result.analysisReport = "ERROR: Failed to get one or both signatures.\n" +
                    "Real signature: " + (result.realSignature != null ? "OK" : "FAILED") + "\n" +
                    "PM signature: " + (result.pmSignature != null ? "OK" : "FAILED");
        }

        return result;
    }

    /**
     * 检测PackageManager是否被Hook
     *
     * @param context 应用Context
     * @return 是否检测到可能的Hook
     */
    public static boolean detectPmHook(Context context) {
        SignatureComparisonResult result = compareSignatures(context);
        return result.hookDetected;
    }
}