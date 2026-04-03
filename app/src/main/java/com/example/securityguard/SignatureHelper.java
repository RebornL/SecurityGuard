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
     * 对于篡改检测：同时获取V1和V2签名进行对比
     * MT管理器显示的签名值来自V2签名块（原始签名）
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

        // 同时获取V1和V2签名进行对比分析
        String v1Signature = getV1SignatureFromApk(apkPath);
        String v2Signature = getV2V3SignatureFromApk(apkPath);

        Log.i(TAG, "=== Signature Analysis ===");
        Log.i(TAG, "V1 (META-INF): " + (v1Signature != null ? v1Signature : "N/A"));
        Log.i(TAG, "V2/V3 (Signing Block): " + (v2Signature != null ? v2Signature : "N/A"));

        // 判断篡改情况：
        // 1. 如果只有V2签名存在，使用V2（这是MT管理器的做法）
        // 2. 如果V1是Debug证书而V2不是，说明被篡改，使用V2
        // 3. 如果两者一致，使用任一
        // 4. 如果只有V1存在，使用V1

        if (v2Signature != null && !v2Signature.isEmpty()) {
            // V2签名存在 - 这通常是原始签名（MT管理器显示的值）
            if (v1Signature != null && !v1Signature.equals(v2Signature)) {
                Log.w(TAG, "*** TAMPERING DETECTED: V1 and V2 signatures differ! ***");
                Log.w(TAG, "V1 (篡改后的签名): " + v1Signature);
                Log.w(TAG, "V2 (原始签名): " + v2Signature);
                Log.i(TAG, "Using V2 signature (原始签名，与MT管理器一致)");
            }
            return v2Signature;
        }

        // 如果只有V1签名
        if (v1Signature != null && !v1Signature.isEmpty()) {
            Log.i(TAG, "Only V1 signature found: " + v1Signature);
            return v1Signature;
        }

        Log.e(TAG, "No signature found in APK");
        return null;
    }

    /**
     * 获取完整的签名分析结果（用于检测篡改）
     * 返回V1和V2签名的对比信息
     * @param apkPath APK路径
     * @return 签名分析结果
     */
    public static SignatureAnalysisResult analyzeApkSignatures(String apkPath) {
        return analyzeApkSignatures(apkPath, null);
    }

    /**
     * 获取完整的签名分析结果（用于检测篡改）
     * @param apkPath APK路径
     * @param pmSignature PackageManager返回的签名（用于对比检测NPatch篡改）
     * @return 签名分析结果
     */
    public static SignatureAnalysisResult analyzeApkSignatures(String apkPath, String pmSignature) {
        SignatureAnalysisResult result = new SignatureAnalysisResult();
        result.v1Signature = getV1SignatureFromApk(apkPath);
        result.v2Signature = getV2V3SignatureFromApk(apkPath);
        result.pmSignature = pmSignature;

        // 判断篡改状态
        if (result.v2Signature != null) {
            result.primarySignature = result.v2Signature; // V2是原始签名

            // 检查V1和V2是否一致
            if (result.v1Signature != null && !result.v1Signature.equals(result.v2Signature)) {
                result.tamperingDetected = true;
                result.tamperingReport = "V1和V2签名不一致，APK可能被篡改！\n" +
                        "V1签名(可能被替换): " + result.v1Signature + "\n" +
                        "V2签名(原始): " + result.v2Signature;
            }
            // 检查真实APK签名与PM签名是否一致（检测NPatch篡改）
            else if (pmSignature != null && !pmSignature.equals(result.v2Signature)) {
                result.tamperingDetected = true;
                result.npatchTampering = true;
                result.tamperingReport = "检测到NPatch签名篡改！\n" +
                        "真实APK签名: " + result.v2Signature + "\n" +
                        "PM返回签名: " + pmSignature + "\n" +
                        "APK被NPatch重新签名，但PM返回原始签名！";
                Log.w(TAG, "=== NPATCH TAMPERING DETECTED ===");
                Log.w(TAG, "Real APK signature: " + result.v2Signature);
                Log.w(TAG, "PM signature: " + pmSignature);
            }
            else if (result.v1Signature == null) {
                result.tamperingReport = "APK仅有V2签名（正常情况）";
            } else {
                result.tamperingReport = "V1和V2签名一致，签名状态正常";
            }
        } else if (result.v1Signature != null) {
            result.primarySignature = result.v1Signature;
            result.tamperingReport = "APK仅有V1签名";
        } else {
            result.tamperingReport = "无法获取任何签名";
        }

        Log.i(TAG, result.tamperingReport);
        return result;
    }

    /**
     * 签名分析结果类
     */
    public static class SignatureAnalysisResult {
        public String v1Signature;      // META-INF签名
        public String v2Signature;      // APK Signing Block签名
        public String pmSignature;      // PackageManager返回的签名
        public String primarySignature; // 主要签名（用于显示）
        public boolean tamperingDetected; // 是否检测到篡改
        public boolean npatchTampering; // 是否是NPatch篡改
        public String tamperingReport;  // 篡改分析报告
    }

    /**
     * 从APK的META-INF目录获取V1签名（JAR签名）
     * 这是篡改后APK的真实签名来源
     */
    private static String getV1SignatureFromApk(String apkPath) {
        try {
            // 使用ZipFile解析META-INF目录
            java.util.zip.ZipFile zipFile = new java.util.zip.ZipFile(apkPath);

            // 查找META-INF目录下的签名块文件
            // 可能的文件名: META-INF/*.RSA, META-INF/*.DSA, META-INF/*.EC
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zipFile.entries();

            byte[] signatureBlockData = null;
            String signatureBlockName = null;

            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // 查找签名块文件 (RSA/DSA/EC)
                if (name.startsWith("META-INF/") &&
                    (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    signatureBlockName = name;
                    Log.d(TAG, "Found V1 signature block: " + name);

                    // 读取签名块内容
                    java.io.InputStream is = zipFile.getInputStream(entry);
                    signatureBlockData = new byte[(int) entry.getSize()];
                    is.read(signatureBlockData);
                    is.close();
                    break;
                }
            }

            zipFile.close();

            if (signatureBlockData == null) {
                Log.d(TAG, "No V1 signature block found in META-INF");
                return null;
            }

            // 解析PKCS#7签名块，提取证书
            byte[] certificate = extractCertificateFromPkcs7(signatureBlockData);
            if (certificate == null) {
                Log.e(TAG, "Failed to extract certificate from PKCS#7 block");
                return null;
            }

            // 检查是否是Android Debug证书（篡改检测）
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(certificate));
                String subject = cert.getSubjectDN().getName();
                if (subject.contains("CN=Android Debug")) {
                    Log.w(TAG, "*** V1 signature is Android Debug certificate! ***");
                    Log.w(TAG, "This usually indicates the APK was signed with debug key after tampering.");
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to check certificate type: " + e.getMessage());
            }

            // 计算证书SHA-256
            String hash = computeSha256Hash(certificate);
            Log.i(TAG, "V1 signature hash: " + hash);
            return hash;

        } catch (Exception e) {
            Log.e(TAG, "Error parsing V1 signature: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * 从PKCS#7签名块中提取证书并计算多种指纹
     * PKCS#7格式复杂，使用多种方法尝试提取
     */
    private static byte[] extractCertificateFromPkcs7(byte[] pkcs7Data) {
        try {
            Log.d(TAG, "PKCS#7 block size: " + pkcs7Data.length);

            // 打印前64字节用于调试
            StringBuilder hexBuilder = new StringBuilder();
            for (int i = 0; i < Math.min(64, pkcs7Data.length); i++) {
                hexBuilder.append(String.format("%02x", pkcs7Data[i]));
            }
            Log.d(TAG, "PKCS#7 first 64 bytes: " + hexBuilder.toString());

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // 方法1: 尝试使用CertPath解析PKCS#7
            try {
                java.security.cert.CertPath certPath = certFactory.generateCertPath(
                        new ByteArrayInputStream(pkcs7Data), "PKCS7");
                java.util.List<? extends java.security.cert.Certificate> certs = certPath.getCertificates();
                if (!certs.isEmpty()) {
                    Log.d(TAG, "PKCS7 CertPath parse succeeded, certificates: " + certs.size());
                    X509Certificate cert = (X509Certificate) certs.get(0);
                    byte[] certEncoded = cert.getEncoded();
                    Log.d(TAG, "Certificate extracted via CertPath, size: " + certEncoded.length);

                    // 打印多种指纹计算方式
                    printAllSignatureFingerprints(cert, certEncoded);

                    return certEncoded;
                }
            } catch (Exception e) {
                Log.d(TAG, "PKCS7 CertPath parse failed: " + e.getMessage());
            }

            // 方法2: 搜索所有可能的证书位置并验证
            for (int i = 0; i < pkcs7Data.length - 10; i++) {
                if (pkcs7Data[i] == 0x30 && (pkcs7Data[i + 1] == 0x82 || pkcs7Data[i + 1] == 0x81)) {
                    int contentLen;
                    if (pkcs7Data[i + 1] == 0x82) {
                        contentLen = ((pkcs7Data[i + 2] & 0xff) << 8) | (pkcs7Data[i + 3] & 0xff);
                    } else {
                        contentLen = pkcs7Data[i + 2] & 0xff;
                    }
                    int totalLen = contentLen + (pkcs7Data[i + 1] == 0x82 ? 4 : 3);

                    if (totalLen >= 500 && totalLen <= 2500 && i + totalLen <= pkcs7Data.length) {
                        byte[] potentialCert = new byte[totalLen];
                        System.arraycopy(pkcs7Data, i, potentialCert, 0, totalLen);

                        try {
                            X509Certificate testCert = (X509Certificate) certFactory.generateCertificate(
                                    new ByteArrayInputStream(potentialCert));
                            Log.d(TAG, "Found valid X.509 certificate at offset " + i + ", size " + totalLen);
                            Log.d(TAG, "Certificate subject: " + testCert.getSubjectDN());

                            // 打印多种指纹计算方式
                            printAllSignatureFingerprints(testCert, potentialCert);

                            return potentialCert;
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            Log.e(TAG, "Could not extract certificate from PKCS#7 after exhaustive search");
            return null;

        } catch (Exception e) {
            Log.e(TAG, "Error extracting certificate from PKCS#7: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * 打印多种签名指纹计算方式，帮助找到和MT管理器一致的方法
     */
    private static void printAllSignatureFingerprints(X509Certificate cert, byte[] certEncoded) {
        try {
            Log.i(TAG, "=== Multiple Signature Fingerprint Methods ===");

            // 方法1: 整个证书DER编码的SHA-256
            String certSha256 = computeSha256Hash(certEncoded);
            Log.i(TAG, "Cert DER SHA-256: " + certSha256);

            // 方法2: 公钥DER编码的SHA-256
            byte[] publicKeyEncoded = cert.getPublicKey().getEncoded();
            String pubKeySha256 = computeSha256Hash(publicKeyEncoded);
            Log.i(TAG, "Public Key DER SHA-256: " + pubKeySha256);

            // 方法3: 公钥原始字节（去掉算法标识包装）的SHA-256
            // RSA公钥在SubjectPublicKeyInfo中，实际公钥数据在BIT STRING内
            byte[] publicKeyRaw = extractRawPublicKeyBytes(publicKeyEncoded);
            if (publicKeyRaw != null) {
                String pubKeyRawSha256 = computeSha256Hash(publicKeyRaw);
                Log.i(TAG, "Public Key Raw SHA-256: " + pubKeyRawSha256);
            }

            // 方法4: 证书签名的SHA-256（签名值本身）
            byte[] signature = cert.getSignature();
            String sigSha256 = computeSha256Hash(signature);
            Log.i(TAG, "Certificate Signature SHA-256: " + sigSha256);

            // 方法5: 整个证书的MD5（某些工具使用）
            String certMd5 = computeMd5Hash(certEncoded);
            Log.i(TAG, "Cert DER MD5: " + certMd5);

            // 方法6: 公钥的MD5
            String pubKeyMd5 = computeMd5Hash(publicKeyEncoded);
            Log.i(TAG, "Public Key DER MD5: " + pubKeyMd5);

            // 打印证书详细信息
            Log.i(TAG, "Certificate Subject: " + cert.getSubjectDN());
            Log.i(TAG, "Certificate Issuer: " + cert.getIssuerDN());
            Log.i(TAG, "Certificate Serial: " + cert.getSerialNumber());
            Log.i(TAG, "Public Key Algorithm: " + cert.getPublicKey().getAlgorithm());
            Log.i(TAG, "Signature Algorithm: " + cert.getSigAlgName());

        } catch (Exception e) {
            Log.e(TAG, "Error computing fingerprints: " + e.getMessage());
        }
    }

    /**
     * 从SubjectPublicKeyInfo DER编码中提取原始公钥字节
     * SubjectPublicKeyInfo结构: SEQUENCE { algorithm SEQUENCE, publicKey BIT STRING }
     */
    private static byte[] extractRawPublicKeyBytes(byte[] publicKeyEncoded) {
        try {
            // 找到BIT STRING的位置（公钥实际数据）
            // BIT STRING tag is 0x03
            for (int i = 0; i < publicKeyEncoded.length - 10; i++) {
                if (publicKeyEncoded[i] == 0x03) {
                    // BIT STRING length
                    int len;
                    if (publicKeyEncoded[i + 1] == 0x82) {
                        len = ((publicKeyEncoded[i + 2] & 0xff) << 8) | (publicKeyEncoded[i + 3] & 0xff);
                        int dataStart = i + 4 + 1; // +1 for unused bits byte
                        if (dataStart + len - 1 <= publicKeyEncoded.length) {
                            byte[] rawKey = new byte[len - 1];
                            System.arraycopy(publicKeyEncoded, dataStart, rawKey, 0, len - 1);
                            return rawKey;
                        }
                    } else if (publicKeyEncoded[i + 1] == 0x81) {
                        len = publicKeyEncoded[i + 2] & 0xff;
                        int dataStart = i + 3 + 1;
                        if (dataStart + len - 1 <= publicKeyEncoded.length) {
                            byte[] rawKey = new byte[len - 1];
                            System.arraycopy(publicKeyEncoded, dataStart, rawKey, 0, len - 1);
                            return rawKey;
                        }
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 计算MD5哈希
     */
    private static String computeMd5Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(data);
        return bytesToHex(hash);
    }

    /**
     * 获取V2/V3签名（从APK Signing Block）
     */
    private static String getV2V3SignatureFromApk(String apkPath) {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(apkPath, "r");

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
            long blockSizeOffset = cdOffset - 24;
            raf.seek(blockSizeOffset);
            long blockSize = readUInt64(raf);
            Log.d(TAG, "APK Signing Block size: " + blockSize);

            if (blockSize == 0 || blockSize > cdOffset) {
                Log.e(TAG, "Invalid block size");
                return null;
            }

            // Step 6: 解析Key-Value Pairs查找签名块
            long blockStart = cdOffset - blockSize - 8;
            raf.seek(blockStart);

            // 读取并验证blockSize1
            long blockSize1 = readUInt64(raf);
            if (blockSize1 != blockSize) {
                Log.e(TAG, String.format("Block size mismatch: size1=%d, size2=%d", blockSize1, blockSize));
                return null;
            }
            Log.d(TAG, "BlockSize verified: " + blockSize);

            byte[] signatureData = null;
            long endOfPairs = cdOffset - 24;

            while (raf.getFilePointer() + 12 <= endOfPairs) {
                long pairSize = readUInt64(raf);
                if (pairSize < 4 || pairSize > Integer.MAX_VALUE) {
                    Log.w(TAG, "Invalid pair size: " + pairSize);
                    break;
                }

                long pairIdLong = readUInt32(raf);
                int pairId = (int) pairIdLong;

                long pairStart = raf.getFilePointer() - 12;
                Log.d(TAG, String.format("Pair ID: 0x%08x, size: %d at pos: %d", pairId, pairSize, pairStart));

                if (pairId == APK_SIGNATURE_SCHEME_V2_BLOCK_ID ||
                    pairId == APK_SIGNATURE_SCHEME_V3_BLOCK_ID) {

                    int dataSize = (int) pairSize - 4;
                    if (raf.getFilePointer() + dataSize > endOfPairs) {
                        Log.e(TAG, "Signature data exceeds block boundary");
                        return null;
                    }
                    signatureData = new byte[dataSize];
                    raf.readFully(signatureData);
                    Log.i(TAG, String.format("Found V2/V3 signature block (ID: 0x%08x), size: %d", pairId, dataSize));
                    break;
                } else {
                    int skipSize = (int) pairSize - 4;
                    raf.skipBytes(skipSize);
                    Log.d(TAG, String.format("Skipped pair 0x%08x, %d bytes", pairId, skipSize));
                }
            }

            if (signatureData == null) {
                Log.e(TAG, "No V2/V3 signature block found in APK");
                return null;
            }

            // Step 7: 从签名块提取证书并解析
            byte[] certificate = extractCertificateFromV2Block(signatureData);
            if (certificate == null) {
                Log.e(TAG, "Failed to extract certificate from signature block");
                return null;
            }

            // Step 8: 解析证书并打印多种指纹
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(certificate));
                printAllSignatureFingerprints(cert, certificate);
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse certificate for fingerprint analysis: " + e.getMessage());
            }

            // Step 9: 计算证书的SHA-256哈希
            String hash = computeSha256Hash(certificate);
            Log.i(TAG, "V2/V3 signature hash: " + hash);
            return hash;

        } catch (Exception e) {
            Log.e(TAG, "Error parsing V2/V3 signature: " + e.getMessage(), e);
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
     * 对于篡改后的APK，签名块中可能有多个证书，需要找到原始签名证书
     *
     * V2 Signature Block格式:
     * - signers: length-prefixed sequence of signer
     *   - signer: length-prefixed
     *     - signed_data: length-prefixed
     *       - digests: length-prefixed sequence
     *       - certificates: length-prefixed sequence of certificate
     *       - additional_attributes: length-prefixed sequence
     *     - min_sdk: uint32
     *     - max_sdk: uint32
     *     - signatures: length-prefixed sequence
     *     - public_key: length-prefixed
     */
    private static byte[] extractCertificateFromV2Block(byte[] block) {
        try {
            Log.d(TAG, "=== Starting V2 block parsing, total size: " + block.length + " ===");

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            java.util.List<byte[]> allCerts = new java.util.ArrayList<>();
            java.util.List<String> allSubjects = new java.util.ArrayList<>();

            // 解析signers数组
            int pos = 0;
            int signersSize = readUInt32(block, pos);
            int signersEnd = pos + 4 + signersSize;
            pos += 4;
            Log.d(TAG, "Signers array size: " + signersSize + ", end at: " + signersEnd);

            // 遍历所有signer
            while (pos + 4 <= signersEnd && pos < block.length - 4) {
                int signerSize = readUInt32(block, pos);
                if (signerSize <= 0 || pos + 4 + signerSize > block.length) break;
                
                int signerStart = pos + 4;
                int signerEnd = signerStart + signerSize;
                Log.d(TAG, "Signer at " + signerStart + ", size: " + signerSize);

                // 解析signed_data
                if (signerStart + 4 > block.length) break;
                int signedDataSize = readUInt32(block, signerStart);
                int signedDataStart = signerStart + 4;
                
                // 解析digests
                if (signedDataStart + 4 > block.length) break;
                int digestsSize = readUInt32(block, signedDataStart);
                int certsArrayPos = signedDataStart + 4 + digestsSize;
                
                // 解析certificates数组
                if (certsArrayPos + 4 > block.length) break;
                int certsArraySize = readUInt32(block, certsArrayPos);
                int certsArrayEnd = certsArrayPos + 4 + certsArraySize;
                certsArrayPos += 4;
                Log.d(TAG, "Certificates array at " + certsArrayPos + ", size: " + certsArraySize);

                // 遍历所有证书
                while (certsArrayPos + 4 <= certsArrayEnd && certsArrayPos < block.length - 4) {
                    int certSize = readUInt32(block, certsArrayPos);
                    if (certSize <= 0 || certSize > 3000 || certsArrayPos + 4 + certSize > block.length) break;
                    
                    byte[] certData = new byte[certSize];
                    System.arraycopy(block, certsArrayPos + 4, certData, 0, certSize);
                    
                    try {
                        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                                new ByteArrayInputStream(certData));
                        String subject = cert.getSubjectDN().getName();
                        Log.d(TAG, "Found certificate: " + subject);
                        
                        allCerts.add(certData);
                        allSubjects.add(subject);
                        
                        // 如果找到NPatch证书，优先返回
                        if (subject.contains("NPatch") || subject.contains("NikoBeillc") || 
                            subject.contains("HSSkyBoy")) {
                            Log.i(TAG, "Found NPatch certificate! Subject: " + subject);
                            return certData;
                        }
                    } catch (Exception e) {
                        Log.d(TAG, "Certificate parse error: " + e.getMessage());
                    }
                    
                    certsArrayPos += 4 + certSize;
                }
                
                pos = signerEnd;
            }

            // 如果没有找到NPatch证书，返回第一个非Debug证书
            for (int i = 0; i < allSubjects.size(); i++) {
                String subject = allSubjects.get(i);
                if (!subject.contains("CN=Android Debug")) {
                    Log.i(TAG, "Returning first non-Debug certificate: " + subject);
                    return allCerts.get(i);
                }
            }

            // 如果所有方法都失败，尝试直接搜索证书模式
            Log.d(TAG, "Trying direct certificate pattern search...");
            return searchCertificatePattern(block);

        } catch (Exception e) {
            Log.e(TAG, "Error extracting certificate: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * 直接搜索证书模式 (30 82 xx xx)
     */
    private static byte[] searchCertificatePattern(byte[] block) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            
            for (int i = 0; i < block.length - 10; i++) {
                if (block[i] == 0x30 && block[i + 1] == 0x82) {
                    int contentLen = ((block[i + 2] & 0xff) << 8) | (block[i + 3] & 0xff);
                    int totalLen = contentLen + 4;
                    
                    if (totalLen >= 400 && totalLen <= 3000 && i + totalLen <= block.length) {
                        byte[] certData = new byte[totalLen];
                        System.arraycopy(block, i, certData, 0, totalLen);
                        
                        try {
                            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                                    new ByteArrayInputStream(certData));
                            String subject = cert.getSubjectDN().getName();
                            Log.i(TAG, "Found certificate via pattern search: " + subject);
                            
                            if (!subject.contains("CN=Android Debug")) {
                                return certData;
                            }
                        } catch (Exception ignored) {}
                    }
                }
            }
            
            Log.e(TAG, "No valid certificate found after exhaustive search");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error in pattern search: " + e.getMessage());
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
     * 注意：NPatch会Hook sourceDir返回原始APK路径
     */
    public static String getApkPath(Context context) {
        if (context == null) return null;
        try {
            // 首先尝试从/proc/self/maps获取真实的APK路径
            String realApkPath = getRealApkPathFromProcMaps();
            if (realApkPath != null && !realApkPath.contains("/cache/npatch/")) {
                Log.i(TAG, "Got real APK path from /proc/self/maps: " + realApkPath);
                return realApkPath;
            }
            
            // 回退到context.getApplicationInfo().sourceDir
            String sourceDir = context.getApplicationInfo().sourceDir;
            Log.d(TAG, "Got APK path from sourceDir: " + sourceDir);
            
            // 检查是否被NPatch重定向
            if (sourceDir != null && sourceDir.contains("/cache/npatch/")) {
                Log.w(TAG, "NPatch detected! APK path redirected to: " + sourceDir);
                // 尝试获取真实安装路径
                String installedPath = guessInstalledApkPath(context.getPackageName());
                if (installedPath != null) {
                    Log.i(TAG, "Using guessed installed APK path: " + installedPath);
                    return installedPath;
                }
            }
            
            return sourceDir;
        } catch (Exception e) {
            Log.e(TAG, "Failed to get APK path: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从/proc/self/maps获取真实的APK路径
     * 绕过NPatch对sourceDir的Hook
     */
    private static String getRealApkPathFromProcMaps() {
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/maps"));
            String line;
            java.util.List<String> foundPaths = new java.util.ArrayList<>();
            int lineCount = 0;
            
            Log.i(TAG, "=== Reading /proc/self/maps ===");
            
            while ((line = reader.readLine()) != null) {
                lineCount++;
                // 输出包含apk的行或前20行用于调试
                if (line.contains(".apk") || lineCount <= 20) {
                    Log.d(TAG, "maps line " + lineCount + ": " + line);
                }
                
                // 查找所有base.apk路径
                if (line.contains("base.apk")) {
                    int pathStart = line.indexOf("/");
                    if (pathStart > 0) {
                        String path = line.substring(pathStart).trim();
                        int apkEnd = path.indexOf("base.apk") + "base.apk".length();
                        if (apkEnd > 0) {
                            String apkPath = path.substring(0, apkEnd);
                            foundPaths.add(apkPath);
                            Log.i(TAG, "Found APK in maps: " + apkPath);
                        }
                    }
                }
            }
            reader.close();
            
            Log.i(TAG, "Total lines in maps: " + lineCount);
            Log.i(TAG, "Total APK paths found in /proc/self/maps: " + foundPaths.size());
            
            // 输出所有找到的路径
            for (int i = 0; i < foundPaths.size(); i++) {
                String path = foundPaths.get(i);
                boolean exists = new java.io.File(path).exists();
                boolean isNpatch = path.contains("/cache/npatch/");
                Log.i(TAG, "Path[" + i + "]: " + path + " (exists=" + exists + ", npatch=" + isNpatch + ")");
            }
            
            // 优先返回非npatch缓存的路径
            for (String path : foundPaths) {
                if (!path.contains("/cache/npatch/") && new java.io.File(path).exists()) {
                    Log.i(TAG, "Selected real APK path: " + path);
                    return path;
                }
            }
            
            // 如果只有npatch路径，也返回（比没有好）
            if (!foundPaths.isEmpty()) {
                String firstPath = foundPaths.get(0);
                Log.w(TAG, "Only NPatch cache path found: " + firstPath);
                return firstPath;
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to read /proc/self/maps: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * 尝试猜测实际安装的APK路径
     * NPatch会将原始APK缓存到cache/npatch目录
     * 真实APK应该在/data/app/目录下
     */
    private static String guessInstalledApkPath(String packageName) {
        try {
            // 遍历/data/app目录查找包含包名的APK
            java.io.File appDir = new java.io.File("/data/app");
            if (appDir.exists() && appDir.isDirectory()) {
                for (java.io.File subDir : appDir.listFiles()) {
                    if (subDir.getName().contains(packageName)) {
                        java.io.File baseApk = new java.io.File(subDir, "base.apk");
                        if (baseApk.exists()) {
                            return baseApk.getAbsolutePath();
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Failed to guess APK path: " + e.getMessage());
        }
        return null;
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
     * 计算签名的SHA-256哈希（对整个证书DER编码计算）
     * MT管理器等工具显示的签名值通常就是这个
     */
    private static String computeSignatureHash(Signature signature) throws Exception {
        byte[] signatureBytes = signature.toByteArray();

        // 解析证书验证格式
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(signatureBytes)
        );

        // 计算整个证书DER编码的SHA-256哈希（和MT管理器一致）
        // 注意：signature.toByteArray() 返回的就是证书的DER编码
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(signatureBytes);

        return bytesToHex(hashBytes);
    }

    // ==================== NPatch篡改检测 ====================

    /**
     * 检测NPatch签名篡改
     *
     * NPatch的签名绕过机制：
     * 1. Hook sourceDir 返回原始APK路径（缓存的未篡改版本）
     * 2. 所有通过PackageManager的签名查询都返回原始签名
     * 3. 但真实安装的APK已被NPatch签名
     *
     * 检测方法：
     * 1. 从/proc/self/maps获取真实安装的APK路径
     * 2. 直接解析真实APK的V2签名
     * 3. 与PackageManager返回的签名对比
     * 4. 如果不一致，说明APK被NPatch篡改
     *
     * @param context 应用Context
     * @return NPatch检测结果
     */
    public static NPatchDetectionResult detectNPatchTampering(Context context) {
        NPatchDetectionResult result = new NPatchDetectionResult();

        try {
            // 1. 获取PM返回的签名（可能被NPatch Hook）
            result.pmSignature = getSignatureHash(context);
            Log.i(TAG, "PM signature: " + result.pmSignature);

            // 2. 从/proc/self/maps获取真实APK路径
            result.realApkPath = getRealApkPathFromProcMaps();
            if (result.realApkPath == null) {
                result.realApkPath = context.getApplicationInfo().sourceDir;
            }
            Log.i(TAG, "Real APK path: " + result.realApkPath);

            // 3. 检查是否是NPatch缓存路径
            result.isNpatchCachePath = result.realApkPath.contains("/cache/npatch/");
            Log.i(TAG, "Is NPatch cache path: " + result.isNpatchCachePath);

            // 4. 从真实APK路径读取签名
            if (!result.isNpatchCachePath) {
                SignatureAnalysisResult analysis = analyzeApkSignatures(result.realApkPath);
                result.realSignature = analysis.primarySignature;
                result.realCertSubject = extractCertSubjectFromV2Block(result.realApkPath);
                Log.i(TAG, "Real signature: " + result.realSignature);
                Log.i(TAG, "Real cert subject: " + result.realCertSubject);

                // 5. 检查是否是NPatch签名
                result.isNpatchSignature = result.realCertSubject != null &&
                        (result.realCertSubject.contains("NPatch") ||
                         result.realCertSubject.contains("NikoBeillc") ||
                         result.realCertSubject.contains("HSSkyBoy"));
                Log.i(TAG, "Is NPatch signature: " + result.isNpatchSignature);
            }

            // 6. 对比签名
            if (result.realSignature != null && result.pmSignature != null) {
                String real = result.realSignature.toLowerCase().trim();
                String pm = result.pmSignature.toLowerCase().trim();
                result.signaturesMatch = real.equals(pm);

                if (!result.signaturesMatch) {
                    result.tamperingDetected = true;
                    result.npatchDetected = result.isNpatchSignature;
                    result.detectionReport = "检测到签名不一致！\n" +
                            "真实APK签名: " + result.realSignature + "\n" +
                            "PM返回签名: " + result.pmSignature + "\n" +
                            (result.isNpatchSignature ?
                             "确认检测到NPatch签名特征: " + result.realCertSubject :
                             "APK可能被其他工具篡改");
                    Log.w(TAG, "=== TAMPERING DETECTED ===");
                    Log.w(TAG, result.detectionReport);
                } else {
                    result.detectionReport = "签名一致，未检测到篡改。";
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "NPatch detection failed: " + e.getMessage(), e);
            result.detectionReport = "检测失败: " + e.getMessage();
        }

        return result;
    }

    /**
     * 从V2签名块提取证书主题
     */
    private static String extractCertSubjectFromV2Block(String apkPath) {
        try {
            RandomAccessFile raf = new RandomAccessFile(apkPath, "r");
            long eocdOffset = findEocd(raf);
            if (eocdOffset < 0) { raf.close(); return null; }

            raf.seek(eocdOffset + 16);
            long cdOffset = readUInt32(raf);
            if (cdOffset < 32) { raf.close(); return null; }

            raf.seek(cdOffset - 16);
            byte[] magic = new byte[16];
            raf.readFully(magic);
            if (!Arrays.equals(magic, APK_SIG_BLOCK_MAGIC)) { raf.close(); return null; }

            raf.seek(cdOffset - 24);
            long blockSize = readUInt64(raf);
            raf.seek(cdOffset - blockSize - 8);
            readUInt64(raf);

            long endOfPairs = cdOffset - 24;
            while (raf.getFilePointer() + 12 <= endOfPairs) {
                long pairSize = readUInt64(raf);
                int pairId = (int) readUInt32(raf);
                if (pairId == APK_SIGNATURE_SCHEME_V2_BLOCK_ID || pairId == APK_SIGNATURE_SCHEME_V3_BLOCK_ID) {
                    int dataSize = (int) pairSize - 4;
                    byte[] sigData = new byte[dataSize];
                    raf.readFully(sigData);
                    raf.close();
                    return extractSubjectFromV2Data(sigData);
                }
                raf.skipBytes((int) pairSize - 4);
            }
            raf.close();
        } catch (Exception e) {
            Log.e(TAG, "Extract cert subject failed: " + e.getMessage());
        }
        return null;
    }

    private static String extractSubjectFromV2Data(byte[] block) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            int pos = 0;
            int signersSize = readUInt32(block, pos);
            pos += 4;
            int signersEnd = pos + signersSize;

            while (pos + 4 <= signersEnd) {
                int signerSize = readUInt32(block, pos);
                int signerStart = pos + 4;
                int signedDataSize = readUInt32(block, signerStart);
                int digestsSize = readUInt32(block, signerStart + 4);
                int certsPos = signerStart + 4 + 4 + digestsSize;
                int certsSize = readUInt32(block, certsPos);
                certsPos += 4;

                while (certsPos + 4 <= certsPos + certsSize) {
                    int certSize = readUInt32(block, certsPos);
                    if (certSize <= 0 || certSize > 3000) break;
                    byte[] certData = new byte[certSize];
                    System.arraycopy(block, certsPos + 4, certData, 0, certSize);
                    try {
                        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                                new ByteArrayInputStream(certData));
                        return cert.getSubjectDN().getName();
                    } catch (Exception ignored) {}
                    certsPos += 4 + certSize;
                }
                pos = signerStart + signerSize;
            }
        } catch (Exception e) {
            Log.e(TAG, "Extract subject from V2 data failed: " + e.getMessage());
        }
        return null;
    }

    /**
     * NPatch检测结果类
     */
    public static class NPatchDetectionResult {
        public String pmSignature;
        public String realSignature;
        public String realApkPath;
        public String realCertSubject;
        public boolean isNpatchCachePath;
        public boolean isNpatchSignature;
        public boolean signaturesMatch;
        public boolean tamperingDetected;
        public boolean npatchDetected;
        public String detectionReport;

        @Override
        public String toString() {
            return "NPatchDetectionResult{" +
                    "pmSig='" + pmSignature + '\'' +
                    ", realSig='" + realSignature + '\'' +
                    ", realPath='" + realApkPath + '\'' +
                    ", certSubject='" + realCertSubject + '\'' +
                    ", npatchSig=" + isNpatchSignature +
                    ", match=" + signaturesMatch +
                    ", tampering=" + tamperingDetected +
                    ", npatch=" + npatchDetected +
                    ", report='" + detectionReport + '\'' +
                    '}';
        }
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