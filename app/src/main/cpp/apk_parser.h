/**
 * APK签名解析器 - Native层直接解析
 *
 * 不依赖Java层PackageManager，直接从APK文件读取签名
 * 防止Xposed Hook PackageManager绕过签名验证
 */

#ifndef APK_PARSER_H
#define APK_PARSER_H

#include <jni.h>
#include <string>
#include <vector>
#include <cstdint>

namespace security {

/**
 * APK签名解析器
 * 直接解析APK文件，不经过Java层PackageManager
 */
class ApkSignatureParser {
public:
    /**
     * 直接从APK文件获取签名
     * @param apkPath APK文件路径
     * @return 签名的SHA-256哈希
     */
    static std::string getSignatureFromApk(const std::string& apkPath);

    /**
     * 从正在运行的进程获取自己的APK路径（无参数版本）
     * @return APK路径
     */
    static std::string getSelfApkPath();

    /**
     * 通过JNI从Context获取APK路径（推荐使用）
     * @param env JNI环境
     * @param context 应用Context
     * @return APK路径
     */
    static std::string getApkPathFromContext(JNIEnv* env, jobject context);

    /**
     * 直接验证当前应用签名（不经过PackageManager）
     * @param expectedSignature 预期签名
     * @return 是否匹配
     */
    static bool verifySignatureDirect(const std::string& expectedSignature);

    /**
     * 解析APK中的签名证书
     * @param apkPath APK路径
     * @return 证书数据
     */
    static std::vector<uint8_t> extractSignatureCertificate(const std::string& apkPath);

private:
    /**
     * 解析ZIP格式的APK文件
     */
    static bool parseZipFile(const std::string& apkPath,
                             std::vector<uint8_t>& certData);

    /**
     * 查找APK中的签名相关文件
     * Android签名相关文件位于 META-INF/ 目录下：
     * - META-INF/CERT.RSA (或 CERT.DSA, CERT.SF)
     * - META-INF/CERT.SF
     * - META-INF/MANIFEST.MF
     *
     * APK Signature Scheme v2/v3:
     * - 签名数据位于APK文件的专门区块中（ZIP文件的Central Directory之前）
     */
    static bool findSignatureBlock(const std::string& apkPath,
                                   std::vector<uint8_t>& signatureBlock);

    /**
     * 解析PKCS7签名块，提取证书
     */
    static bool parsePkcs7Signature(const std::vector<uint8_t>& data,
                                    std::vector<uint8_t>& certificate);

    /**
     * 解析APK Signature Scheme v2/v3
     * Android 7.0+ 使用新的签名方案
     */
    static bool parseApkSignatureSchemeV2(const std::vector<uint8_t>& block,
                                          std::vector<uint8_t>& certificate);

    /**
     * 解析APK Signature Scheme v3
     * Android 9.0+ 使用v3签名方案
     */
    static bool parseApkSignatureSchemeV3(const std::vector<uint8_t>& block,
                                          std::vector<uint8_t>& certificate);

    /**
     * 解析ASN.1 DER编码的证书
     */
    static bool parseDerCertificate(const std::vector<uint8_t>& certData,
                                    std::vector<uint8_t>& publicKey);

    /**
     * 读取文件内容
     */
    static std::vector<uint8_t> readFileContent(const std::string& path);

    /**
     * 计算SHA-256哈希
     */
    static std::string sha256Hash(const std::vector<uint8_t>& data);

    /**
     * 字节数组转十六进制字符串
     */
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);

    // ZIP文件结构常量
    static constexpr uint32_t ZIP_LOCAL_FILE_HEADER_SIG = 0x04034b50;
    static constexpr uint32_t ZIP_CENTRAL_DIR_SIG = 0x02014b50;
    static constexpr uint32_t ZIP_END_CENTRAL_DIR_SIG = 0x06054b50;

    // APK Signing Block常量
    static constexpr uint32_t APK_SIG_BLOCK_MAGIC_LO = 0x3234206b;  // "k2 3"
    static constexpr uint32_t APK_SIG_BLOCK_MAGIC_HI = 0x61734172;  // "rAs"
    static constexpr uint32_t APK_SIG_BLOCK_ID_V2 = 0x7109871a;
    static constexpr uint32_t APK_SIG_BLOCK_ID_V3 = 0xf05368c0;
};

/**
 * 安全签名验证器（不依赖Java层）
 */
class SecureSignatureVerifier {
public:
    /**
     * 安全验证签名（三种方式结合）
     * 1. 直接解析APK文件
     * 2. 通过PackageManager验证（作为对比）
     * 3. 比较两者结果是否一致
     *
     * @param env JNI环境
     * @param context 应用Context
     * @param expectedSignature 预期签名
     * @return 是否验证通过
     */
    static bool verifySignatureSecure(JNIEnv* env, jobject context,
                                       const std::string& expectedSignature);

    /**
     * 检测PackageManager是否被Hook
     * 如果直接解析APK和通过PackageManager获取的签名不一致，
     * 说明PackageManager可能被Hook
     *
     * @param env JNI环境
     * @param context 应用Context
     * @return 是否检测到Hook
     */
    static bool detectPackageManagerHook(JNIEnv* env, jobject context);

    /**
     * 获取签名验证结果详情
     */
    struct VerificationResult {
        std::string apkDirectSignature;     // 直接解析APK获取的签名
        std::string pmSignature;            // 通过PackageManager获取的签名
        bool signaturesMatch;               // 两个签名是否一致
        bool apkSignatureValid;             // APK签名是否匹配预期
        bool pmSignatureValid;              // PM签名是否匹配预期
        bool possibleHookDetected;          // 是否检测到可能的Hook
        std::string errorMessage;           // 错误信息
    };

    /**
     * 获取详细验证结果
     */
    static VerificationResult getDetailedResult(JNIEnv* env, jobject context,
                                                  const std::string& expectedSignature);
};

} // namespace security

#endif // APK_PARSER_H