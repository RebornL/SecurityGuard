/**
 * APK签名解析器实现
 *
 * 直接在Native层解析APK文件获取签名，绕过Java层PackageManager
 */

#include "apk_parser.h"
#include "security_guard.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <sys/stat.h>

#ifdef USE_FALLBACK_HASH
#include "sha256_fallback.h"
#else
#include <openssl/sha.h>
#endif

namespace security {

// ==================== ApkSignatureParser实现 ====================

std::string ApkSignatureParser::getSelfApkPath() {
    // 方法1: 从/proc/self/exe获取（某些情况下可行）
    // 方法2: 解析/proc/self/cmdline获取包名，然后查找APK路径

    char cmdline[256] = {0};
    FILE* cmdlineFile = fopen("/proc/self/cmdline", "r");
    if (cmdlineFile) {
        fgets(cmdline, sizeof(cmdline), cmdlineFile);
        fclose(cmdlineFile);
    }

    // 根据包名构建APK路径
    std::string packageName(cmdline);
    if (!packageName.empty()) {
        // 常见APK路径
        std::vector<std::string> possiblePaths = {
            "/data/app/" + packageName + "-1/base.apk",
            "/data/app/" + packageName + "-2/base.apk",
            "/data/app/" + packageName + "/base.apk",
            "/data/app/" + packageName + "-1.apk",
            "/data/app/" + packageName + "-2.apk",
            "/data/app/" + packageName + ".apk",
            "/data/app-private/" + packageName + ".apk",
            "/system/app/" + packageName + ".apk",
            "/system/priv-app/" + packageName + ".apk"
        };

        for (const auto& path : possiblePaths) {
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                LOGI("Found APK path: %s", path.c_str());
                return path;
            }
        }
    }

    // 尝试从环境变量获取（测试时可能可用）
    // 或从maps文件解析

    LOGE("Failed to find APK path");
    return "";
}

std::vector<uint8_t> ApkSignatureParser::readFileContent(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        LOGE("Failed to open file: %s", path.c_str());
        return {};
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> content(size);
    file.read(reinterpret_cast<char*>(content.data()), size);
    file.close();

    return content;
}

std::string ApkSignatureParser::bytesToHex(const std::vector<uint8_t>& bytes) {
    static const char hexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        result.push_back(hexChars[(byte >> 4) & 0x0F]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    return result;
}

std::string ApkSignatureParser::sha256Hash(const std::vector<uint8_t>& data) {
#ifdef USE_FALLBACK_HASH
    return Sha256Fallback::hash(data);
#else
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return bytesToHex(hash);
#endif
}

bool ApkSignatureParser::findSignatureBlock(const std::string& apkPath,
                                             std::vector<uint8_t>& signatureBlock) {
    std::vector<uint8_t> apkData = readFileContent(apkPath);
    if (apkData.empty()) {
        LOGE("Failed to read APK data");
        return false;
    }

    size_t fileSize = apkData.size();

    // 首先尝试解析APK Signature Scheme V2/V3
    // APK Signing Block位于ZIP Central Directory之前

    // 查找ZIP End of Central Directory (EOCD)
    // EOCD签名: 0x06054b50
    size_t eocdOffset = 0;
    for (size_t i = fileSize - 22; i >= 0 && i > fileSize - 65557; i--) {
        if (apkData[i] == 0x50 && apkData[i+1] == 0x4b &&
            apkData[i+2] == 0x05 && apkData[i+3] == 0x06) {
            eocdOffset = i;
            break;
        }
    }

    if (eocdOffset == 0) {
        LOGE("Failed to find EOCD in APK");
        // 回退到V1签名方案（META-INF目录）
        return parseZipFile(apkPath, signatureBlock);
    }

    // 从EOCD获取Central Directory的偏移量
    // EOCD结构: 4字节签名 + ... + 4字节CD偏移量(从第16字节开始)
    uint32_t cdOffset = 0;
    if (eocdOffset + 16 + 4 <= fileSize) {
        cdOffset = apkData[eocdOffset + 16] |
                   (apkData[eocdOffset + 17] << 8) |
                   (apkData[eocdOffset + 18] << 16) |
                   (apkData[eocdOffset + 19] << 24);
    }

    LOGD("EOCD offset: %zu, CD offset: %u", eocdOffset, cdOffset);

    // 检查是否存在APK Signing Block
    // APK Signing Block紧接在Central Directory之前
    // 结尾有16字节的magic: "APK Sig Block 42" (实际上是小端的数字)

    if (cdOffset >= 24) {
        // 检查APK Signing Block Magic
        size_t magicOffset = cdOffset - 24;
        uint32_t magicLo = apkData[magicOffset] |
                           (apkData[magicOffset + 1] << 8) |
                           (apkData[magicOffset + 2] << 16) |
                           (apkData[magicOffset + 3] << 24);
        uint32_t magicHi = apkData[magicOffset + 4] |
                           (apkData[magicOffset + 5] << 8) |
                           (apkData[magicOffset + 6] << 16) |
                           (apkData[magicOffset + 7] << 24);

        if (magicLo == APK_SIG_BLOCK_MAGIC_LO && magicHi == APK_SIG_BLOCK_MAGIC_HI) {
            LOGI("Found APK Signing Block V2/V3");

            // 读取APK Signing Block大小
            size_t blockSizeOffset = cdOffset - 8;
            uint32_t blockSize = apkData[blockSizeOffset] |
                                 (apkData[blockSizeOffset + 1] << 8) |
                                 (apkData[blockSizeOffset + 2] << 16) |
                                 (apkData[blockSizeOffset + 3] << 24);

            if (blockSize > 0 && cdOffset >= blockSize + 8) {
                // 解析Signing Block中的key-value对
                size_t blockStart = cdOffset - blockSize - 8;
                size_t pos = blockStart;

                while (pos < cdOffset - 24) {
                    uint32_t pairSize = apkData[pos] |
                                       (apkData[pos + 1] << 8) |
                                       (apkData[pos + 2] << 16) |
                                       (apkData[pos + 3] << 24);
                    pos += 4;

                    if (pos + 4 > cdOffset - 24) break;

                    uint32_t pairId = apkData[pos] |
                                     (apkData[pos + 1] << 8) |
                                     (apkData[pos + 2] << 16) |
                                     (apkData[pos + 3] << 24);
                    pos += 4;

                    if (pairId == APK_SIG_BLOCK_ID_V2 || pairId == APK_SIG_BLOCK_ID_V3) {
                        // 提取签名块数据
                        uint32_t signersSize = apkData[pos] |
                                              (apkData[pos + 1] << 8) |
                                              (apkData[pos + 2] << 16) |
                                              (apkData[pos + 3] << 24);
                        pos += 4;

                        // 解析signers
                        // 这里简化处理，直接提取整个块
                        signatureBlock.clear();
                        for (uint32_t i = 0; i < pairSize - 4 && pos + i < fileSize; i++) {
                            signatureBlock.push_back(apkData[pos + i]);
                        }

                        LOGI("Extracted signature block, size: %zu", signatureBlock.size());
                        return true;
                    }

                    pos += pairSize - 4;  // 跳过value部分
                }
            }
        }
    }

    // V2/V3签名块未找到，尝试V1签名（META-INF）
    LOGI("V2/V3 signing block not found, trying V1 signature");
    return parseZipFile(apkPath, signatureBlock);
}

bool ApkSignatureParser::parseZipFile(const std::string& apkPath,
                                       std::vector<uint8_t>& certData) {
    std::vector<uint8_t> apkData = readFileContent(apkPath);
    if (apkData.empty()) return false;

    size_t fileSize = apkData.size();
    size_t pos = 0;

    // 遍历ZIP文件中的Local File Header
    while (pos < fileSize) {
        // 检查Local File Header签名
        if (pos + 30 > fileSize) break;

        uint32_t sig = apkData[pos] |
                      (apkData[pos + 1] << 8) |
                      (apkData[pos + 2] << 16) |
                      (apkData[pos + 3] << 24);

        if (sig != ZIP_LOCAL_FILE_HEADER_SIG) break;

        // 解析Local File Header
        uint16_t nameLen = apkData[pos + 26] | (apkData[pos + 27] << 8);
        uint16_t extraLen = apkData[pos + 28] | (apkData[pos + 29] << 8);
        uint32_t compressedSize = apkData[pos + 18] |
                                 (apkData[pos + 19] << 8) |
                                 (apkData[pos + 20] << 16) |
                                 (apkData[pos + 21] << 24);

        // 获取文件名
        std::string fileName(reinterpret_cast<const char*>(apkData.data() + pos + 30), nameLen);

        // 查找META-INF/CERT.RSA 或 CERT.DSA
        if (fileName.find("META-INF/") != std::string::npos &&
            (fileName.find(".RSA") != std::string::npos ||
             fileName.find(".DSA") != std::string::npos ||
             fileName.find(".EC") != std::string::npos)) {

            LOGI("Found signature file: %s", fileName.c_str());

            // 提取文件内容
            size_t dataStart = pos + 30 + nameLen + extraLen;
            certData.clear();
            for (uint32_t i = 0; i < compressedSize && dataStart + i < fileSize; i++) {
                certData.push_back(apkData[dataStart + i]);
            }

            return parsePkcs7Signature(certData, certData);
        }

        // 移动到下一个文件
        pos += 30 + nameLen + extraLen + compressedSize;
    }

    LOGE("No signature file found in META-INF");
    return false;
}

bool ApkSignatureParser::parsePkcs7Signature(const std::vector<uint8_t>& data,
                                              std::vector<uint8_t>& certificate) {
    // 简化的PKCS7解析
    // 实际PKCS7格式较复杂，这里提取其中的证书部分

    // PKCS7 SignedData结构包含证书
    // 我们需要找到并提取X.509证书

    // 查找证书的OID和内容
    // X.509证书通常以特定的ASN.1序列开始

    for (size_t i = 0; i < data.size() - 10; i++) {
        // 查找证书序列标记 (0x30 0x82 或类似的)
        if (data[i] == 0x30 && data[i+1] >= 0x81 && data[i+1] <= 0x84) {
            // 可能是证书的开始
            // 需要进一步验证

            // 简化处理：假设找到的就是证书数据
            // 实际实现需要完整的ASN.1解析

            size_t certStart = i;
            size_t certLen = 0;

            if (data[i+1] == 0x82) {
                certLen = (data[i+2] << 8) | data[i+3];
                certLen += 4;  // 包括tag和length
            } else if (data[i+1] == 0x81) {
                certLen = data[i+2];
                certLen += 3;
            } else {
                certLen = data[i+1];
                certLen += 2;
            }

            if (certStart + certLen <= data.size()) {
                certificate.clear();
                for (size_t j = certStart; j < certStart + certLen; j++) {
                    certificate.push_back(data[j]);
                }
                LOGI("Extracted certificate, size: %zu", certificate.size());
                return true;
            }
        }
    }

    LOGE("Failed to parse PKCS7 signature");
    return false;
}

bool ApkSignatureParser::parseDerCertificate(const std::vector<uint8_t>& certData,
                                              std::vector<uint8_t>& publicKey) {
    // 解析DER编码的X.509证书，提取公钥
    // 证书结构：Certificate ::= SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }
    // TBSCertificate中包含subjectPublicKeyInfo

    // 简化实现：直接提取证书数据计算哈希
    // 完整实现需要ASN.1解析提取公钥

    publicKey = certData;  // 使用整个证书作为数据源
    return true;
}

std::vector<uint8_t> ApkSignatureParser::extractSignatureCertificate(const std::string& apkPath) {
    std::vector<uint8_t> signatureBlock;
    if (!findSignatureBlock(apkPath, signatureBlock)) {
        return {};
    }

    std::vector<uint8_t> certificate;
    // 尝试解析V2/V3签名
    if (parseApkSignatureSchemeV2(signatureBlock, certificate) ||
        parseApkSignatureSchemeV3(signatureBlock, certificate)) {
        return certificate;
    }

    // 回退到PKCS7/V1
    if (parsePkcs7Signature(signatureBlock, certificate)) {
        return certificate;
    }

    return {};
}

bool ApkSignatureParser::parseApkSignatureSchemeV2(const std::vector<uint8_t>& block,
                                                    std::vector<uint8_t>& certificate) {
    // APK Signature Scheme V2结构:
    // - signers: sequence of signer
    // - signer: signedData, signatures, publicKey

    if (block.size() < 4) return false;

    size_t pos = 0;

    // signers数组大小
    uint32_t signersSize = block[pos] |
                          (block[pos + 1] << 8) |
                          (block[pos + 2] << 16) |
                          (block[pos + 3] << 24);
    pos += 4;

    // 解析第一个signer
    if (pos + 4 > block.size()) return false;

    uint32_t signerSize = block[pos] |
                         (block[pos + 1] << 8) |
                         (block[pos + 2] << 16) |
                         (block[pos + 3] << 24);
    pos += 4;

    // signedData
    if (pos + 4 > block.size()) return false;
    uint32_t signedDataSize = block[pos] |
                             (block[pos + 1] << 8) |
                             (block[pos + 2] << 16) |
                             (block[pos + 3] << 24);
    pos += 4;

    // 跳过signedData中的digests
    if (pos + 4 > block.size()) return false;
    uint32_t digestsSize = block[pos] |
                          (block[pos + 1] << 8) |
                          (block[pos + 2] << 16) |
                          (block[pos + 3] << 24);
    pos += 4 + digestsSize;

    // 跳过certificates
    if (pos + 4 > block.size()) return false;
    uint32_t certsSize = block[pos] |
                        (block[pos + 1] << 8) |
                        (block[pos + 2] << 16) |
                        (block[pos + 3] << 24);
    pos += 4;

    // 提取第一个certificate
    if (pos + 4 > block.size()) return false;
    uint32_t certSize = block[pos] |
                       (block[pos + 1] << 8) |
                       (block[pos + 2] << 16) |
                       (block[pos + 3] << 24);
    pos += 4;

    if (pos + certSize > block.size()) return false;

    certificate.clear();
    for (uint32_t i = 0; i < certSize; i++) {
        certificate.push_back(block[pos + i]);
    }

    LOGI("V2 certificate extracted, size: %zu", certificate.size());
    return true;
}

bool ApkSignatureParser::parseApkSignatureSchemeV3(const std::vector<uint8_t>& block,
                                                    std::vector<uint8_t>& certificate) {
    // V3结构与V2类似，包含额外的minSdkVersion等字段
    // 使用相同的解析逻辑
    return parseApkSignatureSchemeV2(block, certificate);
}

std::string ApkSignatureParser::getSignatureFromApk(const std::string& apkPath) {
    std::vector<uint8_t> certificate = extractSignatureCertificate(apkPath);
    if (certificate.empty()) {
        LOGE("Failed to extract certificate from APK");
        return "";
    }

    std::vector<uint8_t> publicKey;
    if (!parseDerCertificate(certificate, publicKey)) {
        LOGE("Failed to parse certificate");
        return "";
    }

    // 计算证书/公钥的SHA-256哈希
    std::string hash = sha256Hash(publicKey);
    LOGI("Direct APK signature hash: %s", hash.c_str());
    return hash;
}

bool ApkSignatureParser::verifySignatureDirect(const std::string& expectedSignature) {
    std::string apkPath = getSelfApkPath();
    if (apkPath.empty()) {
        LOGE("Cannot find APK path");
        return false;
    }

    std::string currentSignature = getSignatureFromApk(apkPath);
    if (currentSignature.empty()) {
        LOGE("Failed to get signature from APK");
        return false;
    }

    std::string expectedLower = expectedSignature;
    std::string currentLower = currentSignature;
    std::transform(expectedLower.begin(), expectedLower.end(), expectedLower.begin(), ::tolower);
    std::transform(currentLower.begin(), currentLower.end(), currentLower.begin(), ::tolower);

    return expectedLower == currentLower;
}

// ==================== SecureSignatureVerifier实现 ====================

bool SecureSignatureVerifier::verifySignatureSecure(JNIEnv* env, jobject context,
                                                     const std::string& expectedSignature) {
    VerificationResult result = getDetailedResult(env, context, expectedSignature);

    // 关键判断逻辑：
    // 1. 如果两个签名不一致，说明PackageManager可能被Hook
    // 2. 只信任直接解析APK的结果（因为它不经过Java层）
    // 3. 如果直接解析失败，则拒绝通过（安全优先）

    if (!result.signaturesMatch) {
        LOGE("SECURITY WARNING: Signature mismatch detected!");
        LOGE("APK direct: %s", result.apkDirectSignature.c_str());
        LOGE("PM result:  %s", result.pmSignature.c_str());
        LOGE("This may indicate PackageManager is hooked by Xposed!");
    }

    // 只使用直接解析APK的结果进行验证
    // 因为这个方法不经过可能被Hook的Java层
    return result.apkSignatureValid;
}

bool SecureSignatureVerifier::detectPackageManagerHook(JNIEnv* env, jobject context) {
    VerificationResult result = getDetailedResult(env, context, "");

    // 如果直接解析APK成功，但与PackageManager结果不一致
    // 说明PackageManager可能被Hook
    if (!result.apkDirectSignature.empty() &&
        !result.pmSignature.empty() &&
        !result.signaturesMatch) {
        LOGW("PackageManager hook detected!");
        return true;
    }

    return false;
}

SecureSignatureVerifier::VerificationResult SecureSignatureVerifier::getDetailedResult(
        JNIEnv* env, jobject context, const std::string& expectedSignature) {

    VerificationResult result;

    // 方法1: 直接解析APK文件（不经过Java层，无法被Xposed Hook）
    std::string apkPath = ApkSignatureParser::getSelfApkPath();
    if (!apkPath.empty()) {
        result.apkDirectSignature = ApkSignatureParser::getSignatureFromApk(apkPath);
    }

    // 方法2: 通过PackageManager获取（可能被Xposed Hook）
    result.pmSignature = SignatureVerifier::getSignature(env, context);

    // 检查两个签名是否一致
    std::string apkLower = result.apkDirectSignature;
    std::string pmLower = result.pmSignature;
    std::transform(apkLower.begin(), apkLower.end(), apkLower.begin(), ::tolower);
    std::transform(pmLower.begin(), pmLower.end(), pmLower.begin(), ::tolower);

    result.signaturesMatch = (!apkLower.empty() && !pmLower.empty() && apkLower == pmLower);

    // 验证签名（使用期望签名）
    if (!expectedSignature.empty()) {
        std::string expectedLower = expectedSignature;
        std::transform(expectedLower.begin(), expectedLower.end(), expectedLower.begin(), ::tolower);

        result.apkSignatureValid = (apkLower == expectedLower);
        result.pmSignatureValid = (pmLower == expectedLower);
    }

    // 检测可能的Hook
    result.possibleHookDetected = (!apkLower.empty() && !pmLower.empty() && !result.signaturesMatch);

    // 错误信息
    if (result.apkDirectSignature.empty()) {
        result.errorMessage = "Failed to directly parse APK signature";
    } else if (!result.signaturesMatch) {
        result.errorMessage = "Signature mismatch: PM may be hooked";
    }

    return result;
}

} // namespace security