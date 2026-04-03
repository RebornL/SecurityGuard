/**
 * APK签名解析器实现
 *
 * 直接在Native层解析APK文件获取签名，绕过Java层PackageManager
 * 仅支持 APK Signature Scheme V2/V3 (不支持 V1/JAR 签名)
 */

#include "apk_parser.h"
#include "security_guard.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#ifdef USE_FALLBACK_HASH
#include "sha256_fallback.h"
#else
#include <openssl/sha.h>
#endif

namespace security {

// ==================== 辅助函数 ====================

/**
 * 从 /proc/self/maps 获取真实的APK路径
 * 绕过NPatch对sourceDir的Hook
 */
static std::string getRealApkPathFromProcMaps() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return "";
    }

    char line[1024];
    std::vector<std::string> foundPaths;
    int lineCount = 0;

    while (fgets(line, sizeof(line), maps)) {
        lineCount++;
        std::string lineStr(line);

        // 查找 base.apk
        size_t pos = lineStr.find("base.apk");
        if (pos != std::string::npos) {
            // 提取路径
            size_t pathStart = lineStr.find('/');
            if (pathStart != std::string::npos) {
                std::string path = lineStr.substr(pathStart);
                // 去除尾部空白
                while (!path.empty() && (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
                    path.pop_back();
                }
                // 截取到 base.apk 结束
                pos = path.find("base.apk");
                if (pos != std::string::npos) {
                    path = path.substr(0, pos + 8); // 8 = strlen("base.apk")
                    foundPaths.push_back(path);
                    LOGD("Found APK in maps: %s", path.c_str());
                }
            }
        }
    }

    fclose(maps);
    LOGI("Scanned %d lines in /proc/self/maps, found %zu APK paths", lineCount, foundPaths.size());

    // 优先返回非NPatch缓存的路径
    for (const auto& path : foundPaths) {
        if (path.find("/cache/npatch/") == std::string::npos) {
            // 检查文件是否存在
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                LOGI("Selected real APK path from maps: %s", path.c_str());
                return path;
            }
        }
    }

    // 如果只有NPatch缓存路径，也返回
    if (!foundPaths.empty()) {
        LOGW("Only NPatch cache path found: %s", foundPaths[0].c_str());
        return foundPaths[0];
    }

    return "";
}

/**
 * 安全读取文件内容
 */
static std::vector<uint8_t> safeReadFile(const std::string& path, size_t maxSize = 100 * 1024 * 1024) {
    std::vector<uint8_t> content;

    if (path.empty()) {
        LOGE("File path is empty");
        return content;
    }

    FILE* file = fopen(path.c_str(), "rb");
    if (!file) {
        LOGE("Failed to open file: %s (errno: %d)", path.c_str(), errno);
        return content;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize <= 0 || fileSize > (long)maxSize) {
        LOGE("Invalid file size: %ld (max: %zu)", fileSize, maxSize);
        fclose(file);
        return content;
    }

    content.resize(fileSize);
    size_t bytesRead = fread(content.data(), 1, fileSize, file);
    fclose(file);

    if (bytesRead != (size_t)fileSize) {
        LOGE("Read mismatch: expected %ld, got %zu", fileSize, bytesRead);
        content.clear();
        return content;
    }

    LOGI("Successfully read %zu bytes from %s", bytesRead, path.c_str());
    return content;
}

/**
 * 小端序读取 uint16
 */
static inline uint16_t readU16(const uint8_t* data, size_t offset) {
    return data[offset] | (data[offset + 1] << 8);
}

/**
 * 小端序读取 uint32
 */
static inline uint32_t readU32(const uint8_t* data, size_t offset) {
    return data[offset] | (data[offset + 1] << 8) |
           (data[offset + 2] << 16) | (data[offset + 3] << 24);
}

/**
 * 小端序读取 uint64
 */
static inline uint64_t readU64(const uint8_t* data, size_t offset) {
    return (uint64_t)data[offset] |
           ((uint64_t)data[offset + 1] << 8) |
           ((uint64_t)data[offset + 2] << 16) |
           ((uint64_t)data[offset + 3] << 24) |
           ((uint64_t)data[offset + 4] << 32) |
           ((uint64_t)data[offset + 5] << 40) |
           ((uint64_t)data[offset + 6] << 48) |
           ((uint64_t)data[offset + 7] << 56);
}

// ==================== ApkSignatureParser实现 ====================

std::string ApkSignatureParser::getApkPathFromContext(JNIEnv* env, jobject context) {
    if (!env || !context) {
        LOGE("Invalid parameters for getApkPathFromContext");
        return "";
    }

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    // 首先尝试从 /proc/self/maps 获取真实APK路径（绕过NPatch Hook）
    std::string realApkPath = getRealApkPathFromProcMaps();
    if (!realApkPath.empty() && realApkPath.find("/cache/npatch/") == std::string::npos) {
        LOGI("Got real APK path from /proc/self/maps: %s", realApkPath.c_str());
        return realApkPath;
    }

    // 回退到 sourceDir（可能被NPatch Hook）
    try {
        jclass contextClass = env->GetObjectClass(context);
        if (!contextClass) {
            LOGE("Failed to get context class");
            return realApkPath; // 返回proc/maps的结果
        }

        // 方法1: 直接获取 sourceDir
        jmethodID getApplicationInfo = env->GetMethodID(contextClass, "getApplicationInfo",
                                                         "()Landroid/content/pm/ApplicationInfo;");
        if (!getApplicationInfo) {
            env->DeleteLocalRef(contextClass);
            return realApkPath;
        }

        jobject applicationInfo = env->CallObjectMethod(context, getApplicationInfo);
        if (!applicationInfo) {
            env->DeleteLocalRef(contextClass);
            return realApkPath;
        }

        jclass appInfoClass = env->GetObjectClass(applicationInfo);
        jfieldID sourceDirField = env->GetFieldID(appInfoClass, "sourceDir", "Ljava/lang/String;");

        if (sourceDirField) {
            jstring sourceDir = (jstring)env->GetObjectField(applicationInfo, sourceDirField);
            if (sourceDir) {
                const char* pathStr = env->GetStringUTFChars(sourceDir, nullptr);
                std::string apkPath(pathStr);
                env->ReleaseStringUTFChars(sourceDir, pathStr);

                env->DeleteLocalRef(sourceDir);
                env->DeleteLocalRef(appInfoClass);
                env->DeleteLocalRef(applicationInfo);
                env->DeleteLocalRef(contextClass);

                if (!apkPath.empty()) {
                    LOGI("Got APK path from Context sourceDir: %s", apkPath.c_str());
                    // 如果proc/maps找到了非NPatch路径，优先使用
                    if (!realApkPath.empty() && realApkPath.find("/cache/npatch/") == std::string::npos) {
                        return realApkPath;
                    }
                    return apkPath;
                }
            }
        }

        env->DeleteLocalRef(appInfoClass);
        env->DeleteLocalRef(applicationInfo);
        env->DeleteLocalRef(contextClass);

    } catch (...) {
        LOGE("Exception in getApkPathFromContext");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }

    return realApkPath;
}

std::string ApkSignatureParser::getSelfApkPath() {
    // 方法0: 首先尝试从 /proc/self/maps 获取真实APK路径（绕过NPatch）
    std::string mapsPath = getRealApkPathFromProcMaps();
    if (!mapsPath.empty() && mapsPath.find("/cache/npatch/") == std::string::npos) {
        LOGI("Got real APK path from /proc/self/maps: %s", mapsPath.c_str());
        return mapsPath;
    }

    // 方法1: 读取 /proc/self/cmdline 获取包名
    char packageName[256] = {0};
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fgets(packageName, sizeof(packageName), cmdline);
        fclose(cmdline);
    }

    std::string pkgName(packageName);
    // 去除尾部空白
    while (!pkgName.empty() && (pkgName.back() == '\n' || pkgName.back() == '\r' || pkgName.back() == ' ')) {
        pkgName.pop_back();
    }

    LOGI("Package name from cmdline: %s", pkgName.c_str());

    if (!pkgName.empty()) {
        // 方法2: 搜索 /data/app 目录
        DIR* appDir = opendir("/data/app");
        if (appDir) {
            struct dirent* entry;
            while ((entry = readdir(appDir)) != nullptr) {
                std::string dirName(entry->d_name);

                // 检查目录名是否包含包名
                if (dirName.find(pkgName) != std::string::npos) {
                    std::string basePath = std::string("/data/app/") + dirName;

                    // 检查 base.apk
                    std::string apkPath = basePath + "/base.apk";
                    struct stat st;
                    if (stat(apkPath.c_str(), &st) == 0) {
                        closedir(appDir);
                        LOGI("Found APK: %s", apkPath.c_str());
                        return apkPath;
                    }
                }
            }
            closedir(appDir);
        }

        // 方法3: 尝试常见路径格式
        std::vector<std::string> possiblePaths = {
            "/data/app/" + pkgName + "/base.apk",
            "/data/app/" + pkgName + "-1/base.apk",
            "/data/app/" + pkgName + "-2/base.apk",
            "/data/app/" + pkgName + ".apk",
            "/data/app-private/" + pkgName + ".apk",
            "/system/app/" + pkgName + "/" + pkgName + ".apk",
            "/system/priv-app/" + pkgName + "/" + pkgName + ".apk",
        };

        for (const auto& path : possiblePaths) {
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                LOGI("Found APK at fallback path: %s", path.c_str());
                return path;
            }
        }
    }

    // 如果所有方法都失败，返回 /proc/self/maps 的结果（即使是NPatch缓存）
    if (!mapsPath.empty()) {
        LOGW("Returning /proc/self/maps result as fallback: %s", mapsPath.c_str());
        return mapsPath;
    }

    LOGE("Failed to find APK path");
    return "";
}

std::vector<uint8_t> ApkSignatureParser::readFileContent(const std::string& path) {
    return safeReadFile(path);
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

/**
 * 查找 ZIP End of Central Directory
 */
static size_t findEocd(const std::vector<uint8_t>& apkData) {
    size_t fileSize = apkData.size();

    // EOCD 最小22字节，最大可以有65535字节的注释
    size_t searchStart = fileSize > 65557 ? fileSize - 65557 : 0;
    if (searchStart < 22) searchStart = 0;
    else searchStart = fileSize - 22;

    // 从后向前搜索
    for (size_t i = fileSize - 22; i >= searchStart && i > 0; i--) {
        if (apkData[i] == 0x50 && apkData[i+1] == 0x4b &&
            apkData[i+2] == 0x05 && apkData[i+3] == 0x06) {
            LOGI("Found EOCD at offset: %zu", i);
            return i;
        }
    }

    // 检查开头
    if (apkData.size() >= 22 &&
        apkData[0] == 0x50 && apkData[1] == 0x4b &&
        apkData[2] == 0x05 && apkData[3] == 0x06) {
        LOGI("Found EOCD at offset: 0");
        return 0;
    }

    LOGE("EOCD not found");
    return 0;
}

/**
 * 解析 APK Signing Block (V2/V3签名)
 */
static bool parseApkSigningBlock(const std::vector<uint8_t>& apkData, size_t cdOffset,
                                  std::vector<uint8_t>& signatureData) {
    // APK Signing Block 位于 Central Directory 之前
    // 格式: [blockSize1(8)] [signing data] [blockSize2(8)] [magic(16)]
    //                                     ↑               ↑
    //                              cdOffset-24       cdOffset-16

    if (cdOffset < 32) {
        LOGE("Central Directory offset too small: %zu", cdOffset);
        return false;
    }

    // 检查 magic (APK Sig Block 42)
    size_t magicOffset = cdOffset - 16;
    const uint8_t* magic = &apkData[magicOffset];

    // Magic: "APK Sig Block 42" in little endian
    const uint8_t expectedMagic[] = {
        0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
    };

    if (memcmp(magic, expectedMagic, 16) != 0) {
        LOGE("APK Signing Block magic mismatch");
        return false;
    }

    LOGI("Found APK Signing Block");

    // 读取 block size (uint64, 位于 blockSize2 位置)
    size_t blockSizeOffset = cdOffset - 24;
    uint64_t blockSize = readU64(apkData.data(), blockSizeOffset);

    LOGI("APK Signing Block size: %llu", (unsigned long long)blockSize);

    if (blockSize == 0 || blockSize > cdOffset) {
        LOGE("Invalid block size");
        return false;
    }

    // 解析 key-value pairs
    // APK Signing Block结构：
    // [blockSize1(8)] [signing data] [blockSize2(8)] [magic(16)]
    //       ↑              ↑              ↑             ↑
    //  cdOffset-bs-8   cdOffset-bs    cdOffset-24    cdOffset-16
    // 
    // blockSize = signing data + blockSize2(8) + magic(16) = signing data + 24
    
    size_t blockStart = cdOffset - blockSize - 8;
    
    // 读取并验证blockSize1
    uint64_t blockSize1 = readU64(apkData.data(), blockStart);
    if (blockSize1 != blockSize) {
        LOGE("Block size mismatch: size1=%llu, size2=%llu", (unsigned long long)blockSize1, (unsigned long long)blockSize);
        return false;
    }

    // 跳过blockSize1，开始解析pairs (位于 cdOffset - blockSize)
    // signing data 内部格式：
    // repeated ID-value pairs:
    //     uint64: pair_size (excluding this field)
    //     uint32: ID
    //     (pair_size - 4) bytes: value
    size_t pos = blockStart + 8;
    size_t endOfPairs = cdOffset - 24;

    LOGI("Signing data: start=%zu, end=%zu, blockSize=%llu", pos, endOfPairs, (unsigned long long)blockSize);

    while (pos + 12 <= endOfPairs) {  // 8 (size) + 4 (id) minimum
        // pair size 是 uint64
        uint64_t pairSize = readU64(apkData.data(), pos);
        pos += 8;

        if (pos + 4 > endOfPairs) break;

        uint32_t pairId = readU32(apkData.data(), pos);
        pos += 4;

        LOGD("Signing Block Pair ID: 0x%08x, size: %llu", pairId, (unsigned long long)pairSize);

        // V2签名块ID: 0x7109871a
        // V3签名块ID: 0xf05368c0
        if (pairId == 0x7109871a || pairId == 0xf05368c0) {
            size_t dataSize = (size_t)(pairSize - 4);
            if (pos + dataSize <= apkData.size()) {
                signatureData.assign(apkData.begin() + pos, apkData.begin() + pos + dataSize);
                LOGI("Extracted signature block (ID: 0x%08x), size: %zu", pairId, signatureData.size());
                return true;
            }
        }

        pos += (size_t)(pairSize - 4);
    }

    LOGE("No V2/V3 signature block found");
    return false;
}

/**
 * 从 V2/V3 签名块中提取证书
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
static bool extractCertificateFromV2Block(const std::vector<uint8_t>& block,
                                           std::vector<uint8_t>& certificate) {
    if (block.size() < 12) {
        LOGE("Block too small: %zu", block.size());
        return false;
    }

    size_t pos = 0;
    LOGI("=== Starting V2 block parsing, total size: %zu ===", block.size());

    // signers 数组: 4字节长度 + 数据
    uint32_t signersSize = readU32(block.data(), pos);
    pos += 4;
    LOGD("Signers sequence size: %u", signersSize);

    if (pos + 4 > block.size()) {
        LOGE("Block too small for signer");
        return false;
    }

    // signer: 4字节长度 + 数据
    uint32_t signerSize = readU32(block.data(), pos);
    size_t signerStart = pos;
    pos += 4;
    LOGD("Signer size: %u, starts at: %zu", signerSize, signerStart);

    if (pos + 4 > block.size()) {
        LOGE("Block too small for signed_data");
        return false;
    }

    // signed_data: 4字节长度 + 数据
    uint32_t signedDataSize = readU32(block.data(), pos);
    size_t signedDataStart = pos;
    pos += 4;
    LOGD("SignedData size: %u, starts at: %zu", signedDataSize, signedDataStart);

    // 现在解析 signed_data 内部结构
    // digests: 4字节长度 + 数据
    if (pos + 4 > block.size()) {
        LOGE("Block too small for digests size");
        return false;
    }
    uint32_t digestsSize = readU32(block.data(), pos);
    pos += 4 + digestsSize;  // 跳过 digests
    LOGD("Digests size: %u, now at pos: %zu", digestsSize, pos);

    // certificates: 4字节长度 + 数据
    if (pos + 4 > block.size()) {
        LOGE("Block too small for certificates size");
        return false;
    }
    uint32_t certsArraySize = readU32(block.data(), pos);
    size_t certsArrayStart = pos;
    pos += 4;
    LOGD("Certificates array size: %u, starts at: %zu", certsArraySize, certsArrayStart);

    // 第一个 certificate: 4字节长度 + 数据
    if (pos + 4 > block.size()) {
        LOGE("Block too small for certificate size");
        return false;
    }
    uint32_t certSize = readU32(block.data(), pos);
    pos += 4;
    LOGD("First certificate size: %u", certSize);

    if (pos + certSize > block.size()) {
        LOGE("Certificate data exceeds block, pos=%zu, certSize=%u, blockLen=%zu",
             pos, certSize, block.size());
        return false;
    }

    certificate.assign(block.begin() + pos, block.begin() + pos + certSize);
    LOGI("Certificate extracted successfully, %u bytes", certSize);

    // 打印证书的前32字节用于调试
    char hexBuf[128] = {0};
    for (size_t i = 0; i < (size_t)std::min(32, (int)certSize); i++) {
        snprintf(hexBuf + i*2, 3, "%02x", certificate[i]);
    }
    LOGD("Certificate first 32 bytes: %s", hexBuf);

    return true;
}

bool ApkSignatureParser::findSignatureBlock(const std::string& apkPath,
                                             std::vector<uint8_t>& signatureBlock) {
    std::vector<uint8_t> apkData = readFileContent(apkPath);
    if (apkData.empty()) {
        LOGE("Failed to read APK: %s", apkPath.c_str());
        return false;
    }

    LOGI("APK size: %zu bytes", apkData.size());

    // Step 1: 查找 EOCD
    size_t eocdOffset = findEocd(apkData);
    if (eocdOffset == 0 && apkData.size() >= 22) {
        // 可能文件开头就是EOCD（空ZIP）
        if (!(apkData[0] == 0x50 && apkData[1] == 0x4b &&
              apkData[2] == 0x05 && apkData[3] == 0x06)) {
            LOGE("Failed to find EOCD - no V2 signature available");
            return false;
        }
    }

    // Step 2: 获取 Central Directory 偏移
    uint32_t cdOffset = 0;
    if (eocdOffset + 16 + 4 <= apkData.size()) {
        cdOffset = readU32(apkData.data(), eocdOffset + 16);
    }

    LOGI("Central Directory offset: %u", cdOffset);

    // Step 3: 解析 APK Signing Block (V2/V3 only)
    if (cdOffset < 32) {
        LOGE("No APK Signing Block found (APK may only have V1 signature)");
        return false;
    }

    std::vector<uint8_t> signingBlockData;
    if (!parseApkSigningBlock(apkData, cdOffset, signingBlockData)) {
        LOGE("Failed to parse APK Signing Block");
        return false;
    }

    if (!extractCertificateFromV2Block(signingBlockData, signatureBlock)) {
        LOGE("Failed to extract certificate from V2/V3 block");
        return false;
    }

    LOGI("Successfully extracted V2/V3 signature");
    return true;
}

bool ApkSignatureParser::parseZipFile(const std::string& apkPath,
                                       std::vector<uint8_t>& certData) {
    return findSignatureBlock(apkPath, certData);
}

bool ApkSignatureParser::parsePkcs7Signature(const std::vector<uint8_t>& data,
                                              std::vector<uint8_t>& certificate) {
    // V1签名已移除，此函数仅用于兼容性保留
    certificate = data;
    return !certificate.empty();
}

bool ApkSignatureParser::parseDerCertificate(const std::vector<uint8_t>& certData,
                                              std::vector<uint8_t>& publicKey) {
    publicKey = certData;
    return true;
}

std::vector<uint8_t> ApkSignatureParser::extractSignatureCertificate(const std::string& apkPath) {
    std::vector<uint8_t> signatureBlock;
    if (!findSignatureBlock(apkPath, signatureBlock)) {
        LOGE("Failed to find signature block in: %s", apkPath.c_str());
        return {};
    }
    return signatureBlock;
}

bool ApkSignatureParser::parseApkSignatureSchemeV2(const std::vector<uint8_t>& block,
                                                    std::vector<uint8_t>& certificate) {
    return extractCertificateFromV2Block(block, certificate);
}

bool ApkSignatureParser::parseApkSignatureSchemeV3(const std::vector<uint8_t>& block,
                                                    std::vector<uint8_t>& certificate) {
    return extractCertificateFromV2Block(block, certificate);
}

std::string ApkSignatureParser::getSignatureFromApk(const std::string& apkPath) {
    if (apkPath.empty()) {
        LOGE("APK path is empty");
        return "";
    }

    // 检查文件是否存在
    struct stat st;
    if (stat(apkPath.c_str(), &st) != 0) {
        LOGE("APK file not found: %s (errno: %d)", apkPath.c_str(), errno);
        return "";
    }

    LOGI("Parsing APK: %s", apkPath.c_str());

    std::vector<uint8_t> certificate = extractSignatureCertificate(apkPath);
    if (certificate.empty()) {
        LOGE("Failed to extract certificate from APK: %s", apkPath.c_str());
        return "";
    }

    // 计算证书的 SHA-256 哈希
    std::string hash = sha256Hash(certificate);
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

    if (!result.signaturesMatch) {
        LOGE("SECURITY WARNING: Signature mismatch detected!");
        LOGE("APK direct: %s", result.apkDirectSignature.c_str());
        LOGE("PM result:  %s", result.pmSignature.c_str());
    }

    return result.apkSignatureValid;
}

bool SecureSignatureVerifier::detectPackageManagerHook(JNIEnv* env, jobject context) {
    VerificationResult result = getDetailedResult(env, context, "");

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

    // 方法1: 通过 Context 获取 APK 路径
    std::string apkPath = ApkSignatureParser::getApkPathFromContext(env, context);

    // 方法2: 如果失败，尝试手动查找
    if (apkPath.empty()) {
        LOGW("Failed to get APK path from Context, trying fallback");
        apkPath = ApkSignatureParser::getSelfApkPath();
    }

    // 方法3: 直接解析 APK 获取签名
    if (!apkPath.empty()) {
        result.apkDirectSignature = ApkSignatureParser::getSignatureFromApk(apkPath);
        if (!result.apkDirectSignature.empty()) {
            LOGI("Successfully got signature from APK: %s", result.apkDirectSignature.c_str());
        } else {
            LOGE("Failed to get signature from APK: %s", apkPath.c_str());
        }
    } else {
        LOGE("Failed to get APK path");
    }

    // 方法4: 通过 PackageManager 获取签名（可能被Hook）
    result.pmSignature = SignatureVerifier::getSignature(env, context);
    if (!result.pmSignature.empty()) {
        LOGI("Got signature from PackageManager: %s", result.pmSignature.c_str());
    }

    // 比较签名
    std::string apkLower = result.apkDirectSignature;
    std::string pmLower = result.pmSignature;
    std::transform(apkLower.begin(), apkLower.end(), apkLower.begin(), ::tolower);
    std::transform(pmLower.begin(), pmLower.end(), pmLower.begin(), ::tolower);

    result.signaturesMatch = (!apkLower.empty() && !pmLower.empty() && apkLower == pmLower);

    // 验证预期签名
    if (!expectedSignature.empty()) {
        std::string expectedLower = expectedSignature;
        std::transform(expectedLower.begin(), expectedLower.end(), expectedLower.begin(), ::tolower);

        result.apkSignatureValid = (apkLower == expectedLower);
        result.pmSignatureValid = (pmLower == expectedLower);
    }

    // 检测可能的Hook
    result.possibleHookDetected = (!apkLower.empty() && !pmLower.empty() && !result.signaturesMatch);

    // 设置错误信息
    if (result.apkDirectSignature.empty()) {
        result.errorMessage = "Failed to directly parse APK signature";
    } else if (!result.signaturesMatch) {
        result.errorMessage = "Signature mismatch: PackageManager may be hooked";
    }

    return result;
}

} // namespace security