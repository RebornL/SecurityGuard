/**
 * 签名验证实现
 *
 * 提供两种签名获取方式：
 * 1. 直接解析APK文件（安全，不会被Hook）- 推荐使用
 * 2. 通过PackageManager获取（可能被Hook）- 仅用于对比检测
 */

#include "security_guard.h"
#include "apk_parser.h"

// 根据是否有OpenSSL选择不同的哈希实现
#ifdef USE_FALLBACK_HASH
#include "sha256_fallback.h"
#else
#include <openssl/sha.h>
#endif

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <android/log.h>

namespace security {

std::string SignatureVerifier::bytesToHex(const std::vector<uint8_t>& bytes) {
    static const char hexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        result.push_back(hexChars[(byte >> 4) & 0x0F]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    return result;
}

std::string SignatureVerifier::sha256Hash(const std::vector<uint8_t>& data) {
#ifdef USE_FALLBACK_HASH
    return Sha256Fallback::hash(data);
#else
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return bytesToHex(hash);
#endif
}

/**
 * 检查并清除JNI异常
 */
static bool checkAndClearException(JNIEnv* env, const char* operation) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("JNI Exception during: %s", operation);
        return true;
    }
    return false;
}

/**
 * 获取签名 - 优先使用直接解析APK的方式（安全）
 *
 * 此方法现在默认使用直接解析APK文件的方式获取签名，
 * 绕过Java层的PackageManager，因此不会被Xposed Hook。
 */
std::string SignatureVerifier::getSignature(JNIEnv* env, jobject context) {
    if (!env || !context) {
        LOGE("Invalid parameters for getSignature");
        return "";
    }

    // 清除可能存在的异常
    env->ExceptionClear();

    // 优先使用直接解析APK的方式（不会被Hook）
    std::string apkPath = ApkSignatureParser::getApkPathFromContext(env, context);

    if (apkPath.empty()) {
        LOGW("Failed to get APK path from Context, trying fallback");
        apkPath = ApkSignatureParser::getSelfApkPath();
    }

    if (!apkPath.empty()) {
        std::string signature = ApkSignatureParser::getSignatureFromApk(apkPath);
        if (!signature.empty()) {
            LOGI("Got signature from direct APK parsing: %s", signature.c_str());
            return signature;
        }
        LOGW("Failed to get signature from APK directly, falling back to PackageManager");
    }

    // 回退到PackageManager方式（可能被Hook）
    return getSignatureViaPackageManager(env, context);
}

/**
 * 通过PackageManager获取签名（可能被Xposed Hook）
 *
 * 此方法仅用于对比检测，不应作为主要的签名验证方式。
 */
std::string SignatureVerifier::getSignatureViaPackageManager(JNIEnv* env, jobject context) {
    if (!env || !context) {
        LOGE("Invalid parameters for getSignatureViaPackageManager");
        return "";
    }

    env->ExceptionClear();

    try {
        // 获取PackageManager
        jclass contextClass = env->GetObjectClass(context);
        if (!contextClass || checkAndClearException(env, "GetObjectClass")) {
            LOGE("Failed to get context class");
            return "";
        }

        jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager",
                                                        "()Landroid/content/pm/PackageManager;");
        if (!getPackageManager || checkAndClearException(env, "GetMethodID(getPackageManager)")) {
            LOGE("Failed to get getPackageManager method");
            env->DeleteLocalRef(contextClass);
            return "";
        }

        jobject packageManager = env->CallObjectMethod(context, getPackageManager);
        if (!packageManager || checkAndClearException(env, "CallObjectMethod(getPackageManager)")) {
            LOGE("Failed to get PackageManager");
            env->DeleteLocalRef(contextClass);
            return "";
        }

        // 获取包名
        jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
        if (!getPackageName || checkAndClearException(env, "GetMethodID(getPackageName)")) {
            LOGE("Failed to get getPackageName method");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            return "";
        }

        jstring packageName = (jstring)env->CallObjectMethod(context, getPackageName);
        if (!packageName || checkAndClearException(env, "CallObjectMethod(getPackageName)")) {
            LOGE("Failed to get package name");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            return "";
        }

        // 获取PackageInfo - 使用GET_SIGNATURES (兼容旧版本)
        jclass pmClass = env->GetObjectClass(packageManager);
        jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
                                                     "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

        if (!getPackageInfo || checkAndClearException(env, "GetMethodID(getPackageInfo)")) {
            LOGE("Failed to get getPackageInfo method");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            return "";
        }

        const jint GET_SIGNATURES = 0x40;  // PackageManager.GET_SIGNATURES
        jobject packageInfo = env->CallObjectMethod(packageManager, getPackageInfo,
                                                     packageName, GET_SIGNATURES);

        if (!packageInfo || checkAndClearException(env, "CallObjectMethod(getPackageInfo)")) {
            LOGE("Failed to get PackageInfo with GET_SIGNATURES, trying GET_SIGNING_CERTIFICATES");

            // Android P+ 尝试使用新API GET_SIGNING_CERTIFICATES
            const jint GET_SIGNING_CERTIFICATES = 0x08000000;
            packageInfo = env->CallObjectMethod(packageManager, getPackageInfo,
                                                 packageName, GET_SIGNING_CERTIFICATES);

            if (!packageInfo || checkAndClearException(env, "CallObjectMethod(getPackageInfo GET_SIGNING_CERTIFICATES)")) {
                LOGE("Failed to get PackageInfo with both APIs");
                env->DeleteLocalRef(contextClass);
                env->DeleteLocalRef(packageManager);
                env->DeleteLocalRef(packageName);
                env->DeleteLocalRef(pmClass);
                return "";
            }
        }

        // 获取签名数组
        jclass piClass = env->GetObjectClass(packageInfo);
        jfieldID signaturesField = env->GetFieldID(piClass, "signatures",
                                                    "[Landroid/content/pm/Signature;");

        if (!signaturesField || checkAndClearException(env, "GetFieldID(signatures)")) {
            LOGE("Failed to get signatures field");

            // 尝试新的signingInfo API (Android P+)
            jfieldID signingInfoField = env->GetFieldID(piClass, "signingInfo",
                                                        "Landroid/content/pm/SigningInfo;");
            if (signingInfoField && !checkAndClearException(env, "GetFieldID(signingInfo)")) {
                LOGI("Trying signingInfo field (Android P+)");

                jobject signingInfo = env->GetObjectField(packageInfo, signingInfoField);
                if (signingInfo && !checkAndClearException(env, "GetObjectField(signingInfo)")) {
                    jclass signingInfoClass = env->GetObjectClass(signingInfo);
                    jmethodID getApkContentsSigners = env->GetMethodID(signingInfoClass,
                                                                        "getApkContentsSigners",
                                                                        "()[Landroid/content/pm/Signature;");

                    if (getApkContentsSigners && !checkAndClearException(env, "GetMethodID(getApkContentsSigners)")) {
                        jobjectArray signatures = (jobjectArray)env->CallObjectMethod(signingInfo, getApkContentsSigners);
                        if (signatures && !checkAndClearException(env, "CallObjectMethod(getApkContentsSigners)")) {
                            // 成功获取签名，继续处理
                            std::string result = processSignatureArray(env, signatures);
                            env->DeleteLocalRef(signatures);
                            env->DeleteLocalRef(signingInfo);
                            env->DeleteLocalRef(signingInfoClass);
                            env->DeleteLocalRef(contextClass);
                            env->DeleteLocalRef(packageManager);
                            env->DeleteLocalRef(packageName);
                            env->DeleteLocalRef(pmClass);
                            env->DeleteLocalRef(packageInfo);
                            env->DeleteLocalRef(piClass);
                            return result;
                        }
                    }
                    env->DeleteLocalRef(signingInfo);
                }
            }

            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            env->DeleteLocalRef(packageInfo);
            env->DeleteLocalRef(piClass);
            return "";
        }

        jobjectArray signatures = (jobjectArray)env->GetObjectField(packageInfo, signaturesField);
        if (!signatures || checkAndClearException(env, "GetObjectField(signatures)")) {
            LOGE("No signatures found");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            env->DeleteLocalRef(packageInfo);
            env->DeleteLocalRef(piClass);
            return "";
        }

        jsize sigCount = env->GetArrayLength(signatures);
        if (sigCount == 0) {
            LOGE("Signatures array is empty");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            env->DeleteLocalRef(packageInfo);
            env->DeleteLocalRef(piClass);
            env->DeleteLocalRef(signatures);
            return "";
        }

        std::string result = processSignatureArray(env, signatures);

        // 清理所有局部引用
        env->DeleteLocalRef(contextClass);
        env->DeleteLocalRef(packageManager);
        env->DeleteLocalRef(packageName);
        env->DeleteLocalRef(pmClass);
        env->DeleteLocalRef(packageInfo);
        env->DeleteLocalRef(piClass);
        env->DeleteLocalRef(signatures);

        return result;

    } catch (...) {
        LOGE("Exception in getSignatureViaPackageManager");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return "";
    }
}

/**
 * 处理签名数组，提取并计算哈希
 */
std::string SignatureVerifier::processSignatureArray(JNIEnv* env, jobjectArray signatures) {
    if (!signatures || env->GetArrayLength(signatures) == 0) {
        LOGE("Invalid signatures array");
        return "";
    }

    // 获取第一个签名
    jobject signature = env->GetObjectArrayElement(signatures, 0);
    if (!signature || checkAndClearException(env, "GetObjectArrayElement")) {
        LOGE("Failed to get first signature");
        return "";
    }

    jclass signatureClass = env->GetObjectClass(signature);
    if (!signatureClass) {
        LOGE("Failed to get signature class");
        env->DeleteLocalRef(signature);
        return "";
    }

    // 转换为字节数组
    jmethodID toByteArray = env->GetMethodID(signatureClass, "toByteArray", "()[B");
    if (!toByteArray) {
        LOGE("Failed to get toByteArray method");
        env->DeleteLocalRef(signature);
        env->DeleteLocalRef(signatureClass);
        return "";
    }

    jbyteArray byteArray = (jbyteArray)env->CallObjectMethod(signature, toByteArray);
    if (!byteArray || checkAndClearException(env, "CallObjectMethod(toByteArray)")) {
        LOGE("Failed to get signature byte array");
        env->DeleteLocalRef(signature);
        env->DeleteLocalRef(signatureClass);
        return "";
    }

    // 转换为C++字节数组
    jsize length = env->GetArrayLength(byteArray);
    jbyte* bytes = env->GetByteArrayElements(byteArray, nullptr);

    if (!bytes) {
        LOGE("Failed to get byte array elements");
        env->DeleteLocalRef(byteArray);
        env->DeleteLocalRef(signature);
        env->DeleteLocalRef(signatureClass);
        return "";
    }

    std::vector<uint8_t> signatureBytes(length);
    for (jsize i = 0; i < length; i++) {
        signatureBytes[i] = static_cast<uint8_t>(bytes[i]);
    }

    env->ReleaseByteArrayElements(byteArray, bytes, 0);

    // 清理局部引用
    env->DeleteLocalRef(byteArray);
    env->DeleteLocalRef(signature);
    env->DeleteLocalRef(signatureClass);

    // 计算SHA-256哈希
    std::string hash = sha256Hash(signatureBytes);
    LOGI("Signature hash calculated: %s", hash.c_str());

    return hash;
}

/**
 * 验证签名（使用安全方式）
 */
bool SignatureVerifier::verifySignature(JNIEnv* env, jobject context, const std::string& expectedSignature) {
    if (expectedSignature.empty()) {
        LOGE("Expected signature is empty");
        return false;
    }

    // 使用安全的签名获取方式（直接解析APK）
    std::string currentSignature = getSignature(env, context);
    if (currentSignature.empty()) {
        LOGE("Failed to get current signature");
        return false;
    }

    // 转换为小写比较
    std::string expectedLower = expectedSignature;
    std::string currentLower = currentSignature;

    std::transform(expectedLower.begin(), expectedLower.end(), expectedLower.begin(), ::tolower);
    std::transform(currentLower.begin(), currentLower.end(), currentLower.begin(), ::tolower);

    bool result = (expectedLower == currentLower);
    if (result) {
        LOGI("Signature verification passed");
    } else {
        LOGE("Signature verification failed: expected=%s, got=%s",
             expectedSignature.c_str(), currentSignature.c_str());
    }

    return result;
}

/**
 * 检测PackageManager是否被Hook
 *
 * 通过比较直接解析APK和通过PackageManager获取的签名是否一致来判断
 */
bool SignatureVerifier::detectPmHook(JNIEnv* env, jobject context) {
    if (!env || !context) {
        return false;
    }

    // 获取APK路径
    std::string apkPath = ApkSignatureParser::getApkPathFromContext(env, context);
    if (apkPath.empty()) {
        apkPath = ApkSignatureParser::getSelfApkPath();
    }

    // 直接解析APK获取真实签名
    std::string realSignature;
    if (!apkPath.empty()) {
        realSignature = ApkSignatureParser::getSignatureFromApk(apkPath);
    }

    // 通过PackageManager获取签名（可能被Hook）
    std::string pmSignature = getSignatureViaPackageManager(env, context);

    // 对比签名
    if (realSignature.empty() || pmSignature.empty()) {
        LOGW("Cannot compare signatures - one or both are empty");
        return false;
    }

    std::string realLower = realSignature;
    std::string pmLower = pmSignature;
    std::transform(realLower.begin(), realLower.end(), realLower.begin(), ::tolower);
    std::transform(pmLower.begin(), pmLower.end(), pmLower.begin(), ::tolower);

    if (realLower != pmLower) {
        LOGW("PackageManager Hook detected!");
        LOGW("Real signature: %s", realSignature.c_str());
        LOGW("PM signature:   %s", pmSignature.c_str());
        return true;
    }

    return false;
}

} // namespace security