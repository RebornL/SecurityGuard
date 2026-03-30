/**
 * 签名验证实现
 */

#include "security_guard.h"

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

std::string SignatureVerifier::getSignature(JNIEnv* env, jobject context) {
    if (!env || !context) {
        LOGE("Invalid parameters for getSignature");
        return "";
    }

    try {
        // 获取PackageManager
        jclass contextClass = env->GetObjectClass(context);
        if (!contextClass) {
            LOGE("Failed to get context class");
            return "";
        }

        jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager",
                                                        "()Landroid/content/pm/PackageManager;");
        if (!getPackageManager) {
            LOGE("Failed to get getPackageManager method");
            env->DeleteLocalRef(contextClass);
            return "";
        }

        jobject packageManager = env->CallObjectMethod(context, getPackageManager);
        if (!packageManager) {
            LOGE("Failed to get PackageManager");
            env->DeleteLocalRef(contextClass);
            return "";
        }

        // 获取包名
        jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
        if (!getPackageName) {
            LOGE("Failed to get getPackageName method");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            return "";
        }

        jstring packageName = (jstring)env->CallObjectMethod(context, getPackageName);
        if (!packageName) {
            LOGE("Failed to get package name");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            return "";
        }

        // 获取PackageInfo
        jclass pmClass = env->GetObjectClass(packageManager);
        jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
                                                     "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

        const jint GET_SIGNATURES = 0x40;  // PackageManager.GET_SIGNATURES
        jobject packageInfo = env->CallObjectMethod(packageManager, getPackageInfo,
                                                     packageName, GET_SIGNATURES);

        if (!packageInfo) {
            LOGE("Failed to get PackageInfo");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            return "";
        }

        // 获取签名数组
        jclass piClass = env->GetObjectClass(packageInfo);
        jfieldID signaturesField = env->GetFieldID(piClass, "signatures",
                                                    "[Landroid/content/pm/Signature;");

        if (!signaturesField) {
            LOGE("Failed to get signatures field");
            // 尝试获取signatures新API (Android P+)
            // TODO: 处理Android P+的签名验证
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            env->DeleteLocalRef(packageInfo);
            env->DeleteLocalRef(piClass);
            return "";
        }

        jobjectArray signatures = (jobjectArray)env->GetObjectField(packageInfo, signaturesField);
        if (!signatures || env->GetArrayLength(signatures) == 0) {
            LOGE("No signatures found");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            env->DeleteLocalRef(packageInfo);
            env->DeleteLocalRef(piClass);
            return "";
        }

        // 获取第一个签名
        jobject signature = env->GetObjectArrayElement(signatures, 0);
        jclass signatureClass = env->GetObjectClass(signature);

        // 转换为字节数组
        jmethodID toByteArray = env->GetMethodID(signatureClass, "toByteArray", "()[B");
        jbyteArray byteArray = (jbyteArray)env->CallObjectMethod(signature, toByteArray);

        if (!byteArray) {
            LOGE("Failed to get signature byte array");
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(packageManager);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(pmClass);
            env->DeleteLocalRef(packageInfo);
            env->DeleteLocalRef(piClass);
            env->DeleteLocalRef(signatures);
            env->DeleteLocalRef(signature);
            env->DeleteLocalRef(signatureClass);
            return "";
        }

        // 转换为C++字节数组
        jsize length = env->GetArrayLength(byteArray);
        jbyte* bytes = env->GetByteArrayElements(byteArray, nullptr);

        std::vector<uint8_t> signatureBytes(length);
        for (jsize i = 0; i < length; i++) {
            signatureBytes[i] = static_cast<uint8_t>(bytes[i]);
        }

        env->ReleaseByteArrayElements(byteArray, bytes, 0);

        // 清理所有局部引用
        env->DeleteLocalRef(contextClass);
        env->DeleteLocalRef(packageManager);
        env->DeleteLocalRef(packageName);
        env->DeleteLocalRef(pmClass);
        env->DeleteLocalRef(packageInfo);
        env->DeleteLocalRef(piClass);
        env->DeleteLocalRef(signatures);
        env->DeleteLocalRef(signature);
        env->DeleteLocalRef(signatureClass);
        env->DeleteLocalRef(byteArray);

        // 计算SHA-256哈希
        std::string hash = sha256Hash(signatureBytes);
        LOGI("Signature hash calculated: %s", hash.c_str());

        return hash;

    } catch (...) {
        LOGE("Exception in getSignature");
        return "";
    }
}

bool SignatureVerifier::verifySignature(JNIEnv* env, jobject context, const std::string& expectedSignature) {
    if (expectedSignature.empty()) {
        LOGE("Expected signature is empty");
        return false;
    }

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

} // namespace security