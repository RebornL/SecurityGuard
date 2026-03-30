/**
 * JNI接口实现
 *
 * 提供Java/Kotlin调用的Native方法接口
 */

#include "security_guard.h"
#include "apk_parser.h"
#include <jni.h>
#include <string>

using namespace security;

extern "C" {

// ==================== 签名验证接口 ====================

/**
 * 获取应用签名
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @return 签名字符串（SHA-256哈希）
 */
JNIEXPORT jstring JNICALL
Java_com_example_securityguard_SecurityGuard_nativeGetSignature(
        JNIEnv* env,
        jobject /* thiz */,
        jobject context) {

    std::string signature = SignatureVerifier::getSignature(env, context);
    return env->NewStringUTF(signature.c_str());
}

/**
 * 验证应用签名
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @param expectedSignature 预期的签名哈希
 * @return 签名是否匹配
 */
JNIEXPORT jboolean JNICALL
Java_com_example_securityguard_SecurityGuard_nativeVerifySignature(
        JNIEnv* env,
        jobject thiz,
        jobject context,
        jstring expectedSignature) {

    if (!expectedSignature) {
        LOGE("Expected signature is null");
        return JNI_FALSE;
    }

    const char* expectedSigStr = env->GetStringUTFChars(expectedSignature, nullptr);
    if (!expectedSigStr) {
        LOGE("Failed to get expected signature string");
        return JNI_FALSE;
    }

    std::string expectedSig(expectedSigStr);
    env->ReleaseStringUTFChars(expectedSignature, expectedSigStr);

    bool result = SignatureVerifier::verifySignature(env, context, expectedSig);
    return result ? JNI_TRUE : JNI_FALSE;
}

// ==================== Xposed检测接口 ====================

/**
 * 检测Xposed框架
 * @param env JNI环境
 * @param thiz 调用对象
 * @return 是否检测到Xposed
 */
JNIEXPORT jboolean JNICALL
Java_com_example_securityguard_SecurityGuard_nativeDetectXposed(
        JNIEnv* env,
        jobject thiz) {

    bool detected = XposedDetector::detectXposed(env);
    return detected ? JNI_TRUE : JNI_FALSE;
}

/**
 * 获取详细检测结果
 * @param env JNI环境
 * @param thiz 调用对象
 * @return 检测结果对象
 */
JNIEXPORT jobject JNICALL
Java_com_example_securityguard_SecurityGuard_nativeGetDetectionResult(
        JNIEnv* env,
        jobject thiz) {

    XposedDetector::DetectionResult result = XposedDetector::getDetailedDetectionResult(env);

    // 创建DetectionResult Java对象
    jclass resultClass = env->FindClass("com/example/securityguard/DetectionResult");
    if (!resultClass) {
        LOGE("Failed to find DetectionResult class");
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZZZZZZZI)V");
    if (!constructor) {
        LOGE("Failed to find DetectionResult constructor");
        env->DeleteLocalRef(resultClass);
        return nullptr;
    }

    jobject resultObject = env->NewObject(resultClass,
                                          constructor,
                                          result.stackTraceFound,
                                          result.classFound,
                                          result.methodHooked,
                                          result.memoryPatterns,
                                          result.nativeHooked,
                                          result.threadsFound,
                                          result.filesFound,
                                          result.riskLevel);

    env->DeleteLocalRef(resultClass);
    return resultObject;
}

// ==================== 综合安全检查接口 ====================

/**
 * 执行完整安全检查
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @param expectedSignature 预期的签名哈希
 * @return 安全检查是否通过
 */
JNIEXPORT jboolean JNICALL
Java_com_example_securityguard_SecurityGuard_nativePerformSecurityCheck(
        JNIEnv* env,
        jobject thiz,
        jobject context,
        jstring expectedSignature) {

    if (!expectedSignature) {
        LOGE("Expected signature is null");
        return JNI_FALSE;
    }

    const char* expectedSigStr = env->GetStringUTFChars(expectedSignature, nullptr);
    if (!expectedSigStr) {
        LOGE("Failed to get expected signature string");
        return JNI_FALSE;
    }

    std::string expectedSig(expectedSigStr);
    env->ReleaseStringUTFChars(expectedSignature, expectedSigStr);

    // 执行签名验证
    bool signatureValid = SignatureVerifier::verifySignature(env, context, expectedSig);
    if (!signatureValid) {
        LOGE("Signature verification failed");
        return JNI_FALSE;
    }

    // 执行Xposed检测
    bool xposedDetected = XposedDetector::detectXposed(env);
    if (xposedDetected) {
        LOGE("Xposed framework detected");
        return JNI_FALSE;
    }

    LOGI("Security check passed");
    return JNI_TRUE;
}

/**
 * 获取安全报告
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @return 安全报告字符串
 */
JNIEXPORT jstring JNICALL
Java_com_example_securityguard_SecurityGuard_nativeGetSecurityReport(
        JNIEnv* env,
        jobject thiz,
        jobject context) {

    std::string report = SecurityChecker::getSecurityReport(env, context);
    return env->NewStringUTF(report.c_str());
}

// ==================== 检测已安装Xposed应用 ====================

/**
 * 检测已安装的Xposed相关应用
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @return 是否检测到Xposed相关应用
 */
JNIEXPORT jboolean JNICALL
Java_com_example_securityguard_SecurityGuard_nativeDetectXposedPackages(
        JNIEnv* env,
        jobject thiz,
        jobject context) {

    if (!context) {
        return JNI_FALSE;
    }

    // 获取PackageManager
    jclass contextClass = env->GetObjectClass(context);
    if (!contextClass) {
        return JNI_FALSE;
    }

    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager",
                                                    "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(context, getPackageManager);
    if (!packageManager) {
        env->DeleteLocalRef(contextClass);
        return JNI_FALSE;
    }

    // 获取已安装的应用列表
    jclass pmClass = env->GetObjectClass(packageManager);
    jmethodID getInstalledPackages = env->GetMethodID(pmClass, "getInstalledPackages",
                                                        "(I)Ljava/util/List;");
    jobject packageList = env->CallObjectMethod(packageManager, getInstalledPackages, 0);

    if (!packageList) {
        env->DeleteLocalRef(contextClass);
        env->DeleteLocalRef(packageManager);
        env->DeleteLocalRef(pmClass);
        return JNI_FALSE;
    }

    // 遍历列表检查是否有Xposed相关包
    jclass listClass = env->GetObjectClass(packageList);
    jmethodID sizeMethod = env->GetMethodID(listClass, "size", "()I");
    jmethodID getMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");

    jint size = env->CallIntMethod(packageList, sizeMethod);
    bool detected = false;

    // Xposed相关包名列表
    const char* xposedPackages[] = {
        "de.robv.android.xposed.installer",
        "de.robv.android.xposed",
        "org.lsposed.manager",
        "io.github.lsposed.manager",
        "com.saurik.substrate",
        "com.topjohnwu.magisk",
        nullptr
    };

    for (jint i = 0; i < size && !detected; i++) {
        jobject packageInfo = env->CallObjectMethod(packageList, getMethod, i);
        if (!packageInfo) continue;

        jclass piClass = env->GetObjectClass(packageInfo);
        jfieldID packageNameField = env->GetFieldID(piClass, "packageName", "Ljava/lang/String;");
        jstring packageName = (jstring)env->GetObjectField(packageInfo, packageNameField);

        if (packageName) {
            const char* packageNameStr = env->GetStringUTFChars(packageName, nullptr);

            for (int j = 0; xposedPackages[j] != nullptr; j++) {
                if (strcmp(packageNameStr, xposedPackages[j]) == 0) {
                    LOGW("Xposed related package found: %s", packageNameStr);
                    detected = true;
                    break;
                }
            }

            env->ReleaseStringUTFChars(packageName, packageNameStr);
        }

        env->DeleteLocalRef(packageInfo);
        env->DeleteLocalRef(piClass);
        if (packageName) env->DeleteLocalRef(packageName);
    }

    // 清理
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(packageManager);
    env->DeleteLocalRef(pmClass);
    env->DeleteLocalRef(packageList);
    env->DeleteLocalRef(listClass);

    return detected ? JNI_TRUE : JNI_FALSE;
}

// ==================== 安全签名验证接口（绕过PM Hook） ====================

/**
 * 直接从APK文件获取签名（不经过PackageManager）
 * 这个方法不会被Xposed的PM绕过选项影响
 *
 * @param env JNI环境
 * @param thiz 调用对象
 * @return 签名字符串（SHA-256哈希）
 */
JNIEXPORT jstring JNICALL
Java_com_example_securityguard_SecurityGuard_nativeGetSignatureDirect(
        JNIEnv* env,
        jobject thiz) {

    std::string apkPath = ApkSignatureParser::getSelfApkPath();
    if (apkPath.empty()) {
        LOGE("Failed to get APK path");
        return env->NewStringUTF("");
    }

    std::string signature = ApkSignatureParser::getSignatureFromApk(apkPath);
    return env->NewStringUTF(signature.c_str());
}

/**
 * 安全验证签名（同时使用两种方式，检测PM Hook）
 *
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @param expectedSignature 预期的签名哈希
 * @return 验证结果对象
 */
JNIEXPORT jobject JNICALL
Java_com_example_securityguard_SecurityGuard_nativeVerifySignatureSecure(
        JNIEnv* env,
        jobject thiz,
        jobject context,
        jstring expectedSignature) {

    if (!expectedSignature) {
        LOGE("Expected signature is null");
        return nullptr;
    }

    const char* expectedSigStr = env->GetStringUTFChars(expectedSignature, nullptr);
    std::string expectedSig(expectedSigStr);
    env->ReleaseStringUTFChars(expectedSignature, expectedSigStr);

    SecureSignatureVerifier::VerificationResult result =
        SecureSignatureVerifier::getDetailedResult(env, context, expectedSig);

    // 创建SignatureVerificationResult Java对象
    jclass resultClass = env->FindClass("com/example/securityguard/SignatureVerificationResult");
    if (!resultClass) {
        LOGE("Failed to find SignatureVerificationResult class");
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(resultClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;ZZZZZLjava/lang/String;)V");
    if (!constructor) {
        LOGE("Failed to find constructor");
        env->DeleteLocalRef(resultClass);
        return nullptr;
    }

    jstring apkSig = env->NewStringUTF(result.apkDirectSignature.c_str());
    jstring pmSig = env->NewStringUTF(result.pmSignature.c_str());
    jstring errorMsg = env->NewStringUTF(result.errorMessage.c_str());

    jobject resultObject = env->NewObject(resultClass,
                                          constructor,
                                          apkSig,
                                          pmSig,
                                          result.signaturesMatch ? JNI_TRUE : JNI_FALSE,
                                          result.apkSignatureValid ? JNI_TRUE : JNI_FALSE,
                                          result.pmSignatureValid ? JNI_TRUE : JNI_FALSE,
                                          result.possibleHookDetected ? JNI_TRUE : JNI_FALSE,
                                          errorMsg);

    env->DeleteLocalRef(resultClass);
    env->DeleteLocalRef(apkSig);
    env->DeleteLocalRef(pmSig);
    env->DeleteLocalRef(errorMsg);

    return resultObject;
}

/**
 * 检测PackageManager是否被Hook
 * 通过比较直接解析APK和通过PM获取的签名是否一致
 *
 * @param env JNI环境
 * @param thiz 调用对象
 * @param context 应用Context
 * @return 是否检测到Hook
 */
JNIEXPORT jboolean JNICALL
Java_com_example_securityguard_SecurityGuard_nativeDetectPmHook(
        JNIEnv* env,
        jobject thiz,
        jobject context) {

    bool detected = SecureSignatureVerifier::detectPackageManagerHook(env, context);
    return detected ? JNI_TRUE : JNI_FALSE;
}

/**
 * 获取APK路径
 *
 * @param env JNI环境
 * @param thiz 调用对象
 * @return APK文件路径
 */
JNIEXPORT jstring JNICALL
Java_com_example_securityguard_SecurityGuard_nativeGetApkPath(
        JNIEnv* env,
        jobject thiz) {

    std::string apkPath = ApkSignatureParser::getSelfApkPath();
    return env->NewStringUTF(apkPath.c_str());
}

// ==================== 库初始化 ====================

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("SecurityGuard library loaded");

    // 可以在这里进行初始化检查
    // 例如检测是否在模拟器中运行

    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM* vm, void* reserved) {
    LOGI("SecurityGuard library unloaded");
}

} // extern "C"