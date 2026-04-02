/**
 * Security Guard - Native层安全验证头文件
 *
 * 功能：
 * 1. 应用签名验证
 * 2. 反Xposed框架检测
 */

#ifndef SECURITY_GUARD_H
#define SECURITY_GUARD_H

#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>

// 日志宏定义
#define LOG_TAG "SecurityGuard"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace security {

/**
 * 签名验证器
 *
 * 提供两种签名获取方式：
 * 1. 直接解析APK文件（安全，不会被Hook）- 默认使用
 * 2. 通过PackageManager获取（可能被Hook）- 仅用于对比检测
 */
class SignatureVerifier {
public:
    /**
     * 验证应用签名（使用安全方式）
     * @param env JNI环境
     * @param context 应用Context对象
     * @param expectedSignature 预期的签名哈希（SHA-256）
     * @return 验证是否通过
     */
    static bool verifySignature(JNIEnv* env, jobject context, const std::string& expectedSignature);

    /**
     * 获取当前应用签名（默认使用安全方式）
     * 优先使用直接解析APK的方式，绕过PackageManager Hook
     * @param env JNI环境
     * @param context 应用Context对象
     * @return 签名字符串
     */
    static std::string getSignature(JNIEnv* env, jobject context);

    /**
     * 通过PackageManager获取签名（可能被Xposed Hook）
     * 此方法仅用于对比检测，不应作为主要验证方式
     * @param env JNI环境
     * @param context 应用Context对象
     * @return 签名字符串
     */
    static std::string getSignatureViaPackageManager(JNIEnv* env, jobject context);

    /**
     * 检测PackageManager是否被Hook
     * 通过比较直接解析APK和通过PackageManager获取的签名是否一致
     * @param env JNI环境
     * @param context 应用Context对象
     * @return 是否检测到Hook
     */
    static bool detectPmHook(JNIEnv* env, jobject context);

    /**
     * 处理签名数组，提取并计算哈希
     * @param env JNI环境
     * @param signatures 签名数组
     * @return 签名哈希字符串
     */
    static std::string processSignatureArray(JNIEnv* env, jobjectArray signatures);

private:
    /**
     * 计算字节数组的SHA-256哈希
     */
    static std::string sha256Hash(const std::vector<uint8_t>& data);

    /**
     * 字节数组转十六进制字符串
     */
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
};

/**
 * Xposed框架检测器
 */
class XposedDetector {
public:
    /**
     * 综合检测Xposed框架
     * @param env JNI环境
     * @return 是否检测到Xposed
     */
    static bool detectXposed(JNIEnv* env);

    /**
     * 检测方法列表
     */
    struct DetectionResult {
        bool stackTraceFound;      // 堆栈跟踪检测
        bool classFound;           // 类检测
        bool methodHooked;         // 方法Hook检测
        bool memoryPatterns;       // 内存特征检测
        bool nativeHooked;         // Native Hook检测
        bool threadsFound;         // 可疑线程检测
        bool filesFound;           // 文件检测
        int riskLevel;             // 风险等级 0-100
    };

    /**
     * 获取详细检测结果
     */
    static DetectionResult getDetailedDetectionResult(JNIEnv* env);

private:
    // ====== 基础检测方法 ======

    /**
     * 方法1: 堆栈跟踪检测
     * 检查调用堆栈中是否存在Xposed相关类
     */
    static bool detectByStackTrace(JNIEnv* env);

    /**
     * 方法2: 类加载检测
     * 尝试加载Xposed相关类
     */
    static bool detectByClassLoader(JNIEnv* env);

    /**
     * 方法3: 方法Hook检测
     * 检测关键方法是否被Hook
     */
    static bool detectMethodHooks(JNIEnv* env);

    /**
     * 方法4: 内存特征检测
     * 搜索内存中的Xposed特征字符串
     */
    static bool detectByMemoryPatterns(JNIEnv* env);

    /**
     * 方法5: Native Hook检测
     * 检测Native层的Hook
     */
    static bool detectNativeHooks(JNIEnv* env);

    /**
     * 方法6: 线程检测
     * 检测Xposed相关线程
     */
    static bool detectByThreads(JNIEnv* env);

    /**
     * 方法7: 文件系统检测
     * 检测Xposed相关文件和目录
     */
    static bool detectByFiles(JNIEnv* env);

    // ====== 高级检测方法 ======

    /**
     * 检测XposedBridge
     */
    static bool detectXposedBridge(JNIEnv* env);

    /**
     * 检测Hook点
     */
    static bool detectHookPoints(JNIEnv* env, const char* className, const char* methodName);

    /**
     * 检测方法入口点是否被修改
     */
    static bool isMethodEntryPointModified(JNIEnv* env, jmethodID methodId);

    /**
     * 检测内存映射
     */
    static bool detectSuspiciousMemoryMaps();

    /**
     * 读取进程内存映射
     */
    static std::string readMapsFile();

    /**
     * 检查ELF头是否被修改
     */
    static bool checkElfIntegrity(const char* libPath);
};

/**
 * 安全状态检查器
 */
class SecurityChecker {
public:
    /**
     * 执行完整安全检查
     * @param env JNI环境
     * @param context 应用Context
     * @param expectedSignature 预期签名
     * @return 安全检查是否通过
     */
    static bool performSecurityCheck(JNIEnv* env, jobject context, const std::string& expectedSignature);

    /**
     * 获取安全报告
     */
    static std::string getSecurityReport(JNIEnv* env, jobject context);
};

} // namespace security

#endif // SECURITY_GUARD_H