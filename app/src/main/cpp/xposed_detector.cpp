/**
 * Xposed框架检测实现
 *
 * 实现多层检测机制，防止Xposed框架绕过检测
 */

#include "security_guard.h"
#include <dlfcn.h>
#include <link.h>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <cstring>

namespace security {

// Xposed相关类名列表
static const char* XPOSED_CLASS_NAMES[] = {
    "de/robv/android/xposed/XposedBridge",
    "de/robv/android/xposed/XC_MethodHook",
    "de/robv/android/xposed/XC_MethodReplacement",
    "de/robv/android/xposed/callbacks/XC_LayoutInflated",
    "de/robv/android/xposed/callbacks/XC_LoadPackage",
    "de/robv/android/xposed/services/BaseService",
    "de/robv/android/xposed/services/FileResult",
    "de/robv/android/xposed/XSharedPreferences",
    "de/robv/android/xposed/hooks/XSharedPreferencesHook",
    "de/robv/android/xposed/IXposedHookLoadPackage",
    "de/robv/android/xposed/IXposedHookInitPackageResources",
    "de/robv/android/xposed/IXposedHookZygoteInit",
    "de/robv/android/xposed/IXposedMod",
    "de/robv/android/xposed/LspHooker",  // LSPosed
    "io/github/lsposed/manager/Constants",  // LSPosed Manager
    "org/lsposed/lspd/hooker/LSPHookBridge",  // LSPosed Hook
    "com/saurik/substrate/Substrate",  // Cydia Substrate
    "com/saurik/substrate/MSServer",   // Substrate Server
    nullptr
};

// Xposed特征字符串
static const char* XPOSED_KEYWORDS[] = {
    "Xposed",
    "xposed",
    "XPOSED",
    "LSPosed",
    "lsposed",
    "EdXposed",
    "edxposed",
    "substrate",
    "Substrate",
    "frida",
    "Frida",
    "FRIDA",
    "xhook",
    "andhook",
    "dexposed",
    nullptr
};

// Xposed包名
static const char* XPOSED_PACKAGE_NAMES[] = {
    "de.robv.android.xposed.installer",
    "de.robv.android.xposed",
    "org.lsposed.manager",
    "io.github.lsposed.manager",
    "com.saurik.substrate",
    "com.topjohnwu.magisk",  // Magisk
    "me.phh.superuser",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.noshufou.android.su",
    "eu.chainfire.supersu",
    "com.android.vending.billing.InAppBillingService.COIN",  // Lucky Patcher
    "com.chelpus.lackypatch",
    "com.dimonvideo.luckypatcher",
    "com.forpda.lp",
    "com.android.vending.billing.InAppBillingService.LUCK",
    nullptr
};

// 可疑文件路径
static const char* SUSPICIOUS_PATHS[] = {
    "/system/framework/XposedBridge.jar",
    "/system/framework/xposed.jar",
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/system/xposed",
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/org.lsposed.manager",
    "/data/user/0/de.robv.android.xposed.installer",
    "/data/user/0/org.lsposed.manager",
    "/data/misc/lspd",
    "/data/adb/lspd",
    "/data/adb/modules/lsposed",
    "/data/adb/modules/riru_lsposed",
    "/data/adb/modules/zygisk_lsposed",
    "/system/bin/app_process32_xposed",
    "/system/bin/app_process64_xposed",
    "/data/misc/riru",
    "/data/adb/riru",
    "/data/adb/modules/riru_core",
    "/data/adb/zygisk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk",
    "/dev/.magisk_hide",
    nullptr
};

// 可疑线程名
static const char* SUSPICIOUS_THREAD_NAMES[] = {
    "Xposed",
    "xposed",
    "LSPosed",
    "lsposed",
    "riru",
    "Riru",
    "magisk",
    "Magisk",
    "zygisk",
    "Zygisk",
    nullptr
};

// ==================== 基础检测方法实现 ====================

bool XposedDetector::detectByStackTrace(JNIEnv* env) {
    bool detected = false;

    try {
        // 获取当前线程
        jclass threadClass = env->FindClass("java/lang/Thread");
        if (!threadClass) {
            return false;
        }

        jmethodID currentThread = env->GetStaticMethodID(threadClass, "currentThread",
                                                          "()Ljava/lang/Thread;");
        jobject currentThreadObj = env->CallStaticObjectMethod(threadClass, currentThread);

        // 获取堆栈跟踪
        jmethodID getStackTrace = env->GetMethodID(threadClass, "getStackTrace",
                                                    "()[Ljava/lang/StackTraceElement;");
        jobjectArray stackTrace = (jobjectArray)env->CallObjectMethod(currentThreadObj, getStackTrace);

        if (!stackTrace) {
            env->DeleteLocalRef(threadClass);
            env->DeleteLocalRef(currentThreadObj);
            return false;
        }

        jsize stackLength = env->GetArrayLength(stackTrace);

        // 检查堆栈中的每个元素
        for (jsize i = 0; i < stackLength && !detected; i++) {
            jobject element = env->GetObjectArrayElement(stackTrace, i);
            jclass elementClass = env->GetObjectClass(element);

            jmethodID getClassName = env->GetMethodID(elementClass, "getClassName",
                                                       "()Ljava/lang/String;");
            jstring className = (jstring)env->CallObjectMethod(element, getClassName);

            if (className) {
                const char* classNameStr = env->GetStringUTFChars(className, nullptr);

                // 检查是否包含Xposed相关类名
                for (int j = 0; XPOSED_CLASS_NAMES[j] != nullptr; j++) {
                    if (strstr(classNameStr, XPOSED_CLASS_NAMES[j]) != nullptr ||
                        strstr(classNameStr, "xposed") != nullptr ||
                        strstr(classNameStr, "Xposed") != nullptr ||
                        strstr(classNameStr, "lsposed") != nullptr ||
                        strstr(classNameStr, "LSPosed") != nullptr ||
                        strstr(classNameStr, "edxposed") != nullptr ||
                        strstr(classNameStr, "EdXposed") != nullptr) {
                        detected = true;
                        LOGW("Xposed detected in stack trace: %s", classNameStr);
                        break;
                    }
                }

                env->ReleaseStringUTFChars(className, classNameStr);
            }

            env->DeleteLocalRef(element);
            env->DeleteLocalRef(elementClass);
            if (className) env->DeleteLocalRef(className);
        }

        env->DeleteLocalRef(threadClass);
        env->DeleteLocalRef(currentThreadObj);
        env->DeleteLocalRef(stackTrace);

    } catch (...) {
        LOGE("Exception in detectByStackTrace");
    }

    return detected;
}

bool XposedDetector::detectByClassLoader(JNIEnv* env) {
    bool detected = false;

    try {
        // 尝试加载Xposed相关类
        for (int i = 0; XPOSED_CLASS_NAMES[i] != nullptr && !detected; i++) {
            jclass xposedClass = env->FindClass(XPOSED_CLASS_NAMES[i]);
            if (xposedClass != nullptr) {
                LOGW("Xposed class found: %s", XPOSED_CLASS_NAMES[i]);
                detected = true;
                env->DeleteLocalRef(xposedClass);
            }

            // 清除可能的异常
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
        }

        // 尝试通过ClassLoader加载
        jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
        if (classLoaderClass) {
            jmethodID getSystemClassLoader = env->GetStaticMethodID(classLoaderClass,
                "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
            jobject systemClassLoader = env->CallStaticObjectMethod(classLoaderClass,
                getSystemClassLoader);

            if (systemClassLoader) {
                jclass classLoaderObjClass = env->GetObjectClass(systemClassLoader);
                jmethodID loadClass = env->GetMethodID(classLoaderObjClass, "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;");

                for (int i = 0; XPOSED_CLASS_NAMES[i] != nullptr && !detected; i++) {
                    // 将路径格式转换为类名格式
                    std::string className(XPOSED_CLASS_NAMES[i]);
                    std::replace(className.begin(), className.end(), '/', '.');

                    jstring classNameStr = env->NewStringUTF(className.c_str());
                    jclass loadedClass = (jclass)env->CallObjectMethod(systemClassLoader,
                        loadClass, classNameStr);

                    if (loadedClass != nullptr) {
                        LOGW("Xposed class loaded: %s", className.c_str());
                        detected = true;
                        env->DeleteLocalRef(loadedClass);
                    }

                    env->DeleteLocalRef(classNameStr);

                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                    }
                }

                env->DeleteLocalRef(classLoaderObjClass);
            }

            env->DeleteLocalRef(systemClassLoader);
            env->DeleteLocalRef(classLoaderClass);
        }

    } catch (...) {
        LOGE("Exception in detectByClassLoader");
    }

    return detected;
}

bool XposedDetector::detectMethodHooks(JNIEnv* env) {
    bool detected = false;

    try {
        // 检测关键方法是否被Hook
        // 方法1: 检测Method对象的modifiers字段是否被修改

        jclass methodClass = env->FindClass("java/lang/reflect/Method");
        if (methodClass) {
            // 获取一些关键方法并检查其属性
            jclass stringClass = env->FindClass("java/lang/String");
            if (stringClass) {
                jmethodID getMethod = env->GetStaticMethodID(methodClass, "getMethod",
                    "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");

                jstring methodName = env->NewStringUTF("toString");
                jobjectArray paramTypes = nullptr;
                jobject method = env->CallStaticObjectMethod(methodClass, getMethod,
                    methodName, paramTypes);

                if (method) {
                    // 检查方法的修饰符
                    jclass executableClass = env->FindClass("java/lang/reflect/Executable");
                    if (executableClass) {
                        jmethodID getModifiers = env->GetMethodID(executableClass,
                            "getModifiers", "()I");
                        jint modifiers = env->CallIntMethod(method, getModifiers);

                        // 检查是否有异常的修饰符标志
                        // native方法的modifier包含0x100
                        if ((modifiers & 0x100) != 0) {
                            // toString不应该是native方法，如果标记为native可能被hook
                            // 注意：这可能产生误报，需要结合其他检测
                            LOGW("Suspicious method modifier detected");
                        }

                        env->DeleteLocalRef(executableClass);
                    }

                    env->DeleteLocalRef(method);
                }

                env->DeleteLocalRef(methodName);
                env->DeleteLocalRef(stringClass);
            }

            env->DeleteLocalRef(methodClass);
        }

        // 方法2: 检测内存中的Hook点
        detected = detectHookPoints(env, "java/lang/String", "hashCode") ||
                   detectHookPoints(env, "java/lang/String", "equals");

    } catch (...) {
        LOGE("Exception in detectMethodHooks");
    }

    return detected;
}

bool XposedDetector::detectByMemoryPatterns(JNIEnv* env) {
    bool detected = false;

    try {
        // 读取/proc/self/maps
        std::string mapsContent = readMapsFile();
        if (!mapsContent.empty()) {
            // 检查是否有Xposed相关的内存映射
            for (int i = 0; XPOSED_KEYWORDS[i] != nullptr; i++) {
                if (mapsContent.find(XPOSED_KEYWORDS[i]) != std::string::npos) {
                    LOGW("Xposed keyword found in memory maps: %s", XPOSED_KEYWORDS[i]);
                    detected = true;
                    break;
                }
            }

            // 检查可疑的内存区域
            if (mapsContent.find("xposed") != std::string::npos ||
                mapsContent.find("lsposed") != std::string::npos ||
                mapsContent.find("riru") != std::string::npos ||
                mapsContent.find("magisk") != std::string::npos ||
                mapsContent.find("zygisk") != std::string::npos) {
                LOGW("Suspicious memory mapping detected");
                detected = true;
            }
        }

    } catch (...) {
        LOGE("Exception in detectByMemoryPatterns");
    }

    return detected;
}

bool XposedDetector::detectNativeHooks(JNIEnv* env) {
    bool detected = false;

    try {
        // 检测PLT/GOT Hook
        // 检查关键函数的GOT表是否被修改

        // 检测Inline Hook
        // 检查关键函数入口点是否被修改

        // 检测Android Bionic libc中的关键函数
        void* libcHandle = dlopen("libc.so", RTLD_NOW);
        if (libcHandle) {
            // 检查一些关键函数
            const char* criticalFunctions[] = {
                "open", "read", "write", "mmap", "munmap",
                "pthread_create", "fork", "execve",
                nullptr
            };

            for (int i = 0; criticalFunctions[i] != nullptr; i++) {
                void* funcPtr = dlsym(libcHandle, criticalFunctions[i]);
                if (funcPtr) {
                    // 检查函数入口点的字节码
                    // ARM64通常以0xE003开头（STP指令）
                    // 如果入口点是跳转指令，可能被hook
                    uint32_t* ptr = static_cast<uint32_t*>(funcPtr);
                    uint32_t firstInstruction = *ptr;

                    // 检查是否是BR或RET指令（可能被inline hook）
                    // ARM64: BR Xn = 0xD61F0000 | (n << 5)
                    // ARM64: RET = 0xD65F03C0
                    if ((firstInstruction & 0xFC000000) == 0xD6000000 || // BR/BLR指令
                        firstInstruction == 0xD65F03C0) {  // RET指令
                        LOGW("Possible inline hook detected on %s", criticalFunctions[i]);
                        // 注意：这可能产生误报，需要进一步确认
                    }
                }
            }

            dlclose(libcHandle);
        }

        // 检测xhook/PLT Hook
        // 通过读取/proc/self/maps来检查加载的库
        std::ifstream mapsFile("/proc/self/maps");
        if (mapsFile.is_open()) {
            std::string line;
            while (std::getline(mapsFile, line)) {
                // 查找加载的.so库
                if (line.find(".so") != std::string::npos) {
                    size_t pos = line.rfind(" ");
                    if (pos != std::string::npos) {
                        std::string libPath = line.substr(pos + 1);
                        if (!libPath.empty() && libPath[0] == '/') {
                            // 检查每个加载库的完整性
                            if (checkElfIntegrity(libPath.c_str())) {
                                LOGW("ELF integrity check failed for: %s", libPath.c_str());
                                detected = true;
                                break;
                            }
                        }
                    }
                }
            }
            mapsFile.close();
        }

    } catch (...) {
        LOGE("Exception in detectNativeHooks");
    }

    return detected;
}

bool XposedDetector::detectByThreads(JNIEnv* env) {
    bool detected = false;

    try {
        // 读取/proc/self/task目录下的所有线程
        DIR* taskDir = opendir("/proc/self/task");
        if (taskDir) {
            struct dirent* entry;
            while ((entry = readdir(taskDir)) != nullptr) {
                if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 &&
                    strcmp(entry->d_name, "..") != 0) {

                    // 读取每个线程的comm文件
                    char commPath[256];
                    snprintf(commPath, sizeof(commPath), "/proc/self/task/%s/comm", entry->d_name);

                    std::ifstream commFile(commPath);
                    if (commFile.is_open()) {
                        std::string threadName;
                        std::getline(commFile, threadName);
                        commFile.close();

                        // 检查线程名是否包含Xposed相关关键字
                        for (int i = 0; SUSPICIOUS_THREAD_NAMES[i] != nullptr; i++) {
                            if (threadName.find(SUSPICIOUS_THREAD_NAMES[i]) != std::string::npos) {
                                LOGW("Suspicious thread detected: %s", threadName.c_str());
                                detected = true;
                                break;
                            }
                        }
                    }

                    // 读取线程的maps文件检查加载的库
                    char mapsPath[256];
                    snprintf(mapsPath, sizeof(mapsPath), "/proc/self/task/%s/maps", entry->d_name);

                    std::ifstream mapsFile(mapsPath);
                    if (mapsFile.is_open()) {
                        std::string line;
                        while (std::getline(mapsFile, line)) {
                            for (int i = 0; XPOSED_KEYWORDS[i] != nullptr; i++) {
                                if (line.find(XPOSED_KEYWORDS[i]) != std::string::npos) {
                                    LOGW("Suspicious library in thread %s: %s",
                                         entry->d_name, line.c_str());
                                    detected = true;
                                    break;
                                }
                            }
                            if (detected) break;
                        }
                        mapsFile.close();
                    }

                    if (detected) break;
                }
            }
            closedir(taskDir);
        }

    } catch (...) {
        LOGE("Exception in detectByThreads");
    }

    return detected;
}

bool XposedDetector::detectByFiles(JNIEnv* env) {
    bool detected = false;

    try {
        // 检查可疑文件路径
        for (int i = 0; SUSPICIOUS_PATHS[i] != nullptr; i++) {
            struct stat fileStat;
            if (stat(SUSPICIOUS_PATHS[i], &fileStat) == 0) {
                LOGW("Suspicious file/path found: %s", SUSPICIOUS_PATHS[i]);
                detected = true;
                break;
            }
        }

        // 检查已安装的应用
        if (!detected) {
            jclass pmClass = env->FindClass("android/content/pm/PackageManager");
            if (pmClass) {
                jclass contextClass = env->FindClass("android/content/Context");
                if (contextClass) {
                    // 这里需要Context来调用getPackageManager
                    // 由于这是静态方法，我们将返回一个标志
                    // 实际检测将在JNI接口中进行
                    env->DeleteLocalRef(contextClass);
                }
                env->DeleteLocalRef(pmClass);
            }
        }

    } catch (...) {
        LOGE("Exception in detectByFiles");
    }

    return detected;
}

// ==================== 高级检测方法实现 ====================

bool XposedDetector::detectXposedBridge(JNIEnv* env) {
    bool detected = false;

    try {
        // 尝试通过反射获取XposedBridge实例
        jclass xposedBridge = env->FindClass("de/robv/android/xposed/XposedBridge");
        if (xposedBridge) {
            LOGW("XposedBridge class found");
            detected = true;
            env->DeleteLocalRef(xposedBridge);
        }

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }

        // 检查LSPosed的Hooker类
        jclass lspHooker = env->FindClass("de/robv/android/xposed/LspHooker");
        if (lspHooker) {
            LOGW("LSPosed Hooker class found");
            detected = true;
            env->DeleteLocalRef(lspHooker);
        }

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }

    } catch (...) {
        LOGE("Exception in detectXposedBridge");
    }

    return detected;
}

bool XposedDetector::detectHookPoints(JNIEnv* env, const char* className, const char* methodName) {
    bool detected = false;

    try {
        jclass targetClass = env->FindClass(className);
        if (targetClass) {
            // 获取方法
            jmethodID methodId = env->GetMethodID(targetClass, methodName, "()I");
            if (methodId) {
                if (isMethodEntryPointModified(env, methodId)) {
                    LOGW("Method %s.%s appears to be hooked", className, methodName);
                    detected = true;
                }
            }

            env->DeleteLocalRef(targetClass);
        }

    } catch (...) {
        LOGE("Exception in detectHookPoints");
    }

    return detected;
}

bool XposedDetector::isMethodEntryPointModified(JNIEnv* env, jmethodID methodId) {
    // 这是一个简化的检测方法
    // 实际应用中需要更复杂的检测逻辑
    // 例如：检查ArtMethod的结构是否被修改

    // 注意：这需要访问ART运行时的内部结构
    // 在不同Android版本上实现可能不同

    return false;  // 占位实现
}

bool XposedDetector::detectSuspiciousMemoryMaps() {
    std::string mapsContent = readMapsFile();
    if (mapsContent.empty()) {
        return false;
    }

    // 检查可疑的内存区域
    std::vector<std::string> suspiciousPatterns = {
        "xposed", "lsposed", "edxposed", "substrate",
        "frida", "magisk", "zygisk", "riru",
        "libxposed", "liblsposed", "libsubstrate",
        "libfrida-gadget", "libmg"
    };

    for (const auto& pattern : suspiciousPatterns) {
        if (mapsContent.find(pattern) != std::string::npos) {
            LOGW("Suspicious pattern in memory maps: %s", pattern.c_str());
            return true;
        }
    }

    return false;
}

std::string XposedDetector::readMapsFile() {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) {
        LOGE("Failed to open /proc/self/maps");
        return "";
    }

    std::stringstream buffer;
    buffer << mapsFile.rdbuf();
    mapsFile.close();

    return buffer.str();
}

bool XposedDetector::checkElfIntegrity(const char* libPath) {
    // 简化的ELF完整性检查
    // 实际实现需要解析ELF头并验证关键节

    if (!libPath || strlen(libPath) == 0) {
        return false;
    }

    std::ifstream file(libPath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // 读取ELF魔数
    uint8_t magic[4];
    file.read(reinterpret_cast<char*>(magic), 4);
    file.close();

    // 检查ELF魔数
    if (magic[0] != 0x7F || magic[1] != 'E' ||
        magic[2] != 'L' || magic[3] != 'F') {
        return true;  // 不是有效的ELF文件，可能被修改
    }

    return false;  // 完整性检查通过
}

// ==================== 主检测接口 ====================

bool XposedDetector::detectXposed(JNIEnv* env) {
    DetectionResult result = getDetailedDetectionResult(env);
    return result.riskLevel > 50;  // 风险等级超过50则认为检测到Xposed
}

XposedDetector::DetectionResult XposedDetector::getDetailedDetectionResult(JNIEnv* env) {
    DetectionResult result;
    int riskPoints = 0;

    // 方法1: 堆栈跟踪检测
    result.stackTraceFound = detectByStackTrace(env);
    if (result.stackTraceFound) {
        riskPoints += 30;
        LOGW("Detection: Stack trace check positive");
    }

    // 方法2: 类加载检测
    result.classFound = detectByClassLoader(env);
    if (result.classFound) {
        riskPoints += 25;
        LOGW("Detection: Class loader check positive");
    }

    // 方法3: 方法Hook检测
    result.methodHooked = detectMethodHooks(env);
    if (result.methodHooked) {
        riskPoints += 20;
        LOGW("Detection: Method hook check positive");
    }

    // 方法4: 内存特征检测
    result.memoryPatterns = detectByMemoryPatterns(env);
    if (result.memoryPatterns) {
        riskPoints += 25;
        LOGW("Detection: Memory patterns check positive");
    }

    // 方法5: Native Hook检测
    result.nativeHooked = detectNativeHooks(env);
    if (result.nativeHooked) {
        riskPoints += 20;
        LOGW("Detection: Native hook check positive");
    }

    // 方法6: 线程检测
    result.threadsFound = detectByThreads(env);
    if (result.threadsFound) {
        riskPoints += 15;
        LOGW("Detection: Thread check positive");
    }

    // 方法7: 文件检测
    result.filesFound = detectByFiles(env);
    if (result.filesFound) {
        riskPoints += 20;
        LOGW("Detection: File check positive");
    }

    // 计算最终风险等级（最高100）
    result.riskLevel = (riskPoints > 100) ? 100 : riskPoints;

    LOGI("Xposed detection result: risk level = %d", result.riskLevel);

    return result;
}

} // namespace security