# SecurityGuard - Android Native安全验证框架

一个基于Native层（C/C++）实现的Android应用安全验证框架，提供应用签名验证和反Xposed框架检测功能。

## 功能特性

### 1. 应用签名验证
- 通过Native层获取APK数字签名
- 计算签名SHA-256哈希进行比对
- 防止应用被重新打包篡改
- 兼容Android P+新签名API
- **支持直接解析APK文件，绕过PackageManager Hook**

### 2. 反Xposed框架检测
实现7种多层检测机制，有效防止Xposed框架绕过：

| 检测方法 | 描述 | 风险权重 |
|---------|------|---------|
| 堆栈跟踪检测 | 检查调用堆栈中是否存在Xposed相关类 | 30 |
| 类加载检测 | 尝试动态加载Xposed相关类 | 25 |
| 方法Hook检测 | 检测关键方法是否被Hook | 20 |
| 内存特征检测 | 搜索进程内存映射中的特征字符串 | 25 |
| Native Hook检测 | 检测GOT/PLT/Inline Hook | 20 |
| 线程检测 | 检测可疑线程名 | 15 |
| 文件系统检测 | 检查Xposed相关文件和目录 | 20 |

综合风险等级超过50即判定检测到Xposed。

### 3. 绕过PM Hook的签名验证（重要）

Xposed模块可以Hook `PackageManager` 来伪造签名信息。本框架实现了**直接解析APK文件**的功能，完全不依赖Java层：

```
┌─────────────────────────────────────────────────────┐
│                  签名验证方式对比                    │
├─────────────────────┬───────────────────────────────┤
│  旧方式 (可被绕过)   │  新方式 (无法被绕过)          │
├─────────────────────┼───────────────────────────────┤
│  Native JNI         │  Native 直接读取APK文件       │
│       ↓             │       ↓                       │
│  Java PM            │  解析ZIP结构                  │
│       ↓             │       ↓                       │
│  Xposed Hook ← 被篡改│  提取签名块(V1/V2/V3)        │
│       ↓             │       ↓                       │
│  返回伪造签名        │  计算SHA-256                  │
│                     │       ↓                       │
│                     │  返回真实签名                  │
└─────────────────────┴───────────────────────────────┘
```

支持的签名方案：
- **V1签名**: META-INF/CERT.RSA (Android 7.0以下)
- **V2签名**: APK Signing Block (Android 7.0+)
- **V3签名**: APK Signature Scheme V3 (Android 9.0+)

### 4. 附加检测功能
- Root环境检测
- 调试器连接检测
- 模拟器环境检测
- 调试模式检测
- 已安装可疑应用检测
- PackageManager Hook检测

## 项目结构

```
app/src/main/
├── cpp/                              # Native层代码
│   ├── security_guard.h              # 核心头文件
│   ├── signature_verify.cpp          # 签名验证实现
│   ├── xposed_detector.cpp           # Xposed检测实现
│   ├── jni_interface.cpp             # JNI接口
│   ├── security_checker.cpp          # 安全检查器
│   ├── apk_parser.h                  # APK解析器头文件
│   ├── apk_parser.cpp                # APK解析实现
│   ├── sha256_fallback.h             # SHA-256备用实现
│   └── CMakeLists.txt                # CMake构建配置
│
├── java/com/example/securityguard/   # Java层代码
│   ├── SecurityGuard.java            # 主入口类
│   ├── DetectionResult.java          # 检测结果类
│   ├── SignatureVerificationResult.java # 安全签名验证结果
│   ├── SignatureHelper.java          # 签名辅助类
│   ├── AdvancedDetector.java         # 高级检测工具
│   ├── SecurityApplication.java      # Application示例
│   └── MainActivity.java             # Activity示例
│
├── res/layout/activity_main.xml      # UI布局
└── AndroidManifest.xml               # 应用配置
```

## 构建项目

### 环境要求
- Android SDK (API 21+)
- Android NDK r25+
- CMake 3.22.1+
- Gradle 8.2+

### 构建命令

```bash
# Debug版本
./gradlew assembleDebug

# Release版本
./gradlew assembleRelease
```

### 输出路径
- Debug APK: `app/build/outputs/apk/debug/app-debug.apk`
- Release APK: `app/build/outputs/apk/release/app-release.apk`

## 快速开始

### 1. 添加依赖

将项目源码集成到你的Android项目中，确保：
- `app/src/main/cpp/` 目录下的C++代码
- `app/src/main/java/` 目录下的Java代码
- CMakeLists.txt构建配置

### 2. 配置build.gradle

```gradle
android {
    namespace 'com.example.securityguard'
    compileSdk 36

    defaultConfig {
        minSdk 21
        targetSdk 36

        ndk {
            abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'
        }
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++14"
                arguments "-DANDROID_STL=c++_static"
            }
        }
    }
    
    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
        }
    }
}
```

### 3. 获取应用签名

首次使用需要获取你的应用签名哈希：

```java
// 方式1：通过PackageManager获取
String signature = SecurityGuard.getSignature(context);

// 方式2：直接解析APK（推荐，不会被Hook）
String signature = SecurityGuard.getSignatureDirect();
```

将获取到的签名哈希配置到代码中：

```java
private static final String EXPECTED_SIGNATURE = "your_signature_hash_here";
```

### 4. 在Application中初始化

```java
public class MyApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        
        // 推荐：使用终极安全检查
        UltimateSecurityResult result = SecurityGuard.performUltimateSecurityCheck(
            this, EXPECTED_SIGNATURE);
        
        if (!result.isSecure) {
            // 检测到安全问题
            if (result.pmHookDetected) {
                Log.e("Security", "PackageManager可能被Hook!");
            }
            handleSecurityFailure();
        }
    }
}
```

### 5. 在关键操作前验证

```java
// 支付、数据传输等敏感操作前验证
private void performCriticalOperation() {
    // 使用安全验证（绕过PM Hook）
    SignatureVerificationResult result = SecurityGuard.verifySignatureSecure(
        this, EXPECTED_SIGNATURE);
    
    if (!result.isValid()) {
        Toast.makeText(this, "签名验证失败", Toast.LENGTH_SHORT).show();
        return;
    }
    
    if (result.possibleHookDetected) {
        Toast.makeText(this, "检测到PM Hook!", Toast.LENGTH_SHORT).show();
        return;
    }
    
    if (SecurityGuard.detectXposed()) {
        Toast.makeText(this, "检测到Xposed框架", Toast.LENGTH_SHORT).show();
        return;
    }
    
    // 执行关键操作
    doSomethingImportant();
}
```

## API参考

### SecurityGuard类

#### 安全签名验证API（推荐）

```java
// 直接从APK文件获取签名（不经过PackageManager，无法被Hook）
String signature = SecurityGuard.getSignatureDirect();

// 安全验证签名（同时使用两种方式，检测PM Hook）
SignatureVerificationResult result = SecurityGuard.verifySignatureSecure(context, expectedSignature);
// result.apkDirectSignature - 直接解析APK获取的签名
// result.pmSignature - 通过PackageManager获取的签名
// result.signaturesMatch - 两个签名是否一致
// result.apkSignatureValid - APK签名是否匹配预期
// result.possibleHookDetected - 是否检测到PM Hook

// 检测PackageManager是否被Hook
boolean hooked = SecurityGuard.detectPmHook(context);

// 完全绕过PM Hook的验证
boolean valid = SecurityGuard.verifySignatureBypassPmHook(expectedSignature);

// 终极安全检查（最全面）
UltimateSecurityResult result = SecurityGuard.performUltimateSecurityCheck(context, expectedSignature);
```

#### 基础签名验证

```java
// 获取当前应用签名哈希
String signature = SecurityGuard.getSignature(Context context);

// 验证签名是否匹配
boolean valid = SecurityGuard.verifySignature(Context context, String expectedSignature);
```

#### Xposed检测

```java
// 快速检测Xposed框架
boolean detected = SecurityGuard.detectXposed();

// 获取详细检测结果
DetectionResult result = SecurityGuard.getDetectionResult();
// result.stackTraceFound - 堆栈检测结果
// result.classFound - 类加载检测结果
// result.methodHooked - 方法Hook检测结果
// result.memoryPatterns - 内存特征检测结果
// result.nativeHooked - Native Hook检测结果
// result.threadsFound - 线程检测结果
// result.filesFound - 文件检测结果
// result.riskLevel - 综合风险等级(0-100)
```

#### 综合检查

```java
// 执行完整安全检查（签名+Xposed）
boolean secure = SecurityGuard.performSecurityCheck(Context context, String signature);

// 执行全面安全检查（包含更多检测项）
SecurityCheckResult result = SecurityGuard.performFullSecurityCheck(Context context, String signature);

// 获取安全报告文本
String report = SecurityGuard.getSecurityReport(Context context);
```

#### 其他检测

```java
// 检测已安装的Xposed相关应用
boolean detected = SecurityGuard.detectXposedPackages(Context context);

// 检测是否调试模式
boolean debug = SecurityGuard.isDebugMode(Context context);

// 检测是否模拟器环境
boolean emulator = SecurityGuard.isEmulator();
```

### AdvancedDetector类

```java
// 执行全面安全扫描
SecurityScanResult result = AdvancedDetector.performFullScan(Context context);

// 单项检测
List<String> files = AdvancedDetector.detectSuspiciousFiles();
boolean memory = AdvancedDetector.detectSuspiciousMemoryMaps();
boolean debug = AdvancedDetector.isBeingDebugged();
boolean root = AdvancedDetector.isRooted();
boolean hook = AdvancedDetector.detectHookFrameworks();
```

## 防绕过设计

### Native层保护
- 核心检测逻辑在C++层实现，难以通过Java层Hook绕过
- 使用`-fvisibility=hidden`隐藏符号，增加逆向难度
- 使用`-fstack-protector-strong`增强堆栈保护

### 多检测维度
- 7种不同检测方法相互配合
- 单点绕过无法完全隐藏所有特征
- 风险评分机制，综合判断威胁等级

### 内存特征检测
- 直接读取`/proc/self/maps`
- 无法通过文件伪装绕过
- 检测内存中的库加载痕迹

### 签名双重验证
- Native层直接解析APK文件
- 支持V1/V2/V3签名方案
- 完全绕过可能被Hook的PackageManager

## ProGuard配置

项目已包含完整的ProGuard配置，主要规则：

```pro
# 保留Native方法
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留JNI调用的方法签名
-keepclassmembers class com.example.securityguard.SecurityGuard {
    private static native *** native*(***);
}

# 保留结果类
-keep class com.example.securityguard.DetectionResult { *; }
-keep class com.example.securityguard.SignatureVerificationResult { *; }

# 移除日志输出
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}
```

## 最佳实践

### 1. 多时机检测
- Application初始化时检测
- 关键操作前再次检测
- 定时后台检测

### 2. 分级响应
```java
if (riskLevel < 30) {
    // 低风险：记录日志，正常运行
} else if (riskLevel < 60) {
    // 中风险：警告用户，限制部分功能
} else {
    // 高风险：终止应用或禁用所有功能
}
```

### 3. 隐藏检测时机
- 不要在固定时间点检测
- 检测逻辑分散在多处
- 使用随机延迟和异步检测

### 4. 保护核心逻辑
- 将核心业务逻辑也放入Native层
- 关键数据使用Native层加密存储
- 网络请求参数在Native层签名

## 注意事项

1. **签名配置**：务必替换`EXPECTED_SIGNATURE`为你的实际签名哈希
2. **误报处理**：某些检测项可能产生误报，建议结合多项检测结果判断
3. **性能影响**：检测操作有一定性能开销，建议在非UI线程执行
4. **兼容性**：已测试支持Android 5.0+ (API 21+)
5. **更新维护**：Xposed等框架持续更新，检测规则需要定期更新

## 检测覆盖范围

支持的检测框架：
- Xposed Framework
- LSPosed
- EdXposed
- Cydia Substrate
- Magisk (Root/Zygisk)
- Riru
- Frida (部分检测)

## 技术原理

### APK签名解析
1. 读取APK文件（ZIP格式）
2. 查找APK Signing Block（V2/V3签名）
3. 解析签名数据提取证书
4. 计算证书SHA-256哈希

### PM Hook检测原理
```
1. 直接解析APK获取签名A
2. 通过PackageManager获取签名B
3. 如果 A ≠ B，则PackageManager被Hook
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request来改进检测规则和新增检测方法。