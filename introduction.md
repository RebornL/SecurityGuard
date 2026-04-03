# SecurityGuard 项目安全检测能力分析报告

## 一、Xposed框架检测能力 ✅ **具备**

项目在Native C++层实现了多种Xposed检测机制：

| 检测方法 | 实现位置 | 检测原理 |
|---------|---------|---------|
| 堆栈跟踪检测 | xposed_detector.cpp:176 | 检查调用堆栈中是否包含Xposed相关类名 |
| 类加载检测 | xposed_detector.cpp:290 | 尝试加载`de/robv/android/xposed/XposedBridge`等类 |
| 方法Hook检测 | xposed_detector.cpp:393 | 检测Method对象modifiers字段是否被修改 |
| 内存特征检测 | xposed_detector.cpp:485 | 读取`/proc/self/maps`查找Xposed相关库映射 |
| Native Hook检测 | xposed_detector.cpp:525 | 检查libc关键函数入口点是否被Inline Hook |
| 线程检测 | xposed_detector.cpp:600 | 检查线程名是否为"Xposed"等可疑名称 |
| 文件路径检测 | xposed_detector.cpp:666 | 检查`/system/framework/XposedBridge.jar`等路径 |

检测的Xposed特征类名包括：
- `de/robv/android/xposed/XposedBridge`
- `de/robv/android/xposed/XC_MethodHook`
- `com/saurik/substrate/Substrate` (Cydia Substrate)

---

## 二、LSPosed框架检测能力 ✅ **具备**

项目包含专门的LSPosed检测特征：

| 检测特征 | 类型 | 实现位置 |
|---------|------|---------|
| `de/robv/android/xposed/LspHooker` | 类名检测 | xposed_detector.cpp:37 |
| `org/lsposed/lspd/hooker/LSPHookBridge` | 类名检测 | xposed_detector.cpp:39 |
| `org.lsposed.manager` | 包名检测 | xposed_detector.cpp:84 |
| `/data/adb/modules/lsposed` | 文件路径检测 | xposed_detector.cpp:119 |
| `/data/misc/lspd` | 文件路径检测 | xposed_detector.cpp:117 |
| `/data/adb/modules/zygisk_lsposed` | Zygisk版检测 | xposed_detector.cpp:121 |

---

## 三、NPatch框架检测能力 ✅ **具备（核心功能）**

NPatch检测是该项目的**核心亮点**，采用创新的双重签名对比机制：

### 1. NPatch特征检测（传统方法）

| 检测特征 | 类型 | 实现位置 |
|---------|------|---------|
| `org/npatch/NpHooker` | 类名检测 | xposed_detector.cpp:46 |
| `org/npatch/core/NpCore` | 类名检测 | xposed_detector.cpp:47 |
| `org.npatch.manager` | 包名检测 | xposed_detector.cpp:99 |
| `/data/adb/modules/npatch` | 文件路径检测 | xposed_detector.cpp:140 |
| `/data/misc/npatch` | 文件路径检测 | xposed_detector.cpp:138 |

### 2. NPatch签名篡改检测（核心创新机制）

这是项目的**关键技术突破**，专门针对NPatch的签名绕过功能：

**NPatch绕过机制分析：**
- NPatch使用"Signature bypass level: 2"选项
- Hook `sourceDir`字段返回缓存的原始APK路径
- 缓存路径：`/data/user/0/{package}/cache/npatch/origin/`
- 真实安装路径：`/data/app/~~{hash}==/{package}-{hash}==/base.apk`

**项目绕过NPatch Hook的技术方案：**

```cpp
// 核心实现：从 /proc/self/maps 读取真实APK路径
static std::string getRealApkPathFromProcMaps() {
    FILE* maps = fopen("/proc/self/maps", "r");
    // 查找 base.apk 映射
    // 优先返回非NPatch缓存路径
    for (const auto& path : foundPaths) {
        if (path.find("/cache/npatch/") == std::string::npos) {
            return path;  // 真实安装的APK
        }
    }
}
```
实现位置：apk_parser.cpp:31

**签名对比检测流程：**

1. **Native直接解析**：读取`/proc/self/maps`获取真实APK路径 → 解析V2/V3签名块 → 获取NPatch签名
2. **Java PM方式**：通过PackageManager获取签名（NPatch Hook返回原始签名）
3. **对比检测**：两者不一致则判定为NPatch篡改

检测代码位置：jni_interface.cpp:527

---

## 四、检测机制技术实现原理

### 1. APK签名解析（V2/V3 Signing Block）

项目实现了完整的APK Signing Block解析：

```
APK结构：
[ZIP内容] [APK Signing Block] [Central Directory] [EOCD]
                          ↑
                   V2/V3签名在此
```

解析流程（apk_parser.cpp:383）：
1. 查找ZIP EOCD (End of Central Directory)
2. 获取Central Directory偏移
3. 定位APK Signing Block (Magic: "APK Sig Block 42")
4. 解析V2(0x7109871a)/V3(0xf05368c0)签名块
5. 提取X.509证书并计算SHA-256指纹

### 2. 多层检测架构

```
┌─────────────────────────────────────────────────────────┐
│                    Java层检测                            │
│  - AdvancedDetector: 文件/内存/调试/Root/Hook框架检测     │
│  - SignatureHelper: V1/V2签名解析 + PM签名对比           │
└─────────────────────────────────────────────────────────┘
                          ↓ JNI
┌─────────────────────────────────────────────────────────┐
│                   Native C++层检测                       │
│  - XposedDetector: 7种Xposed/LSPosed/NPatch检测方法      │
│  - ApkSignatureParser: 直接解析APK签名（绕过Hook）        │
│  - SignatureVerifier: PM签名获取 + 双重对比检测          │
└─────────────────────────────────────────────────────────┘
```

### 3. 风险评分系统

检测结果采用风险评分机制（满分100）：
- 堆栈检测: +30分
- 类加载检测: +25分
- 内存特征: +25分
- 方法Hook: +20分
- Native Hook: +20分
- 文件检测: +20分
- 线程检测: +15分

风险等级 > 50 则判定为检测到Hook框架。

---

## 五、检测准确性和抗绕过能力分析

### 优势 ✅

| 特性 | 说明 |
|------|------|
| **Native层实现** | C++代码比Java更难被Hook，绕过难度高 |
| **直接解析APK** | 不经过PackageManager，绕过签名伪装Hook |
| **proc/maps绕过** | 创新性地使用内存映射获取真实APK路径，绕过NPatch sourceDir Hook |
| **多重检测** | 7种检测方法组合，单一绕过难以规避全部检测 |
| **签名对比机制** | 真实签名 vs PM签名对比，精准检测NPatch篡改 |

### 局限性 ⚠️

| 局限 | 说明 |
|------|------|
| **V1签名不支持** | 仅支持V2/V3签名，V1(JAR)签名的APK无法检测 |
| **SELinux限制** | 高版本Android SELinux可能限制`/proc/self/maps`访问 |
| **Inline Hook检测不完整** | Native Hook检测代码标注为"简化实现" |
| **Magisk Hide** | Magisk的隐藏功能可能隐藏文件路径检测结果 |
| **Zygisk注入** | Zygisk在zygote进程注入，可能在检测代码执行前就已Hook |

### 抗绕过能力评级

| 检测类型 | 抗绕过能力 | 说明 |
|---------|-----------|------|
| 传统Xposed检测 | 中等 | 可被类隐藏模块绕过 |
| LSPosed检测 | 中等 | Zygisk版本更难检测 |
| **NPatch签名篡改检测** | **高** | `/proc/self/maps`绕过是创新方案，抗绕过能力强 |

---

## 总结

该项目**具备完整的Xposed、LSPosed、NPatch检测能力**，其中：

- **NPatch签名篡改检测**是核心技术亮点，使用创新的`/proc/self/maps`路径获取机制绕过NPatch的sourceDir Hook，实现了精准的双重签名对比检测。

- 项目采用Java + Native C++多层架构，提供了较强的抗绕过能力，但仍存在一些局限需要后续改进（如V1签名支持、完整Inline Hook检测等）。

---

## 关键签名值参考

| 签名类型 | SHA-256哈希值 |
|---------|--------------|
| NPatch签名 | `08b00b38cd98762bf261952c2c1014c09208ac2c278fd3085421994a516c3e23` |
| 原始签名 | `f9f9073cd8a7ac990ea4167b56497f8f8cbb8a3362df7163e7d851f5e282b9cb` |

当检测到Native解析签名与PM返回签名不一致时，可判定APK被NPatch篡改。