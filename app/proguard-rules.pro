# SecurityGuard ProGuard配置
# 用于混淆Java代码，增加逆向难度，同时保证JNI调用正常工作

# ============================================
# JNI相关配置 - 必须保留，不能混淆
# ============================================

# 保留所有Native方法（JNI调用的入口点）
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留JNI调用的Native方法声明
-keepclassmembers class com.example.securityguard.SecurityGuard {
    private static native java.lang.String nativeGetSignature(android.content.Context);
    private static native boolean nativeVerifySignature(android.content.Context, java.lang.String);
    private static native boolean nativeDetectXposed();
    private static native com.example.securityguard.DetectionResult nativeGetDetectionResult();
    private static native boolean nativePerformSecurityCheck(android.content.Context, java.lang.String);
    private static native java.lang.String nativeGetSecurityReport(android.content.Context);
    private static native boolean nativeDetectXposedPackages(android.content.Context);
    private static native java.lang.String nativeGetSignatureDirect();
    private static native com.example.securityguard.SignatureVerificationResult nativeVerifySignatureSecure(android.content.Context, java.lang.String);
    private static native boolean nativeDetectPmHook(android.content.Context);
    private static native java.lang.String nativeGetApkPath();
}

# 保留DetectionResult类的构造方法（JNI创建对象时使用）
-keep class com.example.securityguard.DetectionResult {
    public <init>(boolean, boolean, boolean, boolean, boolean, boolean, boolean, int);
    public <init>();
    public *;
}

# 保留SignatureVerificationResult类（安全签名验证结果，JNI创建对象时使用）
-keep class com.example.securityguard.SignatureVerificationResult {
    public <init>(java.lang.String, java.lang.String, boolean, boolean, boolean, boolean, java.lang.String);
    public <init>();
    public *;
}

# 保留SecurityGuard类中的公共API方法（供外部调用）
-keep class com.example.securityguard.SecurityGuard {
    public static java.lang.String getSignature(android.content.Context);
    public static boolean verifySignature(android.content.Context, java.lang.String);
    public static boolean detectXposed();
    public static com.example.securityguard.DetectionResult getDetectionResult();
    public static boolean performSecurityCheck(android.content.Context, java.lang.String);
    public static java.lang.String getSecurityReport(android.content.Context);
    public static boolean detectXposedPackages(android.content.Context);
    public static boolean isDebugMode(android.content.Context);
    public static boolean isEmulator();
    public static java.lang.String getSignatureDirect();
    public static com.example.securityguard.SignatureVerificationResult verifySignatureSecure(android.content.Context, java.lang.String);
    public static boolean detectPmHook(android.content.Context);
    public static java.lang.String getApkPath();
    public static boolean verifySignatureBypassPmHook(java.lang.String);
    public static com.example.securityguard.SecurityGuard.UltimateSecurityResult performUltimateSecurityCheck(android.content.Context, java.lang.String);
    public static com.example.securityguard.SecurityGuard.SecurityCheckResult performFullSecurityCheck(android.content.Context, java.lang.String);
}

# 保留SecurityCheckResult内部类（供外部访问结果）
-keep class com.example.securityguard.SecurityGuard$SecurityCheckResult {
    public *;
}

# 保留UltimateSecurityResult内部类（终极安全检查结果）
-keep class com.example.securityguard.SecurityGuard$UltimateSecurityResult {
    public *;
}

# ============================================
# 安全增强配置 - 混淆其他代码
# ============================================

# 移除所有日志输出（防止信息泄露）
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}

# 移除System.out打印
-assumenosideeffects class java.io.PrintStream {
    public void println(...);
    public void print(...);
}

# 混淆内部实现方法（增加逆向难度）
# SignatureHelper和AdvancedDetector的内部方法可以混淆
-keepclassmembers class com.example.securityguard.SignatureHelper {
    public static java.lang.String getSignatureHash(android.content.Context);
    public static boolean verifySignature(android.content.Context, java.lang.String);
}
# 其他内部方法允许混淆

-keepclassmembers class com.example.securityguard.AdvancedDetector {
    public static java.util.List detectSuspiciousFiles();
    public static boolean detectSuspiciousMemoryMaps();
    public static boolean isBeingDebugged();
    public static boolean isRooted();
    public static boolean detectHookFrameworks();
    public static com.example.securityguard.AdvancedDetector.SecurityScanResult performFullScan(android.content.Context);
}
# SecurityScanResult内部类保留公共成员
-keep class com.example.securityguard.AdvancedDetector$SecurityScanResult {
    public *;
}

# ============================================
# 优化选项
# ============================================

# 启用优化
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# 允许访问修改（优化时可能改变访问权限）
-allowaccessmodification

# 优化时允许合并类
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*,code/simplification/cast

# ============================================
# 通用Android配置
# ============================================

# 保留四大组件
-keep public class * extends android.app.Activity {
    public <init>(...);
    public void onCreate(android.os.Bundle);
    public *;
}
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# 保留自定义Application的onCreate方法
-keepclassmembers class * extends android.app.Application {
    public void onCreate();
}

# 保留自定义View
-keep public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
    public void set*(...);
}

# 保留View的onClick属性
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# ============================================
# 序列化配置
# ============================================

# 保留Parcelable序列化类
-keepclassmembers class * implements android.os.Parcelable {
    static ** CREATOR;
}

# 保留Serializable序列化类
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    !static !transient <fields>;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ============================================
# 反射相关配置
# ============================================

# 保留通过反射调用的类和方法
# 如果有使用反射调用其他类的代码，需要在此添加保留规则

# ============================================
# 枚举配置
# ============================================

-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
    **[] $VALUES;
    public *;
}

# ============================================
# 注解配置
# ============================================

-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-keepattributes EnclosingMethod

# 如果使用注解，保留注解类
-keep class * extends java.lang.annotation.Annotation { *; }

# ============================================
# 第三方库配置（根据实际使用的库添加）
# ============================================

# OkHttp
-dontwarn okhttp3.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# Okio
-dontwarn okio.**
-keep class okio.** { *; }

# Retrofit
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }
-keepclasseswithmembers class * {
    @retrofit2.http.* <methods>;
}

# Gson
-keepattributes Signature
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# ============================================
# 警告处理
# ============================================

-dontwarn android.support.**
-dontwarn androidx.**
-dontwarn java.lang.**
-dontwarn javax.annotation.**

# ============================================
# 字符串加密（增强安全）
# ============================================

# 加密字符串常量
-adaptclassstrings com.example.securityguard.**

# 重命名源文件属性（增加混淆效果）
-renamesourcefileattribute SourceFile

# ============================================
# 异常处理
# ============================================

# 保留异常堆栈信息（调试时有用，发布时可移除）
# -keepattributes Exceptions

# 保留内部类
-keepattributes InnerClasses

# ============================================
# 其他安全建议
# ============================================

# 合并接口（减少类数量）
-mergeinterfacesaggressively

# 移除无用代码
-shrinkjars

# 重打包（进一步混淆）
-repackageclasses 'a'

# 允许跨包访问优化
-allowaccessmodification