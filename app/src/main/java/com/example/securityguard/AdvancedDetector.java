package com.example.securityguard;

import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 高级安全检测工具类
 *
 * 提供额外的安全检测功能，与Native层检测配合使用
 */
public class AdvancedDetector {

    private static final String TAG = "AdvancedDetector";

    // 可疑文件路径列表
    private static final String[] SUSPICIOUS_PATHS = {
            "/system/framework/XposedBridge.jar",
            "/system/framework/xposed.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/data/data/de.robv.android.xposed.installer",
            "/data/data/org.lsposed.manager",
            "/data/adb/lspd",
            "/data/adb/modules/lsposed",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/dev/.magisk",
            "/data/misc/riru",
            "/data/adb/riru",
            "/data/adb/modules/riru_core",
            "/data/adb/zygisk",
            "/proc/self/maps"
    };

    // 可疑包名列表
    private static final String[] SUSPICIOUS_PACKAGES = {
            "de.robv.android.xposed.installer",
            "de.robv.android.xposed",
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "com.saurik.substrate",
            "com.topjohnwu.magisk",
            "me.phh.superuser",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.noshufou.android.su",
            "eu.chainfire.supersu"
    };

    /**
     * 检测可疑文件
     *
     * @return 检测到的可疑文件列表
     */
    public static List<String> detectSuspiciousFiles() {
        List<String> detectedFiles = new ArrayList<>();

        for (String path : SUSPICIOUS_PATHS) {
            File file = new File(path);
            if (file.exists()) {
                detectedFiles.add(path);
                Log.w(TAG, "Suspicious file detected: " + path);
            }
        }

        return detectedFiles;
    }

    /**
     * 检测进程内存映射中的可疑内容
     *
     * @return 是否检测到可疑内容
     */
    public static boolean detectSuspiciousMemoryMaps() {
        try {
            File mapsFile = new File("/proc/self/maps");
            if (!mapsFile.exists()) {
                return false;
            }

            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;
            while ((line = reader.readLine()) != null) {
                // 检查是否有可疑的库映射
                if (line.contains("xposed") ||
                        line.contains("lsposed") ||
                        line.contains("edxposed") ||
                        line.contains("substrate") ||
                        line.contains("frida") ||
                        line.contains("magisk") ||
                        line.contains("zygisk") ||
                        line.contains("riru")) {
                    Log.w(TAG, "Suspicious memory mapping: " + line);
                    reader.close();
                    return true;
                }
            }
            reader.close();

        } catch (IOException e) {
            Log.e(TAG, "Failed to read memory maps", e);
        }

        return false;
    }

    /**
     * 检测是否处于调试状态
     *
     * @return 是否处于调试状态
     */
    public static boolean isBeingDebugged() {
        // 检查调试器连接
        if (Debug.isDebuggerConnected()) {
            Log.w(TAG, "Debugger connected");
            return true;
        }

        // 检查调试标志
        if (Debug.waitingForDebugger()) {
            Log.w(TAG, "Waiting for debugger");
            return true;
        }

        // 检查TracerPid（Android调试检测）
        try {
            File statusFile = new File("/proc/self/status");
            if (statusFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(statusFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        String[] parts = line.split(":");
                        if (parts.length >= 2) {
                            int tracerPid = Integer.parseInt(parts[1].trim());
                            if (tracerPid > 0) {
                                Log.w(TAG, "TracerPid found: " + tracerPid);
                                reader.close();
                                return true;
                            }
                        }
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to check TracerPid", e);
        }

        return false;
    }

    /**
     * 检测是否Root
     *
     * @return 是否检测到Root
     */
    public static boolean isRooted() {
        // 检查su命令是否存在
        String[] suPaths = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/su/bin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/su"
        };

        for (String path : suPaths) {
            File file = new File(path);
            if (file.exists()) {
                Log.w(TAG, "SU binary found: " + path);
                return true;
            }
        }

        // 检查Magisk相关文件
        String[] magiskPaths = {
                "/sbin/.magisk",
                "/data/adb/magisk",
                "/data/adb/modules/magisk"
        };

        for (String path : magiskPaths) {
            File file = new File(path);
            if (file.exists()) {
                Log.w(TAG, "Magisk detected: " + path);
                return true;
            }
        }

        return false;
    }

    /**
     * 检测Hook框架（Java层）
     *
     * @return 是否检测到Hook框架
     */
    public static boolean detectHookFrameworks() {
        try {
            // 尝试加载Xposed相关类
            Class.forName("de.robv.android.xposed.XposedBridge");
            Log.w(TAG, "XposedBridge class found");
            return true;
        } catch (ClassNotFoundException e) {
            // 正常情况
        }

        try {
            Class.forName("de.robv.android.xposed.LspHooker");
            Log.w(TAG, "LSPosed Hooker class found");
            return true;
        } catch (ClassNotFoundException e) {
            // 正常情况
        }

        try {
            Class.forName("com.saurik.substrate.Substrate");
            Log.w(TAG, "Substrate class found");
            return true;
        } catch (ClassNotFoundException e) {
            // 正常情况
        }

        return false;
    }

    /**
     * 执行全面安全检测
     *
     * @param context 应用Context
     * @return 安全检测结果
     */
    public static SecurityScanResult performFullScan(Context context) {
        SecurityScanResult result = new SecurityScanResult();

        // 文件检测
        result.suspiciousFiles = detectSuspiciousFiles();
        result.hasSuspiciousFiles = !result.suspiciousFiles.isEmpty();

        // 内存映射检测
        result.suspiciousMemoryMaps = detectSuspiciousMemoryMaps();

        // 调试检测
        result.isBeingDebugged = isBeingDebugged();

        // Root检测
        result.isRooted = isRooted();

        // Hook框架检测
        result.hookFrameworksDetected = detectHookFrameworks();

        // 计算风险等级
        result.calculateRiskLevel();

        return result;
    }

    /**
     * 安全扫描结果类
     */
    public static class SecurityScanResult {
        public List<String> suspiciousFiles;
        public boolean hasSuspiciousFiles;
        public boolean suspiciousMemoryMaps;
        public boolean isBeingDebugged;
        public boolean isRooted;
        public boolean hookFrameworksDetected;
        public int riskLevel;

        public SecurityScanResult() {
            suspiciousFiles = new ArrayList<>();
            hasSuspiciousFiles = false;
            suspiciousMemoryMaps = false;
            isBeingDebugged = false;
            isRooted = false;
            hookFrameworksDetected = false;
            riskLevel = 0;
        }

        public void calculateRiskLevel() {
            int level = 0;

            if (hasSuspiciousFiles) level += 20;
            if (suspiciousMemoryMaps) level += 25;
            if (isBeingDebugged) level += 15;
            if (isRooted) level += 20;
            if (hookFrameworksDetected) level += 30;

            // 根据检测到的可疑文件数量增加风险
            level += suspiciousFiles.size() * 5;

            riskLevel = Math.min(level, 100);
        }

        public boolean isSecure() {
            return riskLevel < 30;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("SecurityScanResult {\n");
            sb.append("  suspiciousFiles: ").append(suspiciousFiles).append("\n");
            sb.append("  suspiciousMemoryMaps: ").append(suspiciousMemoryMaps).append("\n");
            sb.append("  isBeingDebugged: ").append(isBeingDebugged).append("\n");
            sb.append("  isRooted: ").append(isRooted).append("\n");
            sb.append("  hookFrameworksDetected: ").append(hookFrameworksDetected).append("\n");
            sb.append("  riskLevel: ").append(riskLevel).append("/100\n");
            sb.append("  isSecure: ").append(isSecure()).append("\n");
            sb.append("}");
            return sb.toString();
        }
    }
}