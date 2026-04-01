package com.example.securityguard;

/**
 * Xposed/NPatch检测结果类
 *
 * 包含各种检测方法的详细结果
 */
public class DetectionResult {

    // 堆栈跟踪检测结果
    public boolean stackTraceFound;

    // 类加载检测结果
    public boolean classFound;

    // 方法Hook检测结果
    public boolean methodHooked;

    // 内存特征检测结果
    public boolean memoryPatterns;

    // Native Hook检测结果
    public boolean nativeHooked;

    // 线程检测结果
    public boolean threadsFound;

    // 文件检测结果
    public boolean filesFound;

    // NPatch框架检测结果
    public boolean npatchDetected;

    // 综合风险等级 (0-100)
    public int riskLevel;

    // 检测到的框架类型
    public String detectedFramework;

    /**
     * 默认构造函数
     */
    public DetectionResult() {
        stackTraceFound = false;
        classFound = false;
        methodHooked = false;
        memoryPatterns = false;
        nativeHooked = false;
        threadsFound = false;
        filesFound = false;
        npatchDetected = false;
        riskLevel = 0;
        detectedFramework = "";
    }

    /**
     * 全参数构造函数（用于JNI调用）
     */
    public DetectionResult(boolean stackTraceFound, boolean classFound,
                          boolean methodHooked, boolean memoryPatterns,
                          boolean nativeHooked, boolean threadsFound,
                          boolean filesFound, int riskLevel) {
        this.stackTraceFound = stackTraceFound;
        this.classFound = classFound;
        this.methodHooked = methodHooked;
        this.memoryPatterns = memoryPatterns;
        this.nativeHooked = nativeHooked;
        this.threadsFound = threadsFound;
        this.filesFound = filesFound;
        this.npatchDetected = false; // 默认值
        this.riskLevel = riskLevel;
        this.detectedFramework = "";
    }

    /**
     * 扩展构造函数（包含NPatch检测）
     */
    public DetectionResult(boolean stackTraceFound, boolean classFound,
                          boolean methodHooked, boolean memoryPatterns,
                          boolean nativeHooked, boolean threadsFound,
                          boolean filesFound, boolean npatchDetected,
                          int riskLevel, String detectedFramework) {
        this.stackTraceFound = stackTraceFound;
        this.classFound = classFound;
        this.methodHooked = methodHooked;
        this.memoryPatterns = memoryPatterns;
        this.nativeHooked = nativeHooked;
        this.threadsFound = threadsFound;
        this.filesFound = filesFound;
        this.npatchDetected = npatchDetected;
        this.riskLevel = riskLevel;
        this.detectedFramework = detectedFramework != null ? detectedFramework : "";
    }

    /**
     * 获取是否检测到任何异常
     * @return 是否存在任何检测结果为true
     */
    public boolean hasAnyDetection() {
        return stackTraceFound || classFound || methodHooked ||
               memoryPatterns || nativeHooked || threadsFound || filesFound || npatchDetected;
    }

    /**
     * 获取检测到的项目数量
     * @return 检测到异常的项目数量
     */
    public int getDetectionCount() {
        int count = 0;
        if (stackTraceFound) count++;
        if (classFound) count++;
        if (methodHooked) count++;
        if (memoryPatterns) count++;
        if (nativeHooked) count++;
        if (threadsFound) count++;
        if (filesFound) count++;
        if (npatchDetected) count++;
        return count;
    }

    /**
     * 获取风险等级描述
     * @return 风险等级的文字描述
     */
    public String getRiskLevelDescription() {
        if (riskLevel == 0) {
            return "安全";
        } else if (riskLevel < 30) {
            return "低风险";
        } else if (riskLevel < 60) {
            return "中风险";
        } else if (riskLevel < 80) {
            return "高风险";
        } else {
            return "严重风险";
        }
    }

    /**
     * 获取检测到的框架类型描述
     * @return 检测到的框架类型
     */
    public String getDetectedFrameworkDescription() {
        if (npatchDetected) {
            return "NPatch框架";
        }
        if (hasAnyDetection()) {
            return "Xposed/LSPosed框架";
        }
        return "未检测到";
    }

    /**
     * 判断是否检测到NPatch框架
     * @return 是否检测到NPatch
     */
    public boolean isNpatchDetected() {
        return npatchDetected;
    }

    /**
     * 判断是否检测到Xposed框架（不包括NPatch）
     * @return 是否检测到Xposed
     */
    public boolean isXposedDetected() {
        return hasAnyDetection() && !npatchDetected;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DetectionResult {\n");
        sb.append("  stackTraceFound: ").append(stackTraceFound).append("\n");
        sb.append("  classFound: ").append(classFound).append("\n");
        sb.append("  methodHooked: ").append(methodHooked).append("\n");
        sb.append("  memoryPatterns: ").append(memoryPatterns).append("\n");
        sb.append("  nativeHooked: ").append(nativeHooked).append("\n");
        sb.append("  threadsFound: ").append(threadsFound).append("\n");
        sb.append("  filesFound: ").append(filesFound).append("\n");
        sb.append("  npatchDetected: ").append(npatchDetected).append("\n");
        sb.append("  riskLevel: ").append(riskLevel).append(" (").append(getRiskLevelDescription()).append(")\n");
        sb.append("  detectionCount: ").append(getDetectionCount()).append("/8\n");
        sb.append("  detectedFramework: ").append(getDetectedFrameworkDescription()).append("\n");
        sb.append("}");
        return sb.toString();
    }
}