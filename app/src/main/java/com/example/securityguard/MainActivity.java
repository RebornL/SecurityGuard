package com.example.securityguard;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

/**
 * 安全检测中心主界面
 *
 * 功能展示：
 * 1. Native层与Java层签名对比检测
 * 2. Xposed框架痕迹检测详情
 * 3. 综合安全状态和风险评估
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    // 你的应用的预期签名哈希
    private static final String EXPECTED_SIGNATURE =
            "YOUR_APP_SIGNATURE_HASH_HERE";

    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    // ==================== 界面视图组件 ====================

    // 综合状态区域
    private LinearLayout overallStatusCard;
    private TextView overallStatusTitle;
    private TextView overallStatusText;
    private ProgressBar riskLevelProgress;
    private TextView riskLevelText;

    // 签名对比区域
    private TextView nativeSignatureTextView;
    private TextView nativeSignatureStatus;
    private TextView nativeApkPath;
    private TextView javaSignatureTextView;
    private TextView javaSignatureStatus;
    private TextView javaDirectSignatureTextView;
    private TextView javaDirectSignatureStatus;
    private LinearLayout signatureComparisonResult;
    private TextView signatureMatchIcon;
    private TextView signatureMatchStatus;
    private TextView comparisonResultTextView;

    // Xposed检测区域
    private LinearLayout xposedOverallStatus;
    private TextView xposedOverallIcon;
    private TextView xposedOverallText;
    private TextView xposedDetailReport;

    // 各检测项视图
    private TextView detectStackTraceIcon, detectStackTraceStatus;
    private TextView detectClassLoaderIcon, detectClassLoaderStatus;
    private TextView detectMethodHookIcon, detectMethodHookStatus;
    private TextView detectMemoryIcon, detectMemoryStatus;
    private TextView detectNativeHookIcon, detectNativeHookStatus;
    private TextView detectThreadsIcon, detectThreadsStatus;
    private TextView detectFilesIcon, detectFilesStatus;
    private TextView detectPmHookIcon, detectPmHookStatus;
    private TextView detectNpatchIcon, detectNpatchStatus;

    // 检测项容器
    private LinearLayout detectItemStackTrace, detectItemClassLoader;
    private LinearLayout detectItemMethodHook, detectItemMemory;
    private LinearLayout detectItemNativeHook, detectItemThreads;
    private LinearLayout detectItemFiles, detectItemPmHook;
    private LinearLayout detectItemNpatch;

    // 报告区域
    private TextView resultTextView;
    private TextView statusTextView;

    // 按钮
    private Button refreshSignatureButton;
    private Button checkButton, reportButton, signatureButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        setupButtons();
        performFullDetection();
    }

    /**
     * 初始化所有视图组件
     */
    private void initViews() {
        // 综合状态
        overallStatusCard = findViewById(R.id.overallStatusCard);
        overallStatusTitle = findViewById(R.id.overallStatusTitle);
        overallStatusText = findViewById(R.id.overallStatusText);
        riskLevelProgress = findViewById(R.id.riskLevelProgress);
        riskLevelText = findViewById(R.id.riskLevelText);

        // 签名对比
        nativeSignatureTextView = findViewById(R.id.nativeSignatureTextView);
        nativeSignatureStatus = findViewById(R.id.nativeSignatureStatus);
        nativeApkPath = findViewById(R.id.nativeApkPath);
        javaSignatureTextView = findViewById(R.id.javaSignatureTextView);
        javaSignatureStatus = findViewById(R.id.javaSignatureStatus);
        javaDirectSignatureTextView = findViewById(R.id.javaDirectSignatureTextView);
        javaDirectSignatureStatus = findViewById(R.id.javaDirectSignatureStatus);
        signatureComparisonResult = findViewById(R.id.signatureComparisonResult);
        signatureMatchIcon = findViewById(R.id.signatureMatchIcon);
        signatureMatchStatus = findViewById(R.id.signatureMatchStatus);
        comparisonResultTextView = findViewById(R.id.comparisonResultTextView);

        // Xposed检测汇总
        xposedOverallStatus = findViewById(R.id.xposedOverallStatus);
        xposedOverallIcon = findViewById(R.id.xposedOverallIcon);
        xposedOverallText = findViewById(R.id.xposedOverallText);
        xposedDetailReport = findViewById(R.id.xposedDetailReport);

        // 检测项
        detectItemStackTrace = findViewById(R.id.detectItemStackTrace);
        detectStackTraceIcon = findViewById(R.id.detectStackTraceIcon);
        detectStackTraceStatus = findViewById(R.id.detectStackTraceStatus);

        detectItemClassLoader = findViewById(R.id.detectItemClassLoader);
        detectClassLoaderIcon = findViewById(R.id.detectClassLoaderIcon);
        detectClassLoaderStatus = findViewById(R.id.detectClassLoaderStatus);

        detectItemMethodHook = findViewById(R.id.detectItemMethodHook);
        detectMethodHookIcon = findViewById(R.id.detectMethodHookIcon);
        detectMethodHookStatus = findViewById(R.id.detectMethodHookStatus);

        detectItemMemory = findViewById(R.id.detectItemMemory);
        detectMemoryIcon = findViewById(R.id.detectMemoryIcon);
        detectMemoryStatus = findViewById(R.id.detectMemoryStatus);

        detectItemNativeHook = findViewById(R.id.detectItemNativeHook);
        detectNativeHookIcon = findViewById(R.id.detectNativeHookIcon);
        detectNativeHookStatus = findViewById(R.id.detectNativeHookStatus);

        detectItemThreads = findViewById(R.id.detectItemThreads);
        detectThreadsIcon = findViewById(R.id.detectThreadsIcon);
        detectThreadsStatus = findViewById(R.id.detectThreadsStatus);

        detectItemFiles = findViewById(R.id.detectItemFiles);
        detectFilesIcon = findViewById(R.id.detectFilesIcon);
        detectFilesStatus = findViewById(R.id.detectFilesStatus);

        detectItemPmHook = findViewById(R.id.detectItemPmHook);
        detectPmHookIcon = findViewById(R.id.detectPmHookIcon);
        detectPmHookStatus = findViewById(R.id.detectPmHookStatus);

        // NPatch检测项
        detectItemNpatch = findViewById(R.id.detectItemNpatch);
        detectNpatchIcon = findViewById(R.id.detectNpatchIcon);
        detectNpatchStatus = findViewById(R.id.detectNpatchStatus);

        // 报告和状态
        resultTextView = findViewById(R.id.resultTextView);
        statusTextView = findViewById(R.id.statusTextView);

        // 按钮
        refreshSignatureButton = findViewById(R.id.refreshSignatureButton);
        checkButton = findViewById(R.id.checkButton);
        reportButton = findViewById(R.id.reportButton);
        signatureButton = findViewById(R.id.signatureButton);
    }

    /**
     * 设置按钮点击事件
     */
    private void setupButtons() {
        refreshSignatureButton.setOnClickListener(v -> performFullDetection());
        checkButton.setOnClickListener(v -> performSecurityCheck());
        reportButton.setOnClickListener(v -> getSecurityReport());
        signatureButton.setOnClickListener(v -> getCurrentSignature());
    }

    /**
     * 执行全面安全检测
     */
    private void performFullDetection() {
        Log.i(TAG, "Starting full security detection...");

        // 显示加载状态
        showLoadingState();
        refreshSignatureButton.setEnabled(false);
        refreshSignatureButton.setText("检测中...");

        // 在后台线程执行检测
        new Thread(() -> {
            // 执行Native安全检查
            NativeSecurityCheckResult nativeResult = SecurityGuard.performNativeSecurityCheck(this);

            // 执行Xposed详细检测
            DetectionResult detectionResult = SecurityGuard.getDetectionResult();

            // 在主线程更新UI
            mainHandler.post(() -> {
                updateAllViews(nativeResult, detectionResult);
                refreshSignatureButton.setEnabled(true);
                refreshSignatureButton.setText("执行全面安全检测");
            });
        }).start();
    }

    /**
     * 显示加载状态
     */
    private void showLoadingState() {
        // 综合状态
        overallStatusCard.setBackgroundColor(getColorRes(R.color.status_loading_bg));
        overallStatusText.setText("正在执行安全检测...");
        overallStatusText.setTextColor(getColorRes(R.color.status_loading));
        riskLevelProgress.setProgress(0);
        riskLevelText.setText("检测中");

        // 签名区域
        nativeSignatureTextView.setText("获取中...");
        nativeSignatureTextView.setTextColor(getColorRes(R.color.text_hint));
        javaSignatureTextView.setText("获取中...");
        javaSignatureTextView.setTextColor(getColorRes(R.color.text_hint));
        javaDirectSignatureTextView.setText("获取中...");
        javaDirectSignatureTextView.setTextColor(getColorRes(R.color.text_hint));
        nativeApkPath.setText("");
        signatureComparisonResult.setBackgroundColor(getColorRes(R.color.status_neutral_bg));
        signatureMatchIcon.setText("...");
        signatureMatchStatus.setText("对比中...");

        // Xposed检测汇总
        xposedOverallStatus.setBackgroundColor(getColorRes(R.color.status_neutral_bg));
        xposedOverallIcon.setText("...");
        xposedOverallText.setText("检测中...");
        xposedDetailReport.setText("");

        // 各检测项显示待检测
        setDetectItemLoading(detectItemStackTrace, detectStackTraceIcon, detectStackTraceStatus);
        setDetectItemLoading(detectItemClassLoader, detectClassLoaderIcon, detectClassLoaderStatus);
        setDetectItemLoading(detectItemMethodHook, detectMethodHookIcon, detectMethodHookStatus);
        setDetectItemLoading(detectItemMemory, detectMemoryIcon, detectMemoryStatus);
        setDetectItemLoading(detectItemNativeHook, detectNativeHookIcon, detectNativeHookStatus);
        setDetectItemLoading(detectItemThreads, detectThreadsIcon, detectThreadsStatus);
        setDetectItemLoading(detectItemFiles, detectFilesIcon, detectFilesStatus);
        setDetectItemLoading(detectItemPmHook, detectPmHookIcon, detectPmHookStatus);
        setDetectItemLoading(detectItemNpatch, detectNpatchIcon, detectNpatchStatus);

        // 报告
        resultTextView.setText("正在生成检测报告...");
    }

    /**
     * 设置检测项为加载状态
     */
    private void setDetectItemLoading(LinearLayout container, TextView icon, TextView status) {
        container.setBackgroundColor(getColorRes(R.color.status_neutral_bg));
        icon.setText("...");
        icon.setTextColor(getColorRes(R.color.text_hint));
        status.setText("检测中");
        status.setTextColor(getColorRes(R.color.text_hint));
    }

    /**
     * 更新所有视图
     */
    private void updateAllViews(NativeSecurityCheckResult nativeResult, DetectionResult detectionResult) {
        // 更新签名对比
        updateSignatureSection(nativeResult);

        // 更新Xposed检测详情
        updateXposedSection(detectionResult, nativeResult);

        // 更新综合状态
        updateOverallStatus(nativeResult, detectionResult);

        // 更新详细报告
        updateDetailedReport(nativeResult, detectionResult);

        // 打印日志
        printDetectionLogs(nativeResult, detectionResult);
    }

    /**
     * 更新签名对比区域
     */
    private void updateSignatureSection(NativeSecurityCheckResult result) {
        // Native层签名
        if (result.nativeSignatureSuccess && result.nativeSignature != null && !result.nativeSignature.isEmpty()) {
            nativeSignatureTextView.setText(result.nativeSignature);
            nativeSignatureTextView.setTextColor(getColorRes(R.color.native_indicator));
            nativeSignatureStatus.setText("直接解析APK - 成功");
            nativeSignatureStatus.setTextColor(getColorRes(R.color.status_safe));
        } else {
            nativeSignatureTextView.setText("获取失败");
            nativeSignatureTextView.setTextColor(getColorRes(R.color.status_danger));
            nativeSignatureStatus.setText("直接解析APK - 失败");
            nativeSignatureStatus.setTextColor(getColorRes(R.color.status_danger));
        }

        // APK路径
        if (result.apkPath != null && !result.apkPath.isEmpty()) {
            nativeApkPath.setText("APK: " + result.apkPath);
        }

        // Java层签名
        if (result.javaSignatureSuccess && result.javaSignature != null && !result.javaSignature.isEmpty()) {
            javaSignatureTextView.setText(result.javaSignature);
            javaSignatureTextView.setTextColor(getColorRes(R.color.java_indicator));
            javaSignatureStatus.setText("PackageManager - 成功");
            javaSignatureStatus.setTextColor(getColorRes(R.color.status_safe));
        } else {
            javaSignatureTextView.setText("获取失败");
            javaSignatureTextView.setTextColor(getColorRes(R.color.status_danger));
            javaSignatureStatus.setText("PackageManager - 失败");
            javaSignatureStatus.setTextColor(getColorRes(R.color.status_danger));
        }

        // Java层直接解析APK签名（不会被Hook）
        String javaDirectSignature = SignatureHelper.getSignatureDirectFromApk(this);
        if (javaDirectSignature != null && !javaDirectSignature.isEmpty()) {
            javaDirectSignatureTextView.setText(javaDirectSignature);
            javaDirectSignatureTextView.setTextColor(getColorRes(R.color.native_indicator));
            javaDirectSignatureStatus.setText("直接解析APK - 成功");
            javaDirectSignatureStatus.setTextColor(getColorRes(R.color.status_safe));
        } else {
            javaDirectSignatureTextView.setText("获取失败");
            javaDirectSignatureTextView.setTextColor(getColorRes(R.color.status_danger));
            javaDirectSignatureStatus.setText("直接解析APK - 失败");
            javaDirectSignatureStatus.setTextColor(getColorRes(R.color.status_danger));
        }

        // 签名对比结果
        if (result.signaturesMatch) {
            signatureComparisonResult.setBackgroundColor(getColorRes(R.color.status_safe_bg));
            signatureMatchIcon.setText("✓");
            signatureMatchIcon.setTextColor(getColorRes(R.color.status_safe));
            signatureMatchStatus.setText("签名一致");
            signatureMatchStatus.setTextColor(getColorRes(R.color.status_safe));
            comparisonResultTextView.setText("Native层与Java层签名完全匹配\nPackageManager未被篡改");
            comparisonResultTextView.setTextColor(getColorRes(R.color.text_secondary));
        } else if (result.pmHookDetected) {
            signatureComparisonResult.setBackgroundColor(getColorRes(R.color.status_danger_bg));
            signatureMatchIcon.setText("✗");
            signatureMatchIcon.setTextColor(getColorRes(R.color.status_danger));
            signatureMatchStatus.setText("签名不一致!");
            signatureMatchStatus.setTextColor(getColorRes(R.color.status_danger));
            comparisonResultTextView.setText("警告：PackageManager可能被Hook篡改!\nJava层返回了被篡改的签名值");
            comparisonResultTextView.setTextColor(getColorRes(R.color.status_danger));
            Toast.makeText(this, "警告：签名不一致，可能存在Hook!", Toast.LENGTH_LONG).show();
        } else if (!result.nativeSignatureSuccess) {
            signatureComparisonResult.setBackgroundColor(getColorRes(R.color.status_warning_bg));
            signatureMatchIcon.setText("!");
            signatureMatchIcon.setTextColor(getColorRes(R.color.status_warning));
            signatureMatchStatus.setText("Native获取失败");
            signatureMatchStatus.setTextColor(getColorRes(R.color.status_warning));
            comparisonResultTextView.setText("无法获取Native层真实签名\n无法验证签名完整性");
            comparisonResultTextView.setTextColor(getColorRes(R.color.status_warning));
        } else {
            signatureComparisonResult.setBackgroundColor(getColorRes(R.color.status_neutral_bg));
            signatureMatchIcon.setText("-");
            signatureMatchIcon.setTextColor(getColorRes(R.color.text_hint));
            signatureMatchStatus.setText("无法对比");
            signatureMatchStatus.setTextColor(getColorRes(R.color.text_hint));
            comparisonResultTextView.setText(result.errorMessage != null ? result.errorMessage : "未知状态");
            comparisonResultTextView.setTextColor(getColorRes(R.color.text_hint));
        }
    }

    /**
     * 更新Xposed检测区域
     */
    private void updateXposedSection(DetectionResult detection, NativeSecurityCheckResult nativeResult) {
        boolean xposedDetected = nativeResult.xposedDetected || detection.hasAnyDetection();
        boolean npatchDetected = detection.npatchDetected;
        int riskLevel = detection.riskLevel;

        // 更新各检测项
        updateDetectItem(detectItemStackTrace, detectStackTraceIcon, detectStackTraceStatus,
                detection.stackTraceFound, "堆栈中发现Xposed调用链");
        updateDetectItem(detectItemClassLoader, detectClassLoaderIcon, detectClassLoaderStatus,
                detection.classFound, "检测到Xposed相关类加载");
        updateDetectItem(detectItemMethodHook, detectMethodHookIcon, detectMethodHookStatus,
                detection.methodHooked, "检测到方法被Hook");
        updateDetectItem(detectItemMemory, detectMemoryIcon, detectMemoryStatus,
                detection.memoryPatterns, "内存中发现Xposed特征");
        updateDetectItem(detectItemNativeHook, detectNativeHookIcon, detectNativeHookStatus,
                detection.nativeHooked, "Native层可能被Hook");
        updateDetectItem(detectItemThreads, detectThreadsIcon, detectThreadsStatus,
                detection.threadsFound, "发现可疑线程");
        updateDetectItem(detectItemFiles, detectFilesIcon, detectFilesStatus,
                detection.filesFound, "发现Xposed相关文件/路径");
        updateDetectItem(detectItemPmHook, detectPmHookIcon, detectPmHookStatus,
                nativeResult.pmHookDetected, "PackageManager签名被篡改");
        // NPatch检测项 - 使用特殊样式突出显示
        updateNpatchDetectItem(detectItemNpatch, detectNpatchIcon, detectNpatchStatus,
                npatchDetected, "检测到NPatch框架痕迹!");

        // 更新汇总状态
        if (npatchDetected) {
            xposedOverallStatus.setBackgroundColor(getColorRes(R.color.status_danger_bg));
            xposedOverallIcon.setText("✗");
            xposedOverallIcon.setTextColor(getColorRes(R.color.status_danger));
            xposedOverallText.setText("检测到NPatch框架!");
            xposedOverallText.setTextColor(getColorRes(R.color.status_danger));
        } else if (xposedDetected) {
            xposedOverallStatus.setBackgroundColor(getColorRes(R.color.status_danger_bg));
            xposedOverallIcon.setText("✗");
            xposedOverallIcon.setTextColor(getColorRes(R.color.status_danger));
            xposedOverallText.setText("检测到Xposed框架痕迹!");
            xposedOverallText.setTextColor(getColorRes(R.color.status_danger));
        } else {
            xposedOverallStatus.setBackgroundColor(getColorRes(R.color.status_safe_bg));
            xposedOverallIcon.setText("✓");
            xposedOverallIcon.setTextColor(getColorRes(R.color.status_safe));
            xposedOverallText.setText("未检测到Hook框架");
            xposedOverallText.setTextColor(getColorRes(R.color.status_safe));
        }

        // 详细报告
        StringBuilder detailReport = new StringBuilder();
        detailReport.append("检测项数量: ").append(detection.getDetectionCount()).append("/9\n");
        detailReport.append("风险等级: ").append(riskLevel).append("/100 (").append(detection.getRiskLevelDescription()).append(")\n\n");

        // NPatch检测优先显示
        if (npatchDetected) {
            detailReport.append("★ NPatch框架: 检测到NPatch框架痕迹!\n");
            detailReport.append("  NPatch是一种类似LSPosed的Hook框架\n\n");
        }

        if (detection.stackTraceFound) {
            detailReport.append("• 堆栈跟踪: 检测到Xposed调用链\n");
        }
        if (detection.classFound) {
            detailReport.append("• 类加载: 发现XposedBridge/LSPosed等类\n");
        }
        if (detection.methodHooked) {
            detailReport.append("• 方法Hook: 关键方法可能被Hook\n");
        }
        if (detection.memoryPatterns) {
            detailReport.append("• 内存特征: /proc/self/maps中发现痕迹\n");
        }
        if (detection.nativeHooked) {
            detailReport.append("• Native Hook: 检测到PLT/Inline Hook迹象\n");
        }
        if (detection.threadsFound) {
            detailReport.append("• 线程检测: 发现Xposed/Magisk相关线程\n");
        }
        if (detection.filesFound) {
            detailReport.append("• 文件检测: 发现Xposed/Magisk相关路径\n");
        }
        if (nativeResult.pmHookDetected) {
            detailReport.append("• PM Hook: PackageManager签名被篡改\n");
        }

        if (!xposedDetected && !npatchDetected) {
            detailReport.append("所有检测项均未发现异常\n");
        }

        xposedDetailReport.setText(detailReport.toString());
    }

    /**
     * 更新单个检测项
     */
    private void updateDetectItem(LinearLayout container, TextView icon, TextView status,
                                  boolean detected, String detail) {
        if (detected) {
            container.setBackgroundColor(getColorRes(R.color.status_danger_bg));
            icon.setText("✗");
            icon.setTextColor(getColorRes(R.color.status_danger));
            status.setText("检测到");
            status.setTextColor(getColorRes(R.color.status_danger));
        } else {
            container.setBackgroundColor(getColorRes(R.color.status_safe_bg));
            icon.setText("✓");
            icon.setTextColor(getColorRes(R.color.status_safe));
            status.setText("未检测到");
            status.setTextColor(getColorRes(R.color.status_safe));
        }
    }

    /**
     * 更新NPatch检测项（使用特殊样式突出显示）
     */
    private void updateNpatchDetectItem(LinearLayout container, TextView icon, TextView status,
                                         boolean detected, String detail) {
        if (detected) {
            container.setBackgroundColor(getColorRes(R.color.status_danger_bg));
            icon.setText("⚠");
            icon.setTextColor(getColorRes(R.color.status_danger));
            status.setText("检测到NPatch!");
            status.setTextColor(getColorRes(R.color.status_danger));
            status.setTextAppearance(android.R.style.TextAppearance_Medium);
        } else {
            container.setBackgroundColor(getColorRes(R.color.status_safe_bg));
            icon.setText("✓");
            icon.setTextColor(getColorRes(R.color.status_safe));
            status.setText("未检测到");
            status.setTextColor(getColorRes(R.color.status_safe));
        }
    }

    /**
     * 更新综合状态
     */
    private void updateOverallStatus(NativeSecurityCheckResult nativeResult, DetectionResult detection) {
        boolean isSecure = nativeResult.isSecure && !detection.hasAnyDetection();
        int totalRisk = calculateTotalRisk(nativeResult, detection);

        // 更新风险进度条
        riskLevelProgress.setProgress(totalRisk);
        riskLevelText.setText(totalRisk + "%");

        if (isSecure) {
            overallStatusCard.setBackgroundColor(getColorRes(R.color.status_safe_bg));
            overallStatusTitle.setTextColor(getColorRes(R.color.status_safe));
            overallStatusText.setText("应用安全：所有检测项通过\n签名验证成功，未检测到安全威胁");
            overallStatusText.setTextColor(getColorRes(R.color.status_safe));
        } else if (totalRisk >= 70) {
            overallStatusCard.setBackgroundColor(getColorRes(R.color.status_danger_bg));
            overallStatusTitle.setTextColor(getColorRes(R.color.status_danger));
            overallStatusText.setText("严重风险：存在多个安全威胁\n建议立即停止使用当前应用");
            overallStatusText.setTextColor(getColorRes(R.color.status_danger));
            Toast.makeText(this, "警告：检测到严重安全风险!", Toast.LENGTH_LONG).show();
        } else if (totalRisk >= 40) {
            overallStatusCard.setBackgroundColor(getColorRes(R.color.status_warning_bg));
            overallStatusTitle.setTextColor(getColorRes(R.color.status_warning));
            overallStatusText.setText("中高风险：检测到安全威胁\n建议谨慎使用当前应用");
            overallStatusText.setTextColor(getColorRes(R.color.status_warning));
            Toast.makeText(this, "警告：检测到安全风险!", Toast.LENGTH_LONG).show();
        } else {
            overallStatusCard.setBackgroundColor(getColorRes(R.color.status_warning_bg));
            overallStatusTitle.setTextColor(getColorRes(R.color.status_warning));
            overallStatusText.setText("低风险：存在潜在安全隐患\n建议关注检测结果");
            overallStatusText.setTextColor(getColorRes(R.color.status_warning));
        }
    }

    /**
     * 计算综合风险等级
     */
    private int calculateTotalRisk(NativeSecurityCheckResult nativeResult, DetectionResult detection) {
        int risk = detection.riskLevel;

        // NPatch检测增加高风险值
        if (detection.npatchDetected) {
            risk += 40;
        }

        if (nativeResult.pmHookDetected) {
            risk += 30;
        }
        if (!nativeResult.nativeSignatureSuccess) {
            risk += 20;
        }
        if (!nativeResult.signaturesMatch) {
            risk += 25;
        }

        return Math.min(risk, 100);
    }

    /**
     * 更新详细报告
     */
    private void updateDetailedReport(NativeSecurityCheckResult nativeResult, DetectionResult detection) {
        StringBuilder report = new StringBuilder();
        report.append("=== 安全检测报告 ===\n\n");

        // 签名验证部分
        report.append("【签名验证】\n");
        report.append("Native签名: ").append(nativeResult.nativeSignatureSuccess ? "成功" : "失败").append("\n");
        report.append("Java签名: ").append(nativeResult.javaSignatureSuccess ? "成功" : "失败").append("\n");
        report.append("签名一致性: ").append(nativeResult.signaturesMatch ? "一致" : "不一致").append("\n");
        report.append("PM Hook: ").append(nativeResult.pmHookDetected ? "检测到" : "未检测到").append("\n\n");

        // 框架检测部分
        report.append("【Hook框架检测】\n");
        report.append("NPatch框架: ").append(detection.npatchDetected ? "检测到!" : "未检测到").append("\n");
        report.append("堆栈跟踪: ").append(detection.stackTraceFound ? "检测到" : "未检测到").append("\n");
        report.append("类加载检测: ").append(detection.classFound ? "检测到" : "未检测到").append("\n");
        report.append("方法Hook: ").append(detection.methodHooked ? "检测到" : "未检测到").append("\n");
        report.append("内存特征: ").append(detection.memoryPatterns ? "检测到" : "未检测到").append("\n");
        report.append("Native Hook: ").append(detection.nativeHooked ? "检测到" : "未检测到").append("\n");
        report.append("线程检测: ").append(detection.threadsFound ? "检测到" : "未检测到").append("\n");
        report.append("文件检测: ").append(detection.filesFound ? "检测到" : "未检测到").append("\n\n");

        // 综合评估
        report.append("【综合评估】\n");
        int totalRisk = calculateTotalRisk(nativeResult, detection);
        report.append("风险等级: ").append(totalRisk).append("/100\n");
        report.append("检测项异常: ").append(detection.getDetectionCount()).append("/9\n");
        if (detection.npatchDetected) {
            report.append("检测到的框架: NPatch\n");
        } else if (detection.hasAnyDetection()) {
            report.append("检测到的框架: Xposed/LSPosed\n");
        }
        report.append("安全状态: ").append(nativeResult.isSecure && !detection.hasAnyDetection() ? "安全" : "存在风险").append("\n");

        resultTextView.setText(report.toString());
    }

    /**
     * 打印检测日志
     */
    private void printDetectionLogs(NativeSecurityCheckResult nativeResult, DetectionResult detection) {
        Log.i(TAG, "=== Security Detection Result ===");
        Log.i(TAG, "Native signature: " + nativeResult.nativeSignature);
        Log.i(TAG, "Java signature: " + nativeResult.javaSignature);
        Log.i(TAG, "Signatures match: " + nativeResult.signaturesMatch);
        Log.i(TAG, "PM Hook detected: " + nativeResult.pmHookDetected);
        Log.i(TAG, "Xposed detected: " + nativeResult.xposedDetected);
        Log.i(TAG, "NPatch detected: " + detection.npatchDetected);
        Log.i(TAG, "Detection risk level: " + detection.riskLevel);
        Log.i(TAG, "Detection count: " + detection.getDetectionCount());
        Log.i(TAG, "Is secure: " + (nativeResult.isSecure && !detection.hasAnyDetection()));
    }

    /**
     * 获取颜色资源
     */
    private int getColorRes(int colorResId) {
        return ContextCompat.getColor(this, colorResId);
    }

    /**
     * 执行安全检查
     */
    private void performSecurityCheck() {
        Log.i(TAG, "Performing security check...");

        SecurityGuard.SecurityCheckResult result =
                SecurityGuard.performFullSecurityCheck(this, EXPECTED_SIGNATURE);

        StringBuilder statusBuilder = new StringBuilder();
        statusBuilder.append("安全检查结果: ").append(result.isSecure ? "安全" : "不安全").append("\n\n");
        statusBuilder.append("签名验证: ").append(result.signatureValid ? "通过" : "失败").append("\n");
        statusBuilder.append("Xposed检测: ").append(result.xposedDetected ? "检测到" : "未检测到").append("\n");
        statusBuilder.append("Xposed应用: ").append(result.xposedPackagesDetected ? "检测到" : "未检测到").append("\n");
        statusBuilder.append("调试模式: ").append(result.debugMode ? "是" : "否").append("\n");
        statusBuilder.append("模拟器: ").append(result.emulatorDetected ? "是" : "否").append("\n");

        Toast.makeText(this, result.isSecure ? "安全检查通过" : "警告：检测到安全风险！", Toast.LENGTH_SHORT).show();
    }

    /**
     * 获取安全报告
     */
    private void getSecurityReport() {
        Log.i(TAG, "Getting security report...");

        String report = SecurityGuard.getSecurityReport(this);
        resultTextView.setText(report);
    }

    /**
     * 获取当前应用签名
     */
    private void getCurrentSignature() {
        Log.i(TAG, "Getting current signature...");

        String signature = SecurityGuard.getSignature(this);

        StringBuilder info = new StringBuilder();
        info.append("当前应用签名哈希:\n\n");
        info.append(signature).append("\n\n");
        info.append("请将此签名添加到EXPECTED_SIGNATURE常量中\n");
        info.append("以启用签名验证功能");

        resultTextView.setText(info.toString());

        Log.i(TAG, "Current signature: " + signature);
        Toast.makeText(this, "签名已获取，请查看日志", Toast.LENGTH_SHORT).show();
    }
}