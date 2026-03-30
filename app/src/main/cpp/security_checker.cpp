/**
 * 安全检查器实现
 */

#include "security_guard.h"
#include <sstream>
#include <ctime>

namespace security {

bool SecurityChecker::performSecurityCheck(JNIEnv* env, jobject context, const std::string& expectedSignature) {
    // 步骤1: 签名验证
    bool signatureValid = SignatureVerifier::verifySignature(env, context, expectedSignature);
    if (!signatureValid) {
        LOGE("Security check failed: Invalid signature");
        return false;
    }

    // 步骤2: Xposed检测
    bool xposedDetected = XposedDetector::detectXposed(env);
    if (xposedDetected) {
        LOGE("Security check failed: Xposed detected");
        return false;
    }

    LOGI("Security check passed");
    return true;
}

std::string SecurityChecker::getSecurityReport(JNIEnv* env, jobject context) {
    std::ostringstream report;

    // 报告头
    report << "=== Security Report ===\n";
    report << "Timestamp: " << time(nullptr) << "\n\n";

    // 签名信息
    report << "--- Signature Info ---\n";
    std::string signature = SignatureVerifier::getSignature(env, context);
    if (!signature.empty()) {
        report << "Current Signature: " << signature << "\n";
    } else {
        report << "Failed to get signature\n";
    }
    report << "\n";

    // Xposed检测结果
    report << "--- Xposed Detection ---\n";
    XposedDetector::DetectionResult detectionResult = XposedDetector::getDetailedDetectionResult(env);

    report << "Stack Trace Detection: " << (detectionResult.stackTraceFound ? "POSITIVE" : "Negative") << "\n";
    report << "Class Loader Detection: " << (detectionResult.classFound ? "POSITIVE" : "Negative") << "\n";
    report << "Method Hook Detection: " << (detectionResult.methodHooked ? "POSITIVE" : "Negative") << "\n";
    report << "Memory Pattern Detection: " << (detectionResult.memoryPatterns ? "POSITIVE" : "Negative") << "\n";
    report << "Native Hook Detection: " << (detectionResult.nativeHooked ? "POSITIVE" : "Negative") << "\n";
    report << "Thread Detection: " << (detectionResult.threadsFound ? "POSITIVE" : "Negative") << "\n";
    report << "File Detection: " << (detectionResult.filesFound ? "POSITIVE" : "Negative") << "\n";
    report << "\n";

    // 风险评估
    report << "--- Risk Assessment ---\n";
    report << "Risk Level: " << detectionResult.riskLevel << "/100\n";

    if (detectionResult.riskLevel == 0) {
        report << "Status: SAFE - No suspicious activity detected\n";
    } else if (detectionResult.riskLevel < 30) {
        report << "Status: LOW RISK - Minor concerns detected\n";
    } else if (detectionResult.riskLevel < 60) {
        report << "Status: MEDIUM RISK - Some suspicious activity detected\n";
    } else if (detectionResult.riskLevel < 80) {
        report << "Status: HIGH RISK - Significant threats detected\n";
    } else {
        report << "Status: CRITICAL - Severe threats detected\n";
    }

    return report.str();
}

} // namespace security