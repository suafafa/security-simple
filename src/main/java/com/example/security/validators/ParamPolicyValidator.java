package com.example.security.validators;

import com.example.security.models.ParamRule;
import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * 요청 파라미터에 대한 다중 계층 보안 검증을 수행하는 모듈형 검증기입니다:
 * - 정의되지 않은 파라미터(allowUndefinedParams) 허용 여부 검사 (기본값: false 차단)
 * - 필수 파라미터(required) 존재 여부 검사
 * - 경로 조작(Path Traversal, CWE-22) 공격 탐지 및 차단
 * - 최소/최대 글자 수(minLength, maxLength) 제한 검사
 * - 정규식 패턴(pattern) 일치 검사
 */
public class ParamPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(ParamPolicyValidator.class);

    /**
     * 검증기 고유 식별자("PARAM")를 반환합니다.
     *
     * @return 검증기 이름 "PARAM"
     */
    @Override
    public String getName() {
        return "PARAM";
    }

    /**
     * 요청 파라미터 전체를 대상으로 필수 여부, 미정의 파라미터 차단, Path Traversal,
     * 최소/최대 글자 수, 정규식 패턴을 순차적으로 검증합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 검증 결과 (ValidationResult)
     */
    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        Map<String, ParamRule> configuredParams = policy.getParams();
        Map<String, String[]> parameterMap = request != null ? request.getParameterMap() : null;

        if ((configuredParams == null || configuredParams.isEmpty())
                && (parameterMap == null || parameterMap.isEmpty())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[PARAM] 설정된 파라미터 및 유입된 요청 파라미터가 모두 없어 즉시 통과합니다 - target=[{}] | PassedConfig=[{}]",
                        policy.getTarget(), describePassedConfig(request, policy, rootConfig));
            }
            return ValidationResult.ok();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("[PARAM] 파라미터 검증 시작 - target=[{}], 요청 파라미터={}, 설정된 파라미터={}, allowUndefinedParams={}",
                    policy.getTarget(),
                    parameterMap != null ? parameterMap.keySet() : "[]",
                    configuredParams != null ? configuredParams.keySet() : "[]",
                    policy.isAllowUndefinedParams());
        }

        // 1. 필수 파라미터(required) 누락 여부 검사
        if (configuredParams != null && !configuredParams.isEmpty()) {
            for (Map.Entry<String, ParamRule> ruleEntry : configuredParams.entrySet()) {
                String paramName = ruleEntry.getKey();
                ParamRule rule = ruleEntry.getValue();

                if (rule.isEnabled() && rule.isRequired()) {
                    String[] values = getParameterValues(parameterMap, paramName);
                    if (values == null || values.length == 0 || StringUtils.isBlank(values[0])) {
                        String blockedConfig = "param=" + paramName + ", required=true, rule=" + rule.toSummaryString() + ", actualValue=MISSING";
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[PARAM] 필수 파라미터 누락으로 차단 - target=[{}], BlockedByConfig=[{}]",
                                    policy.getTarget(), blockedConfig);
                        }
                        return ValidationResult.errorWithConfig(
                                SecurityErrorCode.PARAM_REQUIRED,
                                blockedConfig,
                                "Missing required parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] for target ["
                                        + SecurityUtils.sanitizeForLog(policy.getTarget()) + "] (rule=" + rule.toSummaryString() + ")",
                                paramName
                        );
                    }
                }
            }
        }

        // 2. 유입된 요청 파라미터들의 보안 및 형식 유효성 검사
        if (parameterMap != null && !parameterMap.isEmpty()) {
            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                String paramName = entry.getKey();
                String[] paramValues = entry.getValue();

                ParamRule rule = null;
                if (configuredParams != null && !configuredParams.isEmpty()) {
                    rule = configuredParams.get(paramName);
                    if (rule == null) {
                        rule = configuredParams.get(paramName.toLowerCase());
                    }
                }

                // 2-1. 서블릿 정책에 정의되지 않은 파라미터 처리
                if (rule == null) {
                    if (!policy.isAllowUndefinedParams()) {
                        String blockedConfig = "allowUndefinedParams=false, definedParams="
                                + (configuredParams != null ? configuredParams.keySet() : "[]")
                                + ", undefinedParam=" + SecurityUtils.sanitizeForLog(paramName);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[PARAM] 정의되지 않은 파라미터 유입으로 차단 - target=[{}], BlockedByConfig=[{}]",
                                    policy.getTarget(), blockedConfig);
                        }
                        return ValidationResult.errorWithConfig(
                                SecurityErrorCode.PARAM_UNDEFINED,
                                blockedConfig,
                                "Undefined parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] not permitted for target ["
                                        + SecurityUtils.sanitizeForLog(policy.getTarget()) + "] (allowUndefinedParams=false, definedParams="
                                        + (configuredParams != null ? configuredParams.keySet() : "[]") + ")",
                                paramName
                        );
                    }
                    // allowUndefinedParams=true로 허용된 경우에도 Path Traversal 검사는 수행
                    if (paramValues != null) {
                        for (String val : paramValues) {
                            if (val != null && isPathTraversalAttack(val)) {
                                String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                        + "(undefined), allowPathTraversal=false, actualValue=" + SecurityUtils.sanitizeForLog(val);
                                return ValidationResult.errorWithConfig(
                                        SecurityErrorCode.PARAM_PATH_TRAVERSAL,
                                        blockedConfig,
                                        "Path Traversal attack pattern detected in undefined parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                        paramName
                                );
                            }
                        }
                    }
                    continue;
                }

                // 2-2. 정의된 파라미터 규칙(ParamRule)에 따른 상세 검증
                if (rule.isEnabled() && paramValues != null) {
                    for (String val : paramValues) {
                        if (val != null) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("[PARAM] 파라미터 [{}] 값 검증 중 - valueLength={}, rule={}",
                                        paramName, val.length(), rule.toSummaryString());
                            }

                            // [보안 방어 계층] 경로 조작(Path Traversal / Directory Traversal) 탐지
                            if (!rule.isAllowPathTraversal() && isPathTraversalAttack(val)) {
                                String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                        + ", allowPathTraversal=false, rule=" + rule.toSummaryString()
                                        + ", actualValue=" + SecurityUtils.sanitizeForLog(val);
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("[PARAM] Path Traversal 탐지로 차단 - target=[{}], BlockedByConfig=[{}]",
                                            policy.getTarget(), blockedConfig);
                                }
                                return ValidationResult.errorWithConfig(
                                        SecurityErrorCode.PARAM_PATH_TRAVERSAL,
                                        blockedConfig,
                                        "Path Traversal attack pattern detected in parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                        paramName
                                );
                            }

                            // 최소 글자 수(minLength) 제한 검사
                            if (rule.getMinLength() != null && val.length() < rule.getMinLength()) {
                                String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                        + ", minLength=" + rule.getMinLength()
                                        + ", actualLength=" + val.length()
                                        + ", rule=" + rule.toSummaryString();
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("[PARAM] 최소 길이(minLength) 미달로 차단 - target=[{}], BlockedByConfig=[{}]",
                                            policy.getTarget(), blockedConfig);
                                }
                                return ValidationResult.errorWithConfig(
                                        SecurityErrorCode.PARAM_TOO_SHORT,
                                        blockedConfig,
                                        "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] length (" + val.length() + ") < min (" + rule.getMinLength() + ")",
                                        paramName, rule.getMinLength()
                                );
                            }

                            // 최대 글자 수(maxLength) 제한 검사
                            if (rule.getMaxLength() != null && val.length() > rule.getMaxLength()) {
                                String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                        + ", maxLength=" + rule.getMaxLength()
                                        + ", actualLength=" + val.length()
                                        + ", rule=" + rule.toSummaryString();
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("[PARAM] 최대 길이(maxLength) 초과로 차단 - target=[{}], BlockedByConfig=[{}]",
                                            policy.getTarget(), blockedConfig);
                                }
                                return ValidationResult.errorWithConfig(
                                        SecurityErrorCode.PARAM_TOO_LONG,
                                        blockedConfig,
                                        "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] length (" + val.length() + ") > max (" + rule.getMaxLength() + ")",
                                        paramName, rule.getMaxLength()
                                );
                            }

                            // 정규식 패턴(pattern) 일치 검사
                            if (rule.getCompiledPattern() != null && !rule.getCompiledPattern().matcher(val).matches()) {
                                String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                        + ", pattern=" + rule.getPattern()
                                        + ", actualValue=" + SecurityUtils.sanitizeForLog(val)
                                        + ", rule=" + rule.toSummaryString();
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("[PARAM] 정규식 패턴(pattern) 불일치로 차단 - target=[{}], BlockedByConfig=[{}]",
                                            policy.getTarget(), blockedConfig);
                                }
                                return ValidationResult.errorWithConfig(
                                        SecurityErrorCode.PARAM_INVALID_FORMAT,
                                        blockedConfig,
                                        "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] format validation failed against pattern ["
                                                + rule.getPattern() + "] (actualValue=" + SecurityUtils.sanitizeForLog(val) + ")",
                                        paramName
                                );
                            }
                        }
                    }
                }
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("[PARAM] 모든 파라미터 검증 통과 - target=[{}] | PassedConfig=[{}]",
                    policy.getTarget(), describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    /**
     * 파라미터 검증 통과 시 적용된 파라미터 보안 설정(allowUndefinedParams, params)을 요약하여 반환합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 통과한 설정값 요약 문자열
     */
    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return "NONE";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("allowUndefinedParams=").append(policy.isAllowUndefinedParams());
        Map<String, ParamRule> configuredParams = policy.getParams();
        if (configuredParams != null && !configuredParams.isEmpty()) {
            sb.append(", params={");
            boolean first = true;
            for (Map.Entry<String, ParamRule> entry : configuredParams.entrySet()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(entry.getKey()).append("=").append(entry.getValue() != null ? entry.getValue().toSummaryString() : "{}");
            }
            sb.append("}");
        } else {
            sb.append(", params={}");
        }
        return sb.toString();
    }

    /**
     * 요청 파라미터 맵에서 대소문자 구분 없이 파라미터 배열 값을 추출합니다.
     * 1차로 정확히 일치하는 키를 O(1) 조회하고, 없을 경우에만 대소문자 무시 비교를 수행합니다.
     *
     * @param parameterMap 요청 파라미터 맵
     * @param paramName    찾을 파라미터 이름
     * @return 파라미터 값 배열 (존재하지 않으면 null)
     */
    private static String[] getParameterValues(Map<String, String[]> parameterMap, String paramName) {
        if (parameterMap == null || paramName == null) {
            return null;
        }
        String[] values = parameterMap.get(paramName);
        if (values != null) {
            return values;
        }
        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            if (paramName.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * CWE-22: 파라미터 값에 경로 조작(Path Traversal / Directory Traversal) 공격 패턴이 포함되어 있는지 검사합니다.
     *
     * [방어 대상 공격 유형]:
     * 1. 널 바이트 주입 (%00, \0)
     * 2. 1차 및 2차 URL 인코딩된 상위 디렉토리 이동 (%2e%2e/, %252e%252e%252f, ..%c0%af)
     * 3. 표준 상위 디렉토리 이동 (../, ..\, /.., \..)
     * 4. 웹 서버/리버스 프록시 세미콜론 우회 (..;/, ..;\)
     *
     * @param value 검증할 파라미터 값
     * @return 경로 조작 공격 시그니처가 감지되면 true (위험), 정상이면 false (안전)
     */
    public static boolean isPathTraversalAttack(String value) {
        if (StringUtils.isBlank(value)) {
            return false;
        }

        if (value.indexOf('.') == -1 && value.indexOf('%') == -1 && value.indexOf('\0') == -1) {
            return false;
        }

        if (value.indexOf('\0') != -1) {
            return true;
        }

        String lowerRaw = value.toLowerCase();

        if (lowerRaw.contains("%00")
                || lowerRaw.contains("%2e%2e")
                || lowerRaw.contains("%252e")
                || lowerRaw.contains("..%2f")
                || lowerRaw.contains("..%5c")
                || lowerRaw.contains("%2e.")
                || lowerRaw.contains(".%2e")
                || lowerRaw.contains("..%c0%af")
                || lowerRaw.contains("..%c1%9c")
                || lowerRaw.contains("..%ef%bc%8f")) {
            return true;
        }

        String decoded1 = safeUrlDecode(lowerRaw);
        String decoded2 = safeUrlDecode(decoded1);

        return containsDotDotSlash(lowerRaw)
                || (!decoded1.equals(lowerRaw) && containsDotDotSlash(decoded1))
                || (!decoded2.equals(decoded1) && containsDotDotSlash(decoded2));
    }

    /**
     * 문자열 내에 상위 디렉토리 이동 시퀀스(../, ..\, ..; 등)가 포함되어 있는지 검사합니다.
     *
     * @param str 검사할 소문자 문자열
     * @return 상위 디렉토리 이동 패턴이 있으면 true
     */
    private static boolean containsDotDotSlash(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        if (str.equals("..")) {
            return true;
        }
        return str.contains("../")
                || str.contains("..\\")
                || str.contains("/..")
                || str.contains("\\..")
                || str.contains("..;/")
                || str.contains("..;\\")
                || str.contains("..;");
    }

    /**
     * 잘못된 % 인코딩 문자열이 들어와도 예외 없이 안전하게 URL 디코딩을 수행합니다.
     *
     * @param input 디코딩할 원본 문자열
     * @return URL 디코딩된 문자열 (실패 시 원본 반환)
     */
    private static String safeUrlDecode(String input) {
        if (input == null || (input.indexOf('%') == -1 && input.indexOf('+') == -1)) {
            return input;
        }
        try {
            return java.net.URLDecoder.decode(input, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (Exception ignored) {
            return input;
        }
    }
}
