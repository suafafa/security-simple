package com.example.security.validators;

import com.example.security.models.ParamRule;
import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 요청 파라미터에 대한 다중 계층 보안 검증을 수행하는 모듈형 검증기입니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class ParamPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "PARAM";
    public static final int ORDER = 30;

    public ParamPolicyValidator() {
        super(NAME, ORDER);
    }

    public static boolean isAllowUndefinedParams(final ServletPolicyRule policy) {
        if (policy == null) {
            return false;
        }
        Boolean val = policy.getExtensionBoolean("allowUndefinedParams");
        return val != null && val;
    }

    public static Map<String, ParamRule> getParams(final ServletPolicyRule policy) {
        return ParamRule.extractParams(policy);
    }

    public static Map<String, ParamRule> resolveParams(final ServletPolicyRule policy,
                                                       final ServletSecurityConfig rootConfig) {
        Map<String, ParamRule> childParams = ParamRule.extractParams(policy);
        if (rootConfig != null && rootConfig.getDefaultPolicy() != null && rootConfig.getDefaultPolicy() != policy) {
            Map<String, ParamRule> defaultParams = ParamRule.extractParams(rootConfig.getDefaultPolicy());
            return ParamRule.mergeWithDefault(childParams, defaultParams);
        }
        return childParams;
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return pass();
        }
        Map<String, ParamRule> configuredParams = resolveParams(policy, rootConfig);
        Map<String, String[]> parameterMap = request != null ? request.getParameterMap() : null;
        boolean allowUndefined = isAllowUndefinedParams(policy);

        if ((configuredParams == null || configuredParams.isEmpty())
                && (parameterMap == null || parameterMap.isEmpty())) {
            return pass();
        }

        // 1. 필수 파라미터(required) 누락 여부 검사
        if (configuredParams != null && !configuredParams.isEmpty()) {
            for (Map.Entry<String, ParamRule> ruleEntry : configuredParams.entrySet()) {
                String paramName = ruleEntry.getKey();
                ParamRule rule = ruleEntry.getValue();

                if (rule.isEnabled() && rule.isRequired()) {
                    String[] values = parameterMap != null ? parameterMap.get(paramName) : null;
                    if (values == null || values.length == 0 || StringUtils.isBlank(values[0])) {
                        String blockedConfig = "param=" + paramName + ", required=true, rule=" + rule.toSummaryString() + ", actualValue=MISSING";
                        return block(
                                policy,
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
                ParamRule rule = (configuredParams != null) ? configuredParams.get(paramName) : null;

                // 2-1. 서블릿 정책에 정의되지 않은 파라미터 처리
                if (rule == null) {
                    if (!allowUndefined) {
                        String blockedConfig = "allowUndefinedParams=false, definedParams="
                                + (configuredParams != null ? configuredParams.keySet() : "[]")
                                + ", undefinedParam=" + SecurityUtils.sanitizeForLog(paramName);
                        return block(
                                policy,
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
                                return block(
                                        policy,
                                        SecurityErrorCode.PARAM_PATH_TRAVERSAL,
                                        blockedConfig,
                                        "Path Traversal attack pattern detected in undefined parameter ["
                                                + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
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
                        if (val == null) {
                            continue;
                        }
                        if (!rule.isAllowPathTraversal() && isPathTraversalAttack(val)) {
                            String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                    + ", allowPathTraversal=false, rule=" + rule.toSummaryString()
                                    + ", actualValue=" + SecurityUtils.sanitizeForLog(val);
                            return block(
                                    policy,
                                    SecurityErrorCode.PARAM_PATH_TRAVERSAL,
                                    blockedConfig,
                                    "Path Traversal attack pattern detected in parameter ["
                                            + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                    paramName
                            );
                        }

                        if (rule.getMinLength() != null && val.length() < rule.getMinLength()) {
                            String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                    + ", minLength=" + rule.getMinLength()
                                    + ", actualLength=" + val.length()
                                    + ", rule=" + rule.toSummaryString();
                            return block(
                                    policy,
                                    SecurityErrorCode.PARAM_TOO_SHORT,
                                    blockedConfig,
                                    "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] length ("
                                            + val.length() + ") < min (" + rule.getMinLength() + ")",
                                    paramName, rule.getMinLength()
                            );
                        }

                        if (rule.getMaxLength() != null && val.length() > rule.getMaxLength()) {
                            String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                    + ", maxLength=" + rule.getMaxLength()
                                    + ", actualLength=" + val.length()
                                    + ", rule=" + rule.toSummaryString();
                            return block(
                                    policy,
                                    SecurityErrorCode.PARAM_TOO_LONG,
                                    blockedConfig,
                                    "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] length ("
                                            + val.length() + ") > max (" + rule.getMaxLength() + ")",
                                    paramName, rule.getMaxLength()
                            );
                        }

                        if (rule.getCompiledPattern() != null && !rule.getCompiledPattern().matcher(val).matches()) {
                            String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                    + ", pattern=" + rule.getPattern()
                                    + ", actualValue=" + SecurityUtils.sanitizeForLog(val)
                                    + ", rule=" + rule.toSummaryString();
                            return block(
                                    policy,
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

        return pass();
    }

    public static boolean isPathTraversalAttack(final String value) {
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

    private static boolean containsDotDotSlash(final String str) {
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

    private static String safeUrlDecode(final String input) {
        if (input == null || (input.indexOf('%') == -1 && input.indexOf('+') == -1)) {
            return input;
        }
        try {
            return java.net.URLDecoder.decode(input, StandardCharsets.UTF_8.name());
        } catch (Exception ignored) {
            return input;
        }
    }
}
