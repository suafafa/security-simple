package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * 요청된 HTTP 메서드가 서블릿 보안 정책에 허용된 메서드(GET, POST 등)인지 검증하는 모듈형 검증기입니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class MethodPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "METHOD";
    public static final int ORDER = 20;

    public MethodPolicyValidator() {
        super(NAME, ORDER);
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return pass();
        }
        String httpMethod = request != null ? request.getMethod() : null;

        if (!policy.isMethodAllowed(httpMethod)) {
            String blockedConfig = "allowedMethods=" + policy.getMethods() + ", requestMethod=" + httpMethod;
            return block(
                    policy,
                    SecurityErrorCode.METHOD_NOT_ALLOWED,
                    blockedConfig,
                    "HTTP method [" + httpMethod + "] not allowed for target ["
                            + SecurityUtils.sanitizeForLog(policy.getTarget())
                            + "] (allowedMethods=" + policy.getMethods() + ")",
                    httpMethod
            );
        }
        return pass();
    }

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        String allowed = (policy == null || policy.getMethods().isEmpty()) ? "ALL" : policy.getMethods().toString();
        String method = request != null ? request.getMethod() : "null";
        return "allowedMethods=" + allowed + ", requestMethod=" + method;
    }
}
