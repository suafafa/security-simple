package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 요청된 HTTP 메서드가 서블릿 보안 정책에 허용된 메서드(GET, POST 등)인지 검증하는 모듈형 검증기입니다.
 */
public class MethodPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(MethodPolicyValidator.class);

    @Override
    public String getName() {
        return "METHOD";
    }

    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String httpMethod = request != null ? request.getMethod() : null;

        if (LOG.isDebugEnabled()) {
            LOG.debug("MethodPolicyValidator checking method [{}] against allowed {} for target [{}]",
                    httpMethod, policy.getMethods(), policy.getTarget());
        }

        if (!policy.isMethodAllowed(httpMethod)) {
            return ValidationResult.error(
                    SecurityErrorCode.METHOD_NOT_ALLOWED,
                    "HTTP method [" + httpMethod + "] not allowed for target: " + SecurityUtils.sanitizeForLog(policy.getTarget()),
                    httpMethod
            );
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("MethodPolicyValidator PASSED for target [{}] | PassedConfig=[{}]",
                    policy.getTarget(), describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String allowed = (policy == null || policy.getMethods().isEmpty()) ? "ALL" : policy.getMethods().toString();
        String method = request != null ? request.getMethod() : "null";
        return "allowedMethods=" + allowed + ", requestMethod=" + method;
    }
}
