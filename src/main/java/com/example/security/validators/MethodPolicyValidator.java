package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * 요청된 HTTP 메서드가 서블릿 보안 정책에 허용된 메서드(GET, POST 등)인지 검증하는 모듈형 검증기입니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class MethodPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "METHOD";
    public static final int ORDER = 20;

    public static final Set<String> VALID_HTTP_METHODS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    )));

    public MethodPolicyValidator() {
        super(NAME, ORDER);
    }

    public static Set<String> getAllowedMethods(final ServletPolicyRule policy) {
        if (policy == null) {
            return Collections.emptySet();
        }
        return policy.getExtensionUpperSet("methods");
    }

    public static boolean isMethodAllowed(final ServletPolicyRule policy, final String method) {
        Set<String> allowed = getAllowedMethods(policy);
        if (allowed.isEmpty()) {
            return true;
        }
        return method != null && allowed.contains(method.trim().toUpperCase());
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return pass();
        }
        String httpMethod = request != null ? request.getMethod() : null;
        Set<String> allowedMethods = getAllowedMethods(policy);

        if (!isMethodAllowed(policy, httpMethod)) {
            String blockedConfig = "allowedMethods=" + allowedMethods + ", requestMethod=" + httpMethod;
            return block(
                    policy,
                    SecurityErrorCode.METHOD_NOT_ALLOWED,
                    blockedConfig,
                    "HTTP method [" + httpMethod + "] not allowed for target ["
                            + SecurityUtils.sanitizeForLog(policy.getTarget())
                            + "] (allowedMethods=" + allowedMethods + ")",
                    httpMethod
            );
        }
        return pass();
    }

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        Set<String> allowedMethods = getAllowedMethods(policy);
        String allowed = allowedMethods.isEmpty() ? "ALL" : allowedMethods.toString();
        String method = request != null ? request.getMethod() : "null";
        return "allowedMethods=" + allowed + ", requestMethod=" + method;
    }
}
