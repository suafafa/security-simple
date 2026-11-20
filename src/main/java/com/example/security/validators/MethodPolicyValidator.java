package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Set;

/**
 * 요청된 HTTP 메서드가 서블릿 보안 정책에 허용된 메서드(GET, POST 등)인지 검증하는 모듈형 검증기입니다.
 * <p>
 * {@link ServletPolicyRule}의 {@code extensions} 맵에서 {@code "methods"} 설정을 읽어 동작합니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class MethodPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "METHOD";
    public static final int ORDER = 20;

    /** 기본 생성자입니다 (식별자: "METHOD", 실행 순서: 20). */
    public MethodPolicyValidator() {
        super(NAME, ORDER);
    }

    /**
     * 서블릿 정책의 {@code extensions} 맵에서 허용된 HTTP 메서드 집합(대문자)을 추출합니다.
     *
     * @param policy 대상 서블릿 보안 정책 규칙
     * @return 허용된 HTTP 메서드 Set (미설정 시 빈 Set)
     */
    public static Set<String> getAllowedMethods(final ServletPolicyRule policy) {
        if (policy == null) {
            return Collections.emptySet();
        }
        return policy.getExtensionUpperSet("methods");
    }

    /**
     * 주어진 HTTP 메서드가 서블릿 정책에서 허용되는지 판별합니다.
     *
     * @param policy 대상 서블릿 보안 정책 규칙
     * @param method 검사할 HTTP 메서드 문자열 (예: "GET", "POST")
     * @return 허용된 메서드이면 true, 차단 대상이면 false
     */
    public static boolean isMethodAllowed(final ServletPolicyRule policy, final String method) {
        Set<String> allowed = getAllowedMethods(policy);
        if (allowed.isEmpty()) {
            return true;
        }
        return method != null && allowed.contains(method.trim().toUpperCase());
    }

    /**
     * 요청의 HTTP 메서드가 허용 목록({@code methods})에 포함되는지 검증하며,
     * 허용되지 않은 경우 405 Method Not Allowed (SEC-40501)로 차단합니다.
     */
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
}
