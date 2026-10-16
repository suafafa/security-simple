package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * 요청된 HTTP 메서드가 서블릿 보안 정책에 허용된 메서드(GET, POST 등)인지 검증하는 모듈형 검증기입니다.
 */
public class MethodPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(MethodPolicyValidator.class);

    /**
     * 검증기 고유 식별자("METHOD")를 반환합니다.
     *
     * @return 검증기 이름 "METHOD"
     */
    @Override
    public String getName() {
        return "METHOD";
    }

    /**
     * 요청의 HTTP 메서드(GET, POST, PUT, DELETE 등)가 서블릿 정책의 허용 메서드 목록(methods)에 포함되는지 검증합니다.
     * 허용되지 않은 메서드인 경우 405 Method Not Allowed (SEC-40501)와 함께 차단된 설정 정보를 반환합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 검증 결과 (ValidationResult)
     */
    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String httpMethod = request != null ? request.getMethod() : null;

        if (LOG.isDebugEnabled()) {
            LOG.debug("[METHOD] HTTP 메서드 검증 시작 - target=[{}], 요청 Method=[{}], 허용 Methods={}",
                    policy.getTarget(), httpMethod, policy.getMethods().isEmpty() ? "ALL" : policy.getMethods());
        }

        if (!policy.isMethodAllowed(httpMethod)) {
            String blockedConfig = "allowedMethods=" + policy.getMethods() + ", requestMethod=" + httpMethod;
            if (LOG.isDebugEnabled()) {
                LOG.debug("[METHOD] HTTP 메서드 검증 실패(차단) - target=[{}], BlockedByConfig=[{}]",
                        policy.getTarget(), blockedConfig);
            }
            return ValidationResult.errorWithConfig(
                    SecurityErrorCode.METHOD_NOT_ALLOWED,
                    blockedConfig,
                    "HTTP method [" + httpMethod + "] not allowed for target [" + SecurityUtils.sanitizeForLog(policy.getTarget())
                            + "] (allowedMethods=" + policy.getMethods() + ")",
                    httpMethod
            );
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("[METHOD] HTTP 메서드 검증 통과 - target=[{}] | PassedConfig=[{}]",
                    policy.getTarget(), describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    /**
     * HTTP 메서드 검증 통과 시 적용된 허용 메서드 설정과 실제 요청 메서드를 요약하여 반환합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 통과한 설정값 요약 문자열
     */
    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String allowed = (policy == null || policy.getMethods().isEmpty()) ? "ALL" : policy.getMethods().toString();
        String method = request != null ? request.getMethod() : "null";
        return "allowedMethods=" + allowed + ", requestMethod=" + method;
    }
}
