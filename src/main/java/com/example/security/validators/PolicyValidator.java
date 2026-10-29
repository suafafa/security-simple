package com.example.security.validators;

import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;

import javax.servlet.http.HttpServletRequest;

/**
 * 유입되는 HTTP 요청을 특정 보안 정책 항목에 대해 검증하는 모듈형 전략(Strategy) 인터페이스입니다.
 */
public interface PolicyValidator {

    /**
     * 검증기의 고유 식별자 이름을 반환합니다 (예: "REFERER", "METHOD", "PARAM", "RUNMODE").
     */
    String getName();

    /**
     * 필터 체인 내에서 이 검증기가 실행될 우선순위(오름차순)를 반환합니다.
     * 값이 작을수록 먼저 실행됩니다 (예: RUNMODE=5, REFERER=10, METHOD=20, PARAM=30, 기본값=100).
     *
     * @return 실행 순서 값 (작을수록 먼저 실행)
     */
    default int getOrder() {
        return 100;
    }

    /**
     * 루트 설정 및 개별 서블릿 정책의 On/Off 토글을 기반으로 현재 검증기의 활성화 여부를 판별합니다.
     *
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 활성화 상태이면 true, 검증을 생략(바이패스)해야 하면 false
     */
    default boolean isEnabled(ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String name = getName();
        if (rootConfig != null && !rootConfig.isValidatorEnabled(name)) {
            return false;
        }
        if (policy != null && !policy.isValidatorEnabled(name)) {
            return false;
        }
        return true;
    }

    /**
     * 유입된 HTTP 요청이 매칭된 보안 정책 규칙을 준수하는지 검증합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 성공 또는 차단 상태 코드와 에러 메시지를 담은 ValidationResult
     */
    ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig);

    /**
     * 검증기 통과 시 디버그 로그에 출력할 통과된 설정값 요약 정보를 반환합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 통과한 설정값 요약 문자열
     */
    default String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        return policy != null ? policy.getTargetIdentifier() : "NONE";
    }
}
