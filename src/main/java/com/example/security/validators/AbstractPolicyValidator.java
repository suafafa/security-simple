package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * 새로운 {@link PolicyValidator}를 손쉽게 추가할 수 있도록 공통 보일러플레이트(이름, 실행 순서,
 * 통과/차단 디버그 로깅, {@link ValidationResult} 생성 헬퍼)를 제공하는 추상 베이스 클래스입니다.
 * <p>
 * 새로운 검증기를 만들 때는 이 클래스를 상속받아 {@link #doValidate(HttpServletRequest, ServletPolicyRule, ServletSecurityConfig)}만
 * 구현하고 {@code @Component(service = PolicyValidator.class)} 어노테이션을 붙이면 {@code SecurityFilter}에 자동 등록됩니다.
 */
public abstract class AbstractPolicyValidator implements PolicyValidator {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final String name;
    private final int order;

    /**
     * 검증기 이름과 기본 실행 순서(100)로 초기화합니다.
     *
     * @param name 검증기 고유 식별자 (예: "RUNMODE", "CSRF")
     */
    protected AbstractPolicyValidator(final String name) {
        this(name, 100);
    }

    /**
     * 검증기 이름과 지정된 실행 순서로 초기화합니다.
     *
     * @param name  검증기 고유 식별자 (예: "RUNMODE")
     * @param order 필터 체인 내 실행 순서 (작을수록 먼저 실행)
     */
    protected AbstractPolicyValidator(final String name, final int order) {
        this.name = name != null ? name.trim().toUpperCase() : "CUSTOM";
        this.order = order;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public final ValidationResult validate(final HttpServletRequest request,
                                           final ServletPolicyRule policy,
                                           final ServletSecurityConfig rootConfig) {
        ValidationResult result = doValidate(request, policy, rootConfig);
        if (result == null) {
            result = ValidationResult.ok();
        }
        if (result.isValid() && log.isDebugEnabled()) {
            log.debug("[{}] 검증 통과 - target=[{}] | PassedConfig=[{}]",
                    name,
                    policy != null ? policy.getTarget() : "null",
                    describePassedConfig(request, policy, rootConfig));
        }
        return result;
    }

    /**
     * 하위 클래스에서 실제 보안 정책 검증 로직만 간결하게 구현하는 템플릿 메서드입니다.
     * 통과 시 {@link #pass()}, 차단 시 {@link #block} 메서드를 호출하여 반환하면 됩니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 검증 결과 ({@link ValidationResult})
     */
    protected abstract ValidationResult doValidate(HttpServletRequest request,
                                                   ServletPolicyRule policy,
                                                   ServletSecurityConfig rootConfig);

    /**
     * 검증 통과 결과를 반환합니다.
     *
     * @return {@link ValidationResult#ok()}
     */
    protected ValidationResult pass() {
        return ValidationResult.ok();
    }

    /**
     * 표준 {@link SecurityErrorCode}를 사용하여 차단 결과를 생성하고 디버그 로그를 기록합니다.
     *
     * @param policy          매칭된 서블릿 정책 규칙
     * @param errorCode       표준 보안 에러 코드
     * @param blockedConfig   차단 원인이 된 설정값 및 입력값 요약 문자열
     * @param violationDetail 서버 감사 로그용 상세 위반 사유
     * @param messageArgs     응답 메시지 포맷 인자
     * @return 차단 {@link ValidationResult}
     */
    protected ValidationResult block(final ServletPolicyRule policy,
                                     final SecurityErrorCode errorCode,
                                     final String blockedConfig,
                                     final String violationDetail,
                                     final Object... messageArgs) {
        if (log.isDebugEnabled()) {
            log.debug("[{}] 검증 실패(차단) - target=[{}], BlockedByConfig=[{}]",
                    name, policy != null ? policy.getTarget() : "null", blockedConfig);
        }
        return ValidationResult.errorWithConfig(errorCode, blockedConfig, violationDetail, messageArgs);
    }

    /**
     * {@link SecurityErrorCode} 열거형 수정 없이 커스텀 HTTP 상태 코드와 서브 에러 코드로 차단 결과를 생성합니다.
     *
     * @param policy          매칭된 서블릿 정책 규칙
     * @param statusCode      HTTP 상태 코드 (예: 403, 404)
     * @param customSubCode   커스텀 서브 에러 코드 (예: "SEC-40305")
     * @param blockedConfig   차단 원인이 된 설정값 및 입력값 요약 문자열
     * @param violationDetail 서버 감사 로그용 상세 위반 사유
     * @param responseMessage 클라이언트에 반환할 에러 메시지
     * @return 차단 {@link ValidationResult}
     */
    protected ValidationResult blockCustom(final ServletPolicyRule policy,
                                           final int statusCode,
                                           final String customSubCode,
                                           final String blockedConfig,
                                           final String violationDetail,
                                           final String responseMessage) {
        if (log.isDebugEnabled()) {
            log.debug("[{}] 검증 실패(차단) - target=[{}], BlockedByConfig=[{}]",
                    name, policy != null ? policy.getTarget() : "null", blockedConfig);
        }
        return ValidationResult.errorCustom(statusCode, customSubCode, blockedConfig, violationDetail, responseMessage);
    }
}
