package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * HTTP Referer 및 Origin 헤더가 허용 도메인 목록({@code allowedReferrers} — 기본 정책 {@code default.referrers} 상속 포함)과
 * 일치하는지 검증하는 모듈형 검증기입니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class RefererPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "REFERER";
    public static final int ORDER = 10;

    /** 기본 생성자입니다 (식별자: "REFERER", 실행 순서: 10). */
    public RefererPolicyValidator() {
        super(NAME, ORDER);
    }

    /**
     * 서블릿 정책의 {@code extensions} 맵에서 허용된 Referer 도메인 집합(소문자)을 추출합니다.
     *
     * @param policy 대상 서블릿 보안 정책 규칙
     * @return 허용된 Referer 도메인 Set
     */
    public static Set<String> getAllowedReferrers(final ServletPolicyRule policy) {
        if (policy == null) {
            return Collections.emptySet();
        }
        return policy.getExtensionLowerSet("allowedReferrers");
    }

    /**
     * 요청의 Referer(또는 Origin) 헤더를 추출하여 허용된 도메인인지 검증합니다.
     * 헤더가 누락되었거나 허용 도메인 목록과 일치하지 않으면 403 Forbidden (SEC-40303)으로 차단합니다.
     */
    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        Set<String> effectiveReferrers = resolveEffectiveReferrers(policy, rootConfig);
        String rawReferer = request != null
                ? StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin"))
                : null;

        if (!isRefererAllowed(request, policy, rootConfig)) {
            String blockedConfig = "allowedReferrers=" + effectiveReferrers
                    + ", requestReferer=" + (rawReferer != null ? SecurityUtils.sanitizeForLog(rawReferer) : "MISSING");
            return block(
                    policy,
                    SecurityErrorCode.REFERER_UNTRUSTED,
                    blockedConfig,
                    "Untrusted or missing Referer/Origin header [" + SecurityUtils.sanitizeForLog(rawReferer)
                            + "] for target [" + SecurityUtils.sanitizeForLog(policy != null ? policy.getTarget() : "")
                            + "] (allowedReferrers=" + effectiveReferrers + ")"
            );
        }
        return pass();
    }

    /**
     * 요청의 Referer 또는 Origin 헤더에서 호스트명을 추출하여 허용 도메인 목록(allowedReferrers)과 일치하는지 판별합니다.
     */
    public boolean isRefererAllowed(final HttpServletRequest request,
                                    final ServletPolicyRule policy,
                                    final ServletSecurityConfig rootConfig) {
        if (request == null) {
            return false;
        }
        String referer = StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin"));
        if (StringUtils.isBlank(referer)) {
            return false;
        }

        String host = extractHost(referer);
        if (StringUtils.isBlank(host)) {
            return false;
        }

        for (String allowed : resolveEffectiveReferrers(policy, rootConfig)) {
            if (isDomainMatched(host, allowed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 기본 정책({@code defaultPolicy})의 허용 도메인과 개별 서블릿 정책의 허용 도메인을 병합하여 반환합니다.
     */
    public static Set<String> resolveEffectiveReferrers(final ServletPolicyRule policy, final ServletSecurityConfig rootConfig) {
        Set<String> effective = new LinkedHashSet<>();
        if (rootConfig != null && rootConfig.getDefaultPolicy() != null) {
            effective.addAll(getAllowedReferrers(rootConfig.getDefaultPolicy()));
        }
        if (policy != null) {
            effective.addAll(getAllowedReferrers(policy));
        }
        if (effective.isEmpty()) {
            effective.add("abc.com");
        }
        return Collections.unmodifiableSet(effective);
    }

    /**
     * Referer/Origin URL 문자열에서 소문자 호스트명(Host)을 추출합니다.
     */
    private String extractHost(final String refererUrl) {
        try {
            URI uri = new URI(refererUrl);
            String host = uri.getHost();
            return host != null ? host.toLowerCase().trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 요청 호스트명이 허용 도메인(서브도메인 포함)과 일치하는지 확인합니다.
     */
    private boolean isDomainMatched(final String host, final String domain) {
        if (StringUtils.isBlank(domain) || host == null) {
            return false;
        }
        String d = domain.toLowerCase().trim();
        if (d.startsWith("*.")) {
            d = d.substring(2);
        } else if (d.startsWith(".")) {
            d = d.substring(1);
        }
        return host.equals(d) || host.endsWith("." + d);
    }
}
