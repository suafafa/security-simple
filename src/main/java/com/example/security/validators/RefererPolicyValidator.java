package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Set;

/**
 * HTTP Referer 및 Origin 헤더가 기본 신뢰 도메인(defaultReferrer) 또는 서블릿 정책별 허용 도메인(allowedReferrers)과
 * 일치하는지 검증하는 모듈형 검증기입니다.
 */
public class RefererPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(RefererPolicyValidator.class);

    /**
     * 검증기 고유 식별자("REFERER")를 반환합니다.
     *
     * @return 검증기 이름 "REFERER"
     */
    @Override
    public String getName() {
        return "REFERER";
    }

    /**
     * 요청의 Referer(또는 Origin) 헤더를 추출하여 허용된 도메인인지 검증합니다.
     * 헤더가 누락되었거나 허용 도메인 목록과 일치하지 않으면 403 Forbidden (SEC-40303)으로 차단합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 검증 결과 (ValidationResult)
     */
    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String defaultDomain = rootConfig != null ? rootConfig.getDefaultReferrer() : (policy != null && policy.getDefaultReferrer() != null ? policy.getDefaultReferrer() : "abc.com");
        Set<String> allowedReferrers = policy != null ? policy.getAllowedReferrers() : java.util.Collections.emptySet();
        String rawReferer = request != null ? StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin")) : null;

        if (LOG.isDebugEnabled()) {
            LOG.debug("[REFERER] Referer 검증 시작 - target=[{}], 요청 Referer/Origin=[{}], 기본 도메인=[{}], 추가 허용 도메인={}",
                    policy != null ? policy.getTarget() : "null",
                    SecurityUtils.sanitizeForLog(rawReferer),
                    defaultDomain,
                    allowedReferrers);
        }

        if (!isRefererAllowed(request, policy, rootConfig)) {
            String blockedConfig = "defaultReferrer=" + defaultDomain
                    + ", allowedReferrers=" + allowedReferrers
                    + ", requestReferer=" + (rawReferer != null ? SecurityUtils.sanitizeForLog(rawReferer) : "MISSING");
            if (LOG.isDebugEnabled()) {
                LOG.debug("[REFERER] Referer 검증 실패(차단) - target=[{}], BlockedByConfig=[{}]",
                        policy != null ? policy.getTarget() : "null", blockedConfig);
            }
            return ValidationResult.errorWithConfig(
                    SecurityErrorCode.REFERER_UNTRUSTED,
                    blockedConfig,
                    "Untrusted or missing Referer/Origin header [" + SecurityUtils.sanitizeForLog(rawReferer)
                            + "] for target [" + SecurityUtils.sanitizeForLog(policy != null ? policy.getTarget() : "")
                            + "] (defaultReferrer=" + defaultDomain + ", allowedReferrers=" + allowedReferrers + ")"
            );
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("[REFERER] Referer 검증 통과 - target=[{}] | PassedConfig=[{}]",
                    policy != null ? policy.getTarget() : "null", describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    /**
     * Referer 검증 통과 시 적용된 신뢰 도메인 설정과 실제 요청의 Referer 정보를 요약하여 반환합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 통과한 설정값 요약 문자열
     */
    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String defaultDomain = rootConfig != null ? rootConfig.getDefaultReferrer() : (policy != null ? policy.getDefaultReferrer() : "abc.com");
        Set<String> allowed = policy != null ? policy.getAllowedReferrers() : java.util.Collections.emptySet();
        String reqReferer = request != null ? (StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin"))) : "null";
        return "defaultReferrer=" + defaultDomain + ", allowedReferrers=" + allowed + ", requestReferer=" + reqReferer;
    }

    /**
     * 요청의 Referer 또는 Origin 헤더에서 호스트명을 추출하여 기본 도메인(defaultReferrer) 또는
     * 정책별 추가 허용 도메인(allowedReferrers)과 일치하는지 판별합니다.
     *
     * @param request    유입된 HTTP 요청
     * @param policy     매칭된 서블릿 보안 정책 규칙
     * @param rootConfig 루트 서블릿 보안 설정
     * @return 신뢰할 수 있는 도메인이면 true, 누락되었거나 미인가 도메인이면 false
     */
    public boolean isRefererAllowed(final HttpServletRequest request, final ServletPolicyRule policy, final ServletSecurityConfig rootConfig) {
        String referer = request.getHeader("Referer");
        if (StringUtils.isBlank(referer)) {
            referer = request.getHeader("Origin");
            if (LOG.isDebugEnabled() && StringUtils.isNotBlank(referer)) {
                LOG.debug("[REFERER] Referer 헤더가 없어 Origin 헤더([{}])를 대체 사용합니다.", SecurityUtils.sanitizeForLog(referer));
            }
        }

        if (StringUtils.isBlank(referer)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[REFERER] 요청에 Referer 및 Origin 헤더가 모두 누락되었습니다.");
            }
            return false;
        }

        String host = extractHost(referer);
        if (StringUtils.isBlank(host)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[REFERER] Referer/Origin 값([{}])에서 유효한 호스트명을 추출할 수 없습니다.", SecurityUtils.sanitizeForLog(referer));
            }
            return false;
        }

        // 1. 기본 신뢰 도메인 검사 (예: abc.com 및 *.abc.com)
        String defaultDomain = rootConfig != null ? rootConfig.getDefaultReferrer() : "abc.com";
        if (isDomainMatched(host, defaultDomain)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[REFERER] 요청 호스트([{}])가 기본 신뢰 도메인([{}])과 일치합니다.", host, defaultDomain);
            }
            return true;
        }

        // 2. 개별 서블릿 정책에 추가 지정된 허용 Referer 도메인 검사
        Set<String> allowedReferrers = policy != null ? policy.getAllowedReferrers() : null;
        if (allowedReferrers != null && !allowedReferrers.isEmpty()) {
            for (String allowed : allowedReferrers) {
                if (isDomainMatched(host, allowed)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[REFERER] 요청 호스트([{}])가 서블릿 추가 허용 도메인([{}])과 일치합니다.", host, allowed);
                    }
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Referer 또는 Origin URL 문자열을 파싱하여 소문자 호스트명(Host)만 안전하게 추출합니다.
     *
     * @param refererUrl Referer 또는 Origin 헤더 문자열
     * @return 추출된 소문자 호스트명 (파싱 실패 시 null)
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
     * 추출된 요청 호스트명이 허용 도메인(또는 해당 도메인의 서브도메인)과 일치하는지 확인합니다.
     *
     * @param host   요청에서 추출한 호스트명 (예: "sub.abc.com")
     * @param domain 허용된 도메인 설정값 (예: "abc.com" 또는 "*.abc.com")
     * @return 일치하거나 서브도메인이면 true, 아니면 false
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
