package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * HTTP Referer 및 Origin 헤더가 허용 도메인 목록(allowedReferrers — 기본 정책 default.referrers 상속 포함)과
 * 일치하는지 검증하는 모듈형 검증기입니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class RefererPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(RefererPolicyValidator.class);

    @Override
    public String getName() {
        return "REFERER";
    }

    @Override
    public int getOrder() {
        return 10;
    }

    /**
     * 요청의 Referer(또는 Origin) 헤더를 추출하여 허용된 도메인인지 검증합니다.
     * 헤더가 누락되었거나 허용 도메인 목록과 일치하지 않으면 403 Forbidden (SEC-40303)으로 차단합니다.
     */
    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        Set<String> effectiveReferrers = resolveEffectiveReferrers(policy, rootConfig);
        String rawReferer = request != null ? StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin")) : null;

        if (LOG.isDebugEnabled()) {
            LOG.debug("[REFERER] Referer 검증 시작 - target=[{}], 요청 Referer/Origin=[{}], 허용 도메인={}",
                    policy != null ? policy.getTarget() : "null",
                    SecurityUtils.sanitizeForLog(rawReferer),
                    effectiveReferrers);
        }

        if (!isRefererAllowed(request, policy, rootConfig)) {
            String blockedConfig = "allowedReferrers=" + effectiveReferrers
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
                            + "] (allowedReferrers=" + effectiveReferrers + ")"
            );
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("[REFERER] Referer 검증 통과 - target=[{}] | PassedConfig=[{}]",
                    policy != null ? policy.getTarget() : "null", describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        Set<String> effectiveReferrers = resolveEffectiveReferrers(policy, rootConfig);
        String reqReferer = request != null ? (StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin"))) : "null";
        return "allowedReferrers=" + effectiveReferrers + ", requestReferer=" + reqReferer;
    }

    /**
     * 요청의 Referer 또는 Origin 헤더에서 호스트명을 추출하여 허용 도메인 목록(allowedReferrers)과 일치하는지 판별합니다.
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

        Set<String> effectiveReferrers = resolveEffectiveReferrers(policy, rootConfig);
        for (String allowed : effectiveReferrers) {
            if (isDomainMatched(host, allowed)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("[REFERER] 요청 호스트([{}])가 허용 도메인([{}])과 일치합니다.", host, allowed);
                }
                return true;
            }
        }

        return false;
    }

    private Set<String> resolveEffectiveReferrers(final ServletPolicyRule policy, final ServletSecurityConfig rootConfig) {
        Set<String> effective = new LinkedHashSet<>();
        if (rootConfig != null && rootConfig.getDefaultPolicy() != null && rootConfig.getDefaultPolicy().getAllowedReferrers() != null) {
            effective.addAll(rootConfig.getDefaultPolicy().getAllowedReferrers());
        }
        if (policy != null && policy.getAllowedReferrers() != null) {
            effective.addAll(policy.getAllowedReferrers());
        }
        if (effective.isEmpty()) {
            effective.add("abc.com");
        }
        return Collections.unmodifiableSet(effective);
    }

    private String extractHost(final String refererUrl) {
        try {
            URI uri = new URI(refererUrl);
            String host = uri.getHost();
            return host != null ? host.toLowerCase().trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

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
