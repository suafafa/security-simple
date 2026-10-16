package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Set;

/**
 * HTTP Referer 및 Origin 헤더가 기본 신뢰 도메인(abc.com) 또는 서블릿 정책별 허용 도메인(allowedReferrers)과
 * 일치하는지 검증하는 모듈형 검증기입니다.
 */
public class RefererPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(RefererPolicyValidator.class);

    @Override
    public String getName() {
        return "REFERER";
    }

    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        if (!isRefererAllowed(request, policy, rootConfig)) {
            return ValidationResult.error(
                    SecurityErrorCode.REFERER_UNTRUSTED,
                    "Untrusted or missing Referer header for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
            );
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("RefererPolicyValidator PASSED for target [{}] | PassedConfig=[{}]",
                    policy != null ? policy.getTarget() : "null", describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        String defaultDomain = rootConfig != null ? rootConfig.getDefaultReferrer() : (policy != null ? policy.getDefaultReferrer() : "abc.com");
        Set<String> allowed = policy != null ? policy.getAllowedReferrers() : java.util.Collections.emptySet();
        String reqReferer = request != null ? (StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin"))) : "null";
        return "defaultReferrer=" + defaultDomain + ", allowedReferrers=" + allowed + ", requestReferer=" + reqReferer;
    }

    public boolean isRefererAllowed(final HttpServletRequest request, final ServletPolicyRule policy, final ServletSecurityConfig rootConfig) {
        String referer = request.getHeader("Referer");
        if (StringUtils.isBlank(referer)) {
            referer = request.getHeader("Origin");
        }

        if (StringUtils.isBlank(referer)) {
            return false;
        }

        String host = extractHost(referer);
        if (StringUtils.isBlank(host)) {
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("RefererPolicyValidator checking host [{}] against default [{}] and policy allowed {} for target [{}]",
                    host, rootConfig != null ? rootConfig.getDefaultReferrer() : "abc.com",
                    policy != null ? policy.getAllowedReferrers() : "null",
                    policy != null ? policy.getTarget() : "null");
        }

        // 1. 기본 신뢰 도메인 검사: abc.com (또는 루트 설정에 지정된 defaultReferrer)
        String defaultDomain = rootConfig != null ? rootConfig.getDefaultReferrer() : "abc.com";
        if (isDomainMatched(host, defaultDomain)) {
            return true;
        }

        // 2. 개별 서블릿 정책에 추가 지정된 허용 Referer 도메인 검사
        Set<String> allowedReferrers = policy.getAllowedReferrers();
        if (allowedReferrers != null && !allowedReferrers.isEmpty()) {
            for (String allowed : allowedReferrers) {
                if (isDomainMatched(host, allowed)) {
                    return true;
                }
            }
        }

        return false;
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
        if (host.equals(domain) || host.endsWith("." + domain)) {
            return true;
        }
        String d = domain.toLowerCase().trim();
        return host.equals(d) || host.endsWith("." + d);
    }
}
