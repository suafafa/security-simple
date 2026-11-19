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
 * HTTP Referer 및 Origin 헤더가 허용 도메인 목록(allowedReferrers — 기본 정책 default.referrers 상속 포함)과
 * 일치하는지 검증하는 모듈형 검증기입니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class RefererPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "REFERER";
    public static final int ORDER = 10;

    public RefererPolicyValidator() {
        super(NAME, ORDER);
    }

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

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        Set<String> effectiveReferrers = resolveEffectiveReferrers(policy, rootConfig);
        String reqReferer = request != null
                ? StringUtils.defaultIfBlank(request.getHeader("Referer"), request.getHeader("Origin"))
                : "null";
        return "allowedReferrers=" + effectiveReferrers + ", requestReferer=" + reqReferer;
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
