package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Open Redirect (오픈 리다이렉트) 화이트리스트 방어 검증기 (CWE-601)
 * <p>
 * {@link ServletPolicyRule} 수정 없이 {@code extensions} 맵에서
 * {@code "allowedRedirectDomains"}, {@code "allowRelativeRedirect"}, {@code "redirectParamNames"},
 * {@code "responseType"}, {@code "redirectUrl"} 설정을 읽어 동작합니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class OpenRedirectPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "OPEN_REDIRECT";
    public static final int ORDER = 35;

    private static final Set<String> DEFAULT_REDIRECT_PARAM_NAMES = Collections.unmodifiableSet(new LinkedHashSet<>(
            Arrays.asList("redirect", "redirect_to", "returnurl", "targeturl", "url", "dest", "continue", "next", "goto")
    ));

    private static final String[] ALLOWED_REDIRECT_DOMAINS_KEYS = {
            "allowedRedirectDomains", "allowed_redirect_domains", "redirectDomains", "security.allowedRedirectDomains"
    };
    private static final String[] ALLOW_RELATIVE_REDIRECT_KEYS = {
            "allowRelativeRedirect", "allow_relative_redirect", "security.allowRelativeRedirect"
    };
    private static final String[] REDIRECT_PARAM_NAMES_KEYS = {
            "redirectParamNames", "redirect_param_names", "redirectParams", "security.redirectParamNames"
    };
    private static final String[] RESPONSE_TYPE_KEYS = {
            "responseType", "response_type", "type"
    };
    private static final String[] REDIRECT_URL_KEYS = {
            "redirectUrl", "redirect", "redirect_url"
    };

    public OpenRedirectPolicyValidator() {
        super(NAME, ORDER);
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (request == null || policy == null) {
            return pass();
        }

        // 1. 요청 파라미터에서 리다이렉트 대상 URL 추출
        Set<String> redirectParamKeys = resolveRedirectParamNames(policy);
        Map<String, String[]> parameterMap = request.getParameterMap();

        if (parameterMap != null && !parameterMap.isEmpty() && !redirectParamKeys.isEmpty()) {
            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                String paramName = entry.getKey();
                if (paramName == null) continue;
                boolean isRedirectParam = redirectParamKeys.contains(paramName)
                        || redirectParamKeys.contains(paramName.toLowerCase());
                if (isRedirectParam) {
                    String[] values = entry.getValue();
                    if (values != null) {
                        for (String targetUrl : values) {
                            if (StringUtils.isNotBlank(targetUrl)) {
                                if (!isSafeRedirectUrl(targetUrl, policy, rootConfig)) {
                                    String blockedConfig = "param=" + SecurityUtils.sanitizeForLog(paramName)
                                            + ", redirectUrl=" + SecurityUtils.sanitizeForLog(targetUrl)
                                            + ", allowedRedirectDomains=" + resolveAllowedRedirectDomains(policy);
                                    return block(
                                            policy,
                                            SecurityErrorCode.OPEN_REDIRECT_FORBIDDEN,
                                            blockedConfig,
                                            "Untrusted or dangerous redirect URL detected in parameter [" + paramName + "]: "
                                                    + SecurityUtils.sanitizeForLog(targetUrl),
                                            targetUrl
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. 정책에 정적으로 지정된 redirectUrl이 존재하는 경우 검증
        String responseType = policy.getExtensionString(RESPONSE_TYPE_KEYS);
        String staticRedirectUrl = policy.getExtensionString(REDIRECT_URL_KEYS);
        if ("REDIRECT".equalsIgnoreCase(responseType) && StringUtils.isNotBlank(staticRedirectUrl)) {
            if (!isSafeRedirectUrl(staticRedirectUrl, policy, rootConfig)) {
                String blockedConfig = "responseType=REDIRECT, redirectUrl=" + SecurityUtils.sanitizeForLog(staticRedirectUrl);
                return block(
                        policy,
                        SecurityErrorCode.OPEN_REDIRECT_FORBIDDEN,
                        blockedConfig,
                        "Policy configured redirectUrl is untrusted: " + staticRedirectUrl,
                        staticRedirectUrl
                );
            }
        }

        return pass();
    }

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return "NONE";
        }
        return "allowRelativeRedirect=" + isAllowRelativeRedirect(policy)
                + ", allowedRedirectDomains=" + resolveAllowedRedirectDomains(policy)
                + ", redirectParamNames=" + resolveRedirectParamNames(policy);
    }

    public static boolean isAllowRelativeRedirect(final ServletPolicyRule policy) {
        if (policy == null) {
            return true;
        }
        Boolean val = policy.getExtensionBoolean(ALLOW_RELATIVE_REDIRECT_KEYS);
        return val == null || val;
    }

    public static Set<String> resolveAllowedRedirectDomains(final ServletPolicyRule policy) {
        if (policy == null) {
            return Collections.emptySet();
        }
        return policy.getExtensionLowerSet(ALLOWED_REDIRECT_DOMAINS_KEYS);
    }

    public static Set<String> resolveRedirectParamNames(final ServletPolicyRule policy) {
        Set<String> names = new LinkedHashSet<>(DEFAULT_REDIRECT_PARAM_NAMES);
        if (policy != null) {
            names.addAll(policy.getExtensionLowerSet(REDIRECT_PARAM_NAMES_KEYS));
        }
        return Collections.unmodifiableSet(names);
    }

    /**
     * 리다이렉트 대상 URL이 안전한 화이트리스트 도메인인지 정밀 검증합니다.
     */
    public static boolean isSafeRedirectUrl(final String targetUrl,
                                            final ServletPolicyRule policy,
                                            final ServletSecurityConfig rootConfig) {
        if (StringUtils.isBlank(targetUrl)) {
            return false;
        }

        // 1. CRLF 및 제어문자 인젝션 검사 (HTTP Response Splitting 방어)
        if (targetUrl.indexOf('\r') != -1 || targetUrl.indexOf('\n') != -1
                || targetUrl.contains("%0d") || targetUrl.contains("%0a")
                || targetUrl.contains("%0D") || targetUrl.contains("%0A")
                || targetUrl.indexOf('\0') != -1 || targetUrl.contains("%00")) {
            return false;
        }

        String trimmed = targetUrl.trim();

        // 2. 가상 스키마(javascript:, vbscript:, data:) 차단
        String lower = trimmed.toLowerCase();
        if (lower.startsWith("javascript:") || lower.startsWith("vbscript:") || lower.startsWith("data:")) {
            return false;
        }

        // 3. 프로토콜 상대 URL (//evil.com) 및 역슬래시 결합 (/\\evil.com, \\evil.com) 차단
        if (trimmed.startsWith("//") || trimmed.startsWith("/\\") || trimmed.startsWith("\\\\") || trimmed.startsWith("\\/")) {
            return false;
        }

        // 4. 내부 상대 경로 (/content/...) 처리
        if (trimmed.startsWith("/")) {
            if (trimmed.length() > 1 && (trimmed.charAt(1) == '/' || trimmed.charAt(1) == '\\')) {
                return false;
            }
            return isAllowRelativeRedirect(policy);
        }

        // 5. 절대 경로 (http:// 또는 https://) 도메인 화이트리스트 검사
        try {
            URI uri = URI.create(trimmed);
            String scheme = uri.getScheme();
            if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
                return false;
            }

            // UserInfo 기호 (@) 우회 차단 (예: https://safe.com@evil.com)
            if (StringUtils.isNotBlank(uri.getUserInfo()) || trimmed.contains("@")) {
                return false;
            }

            String host = uri.getHost();
            if (StringUtils.isBlank(host)) {
                return false;
            }

            String lowerHost = host.toLowerCase();

            // 도메인 화이트리스트 비교 (1순위: allowedRedirectDomains)
            Set<String> allowedDomains = resolveAllowedRedirectDomains(policy);
            if (!allowedDomains.isEmpty()) {
                if (matchesDomainWhitelist(lowerHost, allowedDomains)) {
                    return true;
                }
            }

            // 2순위: 서블릿 정책 또는 기본 정책(defaultPolicy)의 allowedReferrers를 신뢰 도메인으로 검사
            if (policy != null && !policy.getAllowedReferrers().isEmpty()) {
                if (matchesDomainWhitelist(lowerHost, policy.getAllowedReferrers())) {
                    return true;
                }
            }
            if (rootConfig != null && rootConfig.getDefaultPolicy() != null
                    && !rootConfig.getDefaultPolicy().getAllowedReferrers().isEmpty()) {
                if (matchesDomainWhitelist(lowerHost, rootConfig.getDefaultPolicy().getAllowedReferrers())) {
                    return true;
                }
            }

            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean matchesDomainWhitelist(final String host, final Set<String> allowedDomains) {
        for (String allowed : allowedDomains) {
            if (StringUtils.isBlank(allowed)) continue;
            String d = allowed.trim().toLowerCase();
            if (d.startsWith("*.")) {
                String baseDomain = d.substring(2);
                if (host.equals(baseDomain) || host.endsWith("." + baseDomain)) {
                    return true;
                }
            } else if (d.startsWith(".")) {
                String baseDomain = d.substring(1);
                if (host.equals(baseDomain) || host.endsWith("." + baseDomain)) {
                    return true;
                }
            } else {
                if (host.equals(d) || host.endsWith("." + d)) {
                    return true;
                }
            }
        }
        return false;
    }
}
