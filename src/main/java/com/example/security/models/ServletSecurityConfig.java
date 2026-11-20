package com.example.security.models;

import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 전역 필터 활성화 여부(enabled), 전역 실행 모드(mode), 기본 정책(defaultPolicy) 및
 * 번들별 {@code .cfg.json}({@code EndpointPolicyRegistry})에서 로드된 엔드포인트 보안 정책을 보관하는 루트 설정 컨테이너입니다.
 */
public class ServletSecurityConfig {

    private static final Logger LOG = LoggerFactory.getLogger(ServletSecurityConfig.class);

    private Boolean enabled = true;
    private String mode = "ENFORCE";
    private ServletPolicyRule defaultPolicy;

    // 단일 O(1) 정책 인덱스 저장소 (.cfg.json 정책 등록용)
    private transient Map<String, ServletPolicyRule> exactUriMap = new ConcurrentHashMap<>();
    private transient Map<String, ServletPolicyRule> resourceTypeMap = new ConcurrentHashMap<>();
    private transient List<ServletPolicyRule> patternPolicies = new CopyOnWriteArrayList<>();
    private transient Map<String, ServletPolicyRule> policiesByTarget = new ConcurrentHashMap<>();

    public ServletSecurityConfig(Boolean enabled) {
        this.enabled = enabled;
        init();
    }

    /**
     * 루트 설정 및 기본 정책(defaultPolicy)의 유효성을 검증하고 인덱스를 초기화합니다.
     */
    public final void init() {
        this.mode = "MONITOR".equalsIgnoreCase(StringUtils.trimToEmpty(this.mode)) ? "MONITOR" : "ENFORCE";

        List<String> allValidationErrors = new ArrayList<>();

        if (defaultPolicy != null) {
            if (StringUtils.isBlank(defaultPolicy.getTarget())) {
                defaultPolicy.setTarget("DEFAULT");
            }
            defaultPolicy.validate(allValidationErrors);
        }

        if (!allValidationErrors.isEmpty()) {
            throw new IllegalArgumentException("Servlet Security Policy Validation Failed (" + allValidationErrors.size() + " error(s) found):\n • "
                    + String.join("\n • ", allValidationErrors));
        }

        if (defaultPolicy != null) {
            defaultPolicy.init();
        }

        if (exactUriMap == null) {
            exactUriMap = new ConcurrentHashMap<>();
        }
        if (resourceTypeMap == null) {
            resourceTypeMap = new ConcurrentHashMap<>();
        }
        if (patternPolicies == null) {
            patternPolicies = new CopyOnWriteArrayList<>();
        }
        if (policiesByTarget == null) {
            policiesByTarget = new ConcurrentHashMap<>();
        }

        if (defaultPolicy != null && !policiesByTarget.isEmpty()) {
            for (ServletPolicyRule rule : policiesByTarget.values()) {
                rule.inheritFrom(defaultPolicy);
                rule.init();
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("ServletSecurityConfig 초기화 완료 - enabled={}, 등록된 정책 수={}",
                    enabled, policiesByTarget.size());
        }
    }

    /**
     * 다계층 O(1) Fast-Path 인덱스를 사용하여 유입된 요청에 매칭되는 보안 정책을 탐색합니다:
     * 1. 전체 URI 직접 일치 조회 (O(1))
     * 2. 확장자 및 셀렉터를 제거한 기본 URI 조회 (O(1))
     * 3. Sling ResourceType 직접 일치 및 상위 타입 조회 (O(1))
     * 4. 정규식 패턴 및 와일드카드 규칙 조회
     * 5. URI 내 상대 컴포넌트 경로 또는 접두사 포함 여부 조회
     * 6. 매칭 실패 시 전사 기본 정책(defaultPolicy)으로 폴백(Fallback)
     *
     * @param request 유입된 HTTP 요청
     * @return 매칭된 ServletPolicyRule (매칭 정책 및 기본 정책이 모두 없으면 null)
     */
    public ServletPolicyRule findMatchingPolicy(final HttpServletRequest request) {
        if (request == null) {
            return defaultPolicy;
        }

        String requestUri = request.getRequestURI();
        if (requestUri != null) {
            String lowerUri = requestUri.toLowerCase();

            // 계층 1: 전체 URI 직접 일치 조회 (O(1))
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                ServletPolicyRule match = exactUriMap.get(lowerUri);
                if (match != null) {
                    return match;
                }
            }

            // 계층 2: 확장자 및 셀렉터 제거 후 기본 URI 조회 (O(1))
            int lastSlash = lowerUri.lastIndexOf('/');
            int dotIdx = lowerUri.indexOf('.', lastSlash >= 0 ? lastSlash : 0);
            if (dotIdx > 0 && exactUriMap != null && !exactUriMap.isEmpty()) {
                String baseUri = lowerUri.substring(0, dotIdx);
                ServletPolicyRule match = exactUriMap.get(baseUri);
                if (match != null) {
                    return match;
                }
            }
        }

        // 계층 3: Sling ResourceType 직접 일치 및 상위 계층 조회 (O(1))
        if (request instanceof SlingHttpServletRequest) {
            Resource resource = ((SlingHttpServletRequest) request).getResource();
            if (resource != null) {
                String resourceType = resource.getResourceType();
                if (resourceType != null && resourceTypeMap != null && !resourceTypeMap.isEmpty()) {
                    ServletPolicyRule match = resourceTypeMap.get(resourceType);
                    if (match != null) {
                        return match;
                    }
                    for (Map.Entry<String, ServletPolicyRule> entry : resourceTypeMap.entrySet()) {
                        if (resource.isResourceType(entry.getKey())) {
                            return entry.getValue();
                        }
                    }
                }
            }
        }

        // 계층 4: 정규식 패턴 및 와일드카드 매칭
        if (patternPolicies != null && !patternPolicies.isEmpty()) {
            for (ServletPolicyRule rule : patternPolicies) {
                if (rule.matches(request)) {
                    return rule;
                }
            }
        }

        // 계층 5: URI 내 상대 컴포넌트 경로 또는 경로 접두사 포함 여부 검사
        if (requestUri != null) {
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                for (ServletPolicyRule rule : exactUriMap.values()) {
                    if (rule.matches(request)) {
                        return rule;
                    }
                }
            }
            if (resourceTypeMap != null && !resourceTypeMap.isEmpty()) {
                for (ServletPolicyRule rule : resourceTypeMap.values()) {
                    if (rule.matches(request)) {
                        return rule;
                    }
                }
            }
        }

        // 계층 6: 매칭된 정책이 없을 경우 기본 정책(defaultPolicy)으로 폴백
        return defaultPolicy;
    }

    /**
     * 보안 정책 규칙을 런타임 인덱스에 등록합니다.
     * 기본 정책({@code defaultPolicy})이 설정되어 있으면 자동으로 상속받은 후 인덱싱합니다.
     *
     * @param rule 등록할 보안 정책 규칙
     */
    public void registerPolicy(final ServletPolicyRule rule) {
        if (rule == null || StringUtils.isBlank(rule.getTarget())) {
            return;
        }
        if (defaultPolicy != null) {
            rule.inheritFrom(defaultPolicy);
        }
        rule.init();

        String trimmed = rule.getTarget().trim();
        policiesByTarget.put(trimmed, rule);

        if (rule.getCompiledTargetPattern() != null || trimmed.contains("*") || trimmed.contains("?") || trimmed.contains("^")) {
            patternPolicies.removeIf(r -> trimmed.equalsIgnoreCase(r.getTarget()));
            patternPolicies.add(rule);
        } else if (trimmed.startsWith("/")) {
            exactUriMap.put(trimmed.toLowerCase(), rule);
        } else {
            resourceTypeMap.put(trimmed, rule);
        }
    }

    /**
     * 등록된 모든 개별 엔드포인트 보안 정책 인덱스를 초기화(전체 삭제)합니다.
     */
    public void clearPolicies() {
        policiesByTarget.clear();
        exactUriMap.clear();
        resourceTypeMap.clear();
        patternPolicies.clear();
    }

    /**
     * 현재 등록된 모든 엔드포인트 보안 정책 맵(읽기 전용)을 반환합니다.
     *
     * @return 타겟별 보안 정책 맵
     */
    public Map<String, ServletPolicyRule> getPolicies() {
        return Collections.unmodifiableMap(policiesByTarget);
    }

    /**
     * 특정 타겟 경로 또는 resourceType에 해당하는 보안 정책을 조회합니다.
     *
     * @param target 조회할 타겟 문자열
     * @return 매칭된 ServletPolicyRule (없을 경우 null)
     */
    public ServletPolicyRule getPolicy(final String target) {
        if (StringUtils.isBlank(target) || policiesByTarget == null) {
            return null;
        }
        String trimmed = target.trim();
        ServletPolicyRule rule = policiesByTarget.get(trimmed);
        if (rule == null) {
            rule = exactUriMap.get(trimmed.toLowerCase());
        }
        return rule;
    }

    /**
     * 전역 보안 필터 설정의 활성화 여부를 반환합니다.
     *
     * @return 활성화 시 true (기본값 true)
     */
    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    /**
     * 전역 보안 필터 설정의 활성화 여부를 설정합니다.
     *
     * @param enabled 활성화 여부
     */
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * 전사 공통 기본 보안 정책(defaultPolicy)을 반환합니다.
     *
     * @return 기본 보안 정책 규칙
     */
    public ServletPolicyRule getDefaultPolicy() {
        return defaultPolicy;
    }

    /**
     * 전사 공통 기본 보안 정책(defaultPolicy)을 설정합니다.
     *
     * @param defaultPolicy 기본 보안 정책 규칙
     */
    public void setDefaultPolicy(ServletPolicyRule defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    /**
     * 전역 보안 실행 모드({@code "ENFORCE"} 또는 {@code "MONITOR"})를 반환합니다.
     *
     * @return 전역 실행 모드 문자열 (기본값 {@code "ENFORCE"})
     */
    public String getMode() {
        return "MONITOR".equalsIgnoreCase(StringUtils.trimToEmpty(mode)) ? "MONITOR" : "ENFORCE";
    }

    /**
     * 문자열({@code "ENFORCE"} 또는 {@code "MONITOR"})로 전역 보안 실행 모드를 설정합니다.
     *
     * @param modeStr 설정할 모드 문자열
     */
    public void setMode(final String modeStr) {
        this.mode = "MONITOR".equalsIgnoreCase(StringUtils.trimToEmpty(modeStr)) ? "MONITOR" : "ENFORCE";
    }
}
