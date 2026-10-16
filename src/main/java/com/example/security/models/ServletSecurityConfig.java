package com.example.security.models;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 전역 필터 활성화 여부(enabled), 기본 신뢰 도메인(defaultReferrer),
 * 전역 검증기(REFERER, METHOD, PARAM) On/Off 설정 및 서블릿 정책 목록을 보관하는 루트 보안 설정 컨테이너입니다.
 * 초고속 정책 탐색을 위한 다계층 O(1) 해시 인덱스 캐싱을 포함합니다.
 */
public class ServletSecurityConfig {

    private static final Logger LOG = LoggerFactory.getLogger(ServletSecurityConfig.class);

    @SerializedName("enabled")
    private Boolean enabled = true;

    @SerializedName(value = "defaultReferrer", alternate = {"defaultReferer", "default_referrer", "default_referer"})
    private String defaultReferrer = "abc.com";

    @SerializedName(value = "validators", alternate = {"validatorSettings"})
    private JsonElement validators;

    @SerializedName(value = "disabledValidators", alternate = {"skipValidators"})
    private List<String> disabledValidators;

    @SerializedName(value = "enabledValidators")
    private List<String> enabledValidators;

    @SerializedName(value = "defaultPolicy", alternate = {"default", "globalPolicy"})
    private ServletPolicyRule defaultPolicy;

    @SerializedName("policies")
    private List<ServletPolicyRule> policies;

    // 런타임 검증기 활성화 상태 맵: 검증기 이름(대문자) -> Boolean
    private transient Map<String, Boolean> validatorStatusMap;

    // 고성능 O(1) Fast-Path 인덱싱 맵
    private transient Map<String, ServletPolicyRule> exactUriMap = Collections.emptyMap();
    private transient Map<String, ServletPolicyRule> resourceTypeMap = Collections.emptyMap();
    private transient List<ServletPolicyRule> patternOrPrefixPolicies = Collections.emptyList();

    // 동적 OSGi 서블릿 정책 등록 저장소
    private transient Map<String, ServletPolicyRule> dynamicExactUriMap = new ConcurrentHashMap<>();
    private transient Map<String, ServletPolicyRule> dynamicResourceTypeMap = new ConcurrentHashMap<>();
    private transient List<ServletPolicyRule> dynamicPatternPolicies = new CopyOnWriteArrayList<>();
    private transient Map<String, ServletPolicyRule> dynamicPoliciesByTarget = new ConcurrentHashMap<>();

    public ServletSecurityConfig() {
    }

    public ServletSecurityConfig(Boolean enabled, List<ServletPolicyRule> policies) {
        this.enabled = enabled;
        this.policies = policies;
        this.defaultReferrer = "abc.com";
        init();
    }

    public final void init() {
        Map<String, Boolean> map = validatorStatusMap != null ? new HashMap<>(validatorStatusMap) : new HashMap<>();
        if (validators != null && validators.isJsonObject()) {
            JsonObject obj = validators.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                try {
                    map.put(entry.getKey().trim().toUpperCase(), entry.getValue().getAsBoolean());
                } catch (Exception ignored) {
                }
            }
        }
        if (disabledValidators != null) {
            for (String v : disabledValidators) {
                if (StringUtils.isNotBlank(v)) {
                    map.put(v.trim().toUpperCase(), false);
                }
            }
        }
        if (enabledValidators != null) {
            for (String v : enabledValidators) {
                if (StringUtils.isNotBlank(v)) {
                    map.put(v.trim().toUpperCase(), true);
                }
            }
        }
        this.validatorStatusMap = Collections.unmodifiableMap(map);

        List<String> allValidationErrors = new ArrayList<>();

        if (defaultPolicy != null) {
            if (StringUtils.isBlank(defaultPolicy.getTarget())) {
                defaultPolicy.setTarget("DEFAULT");
            }
            defaultPolicy.validate(allValidationErrors);

            if (StringUtils.isNotBlank(defaultPolicy.getDefaultReferrer())) {
                this.defaultReferrer = defaultPolicy.getDefaultReferrer().trim();
            }
        }

        if (policies != null) {
            for (ServletPolicyRule rule : policies) {
                if (rule != null) {
                    rule.validate(allValidationErrors);
                }
            }
        }

        if (!allValidationErrors.isEmpty()) {
            throw new IllegalArgumentException("Servlet Security Policy Validation Failed (" + allValidationErrors.size() + " error(s) found):\n • "
                    + String.join("\n • ", allValidationErrors));
        }

        if (defaultPolicy != null) {
            defaultPolicy.init();
        }

        Map<String, ServletPolicyRule> exactMap = new HashMap<>();
        Map<String, ServletPolicyRule> resMap = new HashMap<>();
        List<ServletPolicyRule> patternList = new ArrayList<>();

        if (policies != null) {
            for (ServletPolicyRule rule : policies) {
                if (rule != null) {
                    rule.init();
                    String target = rule.getTarget();
                    if (StringUtils.isNotBlank(target)) {
                        String trimmed = target.trim();
                        if (rule.getCompiledTargetPattern() != null || trimmed.contains("*") || trimmed.contains("?") || trimmed.contains("^")) {
                            patternList.add(rule);
                        } else if (trimmed.startsWith("/")) {
                            exactMap.putIfAbsent(trimmed.toLowerCase(), rule);
                        } else {
                            resMap.putIfAbsent(trimmed, rule);
                        }
                    }
                }
            }
        }

        this.exactUriMap = Collections.unmodifiableMap(exactMap);
        this.resourceTypeMap = Collections.unmodifiableMap(resMap);
        this.patternOrPrefixPolicies = Collections.unmodifiableList(patternList);

        if (LOG.isDebugEnabled()) {
            LOG.debug("ServletSecurityConfig initialized: enabled={}, defaultReferrer={}, indexed: [exactUri={}, resourceType={}, patterns={}]",
                    enabled, defaultReferrer, exactMap.size(), resMap.size(), patternList.size());
        }

        if (dynamicExactUriMap == null) {
            dynamicExactUriMap = new ConcurrentHashMap<>();
        }
        if (dynamicResourceTypeMap == null) {
            dynamicResourceTypeMap = new ConcurrentHashMap<>();
        }
        if (dynamicPatternPolicies == null) {
            dynamicPatternPolicies = new CopyOnWriteArrayList<>();
        }
        if (dynamicPoliciesByTarget == null) {
            dynamicPoliciesByTarget = new ConcurrentHashMap<>();
        }

        if (defaultPolicy != null && !dynamicPoliciesByTarget.isEmpty()) {
            for (ServletPolicyRule dynRule : dynamicPoliciesByTarget.values()) {
                dynRule.inheritFrom(defaultPolicy);
                dynRule.init();
            }
        }
    }

    public ServletPolicyRule findMatchingPolicy(final HttpServletRequest request) {
        if (request == null) {
            return defaultPolicy;
        }

        String requestUri = request.getRequestURI();
        if (requestUri != null) {
            String lowerUri = requestUri.toLowerCase();

            // 계층 1: 전체 URI 직접 일치 조회 (O(1))
            if (dynamicExactUriMap != null) {
                ServletPolicyRule match = dynamicExactUriMap.get(lowerUri);
                if (match != null) {
                    return match;
                }
            }
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                ServletPolicyRule match = exactUriMap.get(lowerUri);
                if (match != null) {
                    return match;
                }
            }

            // 계층 2: 확장자 및 셀렉터 제거 후 기본 URI 조회 (O(1))
            int lastSlash = lowerUri.lastIndexOf('/');
            int dotIdx = lowerUri.indexOf('.', lastSlash >= 0 ? lastSlash : 0);
            if (dotIdx > 0) {
                String baseUri = lowerUri.substring(0, dotIdx);
                if (dynamicExactUriMap != null) {
                    ServletPolicyRule match = dynamicExactUriMap.get(baseUri);
                    if (match != null) {
                        return match;
                    }
                }
                if (exactUriMap != null && !exactUriMap.isEmpty()) {
                    ServletPolicyRule match = exactUriMap.get(baseUri);
                    if (match != null) {
                        return match;
                    }
                }
            }
        }

        // 계층 3: Sling ResourceType 직접 일치 조회 (O(1))
        if (request instanceof SlingHttpServletRequest) {
            Resource resource = ((SlingHttpServletRequest) request).getResource();
            if (resource != null) {
                String resourceType = resource.getResourceType();
                if (resourceType != null) {
                    if (dynamicResourceTypeMap != null) {
                        ServletPolicyRule match = dynamicResourceTypeMap.get(resourceType);
                        if (match != null) {
                            return match;
                        }
                    }
                    if (resourceTypeMap != null && !resourceTypeMap.isEmpty()) {
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
                    if (dynamicResourceTypeMap != null && !dynamicResourceTypeMap.isEmpty()) {
                        for (Map.Entry<String, ServletPolicyRule> entry : dynamicResourceTypeMap.entrySet()) {
                            if (resource.isResourceType(entry.getKey())) {
                                return entry.getValue();
                            }
                        }
                    }
                }
            }
        }

        // 계층 4: 정규식 패턴 및 접두사 매칭
        if (dynamicPatternPolicies != null && !dynamicPatternPolicies.isEmpty()) {
            for (ServletPolicyRule rule : dynamicPatternPolicies) {
                if (rule.matches(request)) {
                    return rule;
                }
            }
        }
        if (patternOrPrefixPolicies != null && !patternOrPrefixPolicies.isEmpty()) {
            for (ServletPolicyRule rule : patternOrPrefixPolicies) {
                if (rule.matches(request)) {
                    return rule;
                }
            }
        }

        // 계층 5: URI 내 상대 컴포넌트 경로 또는 경로 접두사 포함 여부 검사
        if (requestUri != null) {
            if (dynamicExactUriMap != null && !dynamicExactUriMap.isEmpty()) {
                for (ServletPolicyRule rule : dynamicExactUriMap.values()) {
                    if (rule.matches(request)) {
                        return rule;
                    }
                }
            }
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                for (ServletPolicyRule rule : exactUriMap.values()) {
                    if (rule.matches(request)) {
                        return rule;
                    }
                }
            }
            if (dynamicResourceTypeMap != null && !dynamicResourceTypeMap.isEmpty()) {
                for (ServletPolicyRule rule : dynamicResourceTypeMap.values()) {
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

    public void registerDynamicPolicy(final ServletPolicyRule rule) {
        if (rule == null || StringUtils.isBlank(rule.getTarget())) {
            return;
        }
        if (defaultPolicy != null) {
            rule.inheritFrom(defaultPolicy);
        }
        rule.init();

        String trimmed = rule.getTarget().trim();
        dynamicPoliciesByTarget.put(trimmed, rule);

        if (rule.getCompiledTargetPattern() != null || trimmed.contains("*") || trimmed.contains("?") || trimmed.contains("^")) {
            dynamicPatternPolicies.removeIf(r -> trimmed.equalsIgnoreCase(r.getTarget()));
            dynamicPatternPolicies.add(rule);
        } else if (trimmed.startsWith("/")) {
            dynamicExactUriMap.put(trimmed.toLowerCase(), rule);
        } else {
            dynamicResourceTypeMap.put(trimmed, rule);
        }
    }

    public void unregisterDynamicPolicy(final String target) {
        if (StringUtils.isBlank(target)) {
            return;
        }
        String trimmed = target.trim();
        dynamicPoliciesByTarget.remove(trimmed);
        dynamicExactUriMap.remove(trimmed.toLowerCase());
        dynamicResourceTypeMap.remove(trimmed);
        dynamicPatternPolicies.removeIf(r -> trimmed.equalsIgnoreCase(r.getTarget()));
    }

    public Map<String, ServletPolicyRule> getDynamicPolicies() {
        return Collections.unmodifiableMap(dynamicPoliciesByTarget);
    }

    public ServletPolicyRule getDynamicPolicy(final String target) {
        if (StringUtils.isBlank(target) || dynamicPoliciesByTarget == null) {
            return null;
        }
        String trimmed = target.trim();
        ServletPolicyRule rule = dynamicPoliciesByTarget.get(trimmed);
        if (rule == null) {
            rule = dynamicExactUriMap.get(trimmed.toLowerCase());
        }
        return rule;
    }

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getDefaultReferrer() {
        return StringUtils.isNotBlank(defaultReferrer) ? defaultReferrer.trim() : "abc.com";
    }

    public void setDefaultReferrer(String defaultReferrer) {
        this.defaultReferrer = defaultReferrer;
    }

    public ServletPolicyRule getDefaultPolicy() {
        return defaultPolicy;
    }

    public void setDefaultPolicy(ServletPolicyRule defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    public List<ServletPolicyRule> getPolicies() {
        return policies != null ? policies : Collections.emptyList();
    }

    public void setPolicies(List<ServletPolicyRule> policies) {
        this.policies = policies;
    }

    public boolean isValidatorEnabled(String validatorName) {
        if (validatorStatusMap != null && validatorName != null) {
            Boolean status = validatorStatusMap.get(validatorName.trim().toUpperCase());
            if (status != null) {
                return status;
            }
        }
        return true;
    }

    public void setValidatorEnabled(String validatorName, boolean enabled) {
        if (StringUtils.isBlank(validatorName)) {
            return;
        }
        Map<String, Boolean> map = validatorStatusMap != null ? new HashMap<>(validatorStatusMap) : new HashMap<>();
        map.put(validatorName.trim().toUpperCase(), enabled);
        this.validatorStatusMap = Collections.unmodifiableMap(map);
    }

    public Map<String, Boolean> getValidatorStatusMap() {
        return validatorStatusMap != null ? validatorStatusMap : Collections.emptyMap();
    }
}
