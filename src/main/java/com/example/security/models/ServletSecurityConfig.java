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

    /**
     * 개별 서블릿의 security.* 설정을 무시하고 글로벌 defaultPolicy만 강제 적용할지 여부입니다.
     */
    @SerializedName("ignoreServletPolicies")
    private Boolean ignoreServletPolicies = false;

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

    /**
     * 기본 생성자입니다.
     */
    public ServletSecurityConfig() {
    }

    /**
     * 필터 활성화 여부와 정적 정책 리스트로 루트 보안 설정 객체를 생성하고 인덱스를 초기화합니다.
     *
     * @param enabled  전역 필터 활성화 여부
     * @param policies 정적 서블릿 보안 정책 리스트
     */
    public ServletSecurityConfig(Boolean enabled, List<ServletPolicyRule> policies) {
        this.enabled = enabled;
        this.policies = policies;
        this.defaultReferrer = "abc.com";
        init();
    }

    /**
     * 루트 설정, 기본 정책(defaultPolicy), 개별 서블릿 정책(policies)의 유효성을 검증하고
     * 런타임 O(1) 고속 조회를 위한 다계층 해시 인덱스를 초기화합니다.
     */
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
            LOG.debug("ServletSecurityConfig 초기화 완료 - enabled={}, defaultReferrer={}, 인덱싱 현황: [exactUri={}, resourceType={}, patterns={}]",
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

    /**
     * 다계층 O(1) Fast-Path 인덱스를 사용하여 유입된 요청에 매칭되는 서블릿 보안 정책을 탐색합니다:
     * 1. 동적/정적 전체 URI 직접 일치 조회 (O(1))
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

        // 글로벌 기본 정책(defaultPolicy) 강제 적용 모드인 경우 서블릿별 정책 조회를 건너뜁니다.
        if (isIgnoreServletPolicies()) {
            if (defaultPolicy != null && LOG.isDebugEnabled()) {
                LOG.debug("[정책 매칭: ignoreServletPolicies=true] 서블릿 개별 정책을 무시하고 글로벌 defaultPolicy를 강제 적용합니다. URI=[{}]",
                        request.getRequestURI());
            }
            return defaultPolicy;
        }

        String requestUri = request.getRequestURI();
        if (requestUri != null) {
            String lowerUri = requestUri.toLowerCase();

            // 계층 1: 전체 URI 직접 일치 조회 (O(1))
            if (dynamicExactUriMap != null) {
                ServletPolicyRule match = dynamicExactUriMap.get(lowerUri);
                if (match != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 1 - 동적 URI 일치] requestUri=[{}] -> target=[{}]", requestUri, match.getTarget());
                    }
                    return match;
                }
            }
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                ServletPolicyRule match = exactUriMap.get(lowerUri);
                if (match != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 1 - 정적 URI 일치] requestUri=[{}] -> target=[{}]", requestUri, match.getTarget());
                    }
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
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 2 - 동적 Base URI 일치] requestUri=[{}], baseUri=[{}] -> target=[{}]",
                                    requestUri, baseUri, match.getTarget());
                        }
                        return match;
                    }
                }
                if (exactUriMap != null && !exactUriMap.isEmpty()) {
                    ServletPolicyRule match = exactUriMap.get(baseUri);
                    if (match != null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 2 - 정적 Base URI 일치] requestUri=[{}], baseUri=[{}] -> target=[{}]",
                                    requestUri, baseUri, match.getTarget());
                        }
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
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("[정책 매칭: Tier 3 - 동적 ResourceType 일치] resourceType=[{}] -> target=[{}]",
                                        resourceType, match.getTarget());
                            }
                            return match;
                        }
                    }
                    if (resourceTypeMap != null && !resourceTypeMap.isEmpty()) {
                        ServletPolicyRule match = resourceTypeMap.get(resourceType);
                        if (match != null) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("[정책 매칭: Tier 3 - 정적 ResourceType 일치] resourceType=[{}] -> target=[{}]",
                                        resourceType, match.getTarget());
                            }
                            return match;
                        }
                        for (Map.Entry<String, ServletPolicyRule> entry : resourceTypeMap.entrySet()) {
                            if (resource.isResourceType(entry.getKey())) {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("[정책 매칭: Tier 3 - 정적 상위 ResourceType 일치] resourceType=[{}] -> target=[{}]",
                                            resourceType, entry.getValue().getTarget());
                                }
                                return entry.getValue();
                            }
                        }
                    }
                    if (dynamicResourceTypeMap != null && !dynamicResourceTypeMap.isEmpty()) {
                        for (Map.Entry<String, ServletPolicyRule> entry : dynamicResourceTypeMap.entrySet()) {
                            if (resource.isResourceType(entry.getKey())) {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("[정책 매칭: Tier 3 - 동적 상위 ResourceType 일치] resourceType=[{}] -> target=[{}]",
                                            resourceType, entry.getValue().getTarget());
                                }
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
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 4 - 동적 정규식 패턴 일치] requestUri=[{}] -> target=[{}]",
                                requestUri, rule.getTarget());
                    }
                    return rule;
                }
            }
        }
        if (patternOrPrefixPolicies != null && !patternOrPrefixPolicies.isEmpty()) {
            for (ServletPolicyRule rule : patternOrPrefixPolicies) {
                if (rule.matches(request)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 4 - 정적 정규식 패턴 일치] requestUri=[{}] -> target=[{}]",
                                requestUri, rule.getTarget());
                    }
                    return rule;
                }
            }
        }

        // 계층 5: URI 내 상대 컴포넌트 경로 또는 경로 접두사 포함 여부 검사
        if (requestUri != null) {
            if (dynamicExactUriMap != null && !dynamicExactUriMap.isEmpty()) {
                for (ServletPolicyRule rule : dynamicExactUriMap.values()) {
                    if (rule.matches(request)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 5 - 동적 접두사 일치] requestUri=[{}] -> target=[{}]",
                                    requestUri, rule.getTarget());
                        }
                        return rule;
                    }
                }
            }
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                for (ServletPolicyRule rule : exactUriMap.values()) {
                    if (rule.matches(request)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 5 - 정적 접두사 일치] requestUri=[{}] -> target=[{}]",
                                    requestUri, rule.getTarget());
                        }
                        return rule;
                    }
                }
            }
            if (dynamicResourceTypeMap != null && !dynamicResourceTypeMap.isEmpty()) {
                for (ServletPolicyRule rule : dynamicResourceTypeMap.values()) {
                    if (rule.matches(request)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 5 - 동적 컴포넌트 경로 포함] requestUri=[{}] -> target=[{}]",
                                    requestUri, rule.getTarget());
                        }
                        return rule;
                    }
                }
            }
            if (resourceTypeMap != null && !resourceTypeMap.isEmpty()) {
                for (ServletPolicyRule rule : resourceTypeMap.values()) {
                    if (rule.matches(request)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 5 - 정적 컴포넌트 경로 포함] requestUri=[{}] -> target=[{}]",
                                    requestUri, rule.getTarget());
                        }
                        return rule;
                    }
                }
            }
        }

        // 계층 6: 매칭된 정책이 없을 경우 기본 정책(defaultPolicy)으로 폴백
        if (defaultPolicy != null && LOG.isDebugEnabled()) {
            LOG.debug("[정책 매칭: Tier 6 - DefaultPolicy 폴백 적용] requestUri=[{}] -> target=[DEFAULT]", requestUri);
        }
        return defaultPolicy;
    }

    /**
     * 동적으로 바인딩된 서블릿의 보안 정책을 런타임 인덱스에 등록합니다.
     * (서블릿 바인딩 시 로그가 과다 생성되지 않도록 로그 출력을 수행하지 않습니다.)
     *
     * @param rule 등록할 서블릿 보안 정책 규칙
     */
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

    /**
     * 언바인딩된 서블릿의 동적 보안 정책을 런타임 인덱스에서 제거합니다.
     * (서블릿 언바인딩 시 로그가 과다 생성되지 않도록 로그 출력을 수행하지 않습니다.)
     *
     * @param target 제거할 서블릿 타겟(경로 또는 resourceType)
     */
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

    /**
     * 현재 동적으로 등록된 모든 서블릿 정책 맵(읽기 전용)을 반환합니다.
     *
     * @return 타겟별 동적 서블릿 정책 맵
     */
    public Map<String, ServletPolicyRule> getDynamicPolicies() {
        return Collections.unmodifiableMap(dynamicPoliciesByTarget);
    }

    /**
     * 특정 타겟 경로 또는 resourceType에 해당하는 동적 서블릿 정책을 조회합니다.
     *
     * @param target 조회할 타겟 문자열
     * @return 매칭된 동적 ServletPolicyRule (없을 경우 null)
     */
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
     * 전역 기본 신뢰 Referer 도메인(예: "abc.com")을 반환합니다.
     *
     * @return 기본 신뢰 Referer 도메인
     */
    public String getDefaultReferrer() {
        return StringUtils.isNotBlank(defaultReferrer) ? defaultReferrer.trim() : "abc.com";
    }

    /**
     * 전역 기본 신뢰 Referer 도메인을 설정합니다.
     *
     * @param defaultReferrer 기본 신뢰 Referer 도메인
     */
    public void setDefaultReferrer(String defaultReferrer) {
        this.defaultReferrer = defaultReferrer;
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
     * 정적으로 설정된 서블릿 보안 정책 리스트를 반환합니다.
     *
     * @return 서블릿 보안 정책 리스트
     */
    public List<ServletPolicyRule> getPolicies() {
        return policies != null ? policies : Collections.emptyList();
    }

    /**
     * 정적 서블릿 보안 정책 리스트를 설정합니다.
     *
     * @param policies 서블릿 보안 정책 리스트
     */
    public void setPolicies(List<ServletPolicyRule> policies) {
        this.policies = policies;
    }

    /**
     * 개별 서블릿의 security.* 설정을 무시하고 글로벌 defaultPolicy만 강제 적용할지 여부를 반환합니다.
     *
     * @return 글로벌 전용 정책 강제 시 true (기본값 false)
     */
    public boolean isIgnoreServletPolicies() {
        return ignoreServletPolicies != null && ignoreServletPolicies;
    }

    /**
     * 개별 서블릿의 security.* 설정을 무시하고 글로벌 defaultPolicy만 강제 적용할지 여부를 설정합니다.
     *
     * @param ignoreServletPolicies 글로벌 전용 정책 강제 여부
     */
    public void setIgnoreServletPolicies(Boolean ignoreServletPolicies) {
        this.ignoreServletPolicies = ignoreServletPolicies;
    }

    /**
     * 특정 검증기(REFERER, METHOD, PARAM)가 전역적으로 활성화되어 있는지 확인합니다.
     *
     * @param validatorName 검증기 식별자 이름
     * @return 활성화 상태이면 true (기본값 true)
     */
    public boolean isValidatorEnabled(String validatorName) {
        if (validatorStatusMap != null && validatorName != null) {
            Boolean status = validatorStatusMap.get(validatorName.trim().toUpperCase());
            if (status != null) {
                return status;
            }
        }
        return true;
    }

    /**
     * 특정 검증기(REFERER, METHOD, PARAM)의 전역 활성화 상태를 설정합니다.
     *
     * @param validatorName 검증기 식별자 이름
     * @param enabled       활성화 여부
     */
    public void setValidatorEnabled(String validatorName, boolean enabled) {
        if (StringUtils.isBlank(validatorName)) {
            return;
        }
        Map<String, Boolean> map = validatorStatusMap != null ? new HashMap<>(validatorStatusMap) : new HashMap<>();
        map.put(validatorName.trim().toUpperCase(), enabled);
        this.validatorStatusMap = Collections.unmodifiableMap(map);
    }

    /**
     * 전역 검증기 활성화 상태 맵을 반환합니다.
     *
     * @return 검증기 이름별 활성화 여부 맵
     */
    public Map<String, Boolean> getValidatorStatusMap() {
        return validatorStatusMap != null ? validatorStatusMap : Collections.emptyMap();
    }
}
