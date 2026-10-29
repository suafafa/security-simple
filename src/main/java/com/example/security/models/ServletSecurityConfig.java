package com.example.security.models;

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
 * 전역 검증기(REFERER, METHOD, PARAM) On/Off 설정, 기본 정책(defaultPolicy) 및
 * 번들별 {@code .cfg.json}({@code EndpointPolicyRegistry})에서 로드된 엔드포인트 보안 정책을 보관하는 루트 설정 컨테이너입니다.
 * 초고속 정책 탐색을 위한 단일 다계층 O(1) 해시 인덱스를 포함합니다.
 */
public class ServletSecurityConfig {

    private static final Logger LOG = LoggerFactory.getLogger(ServletSecurityConfig.class);

    @SerializedName("enabled")
    private Boolean enabled = true;

    /**
     * 전역 보안 실행 모드 ({@code ENFORCE} 또는 {@code MONITOR}).
     * 전역 모드가 {@link PolicyMode#MONITOR}로 설정되면 모든 서블릿 및 검증기에서 차단 대신 WARN 로그만 남기고 통과합니다.
     */
    @SerializedName(value = "mode", alternate = {"policyMode", "securityMode"})
    private PolicyMode mode = PolicyMode.ENFORCE;

    @SerializedName(value = "defaultReferrer", alternate = {"defaultReferer", "default_referrer", "default_referer"})
    private String defaultReferrer = "abc.com";

    @SerializedName(value = "defaultPolicy", alternate = {"default", "globalPolicy"})
    private ServletPolicyRule defaultPolicy;

    /**
     * 개별 엔드포인트 정책(.cfg.json)을 무시하고 글로벌 defaultPolicy만 강제 적용할지 여부입니다.
     */
    @SerializedName("ignoreServletPolicies")
    private Boolean ignoreServletPolicies = false;

    // 런타임 검증기 활성화 상태 맵: 검증기 이름(대문자) -> Boolean
    private transient Map<String, Boolean> validatorStatusMap = Collections.emptyMap();

    // 런타임 전역 검증기별 모드 맵: 검증기 이름(대문자) -> PolicyMode (ENFORCE / MONITOR)
    private transient Map<String, PolicyMode> validatorModeMap = Collections.emptyMap();

    // 단일 O(1) 정책 인덱스 저장소 (.cfg.json 정책 등록용)
    private transient Map<String, ServletPolicyRule> exactUriMap = new ConcurrentHashMap<>();
    private transient Map<String, ServletPolicyRule> resourceTypeMap = new ConcurrentHashMap<>();
    private transient List<ServletPolicyRule> patternPolicies = new CopyOnWriteArrayList<>();
    private transient Map<String, ServletPolicyRule> policiesByTarget = new ConcurrentHashMap<>();

    /**
     * 기본 생성자입니다.
     */
    public ServletSecurityConfig() {
    }

    /**
     * 필터 활성화 여부로 루트 보안 설정 객체를 생성합니다.
     *
     * @param enabled 전역 필터 활성화 여부
     */
    public ServletSecurityConfig(Boolean enabled) {
        this.enabled = enabled;
        this.defaultReferrer = "abc.com";
        init();
    }

    /**
     * 루트 설정 및 기본 정책(defaultPolicy)의 유효성을 검증하고 인덱스를 초기화합니다.
     */
    public final void init() {
        Map<String, Boolean> map = validatorStatusMap != null ? new HashMap<>(validatorStatusMap) : new HashMap<>();
        this.validatorStatusMap = Collections.unmodifiableMap(map);

        Map<String, PolicyMode> modeMap = validatorModeMap != null ? new HashMap<>(validatorModeMap) : new HashMap<>();
        this.validatorModeMap = Collections.unmodifiableMap(modeMap);

        if (this.mode == null) {
            this.mode = PolicyMode.ENFORCE;
        }

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
            LOG.debug("ServletSecurityConfig 초기화 완료 - enabled={}, defaultReferrer={}, 등록된 정책 수={}",
                    enabled, defaultReferrer, policiesByTarget.size());
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

        // 글로벌 기본 정책(defaultPolicy) 강제 적용 모드인 경우 개별 정책 조회를 건너뜁니다.
        if (isIgnoreServletPolicies()) {
            if (defaultPolicy != null && LOG.isDebugEnabled()) {
                LOG.debug("[정책 매칭: ignoreServletPolicies=true] 개별 정책을 무시하고 글로벌 defaultPolicy를 강제 적용합니다. URI=[{}]",
                        request.getRequestURI());
            }
            return defaultPolicy;
        }

        String requestUri = request.getRequestURI();
        if (requestUri != null) {
            String lowerUri = requestUri.toLowerCase();

            // 계층 1: 전체 URI 직접 일치 조회 (O(1))
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                ServletPolicyRule match = exactUriMap.get(lowerUri);
                if (match != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 1 - URI 정확 일치] requestUri=[{}] -> target=[{}]", requestUri, match.getTarget());
                    }
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
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 2 - Base URI 일치] requestUri=[{}], baseUri=[{}] -> target=[{}]",
                                requestUri, baseUri, match.getTarget());
                    }
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
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 3 - ResourceType 일치] resourceType=[{}] -> target=[{}]",
                                    resourceType, match.getTarget());
                        }
                        return match;
                    }
                    for (Map.Entry<String, ServletPolicyRule> entry : resourceTypeMap.entrySet()) {
                        if (resource.isResourceType(entry.getKey())) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("[정책 매칭: Tier 3 - 상위 ResourceType 일치] resourceType=[{}] -> target=[{}]",
                                        resourceType, entry.getValue().getTarget());
                            }
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
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[정책 매칭: Tier 4 - 정규식 패턴 일치] requestUri=[{}] -> target=[{}]",
                                requestUri, rule.getTarget());
                    }
                    return rule;
                }
            }
        }

        // 계층 5: URI 내 상대 컴포넌트 경로 또는 경로 접두사 포함 여부 검사
        if (requestUri != null) {
            if (exactUriMap != null && !exactUriMap.isEmpty()) {
                for (ServletPolicyRule rule : exactUriMap.values()) {
                    if (rule.matches(request)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("[정책 매칭: Tier 5 - 경로 접두사 일치] requestUri=[{}] -> target=[{}]",
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
                            LOG.debug("[정책 매칭: Tier 5 - 컴포넌트 경로 포함] requestUri=[{}] -> target=[{}]",
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
     * 특정 타겟(경로 또는 resourceType)의 보안 정책을 인덱스에서 제거합니다.
     *
     * @param target 제거할 타겟(경로 또는 resourceType)
     */
    public void unregisterPolicy(final String target) {
        if (StringUtils.isBlank(target)) {
            return;
        }
        String trimmed = target.trim();
        policiesByTarget.remove(trimmed);
        exactUriMap.remove(trimmed.toLowerCase());
        resourceTypeMap.remove(trimmed);
        patternPolicies.removeIf(r -> trimmed.equalsIgnoreCase(r.getTarget()));
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
     * 개별 엔드포인트 정책(.cfg.json)을 무시하고 글로벌 defaultPolicy만 강제 적용할지 여부를 반환합니다.
     *
     * @return 글로벌 전용 정책 강제 시 true (기본값 false)
     */
    public boolean isIgnoreServletPolicies() {
        return ignoreServletPolicies != null && ignoreServletPolicies;
    }

    /**
     * 개별 엔드포인트 정책(.cfg.json)을 무시하고 글로벌 defaultPolicy만 강제 적용할지 여부를 설정합니다.
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

    /**
     * 전역 보안 실행 모드({@link PolicyMode#ENFORCE} 또는 {@link PolicyMode#MONITOR})를 반환합니다.
     *
     * @return 전역 {@link PolicyMode} (기본값 {@link PolicyMode#ENFORCE})
     */
    public PolicyMode getMode() {
        return mode != null ? mode : PolicyMode.ENFORCE;
    }

    /**
     * 전역 보안 실행 모드를 설정합니다.
     *
     * @param mode 설정할 {@link PolicyMode}
     */
    public void setMode(final PolicyMode mode) {
        this.mode = mode != null ? mode : PolicyMode.ENFORCE;
    }

    /**
     * 문자열("ENFORCE", "MONITOR" 등)로 전역 보안 실행 모드를 설정합니다.
     *
     * @param modeStr 설정할 모드 문자열
     */
    public void setMode(final String modeStr) {
        this.mode = PolicyMode.fromStringOrDefault(modeStr, PolicyMode.ENFORCE);
    }

    /**
     * 특정 검증기에 대해 전역적으로 지정된 {@link PolicyMode}를 조회합니다.
     *
     * @param validatorName 검증기 이름 (예: "REFERER", "RUNMODE")
     * @return 전역 지정된 {@link PolicyMode} (미지정 시 null)
     */
    public PolicyMode getValidatorMode(final String validatorName) {
        if (validatorModeMap != null && StringUtils.isNotBlank(validatorName)) {
            return validatorModeMap.get(validatorName.trim().toUpperCase());
        }
        return null;
    }

    /**
     * 특정 검증기의 전역 {@link PolicyMode}({@code ENFORCE} 또는 {@code MONITOR})를 설정합니다.
     *
     * @param validatorName 검증기 이름
     * @param validatorMode 설정할 모드
     */
    public void setValidatorMode(final String validatorName, final PolicyMode validatorMode) {
        if (StringUtils.isBlank(validatorName) || validatorMode == null) {
            return;
        }
        Map<String, PolicyMode> map = validatorModeMap != null ? new HashMap<>(validatorModeMap) : new HashMap<>();
        map.put(validatorName.trim().toUpperCase(), validatorMode);
        this.validatorModeMap = Collections.unmodifiableMap(map);
    }

    /**
     * 전역 검증기별 실행 모드 맵을 반환합니다.
     *
     * @return 검증기 이름별 {@link PolicyMode} 맵
     */
    public Map<String, PolicyMode> getValidatorModeMap() {
        return validatorModeMap != null ? validatorModeMap : Collections.emptyMap();
    }
}
