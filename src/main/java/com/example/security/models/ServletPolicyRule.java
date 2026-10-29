package com.example.security.models;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.regex.Pattern;

/**
 * 특정 타겟(URL 경로 또는 Sling resourceType)에 대한 경량 보안 정책 규칙 모델입니다.
 * Method, Referer, Parameter 3가지 핵심 검증에 필요한 설정만 간결하게 관리합니다.
 */
public class ServletPolicyRule {

    // 허용 HTTP 메소드 화이트리스트 집합
    public static final Set<String> VALID_HTTP_METHODS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    )));

    @SerializedName("target")
    private String target;

    @SerializedName("enabled")
    private Boolean enabled = true;

    @SerializedName("methods")
    private List<String> methods;

    @SerializedName(value = "defaultReferrer", alternate = {"defaultReferer", "default_referrer", "default_referer"})
    private String defaultReferrer;

    @SerializedName("allowedReferrers")
    private List<String> allowedReferrers;

    @SerializedName("allowUndefinedParams")
    private Boolean allowUndefinedParams;

    @SerializedName("params")
    private Map<String, ParamRule> params;

    @SerializedName(value = "validators", alternate = {"validatorSettings"})
    private JsonElement validators;

    @SerializedName(value = "disabledValidators", alternate = {"skipValidators"})
    private List<String> disabledValidators;

    @SerializedName(value = "enabledValidators")
    private List<String> enabledValidators;

    /**
     * 커스텀 {@link com.example.security.validators.PolicyValidator} 플러그인이 {@code ServletPolicyRule} 클래스를
     * 수정하지 않고도 {@code .cfg.json}에 정의된 추가 설정 속성(예: {@code runModes}, {@code csrfHeader}, {@code allowedIps})을
     * 자유롭게 읽고 상속받을 수 있도록 보관하는 확장 속성 맵입니다.
     */
    @SerializedName(value = "extensions", alternate = {"options", "customOptions"})
    private Map<String, Object> extensions;

    // 기본 내장 필드 키 집합 (JSON 파싱 시 이 외의 사용자 정의 키는 자동으로 extensions에 저장됨)
    private static final Set<String> BUILT_IN_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "target", "targets", "path", "paths", "sling.servlet.paths", "resourcetype", "resourcetypes",
            "enabled", "methods", "allowedmethods", "security.methods",
            "defaultreferrer", "defaultreferer", "default_referrer", "default_referer",
            "allowedreferrers", "referrers", "security.referrers",
            "allowundefinedparams", "allow_undefined_params", "security.allowundefinedparams",
            "params", "parameters", "paramrules", "security.params",
            "requiredparams", "required_params", "security.requiredparams", "required",
            "validators", "validatorsettings", "disabledvalidators", "skipvalidators", "enabledvalidators",
            "extensions", "options", "customoptions"
    )));

    // 런타임 캐시 필드
    private transient Set<String> upperMethods;
    private transient Set<String> lowerAllowedReferrers;
    private transient Map<String, Boolean> validatorStatusMap;
    private transient Map<String, ParamRule> lowerParams;
    private transient Pattern compiledTargetPattern;

    /**
     * 정책 규칙의 런타임 캐시(대문자 HTTP 메소드 집합, 소문자 Referer 집합, 소문자 키 파라미터 맵,
     * 타겟 정규식 패턴, 검증기 활성화 맵)를 초기화하고 설정값의 유효성을 검증합니다.
     */
    public void init() {
        if (StringUtils.isNotBlank(target) && (target.contains("*") || target.contains("^") || target.contains("$"))) {
            try {
                this.compiledTargetPattern = Pattern.compile(target.trim());
            } catch (Exception ignored) {
            }
        }

        if (methods != null && !methods.isEmpty()) {
            Set<String> set = new HashSet<>();
            for (String m : methods) {
                if (StringUtils.isNotBlank(m)) {
                    set.add(m.trim().toUpperCase());
                }
            }
            this.upperMethods = Collections.unmodifiableSet(set);
        } else {
            this.upperMethods = Collections.emptySet();
        }

        if (allowedReferrers != null && !allowedReferrers.isEmpty()) {
            Set<String> set = new HashSet<>();
            for (String ref : allowedReferrers) {
                if (StringUtils.isNotBlank(ref)) {
                    set.add(ref.trim().toLowerCase());
                }
            }
            this.lowerAllowedReferrers = Collections.unmodifiableSet(set);
        } else {
            this.lowerAllowedReferrers = Collections.emptySet();
        }

        if (params != null && !params.isEmpty()) {
            Map<String, ParamRule> map = new LinkedHashMap<>();
            for (Map.Entry<String, ParamRule> entry : params.entrySet()) {
                if (StringUtils.isNotBlank(entry.getKey()) && entry.getValue() != null) {
                    ParamRule rule = entry.getValue();
                    rule.init();
                    map.put(entry.getKey().trim().toLowerCase(), rule);
                }
            }
            this.lowerParams = Collections.unmodifiableMap(map);
        } else {
            this.lowerParams = Collections.emptyMap();
        }

        Map<String, Boolean> vMap = new HashMap<>();
        if (validators != null && validators.isJsonObject()) {
            JsonObject obj = validators.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                try {
                    vMap.put(entry.getKey().trim().toUpperCase(), entry.getValue().getAsBoolean());
                } catch (Exception ignored) {
                }
            }
        }
        if (disabledValidators != null) {
            for (String v : disabledValidators) {
                if (StringUtils.isNotBlank(v)) {
                    vMap.put(v.trim().toUpperCase(), false);
                }
            }
        }
        if (enabledValidators != null) {
            for (String v : enabledValidators) {
                if (StringUtils.isNotBlank(v)) {
                    vMap.put(v.trim().toUpperCase(), true);
                }
            }
        }
        this.validatorStatusMap = Collections.unmodifiableMap(vMap);

        List<String> errors = new ArrayList<>();
        validate(errors);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("ServletPolicyRule validation failed: " + String.join("; ", errors));
        }
    }

    /**
     * 로그 및 에러 메시지 출력에 사용할 타겟 식별자를 반환합니다.
     *
     * @return 타겟 문자열 (비어 있을 경우 "(defaultPolicy)")
     */
    public String getTargetIdentifier() {
        return StringUtils.isNotBlank(target) ? target : "(defaultPolicy)";
    }

    /**
     * 정책 규칙의 설정값(허용 HTTP 메소드 목록, 타겟 정규식 문법, 하위 파라미터 규칙)이 유효한지 검증합니다.
     *
     * @param errors 검증 오류 메시지를 수집할 리스트
     */
    public void validate(final List<String> errors) {
        String id = getTargetIdentifier();

        // 1. HTTP 메소드 검증
        if (methods != null) {
            for (String m : methods) {
                if (StringUtils.isNotBlank(m) && !VALID_HTTP_METHODS.contains(m.trim().toUpperCase())) {
                    errors.add("Target '" + id + "': Unsupported HTTP method '" + m + "'. Allowed: " + VALID_HTTP_METHODS);
                }
            }
        }

        // 2. 타겟 정규식(Target Regex) 문법 검증
        if (StringUtils.isNotBlank(target) && (target.contains("*") || target.contains("^") || target.contains("$"))) {
            try {
                Pattern.compile(target.trim());
            } catch (Exception e) {
                errors.add("Target '" + id + "': Invalid regex pattern for target: '" + target + "' (" + e.getMessage() + ")");
            }
        }

        // 3. 파라미터 규칙(Parameter Rules) 검증
        if (params != null) {
            for (Map.Entry<String, ParamRule> entry : params.entrySet()) {
                if (entry.getValue() != null) {
                    entry.getValue().validate(entry.getKey(), id, errors);
                }
            }
        }
    }

    /**
     * 유입된 HTTP 요청이 이 정책 규칙의 타겟(URL 경로 또는 Sling resourceType)과 일치하는지 확인합니다.
     *
     * @param request 검사할 HTTP 요청 객체
     * @return 요청이 타겟과 일치하면 true, 그렇지 않으면 false
     */
    public boolean matches(final HttpServletRequest request) {
        if (StringUtils.isBlank(target) || request == null) {
            return false;
        }

        String requestUri = request.getRequestURI();
        if (requestUri != null) {
            if (compiledTargetPattern != null) {
                if (compiledTargetPattern.matcher(requestUri).matches()) {
                    return true;
                }
            } else if (target.startsWith("/")) {
                String cleanTarget = target.trim();
                if (requestUri.equalsIgnoreCase(cleanTarget)
                        || requestUri.startsWith(cleanTarget + "/")
                        || requestUri.startsWith(cleanTarget + ".")) {
                    return true;
                }
            }
        }

        if (request instanceof SlingHttpServletRequest) {
            Resource resource = ((SlingHttpServletRequest) request).getResource();
            if (resource != null) {
                if (resource.isResourceType(target.trim())) {
                    return true;
                }
                String resourceType = resource.getResourceType();
                if (resourceType != null && resourceType.equals(target.trim())) {
                    return true;
                }
            }
        }

        if (requestUri != null && requestUri.contains(target.trim())) {
            return true;
        }

        return false;
    }

    /**
     * 컴파일된 타겟 정규식 패턴 객체를 반환합니다.
     *
     * @return 컴파일된 {@link Pattern} (정규식 타겟이 아닐 경우 null)
     */
    public Pattern getCompiledTargetPattern() {
        return compiledTargetPattern;
    }

    /**
     * 정책이 적용될 타겟(서블릿 경로 또는 Sling resourceType)을 반환합니다.
     *
     * @return 타겟 문자열
     */
    public String getTarget() {
        return target;
    }

    /**
     * 정책이 적용될 타겟(서블릿 경로 또는 Sling resourceType)을 설정합니다.
     *
     * @param target 설정할 타겟 문자열
     */
    public void setTarget(String target) {
        this.target = target;
    }

    /**
     * 이 보안 정책 규칙의 활성화 여부를 반환합니다.
     *
     * @return 활성화 상태이면 true (기본값 true)
     */
    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    /**
     * 이 보안 정책 규칙의 활성화 여부를 설정합니다.
     *
     * @param enabled 활성화 여부
     */
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * 허용된 HTTP 메소드 집합(대문자)을 반환합니다.
     *
     * @return 허용된 HTTP 메소드 Set (미설정 시 빈 Set)
     */
    public Set<String> getMethods() {
        return upperMethods != null ? upperMethods : Collections.emptySet();
    }

    /**
     * 허용할 HTTP 메소드 목록을 설정합니다.
     *
     * @param methods 허용할 HTTP 메소드 리스트
     */
    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    /**
     * 주어진 HTTP 메소드가 이 정책 규칙에서 허용되는지 확인합니다.
     *
     * @param method 검사할 HTTP 메소드 문자열 (예: "GET", "POST")
     * @return 허용된 메소드이면 true, 차단 대상이면 false
     */
    public boolean isMethodAllowed(final String method) {
        if (upperMethods == null || upperMethods.isEmpty()) {
            return true;
        }
        if (method == null) {
            return false;
        }
        return upperMethods.contains(method.trim().toUpperCase());
    }

    /**
     * 파라미터 이름을 키(소문자)로 하는 파라미터 검증 규칙 맵을 반환합니다.
     *
     * @return 파라미터 규칙 Map
     */
    public Map<String, ParamRule> getParams() {
        if (lowerParams != null) {
            return lowerParams;
        }
        return params != null ? params : Collections.emptyMap();
    }

    /**
     * 파라미터 검증 규칙 맵을 설정합니다.
     *
     * @param params 설정할 파라미터 규칙 Map
     */
    public void setParams(Map<String, ParamRule> params) {
        this.params = params;
        if (this.lowerParams != null) {
            if (params == null || params.isEmpty()) {
                this.lowerParams = Collections.emptyMap();
            } else {
                Map<String, ParamRule> tempParams = new HashMap<>(params.size());
                for (Map.Entry<String, ParamRule> entry : params.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        entry.getValue().init();
                        tempParams.put(entry.getKey().trim().toLowerCase(), entry.getValue());
                    }
                }
                this.lowerParams = Collections.unmodifiableMap(tempParams);
            }
        }
    }

    /**
     * 정책에 명시되지 않은 미정의 파라미터의 허용 여부를 반환합니다.
     *
     * @return 미정의 파라미터를 허용하면 true, 차단하면 false (기본값 false)
     */
    public boolean isAllowUndefinedParams() {
        return allowUndefinedParams != null ? allowUndefinedParams : false;
    }

    /**
     * 정책에 명시되지 않은 미정의 파라미터의 허용 여부를 설정합니다.
     *
     * @param allowUndefinedParams 미정의 파라미터 허용 여부
     */
    public void setAllowUndefinedParams(Boolean allowUndefinedParams) {
        this.allowUndefinedParams = allowUndefinedParams;
    }

    /**
     * 이 정책 규칙에서 추가로 허용하는 Referer 도메인/패턴 집합(소문자)을 반환합니다.
     *
     * @return 허용된 Referer 도메인 Set
     */
    public Set<String> getAllowedReferrers() {
        return lowerAllowedReferrers != null ? lowerAllowedReferrers : Collections.emptySet();
    }

    /**
     * 이 정책 규칙에서 허용할 Referer 도메인/패턴 목록을 설정합니다.
     *
     * @param allowedReferrers 허용할 Referer 목록
     */
    public void setAllowedReferrers(List<String> allowedReferrers) {
        this.allowedReferrers = allowedReferrers;
    }

    /**
     * 기본 허용 Referer 도메인을 반환합니다.
     *
     * @return 기본 허용 Referer 도메인 문자열
     */
    public String getDefaultReferrer() {
        return defaultReferrer;
    }

    /**
     * 기본 허용 Referer 도메인을 설정합니다.
     *
     * @param defaultReferrer 기본 허용 Referer 도메인 문자열
     */
    public void setDefaultReferrer(String defaultReferrer) {
        this.defaultReferrer = defaultReferrer;
    }

    /**
     * 기본 허용 Referer 도메인을 반환합니다 ({@link #getDefaultReferrer()}의 별칭).
     *
     * @return 기본 허용 Referer 도메인 문자열
     */
    public String getDefaultReferer() {
        return defaultReferrer;
    }

    /**
     * 기본 허용 Referer 도메인을 설정합니다 ({@link #setDefaultReferrer(String)}의 별칭).
     *
     * @param defaultReferer 기본 허용 Referer 도메인 문자열
     */
    public void setDefaultReferer(String defaultReferer) {
        this.defaultReferrer = defaultReferer;
    }

    /**
     * 이 정책 규칙에서 특정 검증기(예: "REFERER", "METHOD", "PARAM")가 활성화되어 있는지 확인합니다.
     *
     * @param validatorName 확인할 검증기 이름
     * @return 활성화되어 있으면 true, 비활성화되어 있으면 false
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
     * 커스텀 {@link com.example.security.validators.PolicyValidator}에서 사용할 확장 설정 맵을 반환합니다.
     *
     * @return 확장 설정 맵 (없으면 빈 Map)
     */
    public Map<String, Object> getExtensions() {
        return extensions != null ? Collections.unmodifiableMap(extensions) : Collections.emptyMap();
    }

    /**
     * 커스텀 확장 설정 맵을 설정합니다.
     *
     * @param extensions 설정할 확장 속성 맵
     */
    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions != null ? new LinkedHashMap<>(extensions) : null;
    }

    /**
     * 커스텀 확장 속성을 단일 키-값으로 추가합니다.
     *
     * @param key   속성 키 (예: "runModes")
     * @param value 속성 값
     */
    public void putExtension(String key, Object value) {
        if (StringUtils.isBlank(key) || value == null) {
            return;
        }
        if (this.extensions == null) {
            this.extensions = new LinkedHashMap<>();
        }
        this.extensions.put(key.trim(), value);
    }

    /**
     * 확장 속성 맵({@code extensions})에서 지정된 키 후보들(대소문자 무시) 중 일치하는 값을 문자열 리스트로 조회합니다.
     * 배열, 컬렉션, 쉼표 구분 문자열 모두 자동으로 리스트로 변환해 주므로 신규 Validator에서 설정값을 손쉽게 꺼낼 수 있습니다.
     *
     * @param keys 조회할 설정 키 후보 목록 (예: {@code "runModes", "allowedRunModes"})
     * @return 추출된 문자열 리스트 (미설정 시 빈 리스트)
     */
    public List<String> getExtensionStringList(String... keys) {
        if (extensions == null || extensions.isEmpty() || keys == null) {
            return Collections.emptyList();
        }
        Map<String, Object> matchedMap = resolveCaseInsensitiveKeys(extensions, keys);
        return extractStringList(matchedMap, keys);
    }

    /**
     * 확장 속성 맵({@code extensions})에서 지정된 키 후보들(대소문자 무시) 중 일치하는 값을 소문자 집합(Set)으로 조회합니다.
     *
     * @param keys 조회할 설정 키 후보 목록
     * @return 추출된 소문자 문자열 Set (미설정 시 빈 Set)
     */
    public Set<String> getExtensionLowerSet(String... keys) {
        List<String> list = getExtensionStringList(keys);
        if (list.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> set = new LinkedHashSet<>();
        for (String item : list) {
            if (StringUtils.isNotBlank(item)) {
                set.add(item.trim().toLowerCase());
            }
        }
        return Collections.unmodifiableSet(set);
    }

    /**
     * 확장 속성 맵({@code extensions})에서 지정된 키 후보들 중 일치하는 첫 번째 문자열 값을 조회합니다.
     *
     * @param keys 조회할 설정 키 후보 목록
     * @return 추출된 문자열 (미설정 시 null)
     */
    public String getExtensionString(String... keys) {
        List<String> list = getExtensionStringList(keys);
        return list.isEmpty() ? null : list.get(0);
    }

    /**
     * 확장 속성 맵({@code extensions})에서 지정된 키 후보들 중 일치하는 Boolean 값을 조회합니다.
     *
     * @param keys 조회할 설정 키 후보 목록
     * @return 추출된 Boolean 값 (미설정 시 null)
     */
    public Boolean getExtensionBoolean(String... keys) {
        if (extensions == null || extensions.isEmpty() || keys == null) {
            return null;
        }
        Map<String, Object> matchedMap = resolveCaseInsensitiveKeys(extensions, keys);
        return extractBoolean(matchedMap, keys);
    }

    private static Map<String, Object> resolveCaseInsensitiveKeys(Map<String, Object> source, String... targetKeys) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        for (String tk : targetKeys) {
            if (tk == null) continue;
            if (source.containsKey(tk)) {
                resolved.put(tk, source.get(tk));
            } else {
                for (Map.Entry<String, Object> entry : source.entrySet()) {
                    if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(tk)) {
                        resolved.put(tk, entry.getValue());
                        break;
                    }
                }
            }
        }
        return resolved;
    }

    /**
     * 상위 정책(예: defaultPolicy)으로부터 기본 보안 정책 설정을 상속받습니다.
     * 현재 규칙에 명시적으로 설정된 속성이 항상 우선권을 가집니다.
     *
     * @param parent 상속받을 부모 정책 규칙 (주로 defaultPolicy)
     */
    public void inheritFrom(ServletPolicyRule parent) {
        if (parent == null) {
            return;
        }

        if ((this.methods == null || this.methods.isEmpty()) && parent.methods != null && !parent.methods.isEmpty()) {
            this.methods = new ArrayList<>(parent.methods);
        }

        if (StringUtils.isBlank(this.defaultReferrer) && StringUtils.isNotBlank(parent.defaultReferrer)) {
            this.defaultReferrer = parent.defaultReferrer;
        }

        if (parent.allowedReferrers != null && !parent.allowedReferrers.isEmpty()) {
            if (this.allowedReferrers == null) {
                this.allowedReferrers = new ArrayList<>(parent.allowedReferrers);
            } else {
                Set<String> merged = new LinkedHashSet<>(this.allowedReferrers);
                merged.addAll(parent.allowedReferrers);
                this.allowedReferrers = new ArrayList<>(merged);
            }
        }

        if (this.allowUndefinedParams == null && parent.allowUndefinedParams != null) {
            this.allowUndefinedParams = parent.allowUndefinedParams;
        }

        if (parent.params != null && !parent.params.isEmpty()) {
            Map<String, ParamRule> merged = new LinkedHashMap<>();
            // 1. 개별 서블릿(.cfg.json)에 정의된 파라미터 규칙을 최우선으로 먼저 배치
            if (this.params != null && !this.params.isEmpty()) {
                for (Map.Entry<String, ParamRule> entry : this.params.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        String key = entry.getKey().trim().toLowerCase();
                        ParamRule childCopy = entry.getValue().copy();
                        // 부모(defaultPolicy)에 동일 파라미터가 있는 경우, 자식에 미지정된 길이/패턴 제약만 보완 상속
                        ParamRule parentRule = parent.getParams().get(key);
                        if (parentRule != null) {
                            if (childCopy.getMinLength() == null && parentRule.getMinLength() != null) {
                                childCopy.setMinLength(parentRule.getMinLength());
                            }
                            if (childCopy.getMaxLength() == null && parentRule.getMaxLength() != null) {
                                childCopy.setMaxLength(parentRule.getMaxLength());
                            }
                            if (StringUtils.isBlank(childCopy.getPattern()) && StringUtils.isNotBlank(parentRule.getPattern())) {
                                childCopy.setPattern(parentRule.getPattern());
                            }
                        }
                        childCopy.init();
                        merged.put(key, childCopy);
                    }
                }
            }
            // 2. 개별 서블릿에 없는 공통 기본 파라미터(defaultPolicy)를 후순위로 병합
            for (Map.Entry<String, ParamRule> entry : parent.params.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    String key = entry.getKey().trim().toLowerCase();
                    if (!merged.containsKey(key)) {
                        merged.put(key, entry.getValue().copy());
                    }
                }
            }
            this.params = merged;
        }

        // 확장 속성(extensions) 상속: 자식 정책에 명시되지 않은 키만 부모(defaultPolicy)로부터 상속
        if (parent.extensions != null && !parent.extensions.isEmpty()) {
            if (this.extensions == null) {
                this.extensions = new LinkedHashMap<>(parent.extensions);
            } else {
                for (Map.Entry<String, Object> entry : parent.extensions.entrySet()) {
                    if (entry.getKey() != null && !this.extensions.containsKey(entry.getKey())) {
                        this.extensions.put(entry.getKey(), entry.getValue());
                    }
                }
            }
        }
    }

    /**
     * 다른 {@link ServletPolicyRule} 객체의 모든 설정 필드를 현재 객체로 깊은 복사(Deep Copy)합니다.
     *
     * @param other 복사할 원본 정책 규칙 객체
     */
    public void copyFrom(ServletPolicyRule other) {
        if (other == null) return;
        this.target = other.target;
        this.enabled = other.enabled;
        this.methods = other.methods != null ? new ArrayList<>(other.methods) : null;
        this.defaultReferrer = other.defaultReferrer;
        this.allowedReferrers = other.allowedReferrers != null ? new ArrayList<>(other.allowedReferrers) : null;
        this.allowUndefinedParams = other.allowUndefinedParams;
        this.validators = other.validators;
        this.disabledValidators = other.disabledValidators != null ? new ArrayList<>(other.disabledValidators) : null;
        this.enabledValidators = other.enabledValidators != null ? new ArrayList<>(other.enabledValidators) : null;
        this.extensions = other.extensions != null ? new LinkedHashMap<>(other.extensions) : null;
        if (other.params != null) {
            Map<String, ParamRule> copiedParams = new LinkedHashMap<>(other.params.size());
            for (Map.Entry<String, ParamRule> entry : other.params.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    copiedParams.put(entry.getKey().trim().toLowerCase(), entry.getValue().copy());
                }
            }
            this.params = copiedParams;
        } else {
            this.params = null;
        }
    }

    /**
     * JSON 정책 객체의 필드를 파싱하여 {@link ServletPolicyRule}을 생성합니다.
     *
     * @param props JSON 정책 객체 맵
     * @return 파싱된 {@link ServletPolicyRule} 객체
     */
    private static ServletPolicyRule parseRuleForTarget(Map<String, Object> props) {
        ServletPolicyRule rule = new ServletPolicyRule();

        // 0. 정책 활성화 여부 및 기본 Referer (Enabled & DefaultReferrer)
        Boolean enabledVal = extractBoolean(props, "enabled");
        if (enabledVal != null) {
            rule.setEnabled(enabledVal);
        }
        List<String> defaultRefs = extractStringList(props, "defaultReferrer", "defaultReferer");
        if (!defaultRefs.isEmpty()) {
            rule.setDefaultReferrer(defaultRefs.get(0));
        }

        // 1. 허용 HTTP 메소드 (Methods)
        List<String> methods = extractStringList(props, "methods", "allowedMethods", "security.methods");
        if (!methods.isEmpty()) {
            rule.setMethods(methods);
        }

        // 2. 허용 Referer 도메인 (Referrers)
        List<String> allowedReferrers = extractStringList(props, "allowedReferrers", "referrers", "security.referrers");
        if (!allowedReferrers.isEmpty()) {
            rule.setAllowedReferrers(allowedReferrers);
        }

        // 3. 미정의 파라미터 허용 여부 (Undefined Params)
        Boolean allowUndef = extractBoolean(props, "allowUndefinedParams", "allow_undefined_params", "security.allowUndefinedParams");
        if (allowUndef != null) {
            rule.setAllowUndefinedParams(allowUndef);
        }

        // 4. 파라미터 규칙 통합 (간편 DSL 배열 형식, JSON 객체 배열 형식, JSON 맵 형식 모두 지원)
        Map<String, ParamRule> consolidatedParams = new LinkedHashMap<>();
        parseParamEntriesIntoMap(props, consolidatedParams, "params", "parameters", "paramRules", "security.params");

        // 5. 필수 파라미터 목록 (requiredParams) 추가 지원
        List<String> requiredParams = extractStringList(props, "requiredParams", "required_params", "security.requiredParams", "required");
        for (String reqParam : requiredParams) {
            if (StringUtils.isNotBlank(reqParam)) {
                String key = stripWrappingQuotes(reqParam).toLowerCase();
                if (StringUtils.isNotBlank(key) && !"true".equalsIgnoreCase(key) && !"false".equalsIgnoreCase(key)) {
                    ParamRule pr = consolidatedParams.computeIfAbsent(key, k -> new ParamRule());
                    pr.setRequired(true);
                    pr.init();
                }
            }
        }

        if (!consolidatedParams.isEmpty()) {
            rule.setParams(consolidatedParams);
        }

        // 6. 개별 검증기 On/Off 설정 (disabledValidators, enabledValidators)
        List<String> disabledVals = extractStringList(props, "disabledValidators", "skipValidators");
        if (!disabledVals.isEmpty()) {
            rule.disabledValidators = disabledVals;
        }
        List<String> enabledVals = extractStringList(props, "enabledValidators");
        if (!enabledVals.isEmpty()) {
            rule.enabledValidators = enabledVals;
        }

        // 7. 커스텀 Validator를 위한 확장 속성(extensions) 자동 수집
        Map<String, Object> ext = new LinkedHashMap<>();
        for (String extContainerKey : new String[]{"extensions", "options", "customOptions"}) {
            Object rawExt = props.get(extContainerKey);
            if (rawExt instanceof Map<?, ?>) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) rawExt).entrySet()) {
                    if (e.getKey() != null && e.getValue() != null) {
                        ext.put(e.getKey().toString().trim(), e.getValue());
                    }
                }
            }
        }
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            String key = entry.getKey();
            if (StringUtils.isNotBlank(key) && entry.getValue() != null) {
                String cleanKey = key.trim();
                if (!BUILT_IN_KEYS.contains(cleanKey.toLowerCase())) {
                    ext.put(cleanKey, entry.getValue());
                }
            }
        }
        if (!ext.isEmpty()) {
            rule.setExtensions(ext);
        }

        return rule;
    }

    /**
     * 정책 객체에서 지정된 키들의 파라미터 정의(DSL 문자열, 배열, JSON 객체, Map 등)를 파싱하여 {@code targetMap}에 병합합니다.
     *
     * @param props     정책 속성 맵
     * @param targetMap 파싱된 {@link ParamRule}을 저장할 맵 (키: 소문자 파라미터명)
     * @param keys      추출할 키 후보 목록
     */
    @SuppressWarnings("unchecked")
    private static void parseParamEntriesIntoMap(Map<String, Object> props, Map<String, ParamRule> targetMap, String... keys) {
        for (String key : keys) {
            if (!props.containsKey(key) || props.get(key) == null) {
                continue;
            }
            Object rawVal = props.get(key);
            if (rawVal instanceof Map<?, ?>) {
                parseParamMapObject((Map<?, ?>) rawVal, targetMap);
            } else if (rawVal instanceof Object[]) {
                for (Object item : (Object[]) rawVal) {
                    parseSingleParamElement(item, targetMap);
                }
            } else if (rawVal instanceof Collection<?>) {
                for (Object item : (Collection<?>) rawVal) {
                    parseSingleParamElement(item, targetMap);
                }
            } else {
                parseSingleParamElement(rawVal, targetMap);
            }
        }
    }

    /**
     * 단일 파라미터 요소(DSL 문자열, JSON 문자열, 또는 JSON 객체 Map)를 파싱하여 {@code targetMap}에 추가합니다.
     */
    @SuppressWarnings("unchecked")
    private static void parseSingleParamElement(Object item, Map<String, ParamRule> targetMap) {
        if (item == null) {
            return;
        }
        if (item instanceof Map<?, ?>) {
            parseParamObjectMapElement((Map<?, ?>) item, targetMap);
            return;
        }
        if (item instanceof JsonElement) {
            JsonElement el = (JsonElement) item;
            if (el.isJsonObject()) {
                java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, Object>>() {}.getType();
                Map<String, Object> itemMap = new com.google.gson.Gson().fromJson(el, mapType);
                parseParamObjectMapElement(itemMap, targetMap);
                return;
            } else if (el.isJsonPrimitive()) {
                item = el.getAsString();
            }
        }

        String rawSpec = item.toString().trim();
        if (StringUtils.isBlank(rawSpec)) {
            return;
        }

        // JSON 객체 문자열인지("{ \"name\": ... }") 또는 중괄호 래핑 DSL인지("{name:required:2..20}") 판별
        if (rawSpec.startsWith("{") && rawSpec.endsWith("}")) {
            String inner = rawSpec.substring(1, rawSpec.length() - 1).trim();
            if (inner.startsWith("\"") || inner.startsWith("'")) {
                try {
                    java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, Object>>() {}.getType();
                    Map<String, Object> itemMap = new com.google.gson.Gson().fromJson(rawSpec, mapType);
                    if (itemMap != null) {
                        parseParamObjectMapElement(itemMap, targetMap);
                        return;
                    }
                } catch (Exception ignored) {
                }
            }
            rawSpec = inner;
        }

        List<String> subItems = splitPreservingParens(rawSpec, ',');
        for (String sub : subItems) {
            Map.Entry<String, ParamRule> entry = parseSimpleParamSpec(sub);
            if (entry != null && StringUtils.isNotBlank(entry.getKey())) {
                targetMap.put(entry.getKey().trim().toLowerCase(), entry.getValue());
            }
        }
    }

    /**
     * {@code "params": [ { "name": "userId", "required": true, "type": "alnum", "maxLength": 20 } ]} 형태의
     * 개별 JSON 객체 Map 요소를 파싱합니다.
     */
    private static void parseParamObjectMapElement(Map<?, ?> itemMap, Map<String, ParamRule> targetMap) {
        if (itemMap == null || itemMap.isEmpty()) {
            return;
        }
        Map<String, Object> stringKeyMap = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : itemMap.entrySet()) {
            if (e.getKey() != null) {
                stringKeyMap.put(e.getKey().toString().trim(), e.getValue());
            }
        }

        List<String> names = extractStringList(stringKeyMap, "name", "param", "paramName", "key", "id");
        if (!names.isEmpty()) {
            String pName = names.get(0);
            ParamRule pr = buildParamRuleFromMap(stringKeyMap);
            if (pr != null && StringUtils.isNotBlank(pName)) {
                targetMap.put(pName.trim().toLowerCase(), pr);
            }
        } else {
            // {"userId": "required:alnum:4..20"} 또는 {"userId": {"required": true, ...}} 형태인 경우
            parseParamMapObject(itemMap, targetMap);
        }
    }

    /**
     * {@code "params": { "userId": { "required": true, ... }, "email": "required:email:50" }} 형태의 Map을 파싱합니다.
     */
    private static void parseParamMapObject(Map<?, ?> rawParams, Map<String, ParamRule> targetMap) {
        for (Map.Entry<?, ?> pe : rawParams.entrySet()) {
            if (pe.getKey() == null || pe.getValue() == null) continue;
            String pName = pe.getKey().toString().trim();
            Object pVal = pe.getValue();
            if (pVal instanceof String) {
                Map.Entry<String, ParamRule> parsed = parseSimpleParamSpec(pName + ":" + pVal.toString().trim());
                if (parsed != null) {
                    targetMap.put(pName.toLowerCase(), parsed.getValue());
                }
            } else if (pVal instanceof Map<?, ?>) {
                Map<String, Object> subMap = new LinkedHashMap<>();
                for (Map.Entry<?, ?> se : ((Map<?, ?>) pVal).entrySet()) {
                    if (se.getKey() != null) {
                        subMap.put(se.getKey().toString().trim(), se.getValue());
                    }
                }
                ParamRule pr = buildParamRuleFromMap(subMap);
                if (pr != null) {
                    targetMap.put(pName.toLowerCase(), pr);
                }
            }
        }
    }

    /**
     * JSON 객체 Map에서 {@link ParamRule}을 생성합니다 ({@code required}, {@code minLength}, {@code maxLength}, {@code pattern}, {@code type}/{@code spec} 모두 지원).
     */
    private static ParamRule buildParamRuleFromMap(Map<String, Object> map) {
        ParamRule rule = new ParamRule();

        // 1. spec 또는 type 필드에 간편 DSL 토큰이 있으면 먼저 적용
        List<String> specs = extractStringList(map, "spec", "rule", "type", "format");
        for (String spec : specs) {
            Map.Entry<String, ParamRule> parsed = parseSimpleParamSpec("dummy:" + spec);
            if (parsed != null && parsed.getValue() != null) {
                rule = parsed.getValue();
            }
        }

        // 2. 명시적 필드 오버라이드 (required, minLength, maxLength, pattern, allowPathTraversal)
        Boolean req = extractBoolean(map, "required", "mandatory", "isRequired");
        if (req != null) {
            rule.setRequired(req);
        }
        Boolean allowPt = extractBoolean(map, "allowPathTraversal", "allow_path_traversal");
        if (allowPt != null) {
            rule.setAllowPathTraversal(allowPt);
        }
        Integer minLen = extractInteger(map, "minLength", "min_length", "min");
        if (minLen != null) {
            rule.setMinLength(minLen);
        }
        Integer maxLen = extractInteger(map, "maxLength", "max_length", "max");
        if (maxLen != null) {
            rule.setMaxLength(maxLen);
        }
        List<String> patterns = extractStringList(map, "pattern", "regex");
        if (!patterns.isEmpty()) {
            rule.setPattern(patterns.get(0));
        }

        rule.init();
        return rule;
    }

    /**
     * Map에서 정수형 속성값을 추출합니다.
     */
    private static Integer extractInteger(Map<String, Object> props, String... keys) {
        for (String k : keys) {
            if (props.containsKey(k) && props.get(k) != null) {
                Object val = props.get(k);
                if (val instanceof Number) {
                    return ((Number) val).intValue();
                } else if (val instanceof String) {
                    try {
                        return Integer.parseInt(((String) val).trim());
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }
        return null;
    }

    /**
     * OSGi 프로퍼티 맵에서 단일 키에 저장된 값(String[], Collection, 또는 단일 String)을 문자열 리스트로 추출합니다.
     *
     * @param props OSGi 프로퍼티 맵
     * @param key   추출할 프로퍼티 키
     * @return 문자열 리스트
     */
    private static List<String> extractRawStringsForKey(Map<String, Object> props, String key) {
        if (!props.containsKey(key) || props.get(key) == null) {
            return Collections.emptyList();
        }
        Object val = props.get(key);
        List<String> list = new ArrayList<>();
        if (val instanceof Object[]) {
            for (Object item : (Object[]) val) {
                if (item != null && StringUtils.isNotBlank(item.toString())) {
                    list.add(item.toString().trim());
                }
            }
        } else if (val instanceof Collection<?>) {
            for (Object item : (Collection<?>) val) {
                if (item != null && StringUtils.isNotBlank(item.toString())) {
                    list.add(item.toString().trim());
                }
            }
        } else {
            String str = val.toString().trim();
            if (StringUtils.isNotBlank(str)) {
                list.add(str);
            }
        }
        return list;
    }

    /**
     * OSGi 프로퍼티 맵에서 지정된 키들의 값을 문자열 리스트로 추출합니다.
     *
     * @param props OSGi 프로퍼티 맵
     * @param keys  검색할 키 목록
     * @return 추출된 문자열 리스트
     */
    private static List<String> extractStringList(Map<String, Object> props, String... keys) {
        for (String k : keys) {
            if (props.containsKey(k)) {
                Object val = props.get(k);
                if (val instanceof Object[]) {
                    List<String> list = new ArrayList<>();
                    for (Object item : (Object[]) val) {
                        if (item != null && StringUtils.isNotBlank(item.toString())) {
                            list.add(item.toString().trim());
                        }
                    }
                    return list;
                } else if (val instanceof Collection<?>) {
                    List<String> list = new ArrayList<>();
                    for (Object item : (Collection<?>) val) {
                        if (item != null && StringUtils.isNotBlank(item.toString())) {
                            list.add(item.toString().trim());
                        }
                    }
                    return list;
                } else if (val instanceof String) {
                    String str = (String) val;
                    if (str.contains(",")) {
                        String[] parts = str.split(",");
                        List<String> list = new ArrayList<>();
                        for (String p : parts) {
                            if (StringUtils.isNotBlank(p)) list.add(p.trim());
                        }
                        return list;
                    } else if (StringUtils.isNotBlank(str)) {
                        return Collections.singletonList(str.trim());
                    }
                }
            }
        }
        return Collections.emptyList();
    }

    /**
     * OSGi 프로퍼티 맵에서 지정된 키들의 값을 Boolean으로 추출합니다.
     *
     * @param props OSGi 프로퍼티 맵
     * @param keys  검색할 키 목록
     * @return 추출된 Boolean 값 (없으면 null)
     */
    private static Boolean extractBoolean(Map<String, Object> props, String... keys) {
        for (String k : keys) {
            if (props.containsKey(k)) {
                Object val = props.get(k);
                if (val instanceof Boolean) {
                    return (Boolean) val;
                } else if (val instanceof String) {
                    return Boolean.parseBoolean(((String) val).trim());
                }
            }
        }
        return null;
    }

    /**
     * 소괄호 {@code (...)}, 중괄호 {@code {...}}, 대괄호 {@code [...]} 내부에 있는 구분자(delimiter)는 무시하면서 문자열을 분리합니다.
     * 예: {@code pattern(^[a-z:0-9]+$):10} 또는 {@code userId:required:^[a-zA-Z0-9]{4,20}$}를 안전하게 분리할 때 사용합니다.
     *
     * @param input     분리할 원본 문자열
     * @param delimiter 구분 문자
     * @return 분리된 토큰 리스트
     */
    public static List<String> splitPreservingParens(String input, char delimiter) {
        List<String> tokens = new ArrayList<>();
        if (input == null) return tokens;
        StringBuilder current = new StringBuilder();
        int parenDepth = 0;
        int braceDepth = 0;
        int bracketDepth = 0;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '(') {
                parenDepth++;
                current.append(c);
            } else if (c == ')') {
                if (parenDepth > 0) parenDepth--;
                current.append(c);
            } else if (c == '{') {
                braceDepth++;
                current.append(c);
            } else if (c == '}') {
                if (braceDepth > 0) braceDepth--;
                current.append(c);
            } else if (c == '[') {
                bracketDepth++;
                current.append(c);
            } else if (c == ']') {
                if (bracketDepth > 0) bracketDepth--;
                current.append(c);
            } else if (c == delimiter && parenDepth == 0 && braceDepth == 0 && bracketDepth == 0) {
                tokens.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            tokens.add(current.toString().trim());
        }
        return tokens;
    }

    /**
     * 문자열 양끝에 감싸진 따옴표({@code "..."} 또는 {@code '...'})를 제거합니다.
     */
    private static String stripWrappingQuotes(String input) {
        if (input == null) {
            return "";
        }
        String s = input.trim();
        while (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'")))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        return s;
    }

    /**
     * 간편 DSL 형식의 파라미터 설정 문자열(예: {@code "userId:required:alnum:4..20"})을 파싱하여
     * 파라미터 이름과 {@link ParamRule} 엔트리를 생성합니다.
     *
     * @param fullSpec 간편 DSL 형식의 파라미터 규칙 문자열
     * @return 파싱된 {@code (파라미터명, ParamRule)} 엔트리 (유효하지 않으면 null)
     */
    public static Map.Entry<String, ParamRule> parseSimpleParamSpec(String fullSpec) {
        if (StringUtils.isBlank(fullSpec)) return null;
        String clean = stripWrappingQuotes(fullSpec);
        if (clean.startsWith("{") && clean.endsWith("}")) {
            clean = stripWrappingQuotes(clean.substring(1, clean.length() - 1));
        }
        List<String> parts = splitPreservingParens(clean, ':');
        if (parts.isEmpty() || StringUtils.isBlank(parts.get(0))) return null;

        ParamRule rule = new ParamRule();
        String firstToken = stripWrappingQuotes(parts.get(0));
        String paramName;
        int startIndex = 1;

        // "required:userId:alnum:4..20" 또는 "optional:userId:20" 순서로 작성된 경우도 방어적으로 지원
        if (("required".equalsIgnoreCase(firstToken) || "req".equalsIgnoreCase(firstToken) || "mandatory".equalsIgnoreCase(firstToken))
                && parts.size() >= 2 && StringUtils.isNotBlank(parts.get(1))) {
            rule.setRequired(true);
            paramName = stripWrappingQuotes(parts.get(1));
            startIndex = 2;
        } else if (("optional".equalsIgnoreCase(firstToken) || "opt".equalsIgnoreCase(firstToken))
                && parts.size() >= 2 && StringUtils.isNotBlank(parts.get(1))) {
            rule.setRequired(false);
            paramName = stripWrappingQuotes(parts.get(1));
            startIndex = 2;
        } else {
            paramName = firstToken;
        }

        for (int i = startIndex; i < parts.size(); i++) {
            String token = stripWrappingQuotes(parts.get(i));
            if (token.isEmpty()) continue;

            if ("required".equalsIgnoreCase(token)
                    || "req".equalsIgnoreCase(token)
                    || "mandatory".equalsIgnoreCase(token)
                    || "required=true".equalsIgnoreCase(token)
                    || "true".equalsIgnoreCase(token)) {
                rule.setRequired(true);
            } else if ("optional".equalsIgnoreCase(token)
                    || "opt".equalsIgnoreCase(token)
                    || "required=false".equalsIgnoreCase(token)
                    || "false".equalsIgnoreCase(token)) {
                rule.setRequired(false);
            } else if ("allowPathTraversal".equalsIgnoreCase(token) || "allow_path_traversal".equalsIgnoreCase(token)) {
                rule.setAllowPathTraversal(true);
            } else if ("email".equalsIgnoreCase(token)) {
                rule.setPattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
                if (rule.getMaxLength() == null) rule.setMaxLength(100);
            } else if ("phone".equalsIgnoreCase(token)) {
                rule.setPattern("^01[016789]-?\\d{3,4}-?\\d{4}$");
                if (rule.getMaxLength() == null) rule.setMaxLength(13);
            } else if ("digits".equalsIgnoreCase(token) || "number".equalsIgnoreCase(token) || "numeric".equalsIgnoreCase(token)) {
                rule.setPattern("^[0-9]+$");
            } else if ("alnum".equalsIgnoreCase(token) || "alphanumeric".equalsIgnoreCase(token)) {
                rule.setPattern("^[a-zA-Z0-9_]+$");
            } else if ("alpha".equalsIgnoreCase(token)) {
                rule.setPattern("^[a-zA-Z]+$");
            } else if ("korean".equalsIgnoreCase(token) || "hangul".equalsIgnoreCase(token)) {
                rule.setPattern("^[가-힣a-zA-Z\\s]+$");
            } else if ("date".equalsIgnoreCase(token)) {
                rule.setPattern("^\\d{4}-\\d{2}-\\d{2}$");
                if (rule.getMaxLength() == null) rule.setMaxLength(10);
            } else if ("datetime".equalsIgnoreCase(token)) {
                rule.setPattern("^\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}(?::\\d{2})?$");
                if (rule.getMaxLength() == null) rule.setMaxLength(19);
            } else if ("time".equalsIgnoreCase(token)) {
                rule.setPattern("^\\d{2}:\\d{2}(?::\\d{2})?$");
                if (rule.getMaxLength() == null) rule.setMaxLength(8);
            } else if ("uuid".equalsIgnoreCase(token)) {
                rule.setPattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
                if (rule.getMaxLength() == null) rule.setMaxLength(36);
            } else if ("zipcode".equalsIgnoreCase(token) || "postal".equalsIgnoreCase(token)) {
                rule.setPattern("^\\d{5}$");
                if (rule.getMaxLength() == null) rule.setMaxLength(5);
            } else if ("ip".equalsIgnoreCase(token) || "ipv4".equalsIgnoreCase(token)) {
                rule.setPattern("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
                if (rule.getMaxLength() == null) rule.setMaxLength(15);
            } else if ("url".equalsIgnoreCase(token)) {
                rule.setPattern("^https?://[a-zA-Z0-9.-]+(?:\\.[a-zA-Z]{2,})+(?:/[^\\s<>\"]*)?$");
            } else if (token.contains("..")) {
                String[] range = token.split("\\.\\.");
                if (range.length == 2) {
                    try {
                        rule.setMinLength(Integer.parseInt(range[0].trim()));
                        rule.setMaxLength(Integer.parseInt(range[1].trim()));
                    } catch (NumberFormatException ignored) {}
                }
            } else if (token.startsWith("max:")) {
                try {
                    rule.setMaxLength(Integer.parseInt(token.substring(4).trim()));
                } catch (NumberFormatException ignored) {}
            } else if (token.startsWith("min:")) {
                try {
                    rule.setMinLength(Integer.parseInt(token.substring(4).trim()));
                } catch (NumberFormatException ignored) {}
            } else if (token.matches("^[0-9]+$")) {
                try {
                    rule.setMaxLength(Integer.parseInt(token));
                } catch (NumberFormatException ignored) {}
            } else if ((token.startsWith("pattern(") || token.startsWith("regex(")) && token.endsWith(")")) {
                int open = token.indexOf('(');
                rule.setPattern(token.substring(open + 1, token.length() - 1));
            } else if (("pattern".equalsIgnoreCase(token) || "regex".equalsIgnoreCase(token)) && i + 1 < parts.size()) {
                rule.setPattern(parts.get(i + 1).trim());
                i++;
            } else if (token.startsWith("^") || token.endsWith("$")) {
                rule.setPattern(token);
            } else if (token.contains("|")) {
                rule.setPattern("^(?i)(" + token + ")$");
            }
        }

        rule.init();
        return new java.util.AbstractMap.SimpleEntry<>(paramName, rule);
    }

    /**
     * 번들별 {@code .cfg.json}의 {@code policies} 배열 내 단일 JSON 정책 객체({@code Map}, {@code JsonObject}, 또는 JSON 문자열)를
     * 파싱하여 {@link ServletPolicyRule} 리스트를 생성합니다.
     * <p>
     * 지원 JSON 구조 예시:
     * <pre>
     * {
     *   "target": "/aemapi/user/contact",
     *   "methods": ["POST"],
     *   "allowedReferrers": ["partner.abc.com"],
     *   "params": [
     *     "name:required:2..20:korean",
     *     "email:required:email:50",
     *     "inquiryType:required:tech|billing|general"
     *   ]
     * }
     * </pre>
     *
     * @param entryObj      {@code policies} 배열의 개별 요소 (Map, JsonElement, 또는 JSON String)
     * @param defaultPolicy 상속할 기본 정책 규칙 (없으면 null)
     * @return 파싱 및 초기화된 {@link ServletPolicyRule} 리스트
     */
    @SuppressWarnings("unchecked")
    public static List<ServletPolicyRule> fromPolicyJsonEntry(final Object entryObj, final ServletPolicyRule defaultPolicy) {
        if (entryObj == null) {
            return Collections.emptyList();
        }

        Map<String, Object> map = null;
        if (entryObj instanceof Map<?, ?>) {
            // javax.json.JsonObject / jakarta.json.JsonObject 등 Map을 구현한 JSON AST 객체인 경우
            // 내부 값이 JsonString(따옴표 포함)이므로 JSON 문자열로 직렬화 후 표준 Java Map으로 파싱
            String clsName = entryObj.getClass().getName().toLowerCase();
            if (clsName.contains("json") && !clsName.contains("gson")) {
                try {
                    java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, Object>>() {}.getType();
                    map = new com.google.gson.Gson().fromJson(entryObj.toString(), mapType);
                } catch (Exception ignored) {
                }
            }
            if (map == null) {
                map = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : ((Map<?, ?>) entryObj).entrySet()) {
                    if (e.getKey() != null) {
                        map.put(e.getKey().toString(), e.getValue());
                    }
                }
            }
        } else if (entryObj instanceof JsonElement) {
            JsonElement el = (JsonElement) entryObj;
            if (el.isJsonObject()) {
                java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, Object>>() {}.getType();
                map = new com.google.gson.Gson().fromJson(el, mapType);
            }
        } else {
            String trimmed = stripWrappingQuotes(entryObj.toString());
            if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
                try {
                    java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, Object>>() {}.getType();
                    map = new com.google.gson.Gson().fromJson(trimmed, mapType);
                } catch (Exception ignored) {
                }
            }
        }

        if (map == null || map.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> targets = extractStringList(map, "target", "targets", "path", "paths", "sling.servlet.paths", "resourceType", "resourceTypes");
        if (targets.isEmpty()) {
            return Collections.emptyList();
        }

        List<ServletPolicyRule> result = new ArrayList<>(targets.size());
        for (String t : targets) {
            if (StringUtils.isBlank(t)) {
                continue;
            }
            ServletPolicyRule rule = parseRuleForTarget(map);
            rule.setTarget(t.trim());
            rule.inheritFrom(defaultPolicy);
            rule.init();
            result.add(rule);
        }

        return result;
    }

    /**
     * 해당 서블릿/타겟에 적용된 보안 설정 정보(Method, Referer, Param)를 사람이 읽기 쉬운 요약 문자열로 반환합니다.
     *
     * @return 현재 보안 정책 설정 요약 문자열
     */
    public String toPolicySummaryString() {
        StringBuilder sb = new StringBuilder();
        sb.append("target=").append(StringUtils.defaultIfBlank(target, "UNKNOWN"));
        sb.append(", methods=").append(getMethods().isEmpty() ? "ALL" : getMethods());
        if (StringUtils.isNotBlank(defaultReferrer) || !getAllowedReferrers().isEmpty()) {
            List<String> refs = new ArrayList<>();
            if (StringUtils.isNotBlank(defaultReferrer)) refs.add(defaultReferrer);
            refs.addAll(getAllowedReferrers());
            sb.append(", allowedReferrers=").append(refs);
        }
        sb.append(", allowUndefinedParams=").append(isAllowUndefinedParams());

        Map<String, ParamRule> pMap = getParams();
        if (pMap != null && !pMap.isEmpty()) {
            sb.append(", params={");
            boolean first = true;
            for (Map.Entry<String, ParamRule> entry : pMap.entrySet()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(entry.getKey()).append("=").append(
                        entry.getValue() != null ? entry.getValue().toSummaryString() : "{}"
                );
            }
            sb.append("}");
        } else {
            sb.append(", params={}");
        }
        if (extensions != null && !extensions.isEmpty()) {
            sb.append(", extensions=").append(extensions);
        }
        return sb.toString();
    }

    /**
     * 정책 규칙의 문자열 표현을 반환합니다.
     *
     * @return 요약 문자열을 포함한 문자열 표현
     */
    @Override
    public String toString() {
        return "ServletPolicyRule[" + toPolicySummaryString() + "]";
    }
}
