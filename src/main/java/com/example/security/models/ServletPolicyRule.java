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

    @SerializedName(value = "blockSqlInjection", alternate = {"block_sql_injection", "enableSqlInjectionCheck"})
    private Boolean blockSqlInjection = true;

    @SerializedName(value = "blockXss", alternate = {"block_xss", "enableXssCheck"})
    private Boolean blockXss = true;

    @SerializedName("params")
    private Map<String, ParamRule> params;

    @SerializedName(value = "validators", alternate = {"validatorSettings"})
    private JsonElement validators;

    @SerializedName(value = "disabledValidators", alternate = {"skipValidators"})
    private List<String> disabledValidators;

    @SerializedName(value = "enabledValidators")
    private List<String> enabledValidators;

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
     * 파라미터 값에 대한 SQL/JCR2 인젝션 패턴 차단 활성화 여부를 반환합니다.
     *
     * @return SQL 인젝션 차단이 활성화되어 있으면 true (기본값 true)
     */
    public boolean isBlockSqlInjection() {
        return blockSqlInjection == null || blockSqlInjection;
    }

    /**
     * 파라미터 값에 대한 SQL/JCR2 인젝션 패턴 차단 활성화 여부를 설정합니다.
     *
     * @param blockSqlInjection SQL 인젝션 차단 여부
     */
    public void setBlockSqlInjection(Boolean blockSqlInjection) {
        this.blockSqlInjection = blockSqlInjection;
    }

    /**
     * 파라미터 값에 대한 크로스 사이트 스크립팅(XSS) 패턴 차단 활성화 여부를 반환합니다.
     *
     * @return XSS 차단이 활성화되어 있으면 true (기본값 true)
     */
    public boolean isBlockXss() {
        return blockXss == null || blockXss;
    }

    /**
     * 파라미터 값에 대한 크로스 사이트 스크립팅(XSS) 패턴 차단 활성화 여부를 설정합니다.
     *
     * @param blockXss XSS 차단 여부
     */
    public void setBlockXss(Boolean blockXss) {
        this.blockXss = blockXss;
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

        if (this.blockSqlInjection == null && parent.blockSqlInjection != null) {
            this.blockSqlInjection = parent.blockSqlInjection;
        }

        if (this.blockXss == null && parent.blockXss != null) {
            this.blockXss = parent.blockXss;
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
            if (this.params == null || this.params.isEmpty()) {
                this.params = new LinkedHashMap<>(parent.params);
            } else {
                Map<String, ParamRule> merged = new LinkedHashMap<>(parent.params);
                merged.putAll(this.params); // 개별 서블릿의 파라미터 규칙이 기본 정책보다 우선함
                this.params = merged;
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
        this.blockSqlInjection = other.blockSqlInjection;
        this.blockXss = other.blockXss;
        this.defaultReferrer = other.defaultReferrer;
        this.allowedReferrers = other.allowedReferrers != null ? new ArrayList<>(other.allowedReferrers) : null;
        this.allowUndefinedParams = other.allowUndefinedParams;
        this.params = other.params != null ? new LinkedHashMap<>(other.params) : null;
    }

    /**
     * OSGi 서블릿 컴포넌트 속성을 파싱하여 하나 이상의 {@link ServletPolicyRule} 인스턴스를 생성합니다.
     * {@code sling.servlet.paths} 또는 {@code sling.servlet.resourceTypes}에서 타겟을 추출하고,
     * {@code security.*} 속성을 규칙에 매핑한 뒤 {@code defaultPolicy}로부터 기본 설정을 상속받습니다.
     *
     * @param props         서블릿의 OSGi 컴포넌트 프로퍼티 맵
     * @param defaultPolicy 상속할 기본 정책 규칙
     * @return 생성 및 초기화된 {@link ServletPolicyRule} 리스트
     */
    public static List<ServletPolicyRule> fromOsgiProperties(Map<String, Object> props, ServletPolicyRule defaultPolicy) {
        if (props == null || props.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> targets = new ArrayList<>();
        for (String p : extractStringList(props, "sling.servlet.paths")) {
            if (StringUtils.isNotBlank(p) && !targets.contains(p.trim())) {
                targets.add(p.trim());
            }
        }
        for (String rt : extractStringList(props, "sling.servlet.resourceTypes")) {
            if (StringUtils.isNotBlank(rt) && !targets.contains(rt.trim())) {
                targets.add(rt.trim());
            }
        }
        if (targets.isEmpty()) {
            Object desc = props.get("service.description");
            if (desc != null && StringUtils.isNotBlank(desc.toString())) {
                targets.add(desc.toString().trim());
            }
        }
        if (targets.isEmpty()) {
            return Collections.emptyList();
        }

        List<ServletPolicyRule> rules = new ArrayList<>(targets.size());
        for (String target : targets) {
            if (StringUtils.isBlank(target)) continue;
            String cleanTarget = target.trim();
            ServletPolicyRule rule = parseRuleForTarget(props, cleanTarget, targets);
            rule.setTarget(cleanTarget);
            rule.inheritFrom(defaultPolicy);
            rule.init();
            rules.add(rule);
        }
        return rules;
    }

    /**
     * OSGi 속성으로부터 특정 타겟 경로/resourceType에 대한 {@link ServletPolicyRule}을 파싱합니다.
     * 서블릿 공통 속성(서블릿의 모든 경로에 적용)과 타겟별 개별 재정의(Override)를 모두 지원합니다.
     *
     * @param props         서블릿의 OSGi 컴포넌트 프로퍼티 맵
     * @param currentTarget 현재 파싱 중인 타겟 경로 또는 resourceType
     * @param allTargets    해당 서블릿에 선언된 모든 타겟 목록
     * @return 파싱된 {@link ServletPolicyRule} 객체
     */
    private static ServletPolicyRule parseRuleForTarget(Map<String, Object> props, String currentTarget, List<String> allTargets) {
        ServletPolicyRule rule = new ServletPolicyRule();

        // 1. 허용 HTTP 메소드 (Methods)
        List<String> methods = extractTargetStringList(props, currentTarget, allTargets, "security.methods", "methods");
        if (!methods.isEmpty()) {
            rule.setMethods(methods);
        }

        // 2. 허용 Referer 도메인 (Referrers)
        List<String> allowedReferrers = extractTargetStringList(props, currentTarget, allTargets, "security.allowedReferrers", "allowedReferrers");
        if (!allowedReferrers.isEmpty()) {
            rule.setAllowedReferrers(allowedReferrers);
        }

        // 3. SQLi / XSS 차단 여부
        Boolean blockSql = extractBoolean(props, "security.blockSqlInjection", "blockSqlInjection");
        if (blockSql != null) {
            rule.setBlockSqlInjection(blockSql);
        }
        Boolean blockXss = extractBoolean(props, "security.blockXss", "blockXss");
        if (blockXss != null) {
            rule.setBlockXss(blockXss);
        }

        // 4. 미정의 파라미터 허용 여부 (Undefined Params)
        String allowUndefStr = extractTargetString(props, currentTarget, allTargets, "security.allowUndefinedParams", "allowUndefinedParams");
        if (StringUtils.isNotBlank(allowUndefStr)) {
            rule.setAllowUndefinedParams(Boolean.parseBoolean(allowUndefStr.trim()));
        } else {
            Boolean allowUndef = extractBoolean(props, "security.allowUndefinedParams", "allowUndefinedParams");
            if (allowUndef != null) {
                rule.setAllowUndefinedParams(allowUndef);
            }
        }

        // 5. 가능한 모든 설정 형식(공통 + 타겟별)으로부터 파라미터 규칙 통합
        Map<String, ParamRule> consolidatedParams = new LinkedHashMap<>();

        // 파라미터 (1): JSON 형식 (예: security.params.json)
        String paramsJson = extractTargetString(props, currentTarget, allTargets, "security.params.json", "params.json");
        if (StringUtils.isNotBlank(paramsJson) && paramsJson.trim().startsWith("{")) {
            try {
                java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, ParamRule>>() {}.getType();
                Map<String, ParamRule> parsedParams = new com.google.gson.Gson().fromJson(paramsJson, mapType);
                if (parsedParams != null && !parsedParams.isEmpty()) {
                    consolidatedParams.putAll(parsedParams);
                }
            } catch (Exception ignored) {}
        }

        // 파라미터 (2): 간편 DSL 형식 (공통 "name:required:2..20" 및 경로별 "/aemapi/path:name:required:2..20" 모두 지원)
        List<String> rawParamEntries = extractRawStringEntriesWithTargetKeys(props, currentTarget, "security.params", "security.parameters", "params");
        if (!rawParamEntries.isEmpty()) {
            for (String rawSpec : rawParamEntries) {
                if (StringUtils.isBlank(rawSpec) || rawSpec.trim().startsWith("{")) continue;
                String[] scoped = splitTargetPrefix(rawSpec, allTargets);
                String targetPrefix = scoped[0];
                String specBody = scoped[1];
                if (targetPrefix == null || targetPrefix.equalsIgnoreCase(currentTarget)) {
                    String[] subItems = specBody.contains(",") ? specBody.split(",") : new String[]{specBody};
                    for (String item : subItems) {
                        Map.Entry<String, ParamRule> entry = parseSimpleParamSpec(item);
                        if (entry != null && StringUtils.isNotBlank(entry.getKey())) {
                            consolidatedParams.put(entry.getKey().toLowerCase(), entry.getValue());
                        }
                    }
                }
            }
        }

        // 파라미터 (3): 개별 속성 형식 (예: "security.param.name=required:2..20" 또는 "security./aemapi/path.param.name=required:2..20")
        String targetParamPrefix1 = "security." + currentTarget + ".param.";
        String targetParamPrefix2 = "param[" + currentTarget + "].";
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            String key = entry.getKey();
            if (key == null || entry.getValue() == null) continue;
            String sub = null;
            if (key.startsWith("security.param.")) {
                sub = key.substring("security.param.".length()).trim();
            } else if (key.startsWith(targetParamPrefix1)) {
                sub = key.substring(targetParamPrefix1.length()).trim();
            } else if (key.startsWith(targetParamPrefix2)) {
                sub = key.substring(targetParamPrefix2.length()).trim();
            }
            if (StringUtils.isNotBlank(sub)) {
                if (sub.endsWith(".pattern") || sub.endsWith(".regex")) {
                    String realName = sub.substring(0, sub.lastIndexOf('.')).trim();
                    if (!realName.isEmpty()) {
                        ParamRule pr = consolidatedParams.getOrDefault(realName.toLowerCase(), new ParamRule());
                        pr.setPattern(entry.getValue().toString().trim());
                        consolidatedParams.put(realName.toLowerCase(), pr);
                    }
                } else {
                    String valStr = entry.getValue().toString().trim();
                    String[] scopedVal = splitTargetPrefix(valStr, allTargets);
                    if (scopedVal[0] == null || scopedVal[0].equalsIgnoreCase(currentTarget)) {
                        String spec = sub + ":" + scopedVal[1];
                        Map.Entry<String, ParamRule> parsed = parseSimpleParamSpec(spec);
                        if (parsed != null && StringUtils.isNotBlank(parsed.getKey())) {
                            ParamRule existing = consolidatedParams.get(parsed.getKey().toLowerCase());
                            if (existing != null) {
                                if (parsed.getValue().getPattern() != null) existing.setPattern(parsed.getValue().getPattern());
                                if (parsed.getValue().isRequired()) existing.setRequired(true);
                                if (parsed.getValue().getMinLength() != null) existing.setMinLength(parsed.getValue().getMinLength());
                                if (parsed.getValue().getMaxLength() != null) existing.setMaxLength(parsed.getValue().getMaxLength());
                            } else {
                                consolidatedParams.put(parsed.getKey().toLowerCase(), parsed.getValue());
                            }
                        }
                    }
                }
            }
        }

        // 파라미터 (4): 단순 필수 파라미터 목록 (예: "security.requiredParams")
        List<String> requiredParams = extractTargetStringList(props, currentTarget, allTargets, "security.requiredParams", "requiredParams");
        if (!requiredParams.isEmpty()) {
            for (String rp : requiredParams) {
                ParamRule pr = consolidatedParams.getOrDefault(rp.toLowerCase(), new ParamRule());
                pr.setRequired(true);
                consolidatedParams.put(rp.toLowerCase(), pr);
            }
        }

        if (!consolidatedParams.isEmpty()) {
            rule.setParams(consolidatedParams);
        }

        return rule;
    }

    /**
     * 설정 문자열에서 타겟 경로 접두사(예: {@code [/aemapi/path]value} 또는 {@code /aemapi/path:value})와
     * 실제 설정 본문을 분리합니다.
     *
     * @param rawValue   원본 설정 문자열
     * @param allTargets 서블릿의 전체 타겟 목록
     * @return 길이 2의 배열 {@code [타겟 접두사(없으면 null), 설정 본문]}
     */
    private static String[] splitTargetPrefix(String rawValue, List<String> allTargets) {
        if (rawValue == null) {
            return new String[]{null, ""};
        }
        String trimmed = rawValue.trim();
        if (trimmed.startsWith("[") && trimmed.indexOf(']') > 1) {
            int closeIdx = trimmed.indexOf(']');
            String target = trimmed.substring(1, closeIdx).trim();
            String rest = trimmed.substring(closeIdx + 1).trim();
            if (rest.startsWith(":")) {
                rest = rest.substring(1).trim();
            }
            return new String[]{target, rest};
        }
        if (allTargets != null) {
            for (String t : allTargets) {
                if (StringUtils.isNotBlank(t)) {
                    String cleanT = t.trim();
                    if (trimmed.regionMatches(true, 0, cleanT, 0, cleanT.length())
                            && trimmed.length() > cleanT.length()
                            && trimmed.charAt(cleanT.length()) == ':') {
                        return new String[]{cleanT, trimmed.substring(cleanT.length() + 1).trim()};
                    }
                }
            }
        }
        if (trimmed.startsWith("/")) {
            int colonIdx = trimmed.indexOf(':');
            if (colonIdx > 1) {
                return new String[]{trimmed.substring(0, colonIdx).trim(), trimmed.substring(colonIdx + 1).trim()};
            }
        }
        return new String[]{null, trimmed};
    }

    /**
     * OSGi 프로퍼티 맵에서 기본 키 및 타겟별 확장 키에 해당하는 문자열 항목들을 모두 추출합니다.
     *
     * @param props         OSGi 프로퍼티 맵
     * @param currentTarget 현재 타겟 경로
     * @param baseKeys      검색할 기본 프로퍼티 키 목록
     * @return 추출된 원본 문자열 리스트
     */
    private static List<String> extractRawStringEntriesWithTargetKeys(Map<String, Object> props, String currentTarget, String... baseKeys) {
        List<String> rawEntries = new ArrayList<>();
        for (String k : baseKeys) {
            rawEntries.addAll(extractRawStringsForKey(props, k));
            if (StringUtils.isNotBlank(currentTarget)) {
                String shortKey = k.startsWith("security.") ? k.substring("security.".length()) : k;
                for (String tk : Arrays.asList(
                        k + "[" + currentTarget + "]",
                        shortKey + "[" + currentTarget + "]",
                        "security." + currentTarget + "." + shortKey,
                        currentTarget + "." + shortKey)) {
                    for (String val : extractRawStringsForKey(props, tk)) {
                        rawEntries.add("[" + currentTarget + "]" + val);
                    }
                }
            }
        }
        return rawEntries;
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
        if (val instanceof String[]) {
            for (String s : (String[]) val) {
                if (StringUtils.isNotBlank(s)) list.add(s.trim());
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
     * 특정 타겟에 해당하는 문자열 리스트 설정을 추출합니다.
     * 타겟 전용 설정이 존재하면 공통 설정보다 우선 적용합니다.
     *
     * @param props         OSGi 프로퍼티 맵
     * @param currentTarget 현재 타겟 경로
     * @param allTargets    서블릿의 전체 타겟 목록
     * @param keys          검색할 프로퍼티 키 목록
     * @return 추출된 문자열 리스트
     */
    private static List<String> extractTargetStringList(Map<String, Object> props, String currentTarget, List<String> allTargets, String... keys) {
        List<String> rawEntries = extractRawStringEntriesWithTargetKeys(props, currentTarget, keys);
        List<String> targetSpecific = new ArrayList<>();
        List<String> common = new ArrayList<>();

        for (String raw : rawEntries) {
            String[] scoped = splitTargetPrefix(raw, allTargets);
            String targetPrefix = scoped[0];
            String body = scoped[1];
            if (StringUtils.isBlank(body)) continue;

            if (targetPrefix != null) {
                if (targetPrefix.equalsIgnoreCase(currentTarget)) {
                    for (String part : body.split(",")) {
                        if (StringUtils.isNotBlank(part)) targetSpecific.add(part.trim());
                    }
                }
            } else {
                for (String part : body.split(",")) {
                    if (StringUtils.isNotBlank(part)) common.add(part.trim());
                }
            }
        }
        return !targetSpecific.isEmpty() ? targetSpecific : common;
    }

    /**
     * 특정 타겟에 해당하는 단일 문자열 설정을 추출합니다.
     * 타겟 전용 설정이 존재하면 공통 설정보다 우선 적용합니다.
     *
     * @param props         OSGi 프로퍼티 맵
     * @param currentTarget 현재 타겟 경로
     * @param allTargets    서블릿의 전체 타겟 목록
     * @param keys          검색할 프로퍼티 키 목록
     * @return 추출된 문자열 (없으면 null)
     */
    private static String extractTargetString(Map<String, Object> props, String currentTarget, List<String> allTargets, String... keys) {
        List<String> rawEntries = extractRawStringEntriesWithTargetKeys(props, currentTarget, keys);
        String targetSpecific = null;
        String common = null;

        for (String raw : rawEntries) {
            String[] scoped = splitTargetPrefix(raw, allTargets);
            String targetPrefix = scoped[0];
            String body = scoped[1];
            if (StringUtils.isBlank(body)) continue;

            if (targetPrefix != null) {
                if (targetPrefix.equalsIgnoreCase(currentTarget)) {
                    targetSpecific = body;
                }
            } else if (common == null) {
                common = body;
            }
        }
        return targetSpecific != null ? targetSpecific : common;
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
                if (val instanceof String[]) {
                    List<String> list = new ArrayList<>();
                    for (String s : (String[]) val) {
                        if (StringUtils.isNotBlank(s)) list.add(s.trim());
                    }
                    return list;
                } else if (val instanceof List) {
                    List<String> list = new ArrayList<>();
                    for (Object item : (List<?>) val) {
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
     * 소괄호 {@code (...)} 내부에 있는 구분자(delimiter)는 무시하면서 문자열을 분리합니다.
     * 예: {@code pattern(^[a-z:0-9]+$):10}을 {@code ':'} 기준으로 안전하게 분리할 때 사용합니다.
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
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '(') {
                parenDepth++;
                current.append(c);
            } else if (c == ')') {
                if (parenDepth > 0) parenDepth--;
                current.append(c);
            } else if (c == delimiter && parenDepth == 0) {
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
     * 간편 DSL 형식의 파라미터 설정 문자열(예: {@code "userId:required:alnum:4..20"})을 파싱하여
     * 파라미터 이름과 {@link ParamRule} 엔트리를 생성합니다.
     *
     * @param fullSpec 간편 DSL 형식의 파라미터 규칙 문자열
     * @return 파싱된 {@code (파라미터명, ParamRule)} 엔트리 (유효하지 않으면 null)
     */
    public static Map.Entry<String, ParamRule> parseSimpleParamSpec(String fullSpec) {
        if (StringUtils.isBlank(fullSpec)) return null;
        String clean = fullSpec.trim();
        if (clean.startsWith("{") && clean.endsWith("}")) {
            clean = clean.substring(1, clean.length() - 1).trim();
        }
        List<String> parts = splitPreservingParens(clean, ':');
        if (parts.isEmpty() || StringUtils.isBlank(parts.get(0))) return null;

        String paramName = parts.get(0).trim();
        ParamRule rule = new ParamRule();

        for (int i = 1; i < parts.size(); i++) {
            String token = parts.get(i).trim();
            if (token.isEmpty()) continue;

            if ("required".equalsIgnoreCase(token)) {
                rule.setRequired(true);
            } else if ("optional".equalsIgnoreCase(token)) {
                rule.setRequired(false);
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
            } else if (token.contains("|")) {
                rule.setPattern("^(?i)(" + token + ")$");
            } else if ((token.startsWith("pattern(") || token.startsWith("regex(")) && token.endsWith(")")) {
                int open = token.indexOf('(');
                rule.setPattern(token.substring(open + 1, token.length() - 1));
            } else if (("pattern".equalsIgnoreCase(token) || "regex".equalsIgnoreCase(token)) && i + 1 < parts.size()) {
                rule.setPattern(parts.get(i + 1).trim());
                i++;
            }
        }

        rule.init();
        return new java.util.AbstractMap.SimpleEntry<>(paramName, rule);
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
        sb.append(", blockSqlInjection=").append(isBlockSqlInjection());
        sb.append(", blockXss=").append(isBlockXss());
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
