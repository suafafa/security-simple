package com.example.security.models;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 특정 타겟(URL 경로 또는 Sling resourceType)에 대한 보안 정책 규칙 컨테이너 모델입니다.
 * <p>
 * 특정 {@link com.example.security.validators.PolicyValidator}에 종속된 필드를 가지지 않으며,
 * 공통 라우팅/제어 메타데이터({@code target}, {@code enabled}, {@code mode})와
 * 각 Validator가 자유롭게 조회하는 {@code extensions} 맵만 관리합니다.
 */
public class ServletPolicyRule {

    private static final Gson GSON = new Gson();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();

    // 기본 내장 메타데이터 키 집합 (이 외의 모든 JSON 키는 extensions 맵에 자동 저장됨)
    private static final Set<String> BUILT_IN_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "target", "enabled", "mode", "extensions"
    )));

    /** 정책이 적용될 서블릿 경로(예: "/aemapi/user/contact") 또는 Sling resourceType */
    @SerializedName("target")
    private String target;

    /** 개별 서블릿 정책 활성화 여부 (false 설정 시 해당 서블릿 검증 생략) */
    @SerializedName("enabled")
    private Boolean enabled = true;

    /** 개별 서블릿 보안 실행 모드 ("ENFORCE": 위반 시 차단, "MONITOR": 위반 시 WARN 로그만 기록 후 통과) */
    @SerializedName("mode")
    private String mode;

    /** 각 PolicyValidator가 참조하는 설정 속성 맵 (예: methods, allowedReferrers, params, runModes, auth, csrf 등) */
    @SerializedName("extensions")
    private Map<String, Object> extensions;

    // 와일드카드/정규식 타겟 매칭을 위한 런타임 컴파일 캐시
    private transient Pattern compiledTargetPattern;

    /**
     * 타겟 정규식 패턴을 사전 컴파일하고 실행 모드 정규화 및 설정값 유효성 검증을 수행합니다.
     */
    public void init() {
        if (StringUtils.isNotBlank(target) && (target.contains("*") || target.contains("^") || target.contains("$"))) {
            try {
                this.compiledTargetPattern = Pattern.compile(target.trim());
            } catch (Exception ignored) {
            }
        }

        setMode(this.mode);

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
     * 타겟 정규식(Target Regex) 문법이 유효한지 검증합니다.
     *
     * @param errors 검증 오류 메시지를 수집할 리스트
     */
    public void validate(final List<String> errors) {
        String id = getTargetIdentifier();
        if (StringUtils.isNotBlank(target) && (target.contains("*") || target.contains("^") || target.contains("$"))) {
            try {
                Pattern.compile(target.trim());
            } catch (Exception e) {
                errors.add("Target '" + id + "': Invalid regex pattern for target: '" + target + "' (" + e.getMessage() + ")");
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
                String cleanTarget = target.trim();
                if (resource.isResourceType(cleanTarget)
                        || cleanTarget.equals(resource.getResourceType())) {
                    return true;
                }
            }
        }

        return requestUri != null && requestUri.contains(target.trim());
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
     * 이 서블릿 정책에 설정된 실행 모드({@code "ENFORCE"} 또는 {@code "MONITOR"})를 반환합니다.
     *
     * @return 설정된 모드 문자열 (미설정 시 null)
     */
    public String getMode() {
        if (StringUtils.isBlank(mode)) {
            return null;
        }
        return "MONITOR".equalsIgnoreCase(mode.trim()) ? "MONITOR" : "ENFORCE";
    }

    /**
     * 문자열({@code "ENFORCE"} 또는 {@code "MONITOR"})로 이 서블릿 정책의 모드를 설정합니다.
     *
     * @param mode 설정할 모드 문자열
     */
    public void setMode(final String mode) {
        if (StringUtils.isBlank(mode)) {
            this.mode = null;
        } else {
            this.mode = "MONITOR".equalsIgnoreCase(mode.trim()) ? "MONITOR" : "ENFORCE";
        }
    }

    /**
     * 각 {@link com.example.security.validators.PolicyValidator}에서 참조하는 확장 설정 맵을 반환합니다.
     *
     * @return 확장 설정 맵 (없으면 빈 Map)
     */
    public Map<String, Object> getExtensions() {
        return extensions != null ? Collections.unmodifiableMap(extensions) : Collections.emptyMap();
    }

    /**
     * 확장 설정 맵을 설정합니다.
     *
     * @param extensions 설정할 확장 속성 맵
     */
    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions != null ? new LinkedHashMap<>(extensions) : null;
    }

    /**
     * 확장 속성을 단일 키-값으로 추가합니다.
     *
     * @param key   속성 키 (예: "methods", "allowedReferrers", "params", "runModes")
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
     *
     * @param keys 조회할 설정 키 후보 목록
     * @return 추출된 문자열 리스트 (미설정 시 빈 리스트)
     */
    public List<String> getExtensionStringList(String... keys) {
        if (extensions == null || extensions.isEmpty() || keys == null) {
            return Collections.emptyList();
        }
        return extractStringList(extensions, keys);
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
     * 확장 속성 맵({@code extensions})에서 지정된 키 후보들(대소문자 무시) 중 일치하는 값을 대문자 집합(Set)으로 조회합니다.
     *
     * @param keys 조회할 설정 키 후보 목록
     * @return 추출된 대문자 문자열 Set (미설정 시 빈 Set)
     */
    public Set<String> getExtensionUpperSet(String... keys) {
        List<String> list = getExtensionStringList(keys);
        if (list.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> set = new LinkedHashSet<>();
        for (String item : list) {
            if (StringUtils.isNotBlank(item)) {
                set.add(item.trim().toUpperCase());
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
        return extractBoolean(extensions, keys);
    }

    /**
     * 상위 정책(주로 {@code defaultPolicy})으로부터 미설정된 실행 모드({@code mode})와
     * 확장 속성({@code extensions})을 상속받습니다. 현재 규칙에 명시적으로 설정된 속성이 항상 우선합니다.
     *
     * @param parent 상속받을 부모 정책 규칙
     */
    public void inheritFrom(final ServletPolicyRule parent) {
        if (parent == null) {
            return;
        }

        if (StringUtils.isBlank(this.mode) && StringUtils.isNotBlank(parent.mode)) {
            this.mode = parent.mode;
        }

        if (parent.extensions != null && !parent.extensions.isEmpty()) {
            if (this.extensions == null) {
                this.extensions = new LinkedHashMap<>(parent.extensions);
            } else {
                for (Map.Entry<String, Object> entry : parent.extensions.entrySet()) {
                    if (entry.getKey() != null && !containsKeyIgnoreCase(this.extensions, entry.getKey())) {
                        this.extensions.put(entry.getKey(), entry.getValue());
                    }
                }
            }
        }
    }

    /**
     * 다른 {@link ServletPolicyRule} 객체의 모든 설정 필드를 현재 객체로 복사합니다.
     *
     * @param other 복사할 원본 정책 규칙 객체
     */
    public void copyFrom(final ServletPolicyRule other) {
        if (other == null) {
            return;
        }
        this.target = other.target;
        this.enabled = other.enabled;
        this.mode = other.mode;
        this.extensions = other.extensions != null ? new LinkedHashMap<>(other.extensions) : null;
    }

    /**
     * JSON 정책 객체 맵을 파싱하여 {@link ServletPolicyRule}을 생성합니다.
     * {@code target}, {@code enabled}, {@code mode}를 제외한 모든 속성은 {@code extensions} 맵에 자동 수집됩니다.
     *
     * @param props JSON 정책 객체 맵
     * @return 파싱된 {@link ServletPolicyRule} 객체
     */
    private static ServletPolicyRule parseRuleForTarget(final Map<String, Object> props) {
        ServletPolicyRule rule = new ServletPolicyRule();

        Boolean enabledVal = extractBoolean(props, "enabled");
        if (enabledVal != null) {
            rule.setEnabled(enabledVal);
        }

        List<String> modes = extractStringList(props, "mode");
        if (!modes.isEmpty()) {
            rule.setMode(modes.get(0));
        }

        Map<String, Object> ext = new LinkedHashMap<>();
        Object rawExt = findValueIgnoreCase(props, "extensions");
        if (rawExt instanceof Map<?, ?>) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) rawExt).entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    ext.put(e.getKey().toString().trim(), e.getValue());
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
     * 번들별 {@code .cfg.json}의 {@code policies} 배열 내 단일 JSON 정책 객체를 파싱하여
     * {@link ServletPolicyRule} 리스트를 생성합니다.
     *
     * @param entryObj      {@code policies} 배열의 개별 요소 (Map, JsonElement, 또는 JSON String)
     * @param defaultPolicy 상속할 기본 정책 규칙 (없으면 null)
     * @return 파싱 및 초기화된 {@link ServletPolicyRule} 리스트
     */
    public static List<ServletPolicyRule> fromPolicyJsonEntry(final Object entryObj, final ServletPolicyRule defaultPolicy) {
        if (entryObj == null) {
            return Collections.emptyList();
        }

        Map<String, Object> map = toPolicyMap(entryObj);
        if (map == null || map.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> targets = extractStringList(map, "target");
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
     * 다양한 타입(Map, JsonElement, JSON 문자열)의 정책 엔트리를 표준 {@code Map<String, Object>}으로 변환합니다.
     */
    private static Map<String, Object> toPolicyMap(final Object entryObj) {
        if (entryObj instanceof Map<?, ?>) {
            String clsName = entryObj.getClass().getName().toLowerCase();
            if (clsName.contains("json") && !clsName.contains("gson")) {
                try {
                    return GSON.fromJson(entryObj.toString(), MAP_TYPE);
                } catch (Exception ignored) {
                }
            }
            Map<String, Object> map = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) entryObj).entrySet()) {
                if (e.getKey() != null) {
                    map.put(e.getKey().toString(), e.getValue());
                }
            }
            return map;
        }
        if (entryObj instanceof JsonElement) {
            JsonElement el = (JsonElement) entryObj;
            return el.isJsonObject() ? GSON.fromJson(el, MAP_TYPE) : null;
        }
        String trimmed = stripWrappingQuotes(entryObj.toString());
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                return GSON.fromJson(trimmed, MAP_TYPE);
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    /**
     * 맵에 지정된 키가 존재하는지 대소문자를 무시하고 확인합니다.
     */
    static boolean containsKeyIgnoreCase(final Map<String, ?> map, final String key) {
        if (map == null || key == null) {
            return false;
        }
        if (map.containsKey(key)) {
            return true;
        }
        for (String k : map.keySet()) {
            if (k != null && k.equalsIgnoreCase(key)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 맵에서 대소문자를 구분하지 않고 키에 해당하는 값을 조회합니다.
     */
    public static Object findValueIgnoreCase(final Map<String, Object> props, final String key) {
        if (props == null || key == null) {
            return null;
        }
        if (props.containsKey(key)) {
            return props.get(key);
        }
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * 프로퍼티 맵에서 지정된 키들의 값을 문자열 리스트로 추출합니다 (배열, 컬렉션, 쉼표 구분 문자열 지원).
     */
    public static List<String> extractStringList(final Map<String, Object> props, final String... keys) {
        for (String k : keys) {
            Object val = findValueIgnoreCase(props, k);
            if (val == null) {
                continue;
            }
            if (val instanceof Object[]) {
                List<String> list = new ArrayList<>();
                for (Object item : (Object[]) val) {
                    if (item != null && StringUtils.isNotBlank(item.toString())) {
                        list.add(item.toString().trim());
                    }
                }
                return list;
            }
            if (val instanceof Collection<?>) {
                List<String> list = new ArrayList<>();
                for (Object item : (Collection<?>) val) {
                    if (item != null && StringUtils.isNotBlank(item.toString())) {
                        list.add(item.toString().trim());
                    }
                }
                return list;
            }
            String str = val.toString();
            if (val instanceof String && str.contains(",")) {
                List<String> list = new ArrayList<>();
                for (String p : str.split(",")) {
                    if (StringUtils.isNotBlank(p)) {
                        list.add(p.trim());
                    }
                }
                return list;
            }
            if (StringUtils.isNotBlank(str)) {
                return Collections.singletonList(str.trim());
            }
        }
        return Collections.emptyList();
    }

    /**
     * 프로퍼티 맵에서 지정된 키들의 값을 Boolean으로 추출합니다 (키 대소문자 무시).
     */
    public static Boolean extractBoolean(final Map<String, Object> props, final String... keys) {
        for (String k : keys) {
            Object val = findValueIgnoreCase(props, k);
            if (val instanceof Boolean) {
                return (Boolean) val;
            } else if (val instanceof String) {
                return Boolean.parseBoolean(((String) val).trim());
            }
        }
        return null;
    }

    /**
     * 문자열 양끝에 감싸진 따옴표({@code "..."} 또는 {@code '...'})를 제거합니다.
     */
    public static String stripWrappingQuotes(final String input) {
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
     * 해당 서블릿/타겟에 적용된 보안 설정 정보를 사람이 읽기 쉬운 요약 문자열로 반환합니다.
     *
     * @return 현재 보안 정책 설정 요약 문자열
     */
    public String toPolicySummaryString() {
        StringBuilder sb = new StringBuilder();
        sb.append("target=").append(StringUtils.defaultIfBlank(target, "UNKNOWN"));
        sb.append(", enabled=").append(isEnabled());
        if (getMode() != null) {
            sb.append(", mode=").append(getMode());
        }
        if (extensions != null && !extensions.isEmpty()) {
            sb.append(", extensions=").append(extensions);
        }
        return sb.toString();
    }

    /** 정책 규칙의 문자열 표현을 반환합니다. */
    @Override
    public String toString() {
        return "ServletPolicyRule[" + toPolicySummaryString() + "]";
    }
}
