package com.example.security.models;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Type;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 개별 파라미터의 필수 여부(required), 길이 제약조건(minLength, maxLength),
 * 정규식 패턴(pattern), 경로 조작 허용 여부, 활성화 상태 및 DSL/JSON 파서를 정의하는 모델 클래스입니다.
 */
public class ParamRule {

    private static final Gson GSON = new Gson();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();

    /** 이 파라미터 검증 규칙의 활성화 여부 (기본값: true) */
    @SerializedName("enabled")
    private Boolean enabled = true;

    /** 필수 파라미터 여부 (기본값: false) */
    @SerializedName("required")
    private Boolean required = false;

    /** 허용 최소 글자 수 (미설정 시 null) */
    @SerializedName("minLength")
    private Integer minLength;

    /** 허용 최대 글자 수 (미설정 시 null) */
    @SerializedName("maxLength")
    private Integer maxLength;

    /** 파라미터 값 검증용 정규식 패턴 문자열 */
    @SerializedName("pattern")
    private String pattern;

    /** 경로 조작(Path Traversal: ../ 등) 구문 예외 허용 여부 (기본값: false 차단) */
    @SerializedName("allowPathTraversal")
    private Boolean allowPathTraversal = false;

    // 런타임 정규식 매칭 성능 최적화를 위한 사전 컴파일 캐시
    private transient Pattern compiledPattern;

    /**
     * 설정된 정규식 문자열(pattern)을 사전 컴파일하여 런타임 캐시에 저장합니다.
     */
    public void init() {
        if (StringUtils.isNotBlank(pattern)) {
            this.compiledPattern = Pattern.compile(pattern.trim());
        }
    }

    /**
     * 현재 {@link ParamRule}의 모든 설정값을 깊은 복사(Deep Copy)한 새 인스턴스를 반환합니다.
     *
     * @return 복사된 {@link ParamRule} 객체
     */
    public ParamRule copy() {
        ParamRule cloned = new ParamRule();
        cloned.enabled = this.enabled;
        cloned.required = this.required;
        cloned.minLength = this.minLength;
        cloned.maxLength = this.maxLength;
        cloned.pattern = this.pattern;
        cloned.allowPathTraversal = this.allowPathTraversal;
        cloned.compiledPattern = this.compiledPattern;
        return cloned;
    }

    /**
     * 파라미터 규칙의 정규식 문법 및 최소/최대 길이 설정의 유효성을 검사합니다.
     *
     * @param paramName 파라미터 이름
     * @param target    서블릿 타겟 식별자
     * @param errors    검증 오류 메시지를 수집할 리스트
     */
    public void validate(final String paramName, final String target, final List<String> errors) {
        if (StringUtils.isNotBlank(pattern)) {
            try {
                this.compiledPattern = Pattern.compile(pattern.trim());
            } catch (Exception e) {
                errors.add("Target '" + target + "', Param '" + paramName + "': Invalid regex pattern '" + pattern + "' (" + e.getMessage() + ")");
            }
        }
        if (minLength != null && minLength < 0) {
            errors.add("Target '" + target + "', Param '" + paramName + "': minLength cannot be negative (" + minLength + ")");
        }
        if (maxLength != null && maxLength < 0) {
            errors.add("Target '" + target + "', Param '" + paramName + "': maxLength cannot be negative (" + maxLength + ")");
        }
        if (minLength != null && maxLength != null && minLength > maxLength) {
            errors.add("Target '" + target + "', Param '" + paramName + "': minLength (" + minLength + ") exceeds maxLength (" + maxLength + ")");
        }
    }

    /** 이 파라미터 규칙의 활성화 여부를 반환합니다. */
    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    /** 이 파라미터 규칙의 활성화 여부를 설정합니다. */
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /** 이 파라미터가 필수(required)인지 반환합니다. */
    public boolean isRequired() {
        return required != null && required;
    }

    /** 이 파라미터의 필수 여부를 설정합니다. */
    public void setRequired(Boolean required) {
        this.required = required;
    }

    /** 허용되는 최소 글자 수(minLength)를 반환합니다. */
    public Integer getMinLength() {
        return minLength;
    }

    /** 허용되는 최소 글자 수(minLength)를 설정합니다. */
    public void setMinLength(Integer minLength) {
        this.minLength = minLength;
    }

    /** 허용되는 최대 글자 수(maxLength)를 반환합니다. */
    public Integer getMaxLength() {
        return maxLength;
    }

    /** 허용되는 최대 글자 수(maxLength)를 설정합니다. */
    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    /** 파라미터 값 검증용 정규식 패턴 문자열을 반환합니다. */
    public String getPattern() {
        return pattern;
    }

    /** 파라미터 값 검증용 정규식 패턴 문자열을 설정하고 즉시 컴파일합니다. */
    public void setPattern(String pattern) {
        this.pattern = pattern;
        if (StringUtils.isNotBlank(pattern)) {
            try {
                this.compiledPattern = Pattern.compile(pattern.trim());
            } catch (Exception ignored) {
            }
        }
    }

    /** 사전 컴파일된 정규식 {@link Pattern} 객체를 반환합니다. */
    public Pattern getCompiledPattern() {
        if (compiledPattern == null && StringUtils.isNotBlank(pattern)) {
            compiledPattern = Pattern.compile(pattern.trim());
        }
        return compiledPattern;
    }

    /** 해당 파라미터에 대해 경로 조작(Path Traversal) 구문 허용 여부를 반환합니다. */
    public boolean isAllowPathTraversal() {
        return allowPathTraversal != null && allowPathTraversal;
    }

    /** 해당 파라미터에 대해 경로 조작(Path Traversal) 구문 허용 여부를 설정합니다. */
    public void setAllowPathTraversal(Boolean allowPathTraversal) {
        this.allowPathTraversal = allowPathTraversal;
    }

    /**
     * 로그 출력을 위해 이 파라미터 규칙의 핵심 제약조건(필수 여부, 길이 범위, 정규식)을 요약 문자열로 반환합니다.
     *
     * @return 파라미터 규칙 요약 문자열
     */
    public String toSummaryString() {
        StringBuilder sb = new StringBuilder("{");
        sb.append("required=").append(isRequired());
        if (minLength != null || maxLength != null) {
            sb.append(", len=").append(minLength != null ? minLength : 0)
                    .append("..").append(maxLength != null ? maxLength : "MAX");
        }
        if (StringUtils.isNotBlank(pattern)) {
            sb.append(", pattern=").append(pattern);
        }
        if (isAllowPathTraversal()) {
            sb.append(", allowPathTraversal=true");
        }
        sb.append("}");
        return sb.toString();
    }

    /** 파라미터 규칙의 문자열 표현을 반환합니다. */
    @Override
    public String toString() {
        return toSummaryString();
    }

    // =========================================================================
    // 파라미터 DSL 및 JSON 파싱 유틸리티
    // =========================================================================

    /**
     * {@link ServletPolicyRule}의 {@code extensions} 맵에서 {@code params} 및 {@code requiredParams}를 추출하여
     * {@code Map<String, ParamRule>}로 파싱합니다.
     *
     * @param policy 대상 서블릿 보안 정책 규칙
     * @return 파라미터명을 키(대소문자 구분)로 하는 {@link ParamRule} 맵
     */
    public static Map<String, ParamRule> extractParams(final ServletPolicyRule policy) {
        if (policy == null) {
            return Collections.emptyMap();
        }
        Map<String, Object> ext = policy.getExtensions();
        if (ext == null || ext.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, ParamRule> consolidated = new LinkedHashMap<>();
        parseParamEntriesIntoMap(ext, consolidated, "params");

        for (String reqParam : ServletPolicyRule.extractStringList(ext, "requiredParams")) {
            String key = ServletPolicyRule.stripWrappingQuotes(reqParam).trim();
            if (StringUtils.isNotBlank(key) && !"true".equalsIgnoreCase(key) && !"false".equalsIgnoreCase(key)) {
                ParamRule pr = consolidated.computeIfAbsent(key, k -> new ParamRule());
                pr.setRequired(true);
                pr.init();
            }
        }
        return Collections.unmodifiableMap(consolidated);
    }

    /**
     * 개별 서블릿의 파라미터 규칙과 기본 정책({@code defaultPolicy})의 공통 파라미터 규칙을 병합합니다.
     * 개별 서블릿에 정의된 규칙이 우선하며, 미지정된 길이/정규식 제약만 기본 정책으로부터 보완 상속받습니다.
     *
     * @param childParams  개별 서블릿의 파라미터 규칙 맵
     * @param parentParams 기본 정책(defaultPolicy)의 파라미터 규칙 맵
     * @return 병합된 파라미터 규칙 맵
     */
    public static Map<String, ParamRule> mergeWithDefault(final Map<String, ParamRule> childParams,
                                                          final Map<String, ParamRule> parentParams) {
        if (parentParams == null || parentParams.isEmpty()) {
            return childParams != null ? childParams : Collections.emptyMap();
        }
        if (childParams == null || childParams.isEmpty()) {
            return parentParams;
        }
        Map<String, ParamRule> merged = new LinkedHashMap<>();
        for (Map.Entry<String, ParamRule> entry : childParams.entrySet()) {
            String key = entry.getKey();
            ParamRule childCopy = entry.getValue().copy();
            ParamRule parentRule = parentParams.get(key);
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
        for (Map.Entry<String, ParamRule> entry : parentParams.entrySet()) {
            if (!merged.containsKey(entry.getKey())) {
                merged.put(entry.getKey(), entry.getValue().copy());
            }
        }
        return Collections.unmodifiableMap(merged);
    }

    /**
     * 정책 확장 맵에서 지정된 키들의 파라미터 정의(DSL 문자열, 배열, JSON 객체, Map 등)를 파싱하여 {@code targetMap}에 병합합니다.
     */
    public static void parseParamEntriesIntoMap(final Map<String, Object> props,
                                                final Map<String, ParamRule> targetMap,
                                                final String... keys) {
        for (String key : keys) {
            Object rawVal = ServletPolicyRule.findValueIgnoreCase(props, key);
            if (rawVal == null) {
                continue;
            }
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
    private static void parseSingleParamElement(Object item, final Map<String, ParamRule> targetMap) {
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
                Map<String, Object> itemMap = GSON.fromJson(el, MAP_TYPE);
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

        if (rawSpec.startsWith("{") && rawSpec.endsWith("}")) {
            String inner = rawSpec.substring(1, rawSpec.length() - 1).trim();
            if (inner.startsWith("\"") || inner.startsWith("'")) {
                try {
                    Map<String, Object> itemMap = GSON.fromJson(rawSpec, MAP_TYPE);
                    if (itemMap != null) {
                        parseParamObjectMapElement(itemMap, targetMap);
                        return;
                    }
                } catch (Exception ignored) {
                }
            }
            rawSpec = inner;
        }

        for (String sub : splitPreservingParens(rawSpec, ',')) {
            Map.Entry<String, ParamRule> entry = parseSimpleParamSpec(sub);
            if (entry != null && StringUtils.isNotBlank(entry.getKey())) {
                targetMap.put(entry.getKey().trim(), entry.getValue());
            }
        }
    }

    /**
     * {@code "params": [ { "name": "userId", "required": true, "type": "alnum", "maxLength": 20 } ]} 형태의
     * 개별 JSON 객체 Map 요소를 파싱합니다.
     */
    private static void parseParamObjectMapElement(final Map<?, ?> itemMap, final Map<String, ParamRule> targetMap) {
        if (itemMap == null || itemMap.isEmpty()) {
            return;
        }
        Map<String, Object> stringKeyMap = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : itemMap.entrySet()) {
            if (e.getKey() != null) {
                stringKeyMap.put(e.getKey().toString().trim(), e.getValue());
            }
        }

        List<String> names = ServletPolicyRule.extractStringList(stringKeyMap, "name", "param", "paramName", "key", "id");
        if (!names.isEmpty()) {
            String pName = names.get(0);
            ParamRule pr = buildParamRuleFromMap(stringKeyMap);
            if (pr != null && StringUtils.isNotBlank(pName)) {
                targetMap.put(pName.trim(), pr);
            }
        } else {
            parseParamMapObject(itemMap, targetMap);
        }
    }

    /**
     * {@code "params": { "userId": { "required": true, ... }, "email": "required:email:50" }} 형태의 Map을 파싱합니다.
     */
    private static void parseParamMapObject(final Map<?, ?> rawParams, final Map<String, ParamRule> targetMap) {
        for (Map.Entry<?, ?> pe : rawParams.entrySet()) {
            if (pe.getKey() == null || pe.getValue() == null) {
                continue;
            }
            String pName = pe.getKey().toString().trim();
            Object pVal = pe.getValue();
            if (pVal instanceof ParamRule) {
                ParamRule copy = ((ParamRule) pVal).copy();
                copy.init();
                targetMap.put(pName, copy);
            } else if (pVal instanceof String) {
                Map.Entry<String, ParamRule> parsed = parseSimpleParamSpec(pName + ":" + pVal.toString().trim());
                if (parsed != null) {
                    targetMap.put(pName, parsed.getValue());
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
                    targetMap.put(pName, pr);
                }
            }
        }
    }

    /**
     * JSON 객체 Map에서 {@link ParamRule}을 생성합니다.
     */
    private static ParamRule buildParamRuleFromMap(final Map<String, Object> map) {
        ParamRule rule = new ParamRule();

        for (String spec : ServletPolicyRule.extractStringList(map, "spec", "rule", "type", "format")) {
            Map.Entry<String, ParamRule> parsed = parseSimpleParamSpec("dummy:" + spec);
            if (parsed != null && parsed.getValue() != null) {
                rule = parsed.getValue();
            }
        }

        Boolean req = ServletPolicyRule.extractBoolean(map, "required", "mandatory", "isRequired");
        if (req != null) {
            rule.setRequired(req);
        }
        Boolean allowPt = ServletPolicyRule.extractBoolean(map, "allowPathTraversal", "allow_path_traversal");
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
        List<String> patterns = ServletPolicyRule.extractStringList(map, "pattern", "regex");
        if (!patterns.isEmpty()) {
            rule.setPattern(patterns.get(0));
        }

        rule.init();
        return rule;
    }

    /**
     * Map에서 정수형 속성값을 추출합니다 (키 대소문자 무시).
     */
    private static Integer extractInteger(final Map<String, Object> props, final String... keys) {
        for (String k : keys) {
            Object val = ServletPolicyRule.findValueIgnoreCase(props, k);
            if (val instanceof Number) {
                return ((Number) val).intValue();
            } else if (val instanceof String) {
                try {
                    return Integer.parseInt(((String) val).trim());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    /**
     * 소괄호 {@code (...)}, 중괄호 {@code {...}}, 대괄호 {@code [...]} 내부의 구분자는 무시하면서 문자열을 분리합니다.
     */
    public static List<String> splitPreservingParens(final String input, final char delimiter) {
        List<String> tokens = new ArrayList<>();
        if (input == null) {
            return tokens;
        }
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
     * 간편 DSL 형식의 파라미터 설정 문자열(예: {@code "userId:required:alnum:4..20"})을 파싱하여
     * 파라미터 이름과 {@link ParamRule} 엔트리를 생성합니다.
     *
     * @param fullSpec 간편 DSL 형식의 파라미터 규칙 문자열
     * @return 파싱된 {@code (파라미터명, ParamRule)} 엔트리 (유효하지 않으면 null)
     */
    public static Map.Entry<String, ParamRule> parseSimpleParamSpec(final String fullSpec) {
        if (StringUtils.isBlank(fullSpec)) {
            return null;
        }
        String clean = ServletPolicyRule.stripWrappingQuotes(fullSpec);
        if (clean.startsWith("{") && clean.endsWith("}")) {
            clean = ServletPolicyRule.stripWrappingQuotes(clean.substring(1, clean.length() - 1));
        }
        List<String> parts = splitPreservingParens(clean, ':');
        if (parts.isEmpty() || StringUtils.isBlank(parts.get(0))) {
            return null;
        }

        ParamRule rule = new ParamRule();
        String firstToken = ServletPolicyRule.stripWrappingQuotes(parts.get(0));
        String paramName;
        int startIndex = 1;

        if (("required".equalsIgnoreCase(firstToken) || "req".equalsIgnoreCase(firstToken) || "mandatory".equalsIgnoreCase(firstToken))
                && parts.size() >= 2 && StringUtils.isNotBlank(parts.get(1))) {
            rule.setRequired(true);
            paramName = ServletPolicyRule.stripWrappingQuotes(parts.get(1));
            startIndex = 2;
        } else if (("optional".equalsIgnoreCase(firstToken) || "opt".equalsIgnoreCase(firstToken))
                && parts.size() >= 2 && StringUtils.isNotBlank(parts.get(1))) {
            rule.setRequired(false);
            paramName = ServletPolicyRule.stripWrappingQuotes(parts.get(1));
            startIndex = 2;
        } else {
            paramName = firstToken;
        }

        for (int i = startIndex; i < parts.size(); i++) {
            String token = ServletPolicyRule.stripWrappingQuotes(parts.get(i));
            if (token.isEmpty()) {
                continue;
            }
            applyDslToken(rule, token, parts, i);
            if (("pattern".equalsIgnoreCase(token) || "regex".equalsIgnoreCase(token)) && i + 1 < parts.size()) {
                i++;
            }
        }

        rule.init();
        return new AbstractMap.SimpleEntry<>(paramName, rule);
    }

    /**
     * 개별 DSL 토큰(필수 여부, 내장 타입 별칭, 길이 범위, 커스텀 정규식 등)을 {@link ParamRule}에 반영합니다.
     */
    private static void applyDslToken(final ParamRule rule, final String token, final List<String> parts, final int index) {
        if ("required".equalsIgnoreCase(token) || "req".equalsIgnoreCase(token)
                || "mandatory".equalsIgnoreCase(token) || "required=true".equalsIgnoreCase(token)
                || "true".equalsIgnoreCase(token)) {
            rule.setRequired(true);
        } else if ("optional".equalsIgnoreCase(token) || "opt".equalsIgnoreCase(token)
                || "required=false".equalsIgnoreCase(token) || "false".equalsIgnoreCase(token)) {
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
                } catch (NumberFormatException ignored) {
                }
            }
        } else if (token.startsWith("max:")) {
            try {
                rule.setMaxLength(Integer.parseInt(token.substring(4).trim()));
            } catch (NumberFormatException ignored) {
            }
        } else if (token.startsWith("min:")) {
            try {
                rule.setMinLength(Integer.parseInt(token.substring(4).trim()));
            } catch (NumberFormatException ignored) {
            }
        } else if (token.matches("^[0-9]+$")) {
            try {
                rule.setMaxLength(Integer.parseInt(token));
            } catch (NumberFormatException ignored) {
            }
        } else if ((token.startsWith("pattern(") || token.startsWith("regex(")) && token.endsWith(")")) {
            int open = token.indexOf('(');
            rule.setPattern(token.substring(open + 1, token.length() - 1));
        } else if (("pattern".equalsIgnoreCase(token) || "regex".equalsIgnoreCase(token)) && index + 1 < parts.size()) {
            rule.setPattern(parts.get(index + 1).trim());
        } else if (token.startsWith("^") || token.endsWith("$")) {
            rule.setPattern(token);
        } else if (token.contains("|")) {
            rule.setPattern("^(?i)(" + token + ")$");
        }
    }
}
