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

    @SerializedName("enabled")
    private Boolean enabled = true;

    @SerializedName("required")
    private Boolean required = false;

    @SerializedName("minLength")
    private Integer minLength;

    @SerializedName("maxLength")
    private Integer maxLength;

    @SerializedName("pattern")
    private String pattern;

    @SerializedName("allowPathTraversal")
    private Boolean allowPathTraversal = false;

    private transient Pattern compiledPattern;

    public void init() {
        if (StringUtils.isNotBlank(pattern)) {
            this.compiledPattern = Pattern.compile(pattern.trim());
        }
    }

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

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isRequired() {
        return required != null && required;
    }

    public void setRequired(Boolean required) {
        this.required = required;
    }

    public Integer getMinLength() {
        return minLength;
    }

    public void setMinLength(Integer minLength) {
        this.minLength = minLength;
    }

    public Integer getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
        if (StringUtils.isNotBlank(pattern)) {
            try {
                this.compiledPattern = Pattern.compile(pattern.trim());
            } catch (Exception ignored) {
            }
        }
    }

    public Pattern getCompiledPattern() {
        if (compiledPattern == null && StringUtils.isNotBlank(pattern)) {
            compiledPattern = Pattern.compile(pattern.trim());
        }
        return compiledPattern;
    }

    public boolean isAllowPathTraversal() {
        return allowPathTraversal != null && allowPathTraversal;
    }

    public void setAllowPathTraversal(Boolean allowPathTraversal) {
        this.allowPathTraversal = allowPathTraversal;
    }

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
