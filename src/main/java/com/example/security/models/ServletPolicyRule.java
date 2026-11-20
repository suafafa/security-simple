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
 * 특정 타겟(URL 경로 또는 Sling resourceType)에 대한 보안 정책 규칙 모델입니다.
 */
public class ServletPolicyRule {

    private static final Gson GSON = new Gson();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();

    public static final Set<String> VALID_HTTP_METHODS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    )));

    private static final Set<String> BUILT_IN_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "target", "enabled", "mode", "methods", "allowedreferrers",
            "allowundefinedparams", "params", "requiredparams", "extensions"
    )));

    @SerializedName("target")
    private String target;

    @SerializedName("enabled")
    private Boolean enabled = true;

    @SerializedName("mode")
    private String mode;

    @SerializedName("methods")
    private List<String> methods;

    @SerializedName("allowedReferrers")
    private List<String> allowedReferrers;

    @SerializedName("allowUndefinedParams")
    private Boolean allowUndefinedParams;

    @SerializedName("params")
    private Map<String, ParamRule> params;

    @SerializedName("extensions")
    private Map<String, Object> extensions;

    // 런타임 고속 조회용 캐시 필드
    private transient Set<String> upperMethods = Collections.emptySet();
    private transient Set<String> lowerAllowedReferrers = Collections.emptySet();
    private transient Map<String, ParamRule> lowerParams = Collections.emptyMap();
    private transient Pattern compiledTargetPattern;

    public void init() {
        if (StringUtils.isNotBlank(target) && (target.contains("*") || target.contains("^") || target.contains("$"))) {
            try {
                this.compiledTargetPattern = Pattern.compile(target.trim());
            } catch (Exception ignored) {
            }
        }

        if (methods != null && !methods.isEmpty()) {
            Set<String> set = new LinkedHashSet<>();
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
            Set<String> set = new LinkedHashSet<>();
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
                    map.put(entry.getKey().trim(), rule);
                }
            }
            this.lowerParams = Collections.unmodifiableMap(map);
        } else {
            this.lowerParams = Collections.emptyMap();
        }

        setMode(this.mode);

        List<String> errors = new ArrayList<>();
        validate(errors);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("ServletPolicyRule validation failed: " + String.join("; ", errors));
        }
    }

    public String getTargetIdentifier() {
        return StringUtils.isNotBlank(target) ? target : "(defaultPolicy)";
    }

    public void validate(final List<String> errors) {
        String id = getTargetIdentifier();

        if (methods != null) {
            for (String m : methods) {
                if (StringUtils.isNotBlank(m) && !VALID_HTTP_METHODS.contains(m.trim().toUpperCase())) {
                    errors.add("Target '" + id + "': Unsupported HTTP method '" + m + "'. Allowed: " + VALID_HTTP_METHODS);
                }
            }
        }

        if (StringUtils.isNotBlank(target) && (target.contains("*") || target.contains("^") || target.contains("$"))) {
            try {
                Pattern.compile(target.trim());
            } catch (Exception e) {
                errors.add("Target '" + id + "': Invalid regex pattern for target: '" + target + "' (" + e.getMessage() + ")");
            }
        }

        if (params != null) {
            for (Map.Entry<String, ParamRule> entry : params.entrySet()) {
                if (entry.getValue() != null) {
                    entry.getValue().validate(entry.getKey(), id, errors);
                }
            }
        }
    }

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

    public Pattern getCompiledTargetPattern() {
        return compiledTargetPattern;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getMethods() {
        return upperMethods != null ? upperMethods : Collections.emptySet();
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public boolean isMethodAllowed(final String method) {
        if (upperMethods == null || upperMethods.isEmpty()) {
            return true;
        }
        return method != null && upperMethods.contains(method.trim().toUpperCase());
    }

    public Map<String, ParamRule> getParams() {
        if (lowerParams != null && !lowerParams.isEmpty()) {
            return lowerParams;
        }
        return params != null ? params : Collections.emptyMap();
    }

    public void setParams(Map<String, ParamRule> params) {
        this.params = params;
        if (params == null || params.isEmpty()) {
            this.lowerParams = Collections.emptyMap();
        } else {
            Map<String, ParamRule> tempParams = new LinkedHashMap<>(params.size());
            for (Map.Entry<String, ParamRule> entry : params.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    entry.getValue().init();
                    tempParams.put(entry.getKey().trim(), entry.getValue());
                }
            }
            this.lowerParams = Collections.unmodifiableMap(tempParams);
        }
    }

    public boolean isAllowUndefinedParams() {
        return allowUndefinedParams != null && allowUndefinedParams;
    }

    public void setAllowUndefinedParams(Boolean allowUndefinedParams) {
        this.allowUndefinedParams = allowUndefinedParams;
    }

    public Set<String> getAllowedReferrers() {
        return lowerAllowedReferrers != null ? lowerAllowedReferrers : Collections.emptySet();
    }

    public void setAllowedReferrers(List<String> allowedReferrers) {
        this.allowedReferrers = allowedReferrers;
    }

    public String getMode() {
        if (StringUtils.isBlank(mode)) {
            return null;
        }
        return "MONITOR".equalsIgnoreCase(mode.trim()) ? "MONITOR" : "ENFORCE";
    }

    public void setMode(final String mode) {
        if (StringUtils.isBlank(mode)) {
            this.mode = null;
        } else {
            this.mode = "MONITOR".equalsIgnoreCase(mode.trim()) ? "MONITOR" : "ENFORCE";
        }
    }

    public Map<String, Object> getExtensions() {
        return extensions != null ? Collections.unmodifiableMap(extensions) : Collections.emptyMap();
    }

    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions != null ? new LinkedHashMap<>(extensions) : null;
    }

    public void putExtension(String key, Object value) {
        if (StringUtils.isBlank(key) || value == null) {
            return;
        }
        if (this.extensions == null) {
            this.extensions = new LinkedHashMap<>();
        }
        this.extensions.put(key.trim(), value);
    }

    public List<String> getExtensionStringList(String... keys) {
        if (extensions == null || extensions.isEmpty() || keys == null) {
            return Collections.emptyList();
        }
        return extractStringList(extensions, keys);
    }

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

    public String getExtensionString(String... keys) {
        List<String> list = getExtensionStringList(keys);
        return list.isEmpty() ? null : list.get(0);
    }

    public Boolean getExtensionBoolean(String... keys) {
        if (extensions == null || extensions.isEmpty() || keys == null) {
            return null;
        }
        return extractBoolean(extensions, keys);
    }

    public void inheritFrom(final ServletPolicyRule parent) {
        if (parent == null) {
            return;
        }

        if (StringUtils.isBlank(this.mode) && StringUtils.isNotBlank(parent.mode)) {
            this.mode = parent.mode;
        }

        if ((this.methods == null || this.methods.isEmpty()) && parent.methods != null && !parent.methods.isEmpty()) {
            this.methods = new ArrayList<>(parent.methods);
        }

        if (parent.allowedReferrers != null && !parent.allowedReferrers.isEmpty()) {
            Set<String> merged = new LinkedHashSet<>();
            if (this.allowedReferrers != null) {
                merged.addAll(this.allowedReferrers);
            }
            merged.addAll(parent.allowedReferrers);
            this.allowedReferrers = new ArrayList<>(merged);
        }

        if (this.allowUndefinedParams == null && parent.allowUndefinedParams != null) {
            this.allowUndefinedParams = parent.allowUndefinedParams;
        }

        if (parent.params != null && !parent.params.isEmpty()) {
            Map<String, ParamRule> merged = new LinkedHashMap<>();
            if (this.params != null && !this.params.isEmpty()) {
                for (Map.Entry<String, ParamRule> entry : this.params.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        String key = entry.getKey().trim();
                        ParamRule childCopy = entry.getValue().copy();
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
            for (Map.Entry<String, ParamRule> entry : parent.params.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    String key = entry.getKey().trim();
                    if (!merged.containsKey(key)) {
                        merged.put(key, entry.getValue().copy());
                    }
                }
            }
            this.params = merged;
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

    public void copyFrom(final ServletPolicyRule other) {
        if (other == null) {
            return;
        }
        this.target = other.target;
        this.enabled = other.enabled;
        this.mode = other.mode;
        this.methods = other.methods != null ? new ArrayList<>(other.methods) : null;
        this.allowedReferrers = other.allowedReferrers != null ? new ArrayList<>(other.allowedReferrers) : null;
        this.allowUndefinedParams = other.allowUndefinedParams;
        this.extensions = other.extensions != null ? new LinkedHashMap<>(other.extensions) : null;
        if (other.params != null) {
            Map<String, ParamRule> copiedParams = new LinkedHashMap<>(other.params.size());
            for (Map.Entry<String, ParamRule> entry : other.params.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    copiedParams.put(entry.getKey().trim(), entry.getValue().copy());
                }
            }
            this.params = copiedParams;
        } else {
            this.params = null;
        }
    }

    private static ServletPolicyRule parseRuleForTarget(final Map<String, Object> props) {
        ServletPolicyRule rule = new ServletPolicyRule();

        Boolean enabledVal = extractBoolean(props, "enabled");
        if (enabledVal != null) {
            rule.setEnabled(enabledVal);
        }

        List<String> methods = extractStringList(props, "methods");
        if (!methods.isEmpty()) {
            rule.setMethods(methods);
        }

        List<String> allowedReferrers = extractStringList(props, "allowedReferrers");
        if (!allowedReferrers.isEmpty()) {
            rule.setAllowedReferrers(allowedReferrers);
        }

        Boolean allowUndef = extractBoolean(props, "allowUndefinedParams");
        if (allowUndef != null) {
            rule.setAllowUndefinedParams(allowUndef);
        }

        Map<String, ParamRule> consolidatedParams = new LinkedHashMap<>();
        ParamRule.parseParamEntriesIntoMap(props, consolidatedParams, "params");

        for (String reqParam : extractStringList(props, "requiredParams")) {
            String key = stripWrappingQuotes(reqParam).trim();
            if (StringUtils.isNotBlank(key) && !"true".equalsIgnoreCase(key) && !"false".equalsIgnoreCase(key)) {
                ParamRule pr = consolidatedParams.computeIfAbsent(key, k -> new ParamRule());
                pr.setRequired(true);
                pr.init();
            }
        }

        if (!consolidatedParams.isEmpty()) {
            rule.setParams(consolidatedParams);
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

    public static List<String> splitPreservingParens(final String input, final char delimiter) {
        return ParamRule.splitPreservingParens(input, delimiter);
    }

    public static Map.Entry<String, ParamRule> parseSimpleParamSpec(final String fullSpec) {
        return ParamRule.parseSimpleParamSpec(fullSpec);
    }

    // =========================================================================
    // 공통 프로퍼티 추출 헬퍼 (ParamRule과 공유)
    // =========================================================================

    static boolean containsKeyIgnoreCase(final Map<String, ?> map, final String key) {
        if (map == null || key == null) {
            return false;
        }
        if (map.containsKey(key)) {
            return true;
        }
        boolean isRunModeKey = isRunModeAlias(key);
        for (String k : map.keySet()) {
            if (k != null && (k.equalsIgnoreCase(key) || (isRunModeKey && isRunModeAlias(k)))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRunModeAlias(final String key) {
        return "runmodes".equalsIgnoreCase(key) || "runmode".equalsIgnoreCase(key)
                || "allowedrunmodes".equalsIgnoreCase(key) || "allowedrunmode".equalsIgnoreCase(key);
    }

    static Object findValueIgnoreCase(final Map<String, Object> props, final String key) {
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

    static List<String> extractStringList(final Map<String, Object> props, final String... keys) {
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

    static Boolean extractBoolean(final Map<String, Object> props, final String... keys) {
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

    static String stripWrappingQuotes(final String input) {
        if (input == null) {
            return "";
        }
        String s = input.trim();
        while (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'")))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        return s;
    }

    public String toPolicySummaryString() {
        StringBuilder sb = new StringBuilder();
        sb.append("target=").append(StringUtils.defaultIfBlank(target, "UNKNOWN"));
        if (getMode() != null) {
            sb.append(", mode=").append(getMode());
        }
        sb.append(", methods=").append(getMethods().isEmpty() ? "ALL" : getMethods());
        if (!getAllowedReferrers().isEmpty()) {
            sb.append(", allowedReferrers=").append(getAllowedReferrers());
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

    @Override
    public String toString() {
        return "ServletPolicyRule[" + toPolicySummaryString() + "]";
    }
}
