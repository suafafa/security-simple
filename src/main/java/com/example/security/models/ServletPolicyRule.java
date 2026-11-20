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
 * 특정 {@code PolicyValidator}에 종속된 필드를 가지지 않으며, 공통 라우팅/제어 메타데이터({@code target},
 * {@code enabled}, {@code mode})와 각 Validator가 자유롭게 조회하는 {@code extensions} 맵만 관리합니다.
 */
public class ServletPolicyRule {

    private static final Gson GSON = new Gson();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();

    private static final Set<String> BUILT_IN_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "target", "enabled", "mode", "extensions"
    )));

    @SerializedName("target")
    private String target;

    @SerializedName("enabled")
    private Boolean enabled = true;

    @SerializedName("mode")
    private String mode;

    @SerializedName("extensions")
    private Map<String, Object> extensions;

    private transient Pattern compiledTargetPattern;

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

    public String getTargetIdentifier() {
        return StringUtils.isNotBlank(target) ? target : "(defaultPolicy)";
    }

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

    public Object getExtension(String... keys) {
        if (extensions == null || extensions.isEmpty() || keys == null) {
            return null;
        }
        for (String k : keys) {
            Object val = findValueIgnoreCase(extensions, k);
            if (val != null) {
                return val;
            }
        }
        return null;
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
        this.extensions = other.extensions != null ? new LinkedHashMap<>(other.extensions) : null;
    }

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

    @Override
    public String toString() {
        return "ServletPolicyRule[" + toPolicySummaryString() + "]";
    }
}
