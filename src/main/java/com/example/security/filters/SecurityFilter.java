package com.example.security.filters;

import com.example.security.models.ParamRule;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import com.example.security.validators.MethodPolicyValidator;
import com.example.security.validators.ParamPolicyValidator;
import com.example.security.validators.PolicyValidator;
import com.example.security.validators.RefererPolicyValidator;
import com.example.security.validators.ValidationResult;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * 타겟 기반 서블릿 보안 정책 검증을 수행하는 경량화된 AEM 6.5 Sling 서블릿 필터입니다.
 * 3개의 핵심 PolicyValidator 체인을 순차적으로 실행합니다:
 * 1. RefererPolicyValidator: 기본 도메인(abc.com) 및 정책별 허용 Referer(allowedReferrers) 검증
 * 2. MethodPolicyValidator: 허용된 HTTP 메소드 검증 (GET, POST 등)
 * 3. ParamPolicyValidator: 파라미터 필수 여부, 미정의 파라미터 차단, 길이/정규식 패턴 및 Path Traversal/SQLi/XSS 검증
 */
@Component(
        service = Filter.class,
        immediate = true,
        configurationPolicy = ConfigurationPolicy.OPTIONAL,
        property = {
                "service.description=AEM 6.5 Lightweight Security Filter (Referer, Method, Param)",
                "service.vendor=AEM Engineering",
                "sling.filter.scope=REQUEST",
                "sling.filter.pattern=(/aemapi/.*|/sysapi/.*)",
                "service.ranking:Integer=10000"
        }
)
@Designate(ocd = SecurityFilter.Config.class)
public class SecurityFilter implements Filter {

    public static final String DEFAULT_FILTER_PATTERN = "(/aemapi/.*|/sysapi/.*)";

    /**
     * OSGi Configuration Admin(.config)을 통해 주입되는 경량 보안 필터 설정 인터페이스입니다.
     */
    @ObjectClassDefinition(
            name = "AEM Lightweight Security Filter Configuration",
            description = "OSGi .config Configuration for Lightweight Servlet Security Filter (Referer, Method, Param)"
    )
    public @interface Config {
        @AttributeDefinition(
                name = "Filter Enabled",
                description = "Enable or disable servlet policy validation"
        )
        boolean enabled() default true;

        @AttributeDefinition(
                name = "Sling Filter Pattern",
                description = "Regex pattern matching request paths and target servlets handled by this filter"
        )
        String sling_filter_pattern() default "(/aemapi/.*|/sysapi/.*)";

        @AttributeDefinition(name = "Enable Referer Validator", description = "Globally enable/disable Referer validator")
        boolean validator_referer_enabled() default true;

        @AttributeDefinition(name = "Enable Method Validator", description = "Globally enable/disable Method validator")
        boolean validator_method_enabled() default true;

        @AttributeDefinition(name = "Enable Param Validator", description = "Globally enable/disable Param validator")
        boolean validator_param_enabled() default true;

        @AttributeDefinition(name = "Default Policy: Enabled", description = "Enable baseline default security policy for servlets")
        boolean default_enabled() default true;

        @AttributeDefinition(name = "Default Policy: Allowed Referrer", description = "Default trusted referrer domain (e.g. abc.com)")
        String default_referrer() default "abc.com";

        @AttributeDefinition(name = "Default Policy: Allowed HTTP Methods", description = "Default allowed HTTP methods (e.g. GET, POST)")
        String[] default_methods() default {"GET", "POST"};

        @AttributeDefinition(name = "Default Policy: Block SQL/JCR Injection", description = "Automatically block SQL/JCR2 injection patterns in parameters")
        boolean default_blockSqlInjection() default true;

        @AttributeDefinition(name = "Default Policy: Block XSS", description = "Automatically block Cross-Site Scripting (XSS) patterns in parameters")
        boolean default_blockXss() default true;

        @AttributeDefinition(name = "Default Policy: Allow Undefined Params", description = "Allow request parameters not explicitly listed in params rules")
        boolean default_allowUndefinedParams() default false;

        @AttributeDefinition(name = "Default Policy: Common Parameter Rules (DSL)", description = "Common parameter rules in DSL format (e.g. page:optional:digits:5)")
        String[] default_params() default {
                "page:optional:digits:5",
                "size:optional:digits:4",
                "sort:optional:alnum:30",
                "order:optional:asc|desc:4",
                "lang:optional:pattern(^[a-zA-Z]{2}(?:-[a-zA-Z0-9]{2,})?$):10",
                "keyword:optional:100"
        };
    }

    private static final Logger LOG = LoggerFactory.getLogger(SecurityFilter.class);
    private static final Gson GSON = new Gson();
    private static final ServletPolicyRule REJECTED_POLICY = new ServletPolicyRule();

    private volatile boolean enabled = true;
    private volatile String filterPattern = DEFAULT_FILTER_PATTERN;
    private volatile Pattern compiledFilterPattern = Pattern.compile(DEFAULT_FILTER_PATTERN);
    private volatile ServletSecurityConfig servletSecurityConfig;

    // 동적으로 바인딩된 서블릿 추적 맵 (서블릿 인스턴스 -> OSGi 속성 맵)
    private final Map<Servlet, Map<String, Object>> boundServlets = new ConcurrentHashMap<>();

    // 핵심 3대 정책 검증기 (Referer -> Method -> Param)
    private final RefererPolicyValidator refererPolicyValidator = new RefererPolicyValidator();
    private final MethodPolicyValidator methodPolicyValidator = new MethodPolicyValidator();
    private final ParamPolicyValidator paramPolicyValidator = new ParamPolicyValidator();

    private final List<PolicyValidator> validators = Collections.unmodifiableList(Arrays.asList(
            refererPolicyValidator,
            methodPolicyValidator,
            paramPolicyValidator
    ));

    /**
     * OSGi 컨테이너에서 {@link Servlet} 서비스가 등록될 때 호출되는 동적 바인딩 콜백 메소드입니다.
     * 서블릿의 경로 또는 resourceType이 {@code sling.filter.pattern}과 일치하는 경우에만 동적 보안 정책을 등록합니다.
     * 주의: 서블릿이 다수 등록될 때 로그가 과도하게 발생하는 것을 방지하기 위해 이 메소드에서는 디버그 로그를 출력하지 않습니다.
     *
     * @param servlet    바인딩된 서블릿 인스턴스
     * @param properties 서블릿의 OSGi 컴포넌트 프로퍼티 맵
     */
    @Reference(
            service = Servlet.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            bind = "bindServlet",
            unbind = "unbindServlet"
    )
    public void bindServlet(final Servlet servlet, final Map<String, Object> properties) {
        if (servlet == null || properties == null) {
            return;
        }

        // sling.filter.pattern과 경로 또는 resourceType이 일치하는 서블릿만 바인딩 (로그 출력 없음)
        if (!isApplicableServlet(properties)) {
            return;
        }

        boundServlets.put(servlet, properties);

        if (servletSecurityConfig != null) {
            List<ServletPolicyRule> rules = ServletPolicyRule.fromOsgiProperties(properties, servletSecurityConfig.getDefaultPolicy());
            for (ServletPolicyRule rule : rules) {
                if (matchesFilterPattern(rule.getTarget())) {
                    servletSecurityConfig.registerDynamicPolicy(rule);
                }
            }
        }
    }

    /**
     * OSGi 컨테이너에서 {@link Servlet} 서비스가 해제될 때 호출되는 동적 언바인딩 콜백 메소드입니다.
     * 바인딩 시 등록되었던 서블릿의 동적 보안 정책을 제거합니다.
     * 주의: 서블릿 언바인딩 시에도 로그 폭증을 방지하기 위해 디버그 로그를 출력하지 않습니다.
     *
     * @param servlet    언바인딩된 서블릿 인스턴스
     * @param properties 서블릿의 OSGi 컴포넌트 프로퍼티 맵
     */
    public void unbindServlet(final Servlet servlet, final Map<String, Object> properties) {
        if (servlet == null) {
            return;
        }

        boolean wasBound = boundServlets.containsKey(servlet);
        Map<String, Object> props = properties != null ? properties : boundServlets.remove(servlet);
        boundServlets.remove(servlet);

        if (!wasBound && (props == null || !isApplicableServlet(props))) {
            return;
        }

        if (servletSecurityConfig != null && props != null) {
            List<ServletPolicyRule> rules = ServletPolicyRule.fromOsgiProperties(props, null);
            for (ServletPolicyRule rule : rules) {
                if (matchesFilterPattern(rule.getTarget())) {
                    servletSecurityConfig.unregisterDynamicPolicy(rule.getTarget());
                }
            }
        }
    }

    /**
     * 서블릿의 경로({@code sling.servlet.paths}) 또는 리소스 타입({@code sling.servlet.resourceTypes})이
     * 현재 필터의 {@code sling.filter.pattern}과 일치하는지 판별합니다.
     *
     * @param properties 서블릿의 OSGi 프로퍼티 맵
     * @return 필터 적용 대상 서블릿이면 true, 아니면 false
     */
    public boolean isApplicableServlet(final Map<String, Object> properties) {
        if (properties == null || properties.isEmpty()) {
            return false;
        }
        List<String> targets = extractServletTargets(properties);
        if (targets.isEmpty()) {
            return false;
        }
        for (String target : targets) {
            if (matchesFilterPattern(target)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 대상 경로 또는 resourceType이 컴파일된 {@code sling.filter.pattern} 정규식과 일치하는지 검사합니다.
     *
     * @param target 검사할 타겟 경로 또는 resourceType 문자열
     * @return 패턴과 일치하면 true, 아니면 false
     */
    public boolean matchesFilterPattern(final String target) {
        if (StringUtils.isBlank(target)) {
            return false;
        }
        Pattern pattern = this.compiledFilterPattern;
        if (pattern == null) {
            return false;
        }
        String cleanTarget = target.trim();
        if (pattern.matcher(cleanTarget).matches()) {
            return true;
        }
        if (!cleanTarget.startsWith("/") && pattern.matcher("/" + cleanTarget).matches()) {
            return true;
        }
        return false;
    }

    /**
     * OSGi 속성 맵에서 서블릿의 타겟 경로({@code sling.servlet.paths}) 및
     * 리소스 타입({@code sling.servlet.resourceTypes}) 목록을 추출합니다.
     *
     * @param properties 서블릿의 OSGi 프로퍼티 맵
     * @return 추출된 타겟 문자열 리스트
     */
    public List<String> extractServletTargets(final Map<String, Object> properties) {
        if (properties == null || properties.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> targets = new ArrayList<>();
        targets.addAll(extractStringListFromMap(properties, "sling.servlet.paths"));
        targets.addAll(extractStringListFromMap(properties, "sling.servlet.resourceTypes"));
        if (targets.isEmpty()) {
            targets.addAll(extractStringListFromMap(properties, "service.description"));
        }
        return targets;
    }

    /**
     * 프로퍼티 맵에서 지정된 키의 값을 문자열 리스트로 변환하여 반환합니다.
     *
     * @param map 프로퍼티 맵
     * @param key 조회할 키
     * @return 추출된 문자열 리스트
     */
    private static List<String> extractStringListFromMap(final Map<String, Object> map, final String key) {
        if (map == null || !map.containsKey(key)) {
            return Collections.emptyList();
        }
        Object val = map.get(key);
        if (val instanceof String[]) {
            List<String> list = new ArrayList<>();
            for (String s : (String[]) val) {
                if (StringUtils.isNotBlank(s)) {
                    list.add(s.trim());
                }
            }
            return list;
        } else if (val instanceof Collection) {
            List<String> list = new ArrayList<>();
            for (Object item : (Collection<?>) val) {
                if (item != null && StringUtils.isNotBlank(item.toString())) {
                    list.add(item.toString().trim());
                }
            }
            return list;
        } else if (val instanceof String) {
            String s = (String) val;
            if (StringUtils.isNotBlank(s)) {
                if (s.contains(",")) {
                    String[] parts = s.split(",");
                    List<String> list = new ArrayList<>(parts.length);
                    for (String part : parts) {
                        if (StringUtils.isNotBlank(part)) {
                            list.add(part.trim());
                        }
                    }
                    return list;
                }
                return Collections.singletonList(s.trim());
            }
        }
        return Collections.emptyList();
    }

    /**
     * 필터의 {@code sling.filter.pattern} 정규식을 새로운 패턴으로 업데이트하고,
     * 이미 바인딩된 서블릿 목록을 새 패턴 기준으로 재평가하여 일치하지 않는 동적 정책을 해제합니다.
     *
     * @param newPattern 새로 적용할 정규식 패턴 문자열
     */
    public synchronized void updateFilterPattern(final String newPattern) {
        if (StringUtils.isBlank(newPattern)) {
            return;
        }
        try {
            Pattern compiled = Pattern.compile(newPattern.trim());
            this.filterPattern = newPattern.trim();
            this.compiledFilterPattern = compiled;
            LOG.info("Updated SecurityFilter pattern to: {}", this.filterPattern);

            // 새로운 필터 패턴에 맞춰 기존에 바인딩된 서블릿들을 재평가
            if (!boundServlets.isEmpty()) {
                Iterator<Map.Entry<Servlet, Map<String, Object>>> iterator = boundServlets.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<Servlet, Map<String, Object>> entry = iterator.next();
                    Map<String, Object> props = entry.getValue();
                    if (!isApplicableServlet(props)) {
                        if (servletSecurityConfig != null) {
                            List<ServletPolicyRule> rules = ServletPolicyRule.fromOsgiProperties(props, null);
                            for (ServletPolicyRule rule : rules) {
                                servletSecurityConfig.unregisterDynamicPolicy(rule.getTarget());
                            }
                        }
                        iterator.remove();
                    }
                }
            }
        } catch (Exception e) {
            LOG.error("Failed to compile sling.filter.pattern regex: {}", newPattern, e);
        }
    }

    /**
     * 현재 설정된 {@code sling.filter.pattern} 문자열을 반환합니다.
     *
     * @return 필터 패턴 문자열
     */
    public String getFilterPattern() {
        return filterPattern;
    }

    /**
     * 현재 컴파일된 {@code sling.filter.pattern} {@link Pattern} 객체를 반환합니다.
     *
     * @return 컴파일된 정규식 Pattern 객체
     */
    public Pattern getCompiledFilterPattern() {
        return compiledFilterPattern;
    }

    /**
     * 현재 동적으로 바인딩되어 관리 중인 서블릿 맵(읽기 전용)을 반환합니다.
     *
     * @return 바인딩된 서블릿과 프로퍼티 맵
     */
    public Map<Servlet, Map<String, Object>> getBoundServlets() {
        return Collections.unmodifiableMap(boundServlets);
    }

    /**
     * OSGi 컴포넌트 활성화({@code @Activate}) 및 설정 변경({@code @Modified}) 시 호출됩니다.
     * OSGi {@code .config} 설정 또는 프로퍼티 맵으로부터 기본 보안 정책과 검증기 활성화 상태를 로드하고,
     * 바인딩된 서블릿들의 동적 정책을 동기화합니다.
     *
     * @param config     OSGi OCD 설정 객체
     * @param properties OSGi 컴포넌트 프로퍼티 맵
     */
    @Activate
    @Modified
    public void activate(final Config config, final Map<String, Object> properties) {
        LOG.debug("SecurityFilter activate/modified lifecycle invoked.");

        String configuredPattern = null;
        if (config != null && StringUtils.isNotBlank(config.sling_filter_pattern())) {
            configuredPattern = config.sling_filter_pattern();
        }
        if (properties != null) {
            Object patternProp = properties.get("sling.filter.pattern");
            if (patternProp instanceof String && StringUtils.isNotBlank((String) patternProp)) {
                configuredPattern = (String) patternProp;
            }
        }
        if (StringUtils.isNotBlank(configuredPattern)) {
            updateFilterPattern(configuredPattern);
        }

        boolean isEnabled = config != null ? config.enabled() : true;

        if (properties != null && properties.containsKey("enabled")) {
            Object enObj = properties.get("enabled");
            if (enObj instanceof Boolean) {
                isEnabled = (Boolean) enObj;
            } else if (enObj instanceof String) {
                isEnabled = Boolean.parseBoolean((String) enObj);
            }
        }

        if (config != null || hasOsgiDotConfigProperties(properties)) {
            LOG.debug("Loading SecurityFilter policies from OSGi .config attributes (isEnabled={}).", isEnabled);
            loadFromOsgiConfig(isEnabled, config, properties);
        } else if (properties != null) {
            LOG.debug("Loading SecurityFilter policies from OSGi map/JSON properties (isEnabled={}).", isEnabled);
            parsePoliciesFromProperties(isEnabled, properties);
        }

        applyOsgiValidatorToggles(config, properties);

        // 새로 로드된 defaultPolicy와 동적으로 바인딩된 모든 서블릿을 동기화 (바인딩 루프에서는 로그 생략)
        if (servletSecurityConfig != null && !boundServlets.isEmpty()) {
            for (Map<String, Object> props : boundServlets.values()) {
                if (isApplicableServlet(props)) {
                    List<ServletPolicyRule> rules = ServletPolicyRule.fromOsgiProperties(props, servletSecurityConfig.getDefaultPolicy());
                    for (ServletPolicyRule rule : rules) {
                        if (matchesFilterPattern(rule.getTarget())) {
                            servletSecurityConfig.registerDynamicPolicy(rule);
                        }
                    }
                }
            }
        }

        this.enabled = isEnabled;
        logConfiguredPolicies();

        LOG.info("SecurityFilter activated for AEM 6.5. Filter Enabled: {}, Filter Pattern: {}, Active Policies: {}",
                enabled, filterPattern, servletSecurityConfig != null ? servletSecurityConfig.getPolicies().size() : 0);
    }

    /**
     * 프로퍼티 맵에 OSGi {@code .config} 형식의 {@code default.*} 속성이 포함되어 있는지 확인합니다.
     *
     * @param properties OSGi 프로퍼티 맵
     * @return {@code default.*} 키가 하나라도 존재하면 true
     */
    private boolean hasOsgiDotConfigProperties(final Map<String, Object> properties) {
        if (properties == null || properties.isEmpty()) {
            return false;
        }
        for (String key : properties.keySet()) {
            if (key != null && key.startsWith("default.")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 순수 OSGi {@code .config} 속성({@code default.*} 및 {@code validator.*.enabled})으로부터
     * 직접 {@link ServletSecurityConfig} 및 {@code defaultPolicy}를 생성합니다.
     *
     * @param isEnabled  필터 전체 활성화 여부
     * @param config     OSGi OCD 설정 객체
     * @param properties OSGi 프로퍼티 맵
     */
    private void loadFromOsgiConfig(final boolean isEnabled, final Config config, final Map<String, Object> properties) {
        try {
            Map<String, Object> props = properties != null ? properties : Collections.emptyMap();
            ServletPolicyRule defaultRule = buildDefaultPolicyFromOsgiConfig(config, props);

            List<ServletPolicyRule> policies = Collections.emptyList();
            if (props.containsKey("policies")) {
                policies = parsePolicyRuleList(props.get("policies"));
            }

            ServletSecurityConfig newConfig = new ServletSecurityConfig(isEnabled, policies);
            newConfig.setDefaultPolicy(defaultRule);
            if (StringUtils.isNotBlank(defaultRule.getDefaultReferrer())) {
                newConfig.setDefaultReferrer(defaultRule.getDefaultReferrer());
            }
            newConfig.init();
            this.servletSecurityConfig = newConfig;
            LOG.debug("Initialized ServletSecurityConfig from OSGi .config: defaultPolicy=[{}], explicitPoliciesCount={}",
                    defaultRule.toPolicySummaryString(), policies.size());
            LOG.info("Successfully loaded configuration from OSGi .config (defaultPolicy enabled={}, methods={}, defaultReferrer={}, params={})",
                    defaultRule.isEnabled(), defaultRule.getMethods(), defaultRule.getDefaultReferrer(), defaultRule.getParams().keySet());
        } catch (Exception e) {
            handleConfigFailure("OSGi .config", e, isEnabled);
        }
    }

    /**
     * OSGi {@link Config} 및 프로퍼티 맵에서 {@code default.*} 설정을 읽어 기본 보안 정책({@code defaultPolicy})을 생성합니다.
     *
     * @param config OSGi OCD 설정 객체
     * @param props  OSGi 프로퍼티 맵
     * @return 초기화된 기본 {@link ServletPolicyRule} 객체
     */
    private ServletPolicyRule buildDefaultPolicyFromOsgiConfig(final Config config, final Map<String, Object> props) {
        ServletPolicyRule rule = new ServletPolicyRule();
        rule.setTarget("DEFAULT");

        boolean defEnabled = config != null ? config.default_enabled() : true;
        if (props.containsKey("default.enabled")) {
            defEnabled = toBoolean(props.get("default.enabled"), defEnabled);
        }
        rule.setEnabled(defEnabled);

        String defReferrer = getStringProp(props, "default.referrer",
                config != null ? config.default_referrer() : "abc.com");
        rule.setDefaultReferrer(defReferrer);

        List<String> defMethods = getStringListProp(props, "default.methods",
                config != null ? config.default_methods() : new String[]{"GET", "POST"});
        if (!defMethods.isEmpty()) {
            rule.setMethods(defMethods);
        }

        boolean defBlockSql = config != null ? config.default_blockSqlInjection() : true;
        if (props.containsKey("default.blockSqlInjection")) {
            defBlockSql = toBoolean(props.get("default.blockSqlInjection"), defBlockSql);
        }
        rule.setBlockSqlInjection(defBlockSql);

        boolean defBlockXss = config != null ? config.default_blockXss() : true;
        if (props.containsKey("default.blockXss")) {
            defBlockXss = toBoolean(props.get("default.blockXss"), defBlockXss);
        }
        rule.setBlockXss(defBlockXss);

        boolean defAllowUndefParams = config != null ? config.default_allowUndefinedParams() : false;
        if (props.containsKey("default.allowUndefinedParams")) {
            defAllowUndefParams = toBoolean(props.get("default.allowUndefinedParams"), defAllowUndefParams);
        }
        rule.setAllowUndefinedParams(defAllowUndefParams);

        List<String> defParams = getStringListProp(props, "default.params",
                config != null ? config.default_params() : new String[]{
                        "page:optional:digits:5",
                        "size:optional:digits:4",
                        "sort:optional:alnum:30",
                        "order:optional:asc|desc:4",
                        "lang:optional:pattern(^[a-zA-Z]{2}(?:-[a-zA-Z0-9]{2,})?$):10",
                        "keyword:optional:100"
                });
        Map<String, ParamRule> paramRules = new LinkedHashMap<>();
        for (String spec : defParams) {
            if (StringUtils.isNotBlank(spec)) {
                Map.Entry<String, ParamRule> entry = ServletPolicyRule.parseSimpleParamSpec(spec);
                if (entry != null && StringUtils.isNotBlank(entry.getKey())) {
                    paramRules.put(entry.getKey().toLowerCase(), entry.getValue());
                }
            }
        }
        if (!paramRules.isEmpty()) {
            rule.setParams(paramRules);
        }

        rule.init();
        return rule;
    }

    /**
     * OSGi 프로퍼티 값(Boolean 또는 {@code B"true"} 형식 문자열 포함)을 boolean 타입으로 변환합니다.
     *
     * @param val        변환할 프로퍼티 값
     * @param defaultVal 변환 실패 시 반환할 기본값
     * @return 변환된 boolean 값
     */
    private boolean toBoolean(final Object val, final boolean defaultVal) {
        if (val instanceof Boolean) {
            return (Boolean) val;
        }
        if (val instanceof String) {
            String s = ((String) val).trim();
            if (s.startsWith("B\"") && s.endsWith("\"")) {
                s = s.substring(2, s.length() - 1);
            }
            return Boolean.parseBoolean(s);
        }
        return defaultVal;
    }

    /**
     * 프로퍼티 맵에서 문자열 값을 추출하고 양끝 따옴표가 있으면 제거하여 반환합니다.
     *
     * @param props      프로퍼티 맵
     * @param key        조회할 프로퍼티 키
     * @param defaultVal 키가 없을 때 반환할 기본값
     * @return 추출된 문자열
     */
    private String getStringProp(final Map<String, Object> props, final String key, final String defaultVal) {
        if (props != null && props.containsKey(key) && props.get(key) != null) {
            String s = props.get(key).toString().trim();
            if (s.startsWith("\"") && s.endsWith("\"") && s.length() >= 2) {
                s = s.substring(1, s.length() - 1);
            }
            return s;
        }
        return defaultVal;
    }

    /**
     * 프로퍼티 맵에서 문자열 배열/컬렉션/쉼표 구분 문자열을 추출하여 리스트로 반환합니다.
     *
     * @param props      프로퍼티 맵
     * @param key        조회할 프로퍼티 키
     * @param defaultVal 키가 없을 때 사용할 기본 문자열 배열
     * @return 추출된 문자열 리스트
     */
    private List<String> getStringListProp(final Map<String, Object> props, final String key, final String[] defaultVal) {
        List<String> list = new ArrayList<>();
        if (props != null && props.containsKey(key) && props.get(key) != null) {
            Object v = props.get(key);
            if (v instanceof String[]) {
                for (String s : (String[]) v) {
                    if (StringUtils.isNotBlank(s)) {
                        list.add(s.trim());
                    }
                }
                return list;
            } else if (v instanceof Collection<?>) {
                for (Object item : (Collection<?>) v) {
                    if (item != null && StringUtils.isNotBlank(item.toString())) {
                        list.add(item.toString().trim());
                    }
                }
                return list;
            } else if (v instanceof String) {
                String s = ((String) v).trim();
                if (StringUtils.isNotBlank(s)) {
                    for (String part : s.split(",")) {
                        if (StringUtils.isNotBlank(part)) {
                            list.add(part.trim());
                        }
                    }
                }
                return list;
            }
        }
        if (defaultVal != null) {
            for (String s : defaultVal) {
                if (StringUtils.isNotBlank(s)) {
                    list.add(s.trim());
                }
            }
        }
        return list;
    }

    /**
     * JSON/Map 형태의 OSGi 프로퍼티 맵으로부터 {@link ServletSecurityConfig} 정책 목록을 파싱하여 초기화합니다.
     *
     * @param isEnabled  필터 전체 활성화 여부
     * @param properties OSGi 컴포넌트 프로퍼티 맵
     */
    private void parsePoliciesFromProperties(final boolean isEnabled, final Map<String, Object> properties) {
        try {
            ServletSecurityConfig parsedConfig = null;
            JsonElement rootElement = toNormalizedJsonElement(properties);
            if (rootElement != null && rootElement.isJsonObject()) {
                JsonObject rootObj = rootElement.getAsJsonObject();
                sanitizeRootConfigJsonObject(rootObj);
                try {
                    ServletSecurityConfig cfg = GSON.fromJson(rootObj, ServletSecurityConfig.class);
                    if (cfg != null && ((cfg.getPolicies() != null && !cfg.getPolicies().isEmpty()) || cfg.getDefaultPolicy() != null)) {
                        cfg.setEnabled(isEnabled);
                        parsedConfig = cfg;
                    }
                } catch (Exception e) {
                    LOG.debug("Direct root config deserialization fallback triggered: {}", e.getMessage());
                }
            }

            if (parsedConfig == null) {
                Object policiesObj = properties.get("policies");
                List<ServletPolicyRule> policies = parsePolicyRuleList(policiesObj);
                if (policies != null && !policies.isEmpty()) {
                    parsedConfig = new ServletSecurityConfig(isEnabled, policies);
                } else if (policiesObj != null || properties.containsKey("defaultPolicy")
                        || properties.containsKey("default") || properties.containsKey("globalPolicy")) {
                    parsedConfig = new ServletSecurityConfig(isEnabled, Collections.emptyList());
                }
            }

            Object defPolicyObj = properties.get("defaultPolicy");
            if (defPolicyObj == null) {
                defPolicyObj = properties.get("default");
            }
            if (defPolicyObj == null) {
                defPolicyObj = properties.get("globalPolicy");
            }
            if (defPolicyObj != null && parsedConfig != null && parsedConfig.getDefaultPolicy() == null) {
                ServletPolicyRule defRule = parseSinglePolicyRule(defPolicyObj);
                if (defRule != null) {
                    parsedConfig.setDefaultPolicy(defRule);
                }
            }

            Object validatorsObj = properties.get("validators");
            if (validatorsObj != null && parsedConfig != null) {
                JsonElement valElem = toNormalizedJsonElement(validatorsObj);
                if (valElem != null && valElem.isJsonObject()) {
                    for (Map.Entry<String, JsonElement> entry : valElem.getAsJsonObject().entrySet()) {
                        try {
                            parsedConfig.setValidatorEnabled(entry.getKey(), entry.getValue().getAsBoolean());
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            if (parsedConfig != null) {
                parsedConfig.init();
                this.servletSecurityConfig = parsedConfig;
                LOG.info("Successfully loaded and initialized {} servlet security policies from OSGi properties.",
                        parsedConfig.getPolicies() != null ? parsedConfig.getPolicies().size() : 0);
            } else {
                handleConfigFailure("OSGi properties", new IllegalArgumentException("Parsed configuration resulted in null"), isEnabled);
            }
        } catch (Exception e) {
            handleConfigFailure("OSGi properties", e, isEnabled);
        }
    }

    /**
     * Gson 역직렬화 전에 루트 JSON 객체의 필드 타입(단일 객체 vs 배열 등)을 정규화합니다.
     *
     * @param rootObj 정규화할 루트 {@link JsonObject}
     */
    private void sanitizeRootConfigJsonObject(final JsonObject rootObj) {
        String[] objectKeys = {"defaultPolicy", "default", "globalPolicy"};
        for (String key : objectKeys) {
            if (rootObj.has(key)) {
                JsonElement el = rootObj.get(key);
                if (el != null && el.isJsonArray() && el.getAsJsonArray().size() == 1 && el.getAsJsonArray().get(0).isJsonObject()) {
                    rootObj.add(key, el.getAsJsonArray().get(0));
                } else if (el == null || !el.isJsonObject()) {
                    rootObj.remove(key);
                }
            }
        }
        if (rootObj.has("policies")) {
            JsonElement el = rootObj.get("policies");
            if (el != null && el.isJsonObject()) {
                JsonArray arr = new JsonArray();
                arr.add(el);
                rootObj.add("policies", arr);
            } else if (el == null || !el.isJsonArray()) {
                rootObj.remove("policies");
            }
        }
        String[] arrayKeys = {"disabledValidators", "skipValidators", "enabledValidators"};
        for (String key : arrayKeys) {
            if (rootObj.has(key)) {
                JsonElement el = rootObj.get(key);
                if (el != null && el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
                    String str = el.getAsString().trim();
                    JsonArray arr = new JsonArray();
                    if (!str.isEmpty()) {
                        for (String part : str.split(",")) {
                            if (StringUtils.isNotBlank(part)) {
                                arr.add(new JsonPrimitive(part.trim()));
                            }
                        }
                    }
                    rootObj.add(key, arr);
                } else if (el == null || !el.isJsonArray()) {
                    rootObj.remove(key);
                }
            }
        }
    }

    /**
     * 단일 정책 객체를 파싱하여 {@link ServletPolicyRule}로 변환합니다.
     *
     * @param obj 파싱할 원본 객체(JSON 문자열, Map, JsonElement 등)
     * @return 변환된 {@link ServletPolicyRule} (변환 불가 시 null)
     */
    private ServletPolicyRule parseSinglePolicyRule(final Object obj) {
        if (obj == null) {
            return null;
        }
        JsonElement elem = toNormalizedJsonElement(obj);
        if (elem == null || elem.isJsonNull()) {
            return null;
        }
        if (elem.isJsonArray() && elem.getAsJsonArray().size() == 1) {
            elem = elem.getAsJsonArray().get(0);
        }
        if (elem.isJsonObject()) {
            return GSON.fromJson(elem, ServletPolicyRule.class);
        }
        return null;
    }

    /**
     * 정책 목록 객체(JSON 배열, 문자열 배열, Map 등)를 파싱하여 {@link ServletPolicyRule} 리스트로 변환합니다.
     *
     * @param policiesObj 파싱할 정책 목록 객체
     * @return 변환된 {@link ServletPolicyRule} 리스트
     */
    private List<ServletPolicyRule> parsePolicyRuleList(final Object policiesObj) {
        if (policiesObj == null) {
            return Collections.emptyList();
        }
        JsonElement elem = toNormalizedJsonElement(policiesObj);
        if (elem == null || elem.isJsonNull()) {
            return Collections.emptyList();
        }
        List<ServletPolicyRule> result = new ArrayList<>();
        if (elem.isJsonArray()) {
            for (JsonElement item : elem.getAsJsonArray()) {
                JsonElement normalizedItem = item.isJsonPrimitive() && item.getAsJsonPrimitive().isString()
                        ? toNormalizedJsonElement(item.getAsString())
                        : item;
                if (normalizedItem != null && normalizedItem.isJsonObject()) {
                    ServletPolicyRule rule = GSON.fromJson(normalizedItem, ServletPolicyRule.class);
                    if (rule != null) {
                        result.add(rule);
                    }
                }
            }
        } else if (elem.isJsonObject()) {
            ServletPolicyRule singleRule = GSON.fromJson(elem, ServletPolicyRule.class);
            if (singleRule != null) {
                result.add(singleRule);
            }
        }
        return result;
    }

    /**
     * 임의의 Java 객체(Map, 배열, 컬렉션, JSON 문자열 등)를 재귀적으로 정규화된 {@link JsonElement}로 변환합니다.
     *
     * @param value 변환할 원본 값
     * @return 정규화된 {@link JsonElement}
     */
    private JsonElement toNormalizedJsonElement(final Object value) {
        if (value == null) {
            return JsonNull.INSTANCE;
        }
        if (value instanceof JsonElement) {
            JsonElement el = (JsonElement) value;
            if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
                return parseJsonStringIfApplicable(el.getAsString());
            } else if (el.isJsonArray()) {
                JsonArray normalizedArr = new JsonArray();
                for (JsonElement child : el.getAsJsonArray()) {
                    normalizedArr.add(toNormalizedJsonElement(child));
                }
                return normalizedArr;
            } else if (el.isJsonObject()) {
                JsonObject normalizedObj = new JsonObject();
                for (Map.Entry<String, JsonElement> entry : el.getAsJsonObject().entrySet()) {
                    normalizedObj.add(entry.getKey(), toNormalizedJsonElement(entry.getValue()));
                }
                return normalizedObj;
            }
            return el;
        }
        if (value instanceof Boolean) {
            return new JsonPrimitive((Boolean) value);
        }
        if (value instanceof Number) {
            return new JsonPrimitive((Number) value);
        }
        if (value instanceof Character) {
            return new JsonPrimitive((Character) value);
        }
        if (value instanceof String) {
            return parseJsonStringIfApplicable((String) value);
        }
        if (value instanceof String[]) {
            String[] arr = (String[]) value;
            if (arr.length == 0) {
                return new JsonArray();
            }
            if (arr.length == 1) {
                JsonElement single = parseJsonStringIfApplicable(arr[0]);
                if (single.isJsonArray() || single.isJsonObject()) {
                    return single;
                }
                JsonArray jsonArray = new JsonArray();
                jsonArray.add(single);
                return jsonArray;
            }
            boolean allElementsAreObjects = true;
            for (String s : arr) {
                if (StringUtils.isNotBlank(s)) {
                    String trimmed = s.trim();
                    if (!(trimmed.startsWith("{") && trimmed.endsWith("}"))) {
                        allElementsAreObjects = false;
                        break;
                    }
                }
            }
            if (!allElementsAreObjects) {
                String joined = String.join("\n", arr).trim();
                if ((joined.startsWith("[") && joined.endsWith("]")) || (joined.startsWith("{") && joined.endsWith("}"))) {
                    try {
                        JsonElement parsedJoined = GSON.fromJson(joined, JsonElement.class);
                        if (parsedJoined != null && (parsedJoined.isJsonArray() || parsedJoined.isJsonObject())) {
                            return toNormalizedJsonElement(parsedJoined);
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
            JsonArray jsonArray = new JsonArray();
            for (String s : arr) {
                if (s != null) {
                    jsonArray.add(parseJsonStringIfApplicable(s));
                }
            }
            return jsonArray;
        }
        if (value instanceof Map<?, ?>) {
            JsonObject jsonObject = new JsonObject();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    jsonObject.add(String.valueOf(entry.getKey()), toNormalizedJsonElement(entry.getValue()));
                }
            }
            return jsonObject;
        }
        if (value instanceof Collection<?>) {
            Collection<?> col = (Collection<?>) value;
            boolean allStrings = !col.isEmpty();
            for (Object item : col) {
                if (!(item instanceof String)) {
                    allStrings = false;
                    break;
                }
            }
            if (allStrings) {
                return toNormalizedJsonElement(col.toArray(new String[0]));
            }
            JsonArray jsonArray = new JsonArray();
            for (Object item : col) {
                if (item != null) {
                    jsonArray.add(toNormalizedJsonElement(item));
                }
            }
            return jsonArray;
        }
        if (value.getClass().isArray()) {
            int length = java.lang.reflect.Array.getLength(value);
            JsonArray jsonArray = new JsonArray();
            for (int i = 0; i < length; i++) {
                Object item = java.lang.reflect.Array.get(value, i);
                if (item != null) {
                    jsonArray.add(toNormalizedJsonElement(item));
                }
            }
            return jsonArray;
        }
        return GSON.toJsonTree(value);
    }

    /**
     * 문자열이 JSON 객체({@code {...}}) 또는 JSON 배열({@code [...]}) 형태인 경우 파싱하고,
     * 일반 문자열이면 {@link JsonPrimitive}로 감싸서 반환합니다.
     *
     * @param raw 검사할 문자열
     * @return 파싱된 {@link JsonElement}
     */
    private JsonElement parseJsonStringIfApplicable(final String raw) {
        if (raw == null) {
            return JsonNull.INSTANCE;
        }
        String trimmed = raw.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                JsonElement parsed = GSON.fromJson(trimmed, JsonElement.class);
                if (parsed != null && (parsed.isJsonObject() || parsed.isJsonArray())) {
                    return toNormalizedJsonElement(parsed);
                }
            } catch (Exception ignored) {
            }
        }
        return new JsonPrimitive(raw);
    }

    /**
     * OSGi 컴포넌트 비활성화({@code @Deactivate}) 시 호출되며, 바인딩된 서블릿 캐시를 정리합니다.
     */
    @Deactivate
    protected void deactivate() {
        boundServlets.clear();
        LOG.info("SecurityFilter deactivated.");
    }

    /**
     * 서블릿 필터 초기화 메소드입니다 (OSGi 생명주기는 {@link #activate}에서 처리됨).
     *
     * @param filterConfig 서블릿 필터 설정 객체
     * @throws ServletException 필터 초기화 예외
     */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
    }

    /**
     * 매 HTTP 요청마다 실행되는 메인 보안 필터 메소드입니다.
     * 1. 필터 활성화 여부 및 설정된 필터 패턴({@link #matchesFilterPattern}) 일치 여부를 확인합니다.
     * 2. 요청에 매칭되는 서블릿 보안 정책({@link ServletPolicyRule})을 조회합니다.
     * 3. 3대 핵심 검증기(Referer, Method, Param)를 순차적으로 실행합니다.
     * 4. 검증 실패 시 차단된 설정 항목과 현재 서블릿 보안 설정을 상세히 로깅하고 JSON 에러 응답을 반환합니다.
     *
     * @param servletRequest  유입된 서블릿 요청
     * @param servletResponse 서블릿 응답
     * @param chain           필터 체인
     * @throws IOException      입출력 예외
     * @throws ServletException 서블릿 예외
     */
    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain chain)
            throws IOException, ServletException {

        if (!enabled || !(servletRequest instanceof HttpServletRequest) || !(servletResponse instanceof HttpServletResponse)) {
            LOG.debug("SecurityFilter skipped: filter enabled={}, isHttpRequest={}",
                    enabled, servletRequest instanceof HttpServletRequest);
            chain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        String requestUri = httpRequest.getRequestURI();
        if (!matchesFilterPattern(requestUri)) {
            LOG.debug("SecurityFilter bypassed for non-matching filter pattern ({}): URI=[{}]", filterPattern, requestUri);
            chain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("--> [FILTER START] Evaluating request: Method=[{}], URI=[{}], Query=[{}], ClientIP=[{}]",
                    httpRequest.getMethod(), requestUri, httpRequest.getQueryString(), SecurityUtils.getClientIp(httpRequest));
        }

        ServletPolicyRule activePolicy = evaluatePoliciesAndFindActive(httpRequest, httpResponse);
        if (activePolicy == REJECTED_POLICY) {
            LOG.debug("<-- [FILTER BLOCKED] Request [{} {}] was rejected by security policy.",
                    httpRequest.getMethod(), requestUri);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("<-- [FILTER PASS] Request [{} {}] passed all security validations (Referer, Method, Param).",
                    httpRequest.getMethod(), requestUri);
        }

        chain.doFilter(servletRequest, servletResponse);
    }

    /**
     * 요청에 매칭되는 서블릿 보안 정책을 찾고, 활성화된 검증기 체인(REFERER -> METHOD -> PARAM)을 실행합니다.
     * 검증에 실패하면 즉시 {@link #handleSecurityViolation}을 호출하여 차단 로그 및 에러 응답을 처리합니다.
     *
     * @param request  유입된 HTTP 요청
     * @param response HTTP 응답
     * @return 검증 통과 시 매칭된 {@link ServletPolicyRule}, 차단 시 {@link #REJECTED_POLICY}, 정책 미적용 시 null
     * @throws IOException 응답 작성 중 입출력 예외 발생 시
     */
    private ServletPolicyRule evaluatePoliciesAndFindActive(final HttpServletRequest request,
                                                            final HttpServletResponse response) throws IOException {
        if (servletSecurityConfig == null || !servletSecurityConfig.isEnabled()) {
            LOG.debug("ServletSecurityConfig is null or disabled. Skipping policy evaluation for URI=[{}]", request.getRequestURI());
            return null;
        }

        ServletPolicyRule matchedPolicy = servletSecurityConfig.findMatchingPolicy(request);
        if (matchedPolicy == null) {
            LOG.debug("No matching security policy found for URI=[{}]. Allowing request.", request.getRequestURI());
            return null;
        }

        if (!matchedPolicy.isEnabled()) {
            LOG.debug("Matched policy target=[{}] has enabled=false. Bypassing security validation for URI=[{}].",
                    matchedPolicy.getTarget(), request.getRequestURI());
            return matchedPolicy;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Evaluating policy target [{}] for [{} {}]: AppliedServletPolicy=[{}]",
                    matchedPolicy.getTarget(), request.getMethod(), request.getRequestURI(),
                    formatAppliedPolicyForLog(matchedPolicy));
        }

        // 매칭된 정책에 대해 3대 검증기 체인(REFERER -> METHOD -> PARAM) 실행
        for (PolicyValidator validator : validators) {
            if (!validator.isEnabled(matchedPolicy, servletSecurityConfig)) {
                LOG.debug("  [-] Validator [{}] is skipped/disabled for target [{}]", validator.getName(), matchedPolicy.getTarget());
                continue;
            }

            LOG.debug("  [*] Executing validator [{}] for target [{}]", validator.getName(), matchedPolicy.getTarget());
            ValidationResult result = validator.validate(request, matchedPolicy, servletSecurityConfig);
            if (!result.isValid()) {
                String appliedPolicyInfo = formatAppliedPolicyForLog(matchedPolicy);
                String blockedConfigInfo = StringUtils.defaultIfBlank(result.getBlockedConfig(), result.getViolationDetail());
                LOG.debug("  [!] Validator [{}] FAILED for URI [{}]: Status={}, Code={}, Message={} | BlockedByConfig=[{}] | AppliedServletPolicy=[{}]",
                        validator.getName(), request.getRequestURI(), result.getStatusCode(), result.getSubCode(),
                        result.getResponseMessage(), blockedConfigInfo, appliedPolicyInfo);
                handleSecurityViolation(request, response, matchedPolicy, validator.getName(), result.getStatusCode(),
                        result.getSubCode(), result.getViolationDetail(), blockedConfigInfo, result.getResponseMessage());
                return REJECTED_POLICY;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("  [+] Validator [{}] PASSED for target [{}] | PassedConfig=[{}]",
                        validator.getName(), matchedPolicy.getTarget(),
                        validator.describePassedConfig(request, matchedPolicy, servletSecurityConfig));
            }
        }

        LOG.debug("All active validators PASSED for target [{}] on URI [{}]", matchedPolicy.getTarget(), request.getRequestURI());
        return matchedPolicy;
    }

    /**
     * 설정 로드 또는 파싱 중 예외가 발생했을 때 이전 정상 설정(Last Known Good)을 유지하거나,
     * 초기 기동 시 안전한 폴백 설정으로 초기화합니다.
     *
     * @param source    설정 소스 설명 문자열 (예: "OSGi .config", "OSGi properties")
     * @param e         발생한 예외
     * @param isEnabled 필터 활성화 여부
     */
    private void handleConfigFailure(final String source, final Exception e, final boolean isEnabled) {
        if (this.servletSecurityConfig != null &&
                ((this.servletSecurityConfig.getPolicies() != null && !this.servletSecurityConfig.getPolicies().isEmpty())
                        || this.servletSecurityConfig.getDefaultPolicy() != null)) {
            LOG.error("CRITICAL: Failed to parse servlet policies from {}! Retaining previous active configuration (Last Known Good). Error: {}",
                    source, e.getMessage(), e);
        } else {
            LOG.error("CRITICAL: Failed to parse servlet policies from {} during startup. Initializing safe fallback config. Error: {}",
                    source, e.getMessage(), e);
            ServletSecurityConfig fallback = new ServletSecurityConfig(isEnabled, Collections.emptyList());
            fallback.init();
            this.servletSecurityConfig = fallback;
        }
    }

    /**
     * 현재 활성화된 기본 보안 정책(Default Policy)과 개별 서블릿 정책 목록을 INFO 로그로 출력합니다.
     */
    private void logConfiguredPolicies() {
        if (servletSecurityConfig == null) {
            LOG.info("No Servlet Policies configured.");
            return;
        }

        LOG.info("=== Servlet Security Policies (Enabled: {}) ===", servletSecurityConfig.isEnabled());

        if (servletSecurityConfig.getDefaultPolicy() != null) {
            ServletPolicyRule def = servletSecurityConfig.getDefaultPolicy();
            LOG.info("Default Policy (Fallback): Enabled: [{}], Methods: {}, DefaultReferrer: [{}], AllowUndefinedParams: [{}], Params: {}",
                    def.isEnabled(),
                    def.getMethods().isEmpty() ? "ALL" : def.getMethods(),
                    servletSecurityConfig.getDefaultReferrer(),
                    def.isAllowUndefinedParams(),
                    def.getParams().keySet());
        }

        if (servletSecurityConfig.getPolicies() != null) {
            for (ServletPolicyRule policy : servletSecurityConfig.getPolicies()) {
                LOG.info("Policy Target: [{}], Enabled: [{}], Methods: {}, AllowedReferrers: {}, AllowUndefinedParams: [{}], Params: {}",
                        policy.getTarget(),
                        policy.isEnabled(),
                        policy.getMethods().isEmpty() ? "ALL" : policy.getMethods(),
                        policy.getAllowedReferrers(),
                        policy.isAllowUndefinedParams(),
                        policy.getParams().keySet());
            }
        }
    }

    /**
     * 서블릿 필터 종료 시 호출되는 메소드입니다.
     */
    @Override
    public void destroy() {
    }

    /**
     * 보안 정책 위반으로 요청이 차단되었을 때 호출됩니다.
     * 어떤 검증기와 어떤 설정 규칙({@code BlockedByConfig})에 의해 차단되었는지, 그리고 해당 서블릿에 적용된
     * 전체 보안 설정({@code AppliedServletPolicy})이 무엇인지 WARN 로그에 상세히 기록하고 JSON 에러 응답을 반환합니다.
     *
     * @param request           차단된 HTTP 요청
     * @param response          HTTP 응답
     * @param matchedPolicy     서블릿에 적용된 보안 정책 규칙
     * @param validatorName     차단을 수행한 검증기 이름 (REFERER, METHOD, PARAM)
     * @param statusCode        반환할 HTTP 상태 코드 (400, 403, 405 등)
     * @param subCode           표준 보안 에러 서브 코드
     * @param violationDetail   차단 사유 상세 설명
     * @param blockedConfigInfo 차단을 유발한 구체적인 설정 규칙 및 입력값 정보
     * @param responseMessage   클라이언트에게 반환할 에러 메시지
     * @throws IOException 응답 스트림 기록 중 예외 발생 시
     */
    private void handleSecurityViolation(final HttpServletRequest request, final HttpServletResponse response,
                                         final ServletPolicyRule matchedPolicy, final String validatorName,
                                         final int statusCode, final String subCode,
                                         final String violationDetail, final String blockedConfigInfo,
                                         final String responseMessage)
            throws IOException {
        String clientIp = SecurityUtils.getClientIp(request);
        String appliedPolicyInfo = formatAppliedPolicyForLog(matchedPolicy);
        LOG.warn("SECURITY VIOLATION BLOCKED: Client IP=[{}], Method=[{}], URI=[{}], Validator=[{}], Status=[{}], ErrorCode=[{}], Reason=[{}] | BlockedByConfig=[{}] | AppliedServletPolicy=[{}]",
                clientIp,
                request.getMethod(),
                SecurityUtils.sanitizeForLog(request.getRequestURI()),
                validatorName != null ? validatorName : "UNKNOWN",
                statusCode,
                subCode,
                violationDetail,
                blockedConfigInfo != null ? blockedConfigInfo : "UNKNOWN",
                appliedPolicyInfo);

        if (!response.isCommitted()) {
            response.setStatus(statusCode);
            response.setContentType("application/json;charset=UTF-8");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());

            Map<String, Object> errorBody = new LinkedHashMap<>();
            errorBody.put("code", statusCode);
            if (subCode != null && !subCode.isEmpty()) {
                errorBody.put("errorCode", subCode);
            }
            errorBody.put("message", responseMessage);

            response.getWriter().write(GSON.toJson(errorBody));
            response.getWriter().flush();
        }
    }

    /**
     * 보안 위반 및 디버그 로깅을 위해 매칭된 {@link ServletPolicyRule}의 전체 보안 설정 정보와
     * 원본 서블릿 클래스/출처 정보를 보기 좋게 포맷팅하여 반환합니다.
     *
     * @param matchedPolicy 포맷팅할 서블릿 보안 정책 규칙
     * @return 서블릿 출처 및 현재 적용된 전체 보안 설정 요약 문자열
     */
    public String formatAppliedPolicyForLog(final ServletPolicyRule matchedPolicy) {
        if (matchedPolicy == null) {
            return "NONE";
        }
        String target = matchedPolicy.getTarget();
        String servletSource = resolvePolicySourceLabel(target);
        return "source=" + servletSource + ", " + matchedPolicy.toPolicySummaryString();
    }

    /**
     * 정책 타겟에 해당하는 서블릿의 출처(컴포넌트 이름, 서블릿 클래스명, 또는 기본 정책 여부)를 조회합니다.
     *
     * @param target 조회할 정책 타겟 문자열
     * @return 정책 출처 라벨 문자열
     */
    private String resolvePolicySourceLabel(final String target) {
        if (StringUtils.isBlank(target)) {
            return "UNKNOWN";
        }
        if ("DEFAULT".equalsIgnoreCase(target.trim())) {
            return "DefaultPolicy(SecurityFilter.config)";
        }
        for (Map.Entry<Servlet, Map<String, Object>> entry : boundServlets.entrySet()) {
            List<String> targets = extractServletTargets(entry.getValue());
            for (String t : targets) {
                if (target.trim().equalsIgnoreCase(t.trim())) {
                    Servlet servlet = entry.getKey();
                    Object compName = entry.getValue().get("component.name");
                    if (compName != null && StringUtils.isNotBlank(compName.toString())) {
                        return compName.toString().trim();
                    }
                    return servlet.getClass().getName();
                }
            }
        }
        return "ConfiguredPolicy";
    }

    /**
     * OSGi 설정({@link Config} 및 프로퍼티 맵)의 전역 검증기 On/Off 토글
     * ({@code validator.referer.enabled}, {@code validator.method.enabled}, {@code validator.param.enabled})을
     * {@link ServletSecurityConfig}에 반영합니다.
     *
     * @param config     OSGi OCD 설정 객체
     * @param properties OSGi 프로퍼티 맵
     */
    private void applyOsgiValidatorToggles(final Config config, final Map<String, Object> properties) {
        if (servletSecurityConfig == null) {
            return;
        }
        if (config != null) {
            if (!config.validator_referer_enabled()) servletSecurityConfig.setValidatorEnabled("REFERER", false);
            if (!config.validator_method_enabled()) servletSecurityConfig.setValidatorEnabled("METHOD", false);
            if (!config.validator_param_enabled()) servletSecurityConfig.setValidatorEnabled("PARAM", false);
        }
        if (properties != null) {
            applyPropertyValidatorToggle(properties, "validator.referer.enabled", "REFERER");
            applyPropertyValidatorToggle(properties, "validator.method.enabled", "METHOD");
            applyPropertyValidatorToggle(properties, "validator.param.enabled", "PARAM");
        }
    }

    /**
     * 개별 검증기 토글 프로퍼티 키를 확인하여 {@link ServletSecurityConfig}에 활성화 여부를 설정합니다.
     *
     * @param properties    OSGi 프로퍼티 맵
     * @param key           프로퍼티 키 (예: "validator.referer.enabled")
     * @param validatorName 검증기 이름 (예: "REFERER")
     */
    private void applyPropertyValidatorToggle(final Map<String, Object> properties, final String key, final String validatorName) {
        if (properties.containsKey(key)) {
            Object val = properties.get(key);
            if (val instanceof Boolean) {
                servletSecurityConfig.setValidatorEnabled(validatorName, (Boolean) val);
            } else if (val instanceof String) {
                servletSecurityConfig.setValidatorEnabled(validatorName, toBoolean(val, true));
            }
        }
    }

    /**
     * 현재 필터에 로드된 루트 {@link ServletSecurityConfig} 객체를 반환합니다.
     *
     * @return 현재 {@link ServletSecurityConfig} 인스턴스
     */
    public ServletSecurityConfig getServletSecurityConfig() {
        return servletSecurityConfig;
    }
}
