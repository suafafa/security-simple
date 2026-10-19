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
     * OSGi {@link Config} 객체로부터 기본 보안 정책과 검증기 활성화 상태를 로드하고,
     * 바인딩된 서블릿들의 동적 정책을 동기화합니다.
     *
     * @param config OSGi OCD 설정 객체
     */
    @Activate
    @Modified
    public void activate(final Config config) {
        LOG.debug("SecurityFilter activate/modified lifecycle invoked.");

        if (config != null && StringUtils.isNotBlank(config.sling_filter_pattern())) {
            updateFilterPattern(config.sling_filter_pattern());
        }

        boolean isEnabled = config != null ? config.enabled() : true;
        this.enabled = isEnabled;

        try {
            ServletPolicyRule defaultRule = buildDefaultPolicy(config);

            ServletSecurityConfig newConfig = new ServletSecurityConfig(isEnabled, Collections.emptyList());
            newConfig.setDefaultPolicy(defaultRule);
            if (StringUtils.isNotBlank(defaultRule.getDefaultReferrer())) {
                newConfig.setDefaultReferrer(defaultRule.getDefaultReferrer());
            }

            if (config != null) {
                if (!config.validator_referer_enabled()) newConfig.setValidatorEnabled("REFERER", false);
                if (!config.validator_method_enabled())  newConfig.setValidatorEnabled("METHOD", false);
                if (!config.validator_param_enabled())   newConfig.setValidatorEnabled("PARAM", false);
            }

            newConfig.init();
            this.servletSecurityConfig = newConfig;

            if (!boundServlets.isEmpty()) {
                for (Map<String, Object> props : boundServlets.values()) {
                    if (isApplicableServlet(props)) {
                        List<ServletPolicyRule> rules = ServletPolicyRule.fromOsgiProperties(props, defaultRule);
                        for (ServletPolicyRule rule : rules) {
                            if (matchesFilterPattern(rule.getTarget())) {
                                servletSecurityConfig.registerDynamicPolicy(rule);
                            }
                        }
                    }
                }
            }

            logConfiguredPolicies();
            LOG.info("SecurityFilter activated for AEM 6.5. Filter Enabled: {}, Filter Pattern: {}, Active Policies: {}",
                    enabled, filterPattern, servletSecurityConfig.getPolicies().size());
        } catch (Exception e) {
            handleConfigFailure("OSGi Config", e, isEnabled);
        }
    }

    /**
     * OSGi {@link Config} 객체에서 {@code default.*} 설정을 읽어 기본 보안 정책({@code defaultPolicy})을 생성합니다.
     *
     * @param config OSGi OCD 설정 객체
     * @return 초기화된 기본 {@link ServletPolicyRule} 객체
     */
    private ServletPolicyRule buildDefaultPolicy(final Config config) {
        ServletPolicyRule rule = new ServletPolicyRule();
        rule.setTarget("DEFAULT");

        if (config != null) {
            rule.setEnabled(config.default_enabled());
            rule.setDefaultReferrer(config.default_referrer());
            if (config.default_methods() != null && config.default_methods().length > 0) {
                rule.setMethods(Arrays.asList(config.default_methods()));
            }
            rule.setBlockSqlInjection(config.default_blockSqlInjection());
            rule.setBlockXss(config.default_blockXss());
            rule.setAllowUndefinedParams(config.default_allowUndefinedParams());

            String[] paramsArray = config.default_params();
            if (paramsArray != null && paramsArray.length > 0) {
                Map<String, ParamRule> paramRules = new LinkedHashMap<>();
                for (String spec : paramsArray) {
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
            }
        }

        rule.init();
        return rule;
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
     * 현재 필터에 로드된 루트 {@link ServletSecurityConfig} 객체를 반환합니다.
     *
     * @return 현재 {@link ServletSecurityConfig} 인스턴스
     */
    public ServletSecurityConfig getServletSecurityConfig() {
        return servletSecurityConfig;
    }
}
