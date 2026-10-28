package com.example.security.registry;

import com.example.security.models.ServletPolicyRule;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 번들(모듈) 또는 도메인 단위의 {@code .cfg.json} 파일 1개와 1:1로 매핑되는 OSGi Factory Configuration 컴포넌트입니다.
 * <p>
 * 서블릿 경로별로 배열 형태의 JSON 객체 구조({@code "policies": [ { "target": "/aemapi/...", ... } ]})를 사용합니다.
 * <p>
 * 파일명 규칙 예시:
 * <ul>
 *   <li>{@code com.example.security.registry.EndpointPolicyConfig~core-member.cfg.json}</li>
 *   <li>{@code com.example.security.registry.EndpointPolicyConfig~core-commerce.cfg.json}</li>
 * </ul>
 */
@Component(
        service = EndpointPolicyConfig.class,
        configurationPolicy = ConfigurationPolicy.REQUIRE
)
@Designate(ocd = EndpointPolicyConfig.Config.class, factory = true)
public class EndpointPolicyConfig {

    private static final Logger LOG = LoggerFactory.getLogger(EndpointPolicyConfig.class);
    private static final Gson GSON = new Gson();

    /**
     * 번들별 엔드포인트 보안 정책 Factory OCD 정의입니다.
     */
    @ObjectClassDefinition(
            name = "AEM Endpoint Security Policy Bundle Configuration",
            description = "Bundle/Domain-scoped Servlet Security Policy Configuration (.cfg.json)"
    )
    public @interface Config {

        @AttributeDefinition(
                name = "Bundle Policies Enabled",
                description = "Enable or disable all servlet security policies in this bundle config"
        )
        boolean enabled() default true;

        @AttributeDefinition(
                name = "Bundle / Module ID",
                description = "Logical bundle or domain identifier (e.g. core-member, core-commerce)"
        )
        String bundle_id() default "";

        @AttributeDefinition(
                name = "Servlet Policy JSON Objects",
                description = "Array of JSON policy objects per servlet path"
        )
        String[] policies() default {};
    }

    private volatile boolean enabled = true;
    private volatile String bundleId = "default-bundle";
    private volatile String configPid = "";
    private volatile List<ServletPolicyRule> parsedRules = Collections.emptyList();
    private volatile Runnable modificationListener;

    /**
     * 설정이 {@code @Activate} 또는 {@code @Modified}로 갱신될 때 즉시 호출할 리스너를 등록합니다.
     * OSGi SCR의 {@code updated} 콜백 호출 순서나 생략 여부에 영향받지 않고 레지스트리가 즉시 갱신되도록 보장합니다.
     *
     * @param listener 설정 변경 시 실행할 콜백
     */
    public void setModificationListener(final Runnable listener) {
        this.modificationListener = listener;
    }

    private void notifyModificationListener() {
        Runnable listener = this.modificationListener;
        if (listener != null) {
            listener.run();
        }
    }

    /**
     * OSGi Factory Configuration 활성화({@code @Activate}) 및 실시간 파일 수정({@code @Modified}) 시 호출됩니다.
     *
     * @param config     OSGi OCD 설정 인스턴스
     * @param properties 원본 OSGi 프로퍼티 맵 ({@code .cfg.json}의 전체 키-값 포함)
     */
    @Activate
    @Modified
    public void activate(final Config config, final Map<String, Object> properties) {
        Map<String, Object> safeProps = properties != null ? new LinkedHashMap<>(properties) : new LinkedHashMap<>();

        boolean isEnabled = true;
        if (config != null) {
            isEnabled = config.enabled();
        } else if (safeProps.containsKey("enabled")) {
            Object en = safeProps.get("enabled");
            isEnabled = en instanceof Boolean ? (Boolean) en : Boolean.parseBoolean(en.toString());
        }
        this.enabled = isEnabled;
        this.configPid = resolveConfigPid(safeProps);
        this.bundleId = resolveBundleId(config, safeProps, this.configPid);

        if (!isEnabled) {
            this.parsedRules = Collections.emptyList();
            LOG.info("EndpointPolicyConfig [bundleId={}, pid={}] is disabled. Active rules: 0", bundleId, configPid);
            notifyModificationListener();
            return;
        }

        Map<String, ServletPolicyRule> ruleMap = new LinkedHashMap<>();

        // 서블릿 경로별 배열 형태의 JSON 객체(policies) 파싱
        List<Object> policyEntries = extractPolicyEntries(config, safeProps);
        for (Object entryObj : policyEntries) {
            if (entryObj == null) {
                continue;
            }
            try {
                List<ServletPolicyRule> rules = ServletPolicyRule.fromPolicyJsonEntry(entryObj, null);
                for (ServletPolicyRule rule : rules) {
                    if (rule != null && StringUtils.isNotBlank(rule.getTarget())) {
                        ruleMap.put(rule.getTarget().trim(), rule);
                    }
                }
            } catch (Exception e) {
                LOG.error("Failed to parse policy JSON entry in bundle [{}]: entry='{}', error={}",
                        bundleId, entryObj, e.getMessage());
            }
        }

        this.parsedRules = Collections.unmodifiableList(new ArrayList<>(ruleMap.values()));
        LOG.info("EndpointPolicyConfig activated/modified: bundleId=[{}], pid=[{}], loadedPolicies={}, rules={}",
                bundleId, configPid, this.parsedRules.size(), this.parsedRules);
        notifyModificationListener();
    }

    /**
     * 테스트 또는 직접 로드를 위해 프로퍼티 맵만으로 설정을 초기화합니다.
     *
     * @param properties {@code .cfg.json}에서 파싱된 프로퍼티 맵
     */
    public void activateFromProperties(final Map<String, Object> properties) {
        activate(null, properties);
    }

    /**
     * {@code .cfg.json} 파일의 JSON 문자열을 파싱하여 {@link EndpointPolicyConfig} 인스턴스를 생성합니다.
     *
     * @param factoryAlias 파일명 {@code ~별칭} 또는 번들 식별자 (예: {@code "core-member"})
     * @param jsonContent  {@code .cfg.json} 파일 내용 문자열
     * @return 초기화된 {@link EndpointPolicyConfig} 객체
     */
    public static EndpointPolicyConfig fromCfgJson(final String factoryAlias, final String jsonContent) {
        Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
        Map<String, Object> rawMap = GSON.fromJson(jsonContent, mapType);
        if (rawMap == null) {
            rawMap = new LinkedHashMap<>();
        }
        if (StringUtils.isNotBlank(factoryAlias) && !rawMap.containsKey("service.pid")) {
            rawMap.put("service.pid", "com.example.security.registry.EndpointPolicyConfig~" + factoryAlias.trim());
        }
        EndpointPolicyConfig instance = new EndpointPolicyConfig();
        instance.activateFromProperties(rawMap);
        return instance;
    }

    private static List<Object> extractPolicyEntries(final Config config, final Map<String, Object> props) {
        List<Object> result = new ArrayList<>();
        Object raw = props.get("policies");
        if (raw == null) {
            raw = props.get("security.policies");
        }
        if (raw instanceof Object[]) {
            for (Object item : (Object[]) raw) {
                if (item != null) {
                    result.add(item);
                }
            }
            return result;
        } else if (raw instanceof Iterable<?>) {
            for (Object item : (Iterable<?>) raw) {
                if (item != null) {
                    result.add(item);
                }
            }
            return result;
        } else if (raw instanceof String && StringUtils.isNotBlank((String) raw)) {
            String trimmed = ((String) raw).trim();
            if (trimmed.startsWith("[")) {
                Type listType = new TypeToken<List<Map<String, Object>>>() {}.getType();
                List<Map<String, Object>> parsedList = GSON.fromJson(trimmed, listType);
                if (parsedList != null) {
                    result.addAll(parsedList);
                    return result;
                }
            }
            result.add(trimmed);
            return result;
        }

        if (config != null && config.policies() != null && config.policies().length > 0) {
            for (String s : config.policies()) {
                if (StringUtils.isNotBlank(s)) {
                    result.add(s.trim());
                }
            }
        }
        return result;
    }

    private static String resolveConfigPid(final Map<String, Object> props) {
        for (String key : new String[]{"service.pid", "component.name"}) {
            Object val = props.get(key);
            if (val != null && StringUtils.isNotBlank(val.toString())) {
                return val.toString().trim();
            }
        }
        return "";
    }

    private static String resolveBundleId(final Config config, final Map<String, Object> props, final String pid) {
        if (config != null && StringUtils.isNotBlank(config.bundle_id())) {
            return config.bundle_id().trim();
        }
        for (String key : new String[]{"bundle.id", "bundle_id", "bundleId"}) {
            Object val = props.get(key);
            if (val != null && StringUtils.isNotBlank(val.toString())) {
                return val.toString().trim();
            }
        }
        if (StringUtils.isNotBlank(pid)) {
            int tildeIdx = pid.indexOf('~');
            if (tildeIdx >= 0 && tildeIdx + 1 < pid.length()) {
                return pid.substring(tildeIdx + 1).trim();
            }
            return pid;
        }
        return "default-bundle";
    }

    /**
     * 이 번들 설정 파일의 활성화 여부를 반환합니다.
     *
     * @return 활성화 시 true
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 이 설정 파일의 번들/도메인 식별자(예: {@code "core-member"})를 반환합니다.
     *
     * @return 번들 식별자 문자열
     */
    public String getBundleId() {
        return bundleId;
    }

    /**
     * OSGi Configuration PID를 반환합니다.
     *
     * @return OSGi Configuration PID 문자열
     */
    public String getConfigPid() {
        return configPid;
    }

    /**
     * 이 번들 설정 파일에서 파싱된 서블릿 보안 정책 목록(읽기 전용)을 반환합니다.
     *
     * @return {@link ServletPolicyRule} 리스트
     */
    public List<ServletPolicyRule> getParsedRules() {
        return parsedRules;
    }
}
