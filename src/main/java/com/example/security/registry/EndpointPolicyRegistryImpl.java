package com.example.security.registry;

import com.example.security.models.ServletPolicyRule;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * {@link EndpointPolicyConfig} Factory Configuration 인스턴스들을 동적으로 바인딩하여
 * 등록된 {@code .cfg.json} 파일들의 서블릿 보안 정책만 중앙에서 통합 관리하는 OSGi 컴포넌트입니다.
 * <p>
 * 핵심 동작:
 * <ul>
 *   <li>{@code bindPolicyConfig}: 새 {@code .cfg.json} 파일 추가 시 자동 호출</li>
 *   <li>{@code updatedPolicyConfig}: 운영 중 특정 {@code .cfg.json} 파일 수정 시 재기동 없이 자동 호출</li>
 *   <li>{@code unbindPolicyConfig}: {@code .cfg.json} 파일 삭제 시 자동 호출</li>
 * </ul>
 */
@Component(
        service = EndpointPolicyRegistry.class,
        immediate = true,
        property = {
                "service.description=AEM Endpoint Security Policy Registry (Bundle .cfg.json Collector)",
                "service.vendor=AEM Engineering"
        }
)
public class EndpointPolicyRegistryImpl implements EndpointPolicyRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(EndpointPolicyRegistryImpl.class);

    // 바인딩된 Factory Config 인스턴스별 키 매핑 (인스턴스 해시/PID -> EndpointPolicyConfig)
    private final Map<EndpointPolicyConfig, String> configInstanceKeys = new ConcurrentHashMap<>();
    private final Map<String, EndpointPolicyConfig> boundConfigsByKey = new ConcurrentHashMap<>();

    // 실시간 재구성되는 불변 스냅샷 캐시
    private volatile List<ServletPolicyRule> activePolicies = Collections.emptyList();
    private volatile Map<String, ServletPolicyRule> policiesByTarget = Collections.emptyMap();
    private volatile Map<String, String> sourceByTarget = Collections.emptyMap();
    private volatile Map<String, List<ServletPolicyRule>> policiesByBundle = Collections.emptyMap();

    // SecurityFilter 등 상위 컴포넌트에 실시간 정책 변경을 알리는 리스너 목록
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    /**
     * OSGi 컨테이너에서 {@link EndpointPolicyConfig}({@code .cfg.json})가 등록될 때 호출됩니다.
     *
     * @param config     바인딩된 번들 정책 설정 컴포넌트
     * @param properties OSGi 서비스 프로퍼티 맵
     */
    @Reference(
            service = EndpointPolicyConfig.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            bind = "bindPolicyConfig",
            unbind = "unbindPolicyConfig",
            updated = "updatedPolicyConfig"
    )
    public void bindPolicyConfig(final EndpointPolicyConfig config, final Map<String, Object> properties) {
        if (config == null) {
            return;
        }
        String key = resolveConfigKey(config, properties);
        configInstanceKeys.put(config, key);
        boundConfigsByKey.put(key, config);

        LOG.info("Bound EndpointPolicyConfig [key={}, bundleId={}, policies={}]",
                key, config.getBundleId(), config.getParsedRules().size());
        rebuildActivePolicyCache();
    }

    /**
     * 운영 중 특정 {@code .cfg.json} 파일 내용이 변경되었을 때 OSGi가 자동으로 호출하는 콜백입니다.
     *
     * @param config     수정된 번들 정책 설정 컴포넌트
     * @param properties 변경된 OSGi 서비스 프로퍼티 맵
     */
    public void updatedPolicyConfig(final EndpointPolicyConfig config, final Map<String, Object> properties) {
        if (config == null) {
            return;
        }
        String oldKey = configInstanceKeys.get(config);
        String newKey = resolveConfigKey(config, properties);
        if (oldKey != null && !oldKey.equals(newKey)) {
            boundConfigsByKey.remove(oldKey);
        }
        configInstanceKeys.put(config, newKey);
        boundConfigsByKey.put(newKey, config);

        LOG.info("Updated EndpointPolicyConfig [key={}, bundleId={}, policies={}]",
                newKey, config.getBundleId(), config.getParsedRules().size());
        rebuildActivePolicyCache();
    }

    /**
     * {@code .cfg.json} 파일이 삭제되거나 번들 설정 컴포넌트가 비활성화될 때 OSGi가 자동으로 호출하는 콜백입니다.
     *
     * @param config     언바인딩된 번들 정책 설정 컴포넌트
     * @param properties OSGi 서비스 프로퍼티 맵
     */
    public void unbindPolicyConfig(final EndpointPolicyConfig config, final Map<String, Object> properties) {
        if (config == null) {
            return;
        }
        String key = configInstanceKeys.remove(config);
        if (key == null) {
            key = resolveConfigKey(config, properties);
        }
        boundConfigsByKey.remove(key);

        LOG.info("Unbound EndpointPolicyConfig [key={}, bundleId={}]", key, config.getBundleId());
        rebuildActivePolicyCache();
    }

    /**
     * 바인딩된 모든 {@link EndpointPolicyConfig} 인스턴스의 정책들을 취합하여
     * 스레드 안전한 불변 캐시를 재구성하고 변경 리스너들에게 즉시 알립니다.
     * 서로 다른 번들 설정 파일 간에 동일한 {@code target} 경로가 중복 정의된 경우 경고 로그를 출력합니다.
     */
    public synchronized void rebuildActivePolicyCache() {
        Map<String, ServletPolicyRule> targetRuleMap = new LinkedHashMap<>();
        Map<String, String> targetSourceMap = new LinkedHashMap<>();
        Map<String, List<ServletPolicyRule>> bundleMap = new LinkedHashMap<>();

        for (EndpointPolicyConfig cfg : boundConfigsByKey.values()) {
            if (cfg == null || !cfg.isEnabled()) {
                continue;
            }
            String bundleId = StringUtils.defaultIfBlank(cfg.getBundleId(), "default-bundle");
            String sourceLabel = "EndpointPolicyConfig~" + bundleId;
            List<ServletPolicyRule> rules = cfg.getParsedRules();
            if (rules == null || rules.isEmpty()) {
                continue;
            }

            List<ServletPolicyRule> bundleList = bundleMap.computeIfAbsent(bundleId, k -> new ArrayList<>());
            for (ServletPolicyRule rule : rules) {
                if (rule == null || StringUtils.isBlank(rule.getTarget())) {
                    continue;
                }
                String targetKey = rule.getTarget().trim();
                String existingSource = targetSourceMap.get(targetKey);
                if (existingSource != null && !existingSource.equals(sourceLabel)) {
                    LOG.warn("Duplicate endpoint policy target [{}] detected! Overriding previous policy from [{}] with [{}].",
                            targetKey, existingSource, sourceLabel);
                }
                // 원본 규칙 오염 방지를 위해 복사본 보관
                ServletPolicyRule copy = new ServletPolicyRule();
                copy.copyFrom(rule);
                copy.init();

                targetRuleMap.put(targetKey, copy);
                targetSourceMap.put(targetKey, sourceLabel);
                bundleList.add(copy);
            }
        }

        Map<String, List<ServletPolicyRule>> immutableBundleMap = new LinkedHashMap<>();
        for (Map.Entry<String, List<ServletPolicyRule>> entry : bundleMap.entrySet()) {
            immutableBundleMap.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }

        this.activePolicies = Collections.unmodifiableList(new ArrayList<>(targetRuleMap.values()));
        this.policiesByTarget = Collections.unmodifiableMap(targetRuleMap);
        this.sourceByTarget = Collections.unmodifiableMap(targetSourceMap);
        this.policiesByBundle = Collections.unmodifiableMap(immutableBundleMap);

        notifyChangeListeners();
    }

    private void notifyChangeListeners() {
        for (Runnable listener : changeListeners) {
            try {
                listener.run();
            } catch (Exception e) {
                LOG.error("Error notifying EndpointPolicyRegistry change listener: {}", e.getMessage(), e);
            }
        }
    }

    private static String resolveConfigKey(final EndpointPolicyConfig config, final Map<String, Object> properties) {
        if (properties != null) {
            for (String k : new String[]{"service.pid", "component.name", "service.id"}) {
                Object val = properties.get(k);
                if (val != null && StringUtils.isNotBlank(val.toString())) {
                    return val.toString().trim();
                }
            }
        }
        if (StringUtils.isNotBlank(config.getConfigPid())) {
            return config.getConfigPid();
        }
        if (StringUtils.isNotBlank(config.getBundleId())) {
            return "bundle:" + config.getBundleId();
        }
        return "instance:" + System.identityHashCode(config);
    }

    @Deactivate
    protected void deactivate() {
        configInstanceKeys.clear();
        boundConfigsByKey.clear();
        activePolicies = Collections.emptyList();
        policiesByTarget = Collections.emptyMap();
        sourceByTarget = Collections.emptyMap();
        policiesByBundle = Collections.emptyMap();
        changeListeners.clear();
        LOG.info("EndpointPolicyRegistryImpl deactivated.");
    }

    @Override
    public List<ServletPolicyRule> getAllPolicies() {
        return activePolicies;
    }

    @Override
    public ServletPolicyRule getPolicy(final String target) {
        if (StringUtils.isBlank(target)) {
            return null;
        }
        String trimmed = target.trim();
        ServletPolicyRule exact = policiesByTarget.get(trimmed);
        if (exact != null) {
            return exact;
        }
        for (Map.Entry<String, ServletPolicyRule> entry : policiesByTarget.entrySet()) {
            if (trimmed.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    @Override
    public String getPolicySource(final String target) {
        if (StringUtils.isBlank(target)) {
            return null;
        }
        String trimmed = target.trim();
        String source = sourceByTarget.get(trimmed);
        if (source != null) {
            return source;
        }
        for (Map.Entry<String, String> entry : sourceByTarget.entrySet()) {
            if (trimmed.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    @Override
    public Map<String, List<ServletPolicyRule>> getPoliciesByBundle() {
        return policiesByBundle;
    }

    @Override
    public void addChangeListener(final Runnable listener) {
        if (listener != null && !changeListeners.contains(listener)) {
            changeListeners.add(listener);
        }
    }

    @Override
    public void removeChangeListener(final Runnable listener) {
        if (listener != null) {
            changeListeners.remove(listener);
        }
    }
}
