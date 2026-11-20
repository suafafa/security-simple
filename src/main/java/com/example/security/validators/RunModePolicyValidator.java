package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.settings.SlingSettingsService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * AEM 인스턴스의 현재 활성 RunMode(예: {@code author}, {@code publish}, {@code dev}, {@code stage}, {@code prod})를
 * 확인하여 서블릿 엔드포인트 접근을 허용하거나 차단하는 모듈형 검증기 예제입니다.
 * <p>
 * <b>플러그인 아키텍처 특징:</b>
 * <ul>
 *   <li>{@link AbstractPolicyValidator}를 상속하고 {@code @Component(service = PolicyValidator.class)}를 선언하여
 *       {@code SecurityFilter} 수정 없이 자동으로 검증 체인(순서: 5)에 등록됩니다.</li>
 *   <li>{@link ServletPolicyRule#getExtensionLowerSet(String...)}을 사용하여 {@code ServletPolicyRule} 모델 수정 없이
 *       {@code .cfg.json}의 {@code "runModes"} (또는 {@code "allowedRunModes"}) 설정과 {@code "blockedRunModes"} 설정을 즉시 읽어옵니다.</li>
 * </ul>
 * <p>
 * <b>{@code .cfg.json} 설정 예시:</b>
 * <pre>
 * {
 *   "target": "/aemapi/admin/reindex",
 *   "runModes": ["author", "dev"],
 *   "blockedRunModes": ["publish", "prod"],
 *   "methods": ["POST"]
 * }
 * </pre>
 */
@Component(service = PolicyValidator.class, immediate = true)
public class RunModePolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "RUNMODE";
    public static final int ORDER = 5;

    private static final String[] ALLOWED_RUNMODE_KEYS = {
            "runModes", "allowedRunModes"
    };
    private static final String[] BLOCKED_RUNMODE_KEYS = {
            "blockedRunModes"
    };

    @Reference(
            service = SlingSettingsService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            policyOption = ReferencePolicyOption.GREEDY
    )
    private volatile SlingSettingsService slingSettings;

    // 단위 테스트 또는 로컬 환경에서 직접 RunMode를 주입할 수 있는 오버라이드 집합
    private volatile Set<String> customActiveRunModes;

    /** 기본 생성자입니다 (식별자: "RUNMODE", 실행 순서: 5). */
    public RunModePolicyValidator() {
        super(NAME, ORDER);
    }

    /**
     * 현재 AEM 인스턴스의 RunMode가 서블릿 정책의 {@code runModes}(허용) 및 {@code blockedRunModes}(차단) 조건을 충족하는지 검증합니다.
     */
    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return pass();
        }

        Set<String> allowedRunModes = policy.getExtensionLowerSet(ALLOWED_RUNMODE_KEYS);
        Set<String> blockedRunModes = policy.getExtensionLowerSet(BLOCKED_RUNMODE_KEYS);

        // 정책에 runModes 및 blockedRunModes 제약이 모두 없으면 즉시 통과
        if (allowedRunModes.isEmpty() && blockedRunModes.isEmpty()) {
            return pass();
        }

        Set<String> activeRunModes = resolveActiveRunModes();

        // 1. 차단 대상 RunMode(blockedRunModes)에 현재 RunMode가 하나라도 포함(대소문자 무시)되면 즉시 차단
        if (!blockedRunModes.isEmpty()) {
            for (String blocked : blockedRunModes) {
                if (containsIgnoreCase(activeRunModes, blocked)) {
                    String blockedConfig = "blockedRunModes=" + blockedRunModes + ", activeRunModes=" + activeRunModes;
                    return block(
                            policy,
                            SecurityErrorCode.RUNMODE_NOT_ALLOWED,
                            blockedConfig,
                            "Endpoint [" + SecurityUtils.sanitizeForLog(policy.getTarget())
                                    + "] is blocked in runmode [" + blocked + "] (activeRunModes=" + activeRunModes + ")"
                    );
                }
            }
        }

        // 2. 허용 대상 RunMode(allowedRunModes)가 지정된 경우, 현재 RunMode와 최소 1개 이상 일치(대소문자 무시)해야 통과
        if (!allowedRunModes.isEmpty()) {
            boolean matched = false;
            for (String allowed : allowedRunModes) {
                if (containsIgnoreCase(activeRunModes, allowed)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                String blockedConfig = "allowedRunModes=" + allowedRunModes + ", activeRunModes=" + activeRunModes;
                return block(
                        policy,
                        SecurityErrorCode.RUNMODE_NOT_ALLOWED,
                        blockedConfig,
                        "Endpoint [" + SecurityUtils.sanitizeForLog(policy.getTarget())
                                + "] requires one of runModes " + allowedRunModes + ", but activeRunModes=" + activeRunModes
                );
            }
        }

        return pass();
    }

    /**
     * 문자열 집합 내에 대상 문자열이 대소문자 구분 없이 포함되어 있는지 확인합니다.
     */
    private static boolean containsIgnoreCase(final Set<String> set, final String target) {
        if (set == null || set.isEmpty() || StringUtils.isBlank(target)) {
            return false;
        }
        String trimmedTarget = target.trim();
        if (set.contains(trimmedTarget.toLowerCase())) {
            return true;
        }
        for (String item : set) {
            if (item != null && item.trim().equalsIgnoreCase(trimmedTarget)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 현재 AEM 인스턴스의 활성 RunMode 집합(소문자)을 조회합니다.
     * 우선순위:
     * 1. {@link #setActiveRunModes(Set)}로 직접 설정된 RunMode
     * 2. OSGi {@link SlingSettingsService#getRunModes()}
     * 3. JVM 시스템 프로퍼티 {@code sling.run.modes} (쉼표 구분)
     *
     * @return 소문자 RunMode 집합
     */
    public Set<String> resolveActiveRunModes() {
        Set<String> custom = this.customActiveRunModes;
        if (custom != null) {
            return custom;
        }

        SlingSettingsService settings = this.slingSettings;
        if (settings != null && settings.getRunModes() != null) {
            Set<String> lower = new LinkedHashSet<>();
            for (String rm : settings.getRunModes()) {
                if (StringUtils.isNotBlank(rm)) {
                    lower.add(rm.trim().toLowerCase());
                }
            }
            return Collections.unmodifiableSet(lower);
        }

        String sysProp = System.getProperty("sling.run.modes");
        if (StringUtils.isNotBlank(sysProp)) {
            Set<String> lower = new LinkedHashSet<>();
            for (String part : sysProp.split(",")) {
                if (StringUtils.isNotBlank(part)) {
                    lower.add(part.trim().toLowerCase());
                }
            }
            return Collections.unmodifiableSet(lower);
        }

        return Collections.emptySet();
    }

    /**
     * 단위 테스트 또는 커스텀 환경을 위해 활성 RunMode 집합을 직접 설정합니다.
     *
     * @param runModes 활성 RunMode 집합 (null 전달 시 OSGi/시스템 프로퍼티 모드로 복귀)
     */
    public void setActiveRunModes(final Set<String> runModes) {
        if (runModes == null) {
            this.customActiveRunModes = null;
            return;
        }
        Set<String> lower = new LinkedHashSet<>();
        for (String rm : runModes) {
            if (StringUtils.isNotBlank(rm)) {
                lower.add(rm.trim().toLowerCase());
            }
        }
        this.customActiveRunModes = Collections.unmodifiableSet(lower);
    }
}
