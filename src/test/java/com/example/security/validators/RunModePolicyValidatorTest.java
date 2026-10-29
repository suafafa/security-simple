package com.example.security.validators;

import com.example.security.filters.SecurityFilter;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.registry.EndpointPolicyConfig;
import com.example.security.registry.EndpointPolicyRegistryImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RunModePolicyValidatorTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private SecurityFilter securityFilter;
    private EndpointPolicyRegistryImpl registry;
    private RunModePolicyValidator runModeValidator;

    @BeforeEach
    void setUp() {
        registry = new EndpointPolicyRegistryImpl();
        securityFilter = new SecurityFilter();
        securityFilter.activate(null);
        securityFilter.bindPolicyRegistry(registry);

        runModeValidator = new RunModePolicyValidator();
        // OSGi 동적 바인딩과 동일하게 bindValidator로 주입
        securityFilter.bindValidator(runModeValidator);
    }

    @Test
    @DisplayName("OSGi 동적 바인딩 시 getOrder() 우선순위(RUNMODE=5 -> REFERER=10 -> METHOD=20 -> PARAM=30)대로 자동 정렬 검증")
    void testValidatorOrderingAndAutoRegistration() {
        List<PolicyValidator> validators = securityFilter.getValidators();
        assertEquals(4, validators.size());
        assertEquals("RUNMODE", validators.get(0).getName());
        assertEquals("REFERER", validators.get(1).getName());
        assertEquals("METHOD", validators.get(2).getName());
        assertEquals("PARAM", validators.get(3).getName());
    }

    @Test
    @DisplayName(".cfg.json에 정의된 runModes 및 blockedRunModes 확장 속성이 ServletPolicyRule 수정 없이 자동 파싱 및 검증되는지 확인")
    void testRunModeValidationFromCfgJson() throws Exception {
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-admin\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/admin/reindex\",\n" +
                "      \"runModes\": [\"author\", \"dev\"],\n" +
                "      \"blockedRunModes\": [\"prod\"],\n" +
                "      \"methods\": [\"POST\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        EndpointPolicyConfig adminConfig = EndpointPolicyConfig.fromCfgJson("core-admin", json);
        registry.bindPolicyConfig(adminConfig, Collections.singletonMap("service.pid", adminConfig.getConfigPid()));

        when(request.getRequestURI()).thenReturn("/aemapi/admin/reindex");
        ServletSecurityConfig rootConfig = securityFilter.getServletSecurityConfig();
        ServletPolicyRule rule = rootConfig.findMatchingPolicy(request);
        assertNotNull(rule);

        // 1. 현재 RunMode가 [author, dev] 일 때 -> 통과
        runModeValidator.setActiveRunModes(new HashSet<>(Arrays.asList("author", "dev")));
        ValidationResult passResult = runModeValidator.validate(request, rule, rootConfig);
        assertTrue(passResult.isValid());

        // 2. 현재 RunMode가 [publish, stage] 일 때 (allowedRunModes 미일치) -> 차단 (403, SEC-40305)
        runModeValidator.setActiveRunModes(new HashSet<>(Arrays.asList("publish", "stage")));
        ValidationResult failAllowed = runModeValidator.validate(request, rule, rootConfig);
        assertFalse(failAllowed.isValid());
        assertEquals(403, failAllowed.getStatusCode());
        assertEquals("SEC-40305", failAllowed.getSubCode());

        // 3. 현재 RunMode가 [author, prod] 일 때 (author는 허용이지만 prod가 blockedRunModes에 포함됨) -> 차단
        runModeValidator.setActiveRunModes(new HashSet<>(Arrays.asList("author", "prod")));
        ValidationResult failBlocked = runModeValidator.validate(request, rule, rootConfig);
        assertFalse(failBlocked.isValid());
        assertEquals(403, failBlocked.getStatusCode());
        assertEquals("SEC-40305", failBlocked.getSubCode());
    }

    @Test
    @DisplayName("SecurityFilter 전체 체인 실행 시 RunMode 위반 요청이 가장 먼저 403 SEC-40305로 차단되는지 검증")
    void testSecurityFilterBlocksDisallowedRunModeInFilterChain() throws Exception {
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-debug\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/debug/env\",\n" +
                "      \"runModes\": [\"author\", \"dev\"],\n" +
                "      \"methods\": [\"GET\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        EndpointPolicyConfig debugConfig = EndpointPolicyConfig.fromCfgJson("core-debug", json);
        registry.bindPolicyConfig(debugConfig, Collections.singletonMap("service.pid", debugConfig.getConfigPid()));

        // 현재 인스턴스가 publish, prod 인 상황 시뮬레이션
        runModeValidator.setActiveRunModes(new HashSet<>(Arrays.asList("publish", "prod")));

        when(request.getRequestURI()).thenReturn("/aemapi/debug/env");
        when(request.getMethod()).thenReturn("GET");
        StringWriter bodyWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(bodyWriter));

        securityFilter.doFilter(request, response, filterChain);

        verify(response).setStatus(403);
        verify(filterChain, never()).doFilter(request, response);
        assertTrue(bodyWriter.toString().contains("SEC-40305"));
    }

    @Test
    @DisplayName("AbstractPolicyValidator 상속만으로 10줄 내외의 초간단 커스텀 Validator를 즉석 추가·동작하는지 검증")
    void testCustomLambdaStyleValidatorAddition() {
        PolicyValidator customHeaderValidator = new AbstractPolicyValidator("API_KEY", 15) {
            @Override
            protected ValidationResult doValidate(HttpServletRequest req, ServletPolicyRule policy, ServletSecurityConfig root) {
                String requiredHeader = policy.getExtensionString("requiredHeader");
                if (requiredHeader != null && req.getHeader(requiredHeader) == null) {
                    return blockCustom(policy, 401, "SEC-40101",
                            "requiredHeader=" + requiredHeader,
                            "Missing required header: " + requiredHeader,
                            "Unauthorized: Missing header " + requiredHeader);
                }
                return pass();
            }
        };

        securityFilter.bindValidator(customHeaderValidator);

        ServletPolicyRule rule = new ServletPolicyRule();
        rule.setTarget("/aemapi/partner/sync");
        rule.putExtension("requiredHeader", "X-Partner-Key");
        rule.init();

        // 헤더 누락 시 401 SEC-40101 차단
        ValidationResult blocked = customHeaderValidator.validate(request, rule, securityFilter.getServletSecurityConfig());
        assertFalse(blocked.isValid());
        assertEquals(401, blocked.getStatusCode());
        assertEquals("SEC-40101", blocked.getSubCode());

        // 헤더 포함 시 통과
        when(request.getHeader("X-Partner-Key")).thenReturn("secret-token");
        ValidationResult passed = customHeaderValidator.validate(request, rule, securityFilter.getServletSecurityConfig());
        assertTrue(passed.isValid());

        securityFilter.unbindValidator(customHeaderValidator);
    }
}
