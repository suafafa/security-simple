package com.example.security.models;

import com.example.security.filters.SecurityFilter;
import com.example.security.registry.EndpointPolicyConfig;
import com.example.security.registry.EndpointPolicyRegistryImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class IgnoreServletPoliciesTest {

    @Mock
    private HttpServletRequest request;

    private ServletSecurityConfig config;
    private ServletPolicyRule defaultPolicy;
    private ServletPolicyRule servletPolicy;

    @BeforeEach
    void setUp() {
        config = new ServletSecurityConfig();

        defaultPolicy = new ServletPolicyRule();
        defaultPolicy.setTarget("DEFAULT");
        defaultPolicy.setDefaultReferrer("abc.com");
        config.setDefaultPolicy(defaultPolicy);

        servletPolicy = new ServletPolicyRule();
        servletPolicy.setTarget("/aemapi/user/contact");
        servletPolicy.setDefaultReferrer("custom.com");
        config.registerPolicy(servletPolicy);
    }

    @Test
    @DisplayName("ignoreServletPolicies=false(기본)일 때 개별 서블릿 정책 우선 매칭")
    void testNormalServletMatchingWhenIgnoreFalse() {
        when(request.getRequestURI()).thenReturn("/aemapi/user/contact");

        config.setIgnoreServletPolicies(false);
        ServletPolicyRule matched = config.findMatchingPolicy(request);

        assertNotNull(matched);
        assertEquals("/aemapi/user/contact", matched.getTarget());
        assertEquals("custom.com", matched.getDefaultReferrer());
    }

    @Test
    @DisplayName("ignoreServletPolicies=true일 때 서블릿 정책 무시하고 글로벌 defaultPolicy 강제 적용")
    void testGlobalPolicyEnforcedWhenIgnoreTrue() {
        when(request.getRequestURI()).thenReturn("/aemapi/user/contact");

        config.setIgnoreServletPolicies(true);
        ServletPolicyRule matched = config.findMatchingPolicy(request);

        assertNotNull(matched);
        assertEquals("DEFAULT", matched.getTarget());
        assertEquals("abc.com", matched.getDefaultReferrer());
    }

    @Test
    @DisplayName("SecurityFilter: EndpointPolicyRegistry(.cfg.json)는 정상 동기화되지만, ignoreServletPolicies=true 시 defaultPolicy 강제")
    void testRegistrySyncedButEvaluationEnforcesDefaultPolicy() {
        SecurityFilter filter = new SecurityFilter();
        ServletSecurityConfig secConfig = new ServletSecurityConfig();
        secConfig.setDefaultPolicy(defaultPolicy);
        secConfig.setIgnoreServletPolicies(true);

        try {
            java.lang.reflect.Field f = SecurityFilter.class.getDeclaredField("servletSecurityConfig");
            f.setAccessible(true);
            f.set(filter, secConfig);
        } catch (Exception e) {
            fail("Reflection setup failed: " + e.getMessage());
        }

        EndpointPolicyRegistryImpl registry = new EndpointPolicyRegistryImpl();
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-member\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/user/test\",\n" +
                "      \"defaultReferrer\": \"custom.com\",\n" +
                "      \"methods\": [\"POST\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        EndpointPolicyConfig policyCfg = EndpointPolicyConfig.fromCfgJson("core-member", json);
        registry.bindPolicyConfig(policyCfg, Collections.singletonMap("service.pid", policyCfg.getConfigPid()));
        filter.bindPolicyRegistry(registry);

        // 1. 레지스트리 정책은 정상 등록됨 (설정 토글 지원을 위해 보존)
        assertNotNull(secConfig.getPolicy("/aemapi/user/test"));

        // 2. 그러나 실제 요청 시에는 ignoreServletPolicies=true이므로 defaultPolicy만 반환됨
        when(request.getRequestURI()).thenReturn("/aemapi/user/test");
        ServletPolicyRule evaluated = secConfig.findMatchingPolicy(request);
        assertEquals("DEFAULT", evaluated.getTarget());
        assertEquals("abc.com", evaluated.getDefaultReferrer());
    }
}
