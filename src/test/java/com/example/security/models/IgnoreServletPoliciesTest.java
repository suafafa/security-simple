package com.example.security.models;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;

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
        config.registerDynamicPolicy(servletPolicy);
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
}
