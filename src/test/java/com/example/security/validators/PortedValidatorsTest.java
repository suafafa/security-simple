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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class PortedValidatorsTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpSession session;

    private SecurityFilter securityFilter;
    private EndpointPolicyRegistryImpl registry;

    @BeforeEach
    void setUp() {
        registry = new EndpointPolicyRegistryImpl();
        securityFilter = new SecurityFilter();
        securityFilter.activate(null);
        securityFilter.bindPolicyRegistry(registry);
    }

    @Test
    @DisplayName("1. AuthPolicyValidator: .cfg.json의 auth 및 roles 확장 속성 기반 인증/권한 검증")
    void testAuthPolicyValidator() {
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-auth\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/admin/users\",\n" +
                "      \"auth\": \"AEM_USER\",\n" +
                "      \"roles\": [\"administrators\", \"authors\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        EndpointPolicyConfig cfg = EndpointPolicyConfig.fromCfgJson("core-auth", json);
        registry.bindPolicyConfig(cfg, Collections.singletonMap("service.pid", cfg.getConfigPid()));

        when(request.getRequestURI()).thenReturn("/aemapi/admin/users");
        ServletSecurityConfig rootConfig = securityFilter.getServletSecurityConfig();
        ServletPolicyRule rule = rootConfig.findMatchingPolicy(request);
        AuthPolicyValidator validator = new AuthPolicyValidator();

        // 1) 비로그인(anonymous) 요청 -> 401 SEC-40101 차단
        when(request.getRemoteUser()).thenReturn(null);
        ValidationResult anonResult = validator.validate(request, rule, rootConfig);
        assertFalse(anonResult.isValid());
        assertEquals(401, anonResult.getStatusCode());
        assertEquals("SEC-40101", anonResult.getSubCode());

        // 2) 일반 SA_USER 로그인 요청 -> 403 SEC-40301 차단
        when(request.getRemoteUser()).thenReturn("customer01");
        ValidationResult saUserResult = validator.validate(request, rule, rootConfig);
        assertFalse(saUserResult.isValid());
        assertEquals(403, saUserResult.getStatusCode());
        assertEquals("SEC-40301", saUserResult.getSubCode());

        // 3) AEM_USER이나 요구된 그룹(roles)이 없는 경우 -> 403 SEC-40302 차단
        when(request.getRemoteUser()).thenReturn("aem-viewer");
        ValidationResult noRoleResult = validator.validate(request, rule, rootConfig);
        assertFalse(noRoleResult.isValid());
        assertEquals(403, noRoleResult.getStatusCode());
        assertEquals("SEC-40302", noRoleResult.getSubCode());

        // 4) AEM_USER이면서 authors 그룹에 속한 경우 -> 200 통과
        when(request.isUserInRole("authors")).thenReturn(true);
        ValidationResult passResult = validator.validate(request, rule, rootConfig);
        assertTrue(passResult.isValid());
    }

    @Test
    @DisplayName("2. CsrfPolicyValidator: TOKEN, GRANITE, OAUTH_STATE 검증")
    void testCsrfPolicyValidator() {
        CsrfPolicyValidator validator = new CsrfPolicyValidator();
        ServletSecurityConfig rootConfig = securityFilter.getServletSecurityConfig();

        // TOKEN 모드 검증
        ServletPolicyRule tokenRule = new ServletPolicyRule();
        tokenRule.setTarget("/aemapi/user/update");
        tokenRule.putExtension("csrf", "TOKEN");
        tokenRule.init();

        ValidationResult missingToken = validator.validate(request, tokenRule, rootConfig);
        assertFalse(missingToken.isValid());
        assertEquals(403, missingToken.getStatusCode());
        assertEquals("SEC-40304", missingToken.getSubCode());

        when(request.getHeader("X-CSRF-Token")).thenReturn("valid-csrf-token-12345");
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("CSRF_TOKEN")).thenReturn("different-token");
        ValidationResult mismatchToken = validator.validate(request, tokenRule, rootConfig);
        assertFalse(mismatchToken.isValid());
        assertEquals("SEC-40306", mismatchToken.getSubCode());

        when(session.getAttribute("CSRF_TOKEN")).thenReturn("valid-csrf-token-12345");
        assertTrue(validator.validate(request, tokenRule, rootConfig).isValid());
    }

    @Test
    @DisplayName("3. RateLimitPolicyValidator: 슬라이딩 윈도우 기반 요청 빈도 제한(429 SEC-42901) 검증")
    void testRateLimitPolicyValidator() {
        RateLimitPolicyValidator validator = new RateLimitPolicyValidator();
        ServletPolicyRule rule = new ServletPolicyRule();
        rule.setTarget("/aemapi/public/otp");
        rule.putExtension("rateLimit", 2);
        rule.putExtension("rateLimitWindow", 60);
        rule.putExtension("rateLimitKey", "IP_TARGET");
        rule.init();

        when(request.getRemoteAddr()).thenReturn("203.0.113.10");

        assertTrue(validator.validate(request, rule, null).isValid());
        assertTrue(validator.validate(request, rule, null).isValid());

        // 3번째 요청 시 한도(2회) 초과 -> 429 SEC-42901 차단
        ValidationResult exceeded = validator.validate(request, rule, null);
        assertFalse(exceeded.isValid());
        assertEquals(429, exceeded.getStatusCode());
        assertEquals("SEC-42901", exceeded.getSubCode());
    }

    @Test
    @DisplayName("4. PayloadSizePolicyValidator: maxPayloadSize(예: 1KB) 초과 시 413 SEC-41301 차단 검증")
    void testPayloadSizePolicyValidator() {
        PayloadSizePolicyValidator validator = new PayloadSizePolicyValidator();
        ServletPolicyRule rule = new ServletPolicyRule();
        rule.setTarget("/aemapi/upload/avatar");
        rule.putExtension("maxPayloadSize", "1KB");
        rule.init();

        when(request.getMethod()).thenReturn("POST");
        when(request.getContentLengthLong()).thenReturn(512L);
        assertTrue(validator.validate(request, rule, null).isValid());

        when(request.getContentLengthLong()).thenReturn(2048L);
        ValidationResult tooLarge = validator.validate(request, rule, null);
        assertFalse(tooLarge.isValid());
        assertEquals(413, tooLarge.getStatusCode());
        assertEquals("SEC-41301", tooLarge.getSubCode());
    }

    @Test
    @DisplayName("5. OpenRedirectPolicyValidator: 외부 악성 도메인 및 스키마 리다이렉트(400 SEC-40010) 차단 검증")
    void testOpenRedirectPolicyValidator() {
        OpenRedirectPolicyValidator validator = new OpenRedirectPolicyValidator();
        ServletPolicyRule rule = new ServletPolicyRule();
        rule.setTarget("/aemapi/auth/login");
        rule.putExtension("allowedRedirectDomains", Collections.singletonList("*.abc.com"));
        rule.init();

        Map<String, String[]> params = new HashMap<>();
        params.put("redirect", new String[]{"https://evil.com/phishing"});
        when(request.getParameterMap()).thenReturn(params);

        ValidationResult blocked = validator.validate(request, rule, securityFilter.getServletSecurityConfig());
        assertFalse(blocked.isValid());
        assertEquals(400, blocked.getStatusCode());
        assertEquals("SEC-40010", blocked.getSubCode());

        params.put("redirect", new String[]{"https://login.abc.com/welcome"});
        assertTrue(validator.validate(request, rule, securityFilter.getServletSecurityConfig()).isValid());
    }

    @Test
    @DisplayName("6. ResponsePolicyValidator: Accept 헤더 호환성(406 SEC-40601) 및 JSONP 콜백 XSS 방어(400 SEC-40006) 검증")
    void testResponsePolicyValidator() {
        ResponsePolicyValidator validator = new ResponsePolicyValidator();
        ServletPolicyRule jsonRule = new ServletPolicyRule();
        jsonRule.setTarget("/aemapi/data/json");
        jsonRule.putExtension("responseType", "JSON");
        jsonRule.init();

        when(request.getHeader("Accept")).thenReturn("text/html");
        ValidationResult notAcceptable = validator.validate(request, jsonRule, null);
        assertFalse(notAcceptable.isValid());
        assertEquals(406, notAcceptable.getStatusCode());
        assertEquals("SEC-40601", notAcceptable.getSubCode());

        when(request.getHeader("Accept")).thenReturn("application/json");
        assertTrue(validator.validate(request, jsonRule, null).isValid());

        // JSONP 콜백 검증
        ServletPolicyRule jsonpRule = new ServletPolicyRule();
        jsonpRule.setTarget("/aemapi/data/jsonp");
        jsonpRule.putExtension("responseType", "JSONP");
        jsonpRule.init();

        when(request.getHeader("Accept")).thenReturn("*/*");
        when(request.getParameter("callback")).thenReturn("<script>alert(1)</script>");
        ValidationResult badCallback = validator.validate(request, jsonpRule, null);
        assertFalse(badCallback.isValid());
        assertEquals(400, badCallback.getStatusCode());
        assertEquals("SEC-40006", badCallback.getSubCode());

        when(request.getParameter("callback")).thenReturn("jQuery_callback_123");
        assertTrue(validator.validate(request, jsonpRule, null).isValid());
    }
}
