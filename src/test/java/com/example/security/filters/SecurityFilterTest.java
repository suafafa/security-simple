package com.example.security.filters;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityFilterTest {

    private SecurityFilter filter;
    private static final Gson GSON = new Gson();

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private StringWriter responseOutput;

    private static final String SAMPLE_JSON_CONFIG = "{\n" +
            "  \"enabled\": true,\n" +
            "  \"defaultReferrer\": \"abc.com\",\n" +
            "  \"policies\": [\n" +
            "    {\n" +
            "      \"target\": \"myproject/components/user-profile\",\n" +
            "      \"enabled\": true,\n" +
            "      \"methods\": [\"GET\", \"POST\"],\n" +
            "      \"params\": {\n" +
            "        \"userId\": {\n" +
            "          \"enabled\": true,\n" +
            "          \"maxLength\": 20,\n" +
            "          \"pattern\": \"^[a-zA-Z0-9_]+$\"\n" +
            "        }\n" +
            "      }\n" +
            "    },\n" +
            "    {\n" +
            "      \"target\": \"/aemapi/order-cancel\",\n" +
            "      \"enabled\": true,\n" +
            "      \"methods\": [\"POST\", \"DELETE\"],\n" +
            "      \"params\": {}\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    @BeforeEach
    void setUp() throws IOException {
        filter = new SecurityFilter();
        Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
        Map<String, Object> properties = GSON.fromJson(SAMPLE_JSON_CONFIG, mapType);
        filter.activate(null, properties);

        responseOutput = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseOutput));
        lenient().when(request.getHeader("Referer")).thenReturn("https://www.abc.com/page.html");
    }

    @Test
    @DisplayName("Method/Param/Referer 정상 요청 통과 (GET, 유효한 userId, 신뢰된 Referer)")
    void testTargetUserProfileGetPasses() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/content/page/jcr:content/myproject/components/user-profile");
        when(request.getMethod()).thenReturn("GET");
        Map<String, String[]> params = new HashMap<>();
        params.put("userId", new String[]{"user_123"});
        when(request.getParameterMap()).thenReturn(params);

        filter.doFilter(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    @DisplayName("MethodPolicyValidator: 허용되지 않은 메서드 호출 시 405 Method Not Allowed 차단 (SEC-40501)")
    void testTargetUserProfileDeleteBlocks() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/content/page/jcr:content/myproject/components/user-profile");
        when(request.getMethod()).thenReturn("DELETE");

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        org.junit.jupiter.api.Assertions.assertTrue(responseOutput.toString().contains("SEC-40501"));
    }

    @Test
    @DisplayName("ParamPolicyValidator: 파라미터 maxLength(20) 초과 시 400 Bad Request 차단 (SEC-40004)")
    void testTargetUserProfileMaxLengthBlocks() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/content/page/jcr:content/myproject/components/user-profile");
        when(request.getMethod()).thenReturn("POST");
        Map<String, String[]> params = new HashMap<>();
        params.put("userId", new String[]{"123456789012345678901"});
        when(request.getParameterMap()).thenReturn(params);

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        org.junit.jupiter.api.Assertions.assertTrue(responseOutput.toString().contains("SEC-40004"));
    }

    @Test
    @DisplayName("ParamPolicyValidator: 정의되지 않은 파라미터 전달 시 기본 차단 (allowUndefinedParams 기본값 false, SEC-40002)")
    void testUndefinedParameterBlockedByDefault() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/content/page/jcr:content/myproject/components/user-profile");
        when(request.getMethod()).thenReturn("GET");
        Map<String, String[]> params = new HashMap<>();
        params.put("userId", new String[]{"user123"});
        params.put("extraParam", new String[]{"someValue"});
        when(request.getParameterMap()).thenReturn(params);

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        org.junit.jupiter.api.Assertions.assertTrue(responseOutput.toString().contains("SEC-40002"));
    }

    @Test
    @DisplayName("ParamPolicyValidator: allowUndefinedParams=true 설정 시 미정의 파라미터 통과")
    void testUndefinedParameterAllowedWhenConfigured() throws IOException, ServletException {
        String lenientJson = "{\"enabled\": true, \"policies\": [{\"target\": \"/aemapi/lenient\", \"methods\": [\"GET\"], \"allowUndefinedParams\": true, \"params\": {\"id\": {\"maxLength\": 10}}}]}";
        Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
        Map<String, Object> properties = GSON.fromJson(lenientJson, mapType);
        filter.activate(null, properties);

        when(request.getRequestURI()).thenReturn("/aemapi/lenient");
        when(request.getMethod()).thenReturn("GET");
        Map<String, String[]> params = new HashMap<>();
        params.put("id", new String[]{"123"});
        params.put("extraField", new String[]{"val"});
        when(request.getParameterMap()).thenReturn(params);

        filter.doFilter(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    @DisplayName("RefererPolicyValidator: 기본 허용 도메인 abc.com 및 서브도메인 정상 통과")
    void testDefaultRefererAllowed() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/aemapi/order-cancel");
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Referer")).thenReturn("https://sub.abc.com/checkout");

        filter.doFilter(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    @DisplayName("RefererPolicyValidator: 허용되지 않은 외부 레퍼러 유입 시 403 Forbidden 차단 (SEC-40303)")
    void testUntrustedRefererBlocked() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/aemapi/order-cancel");
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Referer")).thenReturn("https://evil-attacker.com/csrf");

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        org.junit.jupiter.api.Assertions.assertTrue(responseOutput.toString().contains("SEC-40303"));
    }

    @Test
    @DisplayName("복수 경로 서블릿: 경로별로 서로 다른 HTTP Method, Referer, 파라미터 규칙 적용 검증")
    void testMultiplePathsServletWithPerPathRules() throws IOException, ServletException {
        Servlet multiPathServlet = mock(Servlet.class);
        Map<String, Object> props = new HashMap<>();
        props.put("sling.servlet.paths", new String[]{"/aemapi/order/list", "/aemapi/order/cancel"});
        props.put("security.methods", new String[]{
                "/aemapi/order/list:GET",
                "/aemapi/order/cancel:POST"
        });
        props.put("security.params", new String[]{
                "lang:optional:alpha:5",
                "/aemapi/order/list:page:optional:digits:5",
                "/aemapi/order/cancel:orderId:required:alphanumeric:20"
        });

        filter.bindServlet(multiPathServlet, props);

        // 1. /aemapi/order/list GET + page=1 -> 통과
        when(request.getRequestURI()).thenReturn("/aemapi/order/list");
        when(request.getMethod()).thenReturn("GET");
        Map<String, String[]> listParams = new HashMap<>();
        listParams.put("page", new String[]{"1"});
        listParams.put("lang", new String[]{"ko"});
        when(request.getParameterMap()).thenReturn(listParams);
        filter.doFilter(request, response, filterChain);
        verify(filterChain, times(1)).doFilter(request, response);

        // 2. /aemapi/order/list POST -> 405 차단
        when(request.getMethod()).thenReturn("POST");
        filter.doFilter(request, response, filterChain);
        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);

        // 3. /aemapi/order/cancel POST + orderId=ORD_100 -> 통과
        reset(response);
        responseOutput.getBuffer().setLength(0);
        when(response.getWriter()).thenReturn(new PrintWriter(responseOutput));
        when(request.getRequestURI()).thenReturn("/aemapi/order/cancel");
        when(request.getMethod()).thenReturn("POST");
        Map<String, String[]> cancelParams = new HashMap<>();
        cancelParams.put("orderId", new String[]{"ORD_100"});
        when(request.getParameterMap()).thenReturn(cancelParams);
        filter.doFilter(request, response, filterChain);
        verify(filterChain, times(2)).doFilter(request, response);
    }

    @Test
    @DisplayName("Validator 통과 설정값(describePassedConfig) 및 차단 로그 요약 포맷 검증")
    void testPassedConfigAndViolationLogFormat() {
        Servlet contactServlet = mock(Servlet.class);
        Map<String, Object> props = new HashMap<>();
        props.put("component.name", "com.example.security.servlets.UserContactServlet");
        props.put("sling.servlet.paths", "/aemapi/user/contact");
        props.put("security.methods", "POST");
        props.put("security.allowedReferrers", "partner.abc.com");
        props.put("security.params", new String[]{
                "name:required:2..20:korean",
                "email:required:email:50"
        });

        filter.bindServlet(contactServlet, props);

        com.example.security.models.ServletPolicyRule matched =
                filter.getServletSecurityConfig().getDynamicPolicy("/aemapi/user/contact");
        org.junit.jupiter.api.Assertions.assertNotNull(matched);

        String logSummary = filter.formatAppliedPolicyForLog(matched);
        org.junit.jupiter.api.Assertions.assertTrue(logSummary.contains("source=com.example.security.servlets.UserContactServlet"));
        org.junit.jupiter.api.Assertions.assertTrue(logSummary.contains("target=/aemapi/user/contact"));
        org.junit.jupiter.api.Assertions.assertTrue(logSummary.contains("methods=[POST]"));
        org.junit.jupiter.api.Assertions.assertTrue(logSummary.contains("name={required=true, len=2..20"));

        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Referer")).thenReturn("https://partner.abc.com/form");

        com.example.security.validators.RefererPolicyValidator refererVal =
                new com.example.security.validators.RefererPolicyValidator();
        org.junit.jupiter.api.Assertions.assertTrue(
                refererVal.describePassedConfig(request, matched, filter.getServletSecurityConfig()).contains("allowedReferrers=[partner.abc.com]"));

        com.example.security.validators.MethodPolicyValidator methodVal =
                new com.example.security.validators.MethodPolicyValidator();
        org.junit.jupiter.api.Assertions.assertTrue(
                methodVal.describePassedConfig(request, matched, filter.getServletSecurityConfig()).contains("allowedMethods=[POST]"));

        com.example.security.validators.ParamPolicyValidator paramVal =
                new com.example.security.validators.ParamPolicyValidator();
        org.junit.jupiter.api.Assertions.assertTrue(
                paramVal.describePassedConfig(request, matched, filter.getServletSecurityConfig()).contains("allowUndefinedParams=false"));
    }
}
