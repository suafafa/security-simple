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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class PolicyModeExecutionTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private SecurityFilter securityFilter;
    private EndpointPolicyRegistryImpl registry;

    @BeforeEach
    void setUp() {
        registry = new EndpointPolicyRegistryImpl();
        securityFilter = new SecurityFilter();
        securityFilter.activate(null); // 기본 전역 mode = ENFORCE
        securityFilter.bindPolicyRegistry(registry);
    }

    @Test
    @DisplayName("1. 전역 기본 ENFORCE 모드일 때 보안 위반 발생 시 에러(405)를 반환하고 서블릿 진행을 차단")
    void testGlobalEnforceModeBlocksViolation() throws Exception {
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-mode\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/mode/enforce\",\n" +
                "      \"mode\": \"ENFORCE\",\n" +
                "      \"methods\": [\"POST\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        EndpointPolicyConfig cfg = EndpointPolicyConfig.fromCfgJson("core-mode", json);
        registry.bindPolicyConfig(cfg, Collections.singletonMap("service.pid", cfg.getConfigPid()));

        when(request.getRequestURI()).thenReturn("/aemapi/mode/enforce");
        when(request.getHeader("Referer")).thenReturn("https://www.abc.com/page");
        when(request.getMethod()).thenReturn("DELETE"); // 허용되지 않은 메서드
        StringWriter body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));

        securityFilter.doFilter(request, response, filterChain);

        verify(response).setStatus(405);
        verify(filterChain, never()).doFilter(request, response);
        assertTrue(body.toString().contains("SEC-40501"));
    }

    @Test
    @DisplayName("2. 전역 mode가 ENFORCE이더라도 개별 서블릿 정책이 mode=MONITOR이면 위반 시 WARN 로그만 남기고 통과")
    void testIndividualServletMonitorModeWorksUnderGlobalEnforce() throws Exception {
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-mode\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/mode/monitor\",\n" +
                "      \"MODE\": \"monitor\",\n" +
                "      \"methods\": [\"POST\"],\n" +
                "      \"params\": [\"userId:required:alnum:4..20\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        EndpointPolicyConfig cfg = EndpointPolicyConfig.fromCfgJson("core-mode", json);
        registry.bindPolicyConfig(cfg, Collections.singletonMap("service.pid", cfg.getConfigPid()));

        // 전역 모드는 ENFORCE 상태 확인
        assertEquals("ENFORCE", securityFilter.getServletSecurityConfig().getMode());

        // Referer 누락(403 위반) + DELETE 메서드(405 위반) + 필수 파라미터 userId 누락(400 위반) 동시 발생
        when(request.getRequestURI()).thenReturn("/aemapi/mode/monitor");
        when(request.getMethod()).thenReturn("DELETE");
        when(request.getParameterMap()).thenReturn(Collections.emptyMap());

        securityFilter.doFilter(request, response, filterChain);

        // 개별 서블릿이 MONITOR 모드이므로 에러 상태 코드 설정 없이 모든 검증기를 거쳐 chain.doFilter가 정상 실행되어야 함
        verify(response, never()).setStatus(anyInt());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("3. 전체 설정(Global Mode = MONITOR)이 개별 설정(mode = ENFORCE)보다 우선하여 통과하는지 검증")
    void testGlobalMonitorModeOverridesIndividualEnforcePolicy() throws Exception {
        String json = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-mode\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/mode/strict\",\n" +
                "      \"mode\": \"ENFORCE\",\n" +
                "      \"methods\": [\"POST\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        EndpointPolicyConfig cfg = EndpointPolicyConfig.fromCfgJson("core-mode", json);
        registry.bindPolicyConfig(cfg, Collections.singletonMap("service.pid", cfg.getConfigPid()));

        // 전체 설정을 소문자 "monitor"로 변경해도 대소문자 구분 없이 MONITOR로 동작하는지 확인
        securityFilter.getServletSecurityConfig().setMode("monitor");

        when(request.getRequestURI()).thenReturn("/aemapi/mode/strict");
        when(request.getHeader("Referer")).thenReturn("https://evil.com");
        when(request.getMethod()).thenReturn("DELETE");

        securityFilter.doFilter(request, response, filterChain);

        // 개별 서블릿이 ENFORCE이더라도 전체 설정(MONITOR)이 우선하여 차단되지 않고 통과해야 함
        verify(response, never()).setStatus(anyInt());
        verify(filterChain, times(1)).doFilter(request, response);
    }
}
