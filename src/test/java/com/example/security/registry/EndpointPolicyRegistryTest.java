package com.example.security.registry;

import com.example.security.filters.SecurityFilter;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class EndpointPolicyRegistryTest {

    @Mock
    private HttpServletRequest request;

    private EndpointPolicyRegistryImpl registry;
    private SecurityFilter securityFilter;

    @BeforeEach
    void setUp() {
        registry = new EndpointPolicyRegistryImpl();
        securityFilter = new SecurityFilter();
        securityFilter.activate(null); // 기본 정책(defaultPolicy) 초기화
        securityFilter.bindPolicyRegistry(registry);
    }

    @Test
    @DisplayName("서블릿 경로별 배열 형태의 JSON 구조(.cfg.json) 다중 파일 자동 로드 및 통합 검증")
    void testLoadMultipleBundleCfgJsonFiles() throws Exception {
        String memberJson = new String(
                Files.readAllBytes(Paths.get("config/com.example.security.registry.EndpointPolicyConfig~core-member.cfg.json")),
                StandardCharsets.UTF_8
        );
        String commerceJson = new String(
                Files.readAllBytes(Paths.get("config/com.example.security.registry.EndpointPolicyConfig~core-commerce.cfg.json")),
                StandardCharsets.UTF_8
        );

        EndpointPolicyConfig memberConfig = EndpointPolicyConfig.fromCfgJson("core-member", memberJson);
        EndpointPolicyConfig commerceConfig = EndpointPolicyConfig.fromCfgJson("core-commerce", commerceJson);

        registry.bindPolicyConfig(memberConfig, Collections.singletonMap("service.pid", memberConfig.getConfigPid()));
        registry.bindPolicyConfig(commerceConfig, Collections.singletonMap("service.pid", commerceConfig.getConfigPid()));

        // 1. 총 4개 엔드포인트 정책(member 2개 + commerce 2개)이 자동 수집되었는지 확인
        List<ServletPolicyRule> allPolicies = registry.getAllPolicies();
        assertEquals(4, allPolicies.size());

        // 2. 번들별 그룹화 맵 확인
        Map<String, List<ServletPolicyRule>> byBundle = registry.getPoliciesByBundle();
        assertEquals(2, byBundle.get("core-member").size());
        assertEquals(2, byBundle.get("core-commerce").size());

        // 3. 출처(Source) 라벨 확인
        assertEquals("EndpointPolicyConfig~core-member", registry.getPolicySource("/aemapi/user/contact"));
        assertEquals("EndpointPolicyConfig~core-commerce", registry.getPolicySource("/aemapi/order/inquiry"));

        // 4. SecurityFilter에 자동 동기화 및 defaultPolicy 상속 여부 확인
        ServletSecurityConfig filterConfig = securityFilter.getServletSecurityConfig();
        when(request.getRequestURI()).thenReturn("/aemapi/user/contact");
        ServletPolicyRule matched = filterConfig.findMatchingPolicy(request);
        assertNotNull(matched);
        assertEquals("/aemapi/user/contact", matched.getTarget());
        assertTrue(matched.isMethodAllowed("POST"));
        assertFalse(matched.isMethodAllowed("GET"));
        assertTrue(matched.getParams().containsKey("name"));
        assertTrue(matched.getParams().containsKey("inquirytype"));
        assertTrue(matched.getParams().get("inquirytype").getCompiledPattern().matcher("billing").matches());

        // 5. core-commerce의 /aemapi/order/inquiry 정책 검증
        when(request.getRequestURI()).thenReturn("/aemapi/order/inquiry");
        ServletPolicyRule orderRule = filterConfig.findMatchingPolicy(request);
        assertNotNull(orderRule);
        assertEquals("/aemapi/order/inquiry", orderRule.getTarget());
        assertTrue(orderRule.isMethodAllowed("GET"));
        assertTrue(orderRule.isMethodAllowed("POST"));
        assertTrue(orderRule.getAllowedReferrers().contains("shop.abc.com"));
        assertTrue(orderRule.getParams().containsKey("orderid"));
        assertTrue(orderRule.getParams().containsKey("includehistory"));

        // SecurityFilter 로그 출처 포맷 확인
        String logSummary = securityFilter.formatAppliedPolicyForLog(matched);
        assertTrue(logSummary.contains("source=EndpointPolicyConfig~core-member"));
    }

    @Test
    @DisplayName("운영 중 특정 .cfg.json 파일 수정(updatedPolicyConfig) 및 삭제(unbindPolicyConfig) 시 실시간 자동 반영 검증")
    void testDynamicModifyAndUnbindCfgJson() {
        String initialMemberJson = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-member\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/user/profile\",\n" +
                "      \"methods\": [\"GET\"],\n" +
                "      \"params\": [\n" +
                "        \"userId:required:alnum:4..20\"\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        EndpointPolicyConfig memberConfig = EndpointPolicyConfig.fromCfgJson("core-member", initialMemberJson);
        Map<String, Object> pidProps = Collections.singletonMap("service.pid", memberConfig.getConfigPid());

        // 1. 초기 바인딩: GET만 허용
        registry.bindPolicyConfig(memberConfig, pidProps);
        when(request.getRequestURI()).thenReturn("/aemapi/user/profile");
        ServletPolicyRule initialRule = securityFilter.getServletSecurityConfig().findMatchingPolicy(request);
        assertTrue(initialRule.isMethodAllowed("GET"));
        assertFalse(initialRule.isMethodAllowed("POST"));

        // 2. 운영 중 .cfg.json 수정: POST 추가 및 신규 엔드포인트(/aemapi/user/avatar) 추가
        String updatedMemberJson = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-member\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/user/profile\",\n" +
                "      \"methods\": [\"GET\", \"POST\"],\n" +
                "      \"params\": [\n" +
                "        \"userId:required:alnum:4..20\"\n" +
                "      ]\n" +
                "    },\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/user/avatar\",\n" +
                "      \"methods\": [\"POST\"],\n" +
                "      \"params\": [\n" +
                "        \"avatarUrl:required:url:200\"\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        // 2. 운영 중 .cfg.json 수정: OSGi @Modified가 기존 memberConfig.activate()만 호출하더라도
        //    modificationListener를 통해 레지스트리와 SecurityFilter가 즉시 자동 갱신되는지 검증
        java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<Map<String, Object>>() {}.getType();
        Map<String, Object> updatedProps = new com.google.gson.Gson().fromJson(updatedMemberJson, mapType);
        updatedProps.put("service.pid", memberConfig.getConfigPid());
        memberConfig.activateFromProperties(updatedProps);

        // 재기동 없이 SecurityFilter에서 POST 허용 및 신규 엔드포인트 즉시 인식 확인
        ServletPolicyRule updatedRule = securityFilter.getServletSecurityConfig().findMatchingPolicy(request);
        assertTrue(updatedRule.isMethodAllowed("POST"));

        when(request.getRequestURI()).thenReturn("/aemapi/user/avatar");
        ServletPolicyRule avatarRule = securityFilter.getServletSecurityConfig().findMatchingPolicy(request);
        assertEquals("/aemapi/user/avatar", avatarRule.getTarget());

        // 3. .cfg.json 파일 삭제(unbindPolicyConfig): 정책 즉시 해제 및 DEFAULT 폴백 확인
        registry.unbindPolicyConfig(memberConfig, pidProps);
        assertNull(securityFilter.getServletSecurityConfig().getPolicy("/aemapi/user/profile"));
        ServletPolicyRule fallbackRule = securityFilter.getServletSecurityConfig().findMatchingPolicy(request);
        assertEquals("DEFAULT", fallbackRule.getTarget());
    }

    @Test
    @DisplayName(".cfg.json 내 다양한 required 파라미터 정의 형식(DSL, JSON 객체 배열, JSON 맵, requiredParams, default.params 오버라이드) 등록 및 검증")
    void testRequiredParamRegistrationAndValidation() {
        String testJson = "{\n" +
                "  \"enabled\": true,\n" +
                "  \"bundle.id\": \"core-test\",\n" +
                "  \"policies\": [\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/test/dsl\",\n" +
                "      \"methods\": [\"POST\"],\n" +
                "      \"params\": [\n" +
                "        \"userId:required:alnum:4..20\",\n" +
                "        \"userName:2..20:korean:required\",\n" +
                "        \"required:email:email:50\",\n" +
                "        \"{phone:required:phone}\",\n" +
                "        \"code:required:^[A-Z0-9]{4,10}$\",\n" +
                "        \"id:required\"\n" +
                "      ]\n" +
                "    },\n" +
                "    {\n" +
                "      \"target\": \"/aemapi/test/json-array\",\n" +
                "      \"methods\": [\"POST\"],\n" +
                "      \"params\": [\n" +
                "        {\n" +
                "          \"name\": \"accountNo\",\n" +
                "          \"required\": true,\n" +
                "          \"minLength\": 10,\n" +
                "          \"maxLength\": 14,\n" +
                "          \"type\": \"digits\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"memo\",\n" +
                "          \"required\": false,\n" +
                "          \"maxLength\": 100\n" +
                "        }\n" +
                "      ],\n" +
                "      \"requiredParams\": [\"txToken\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        EndpointPolicyConfig testConfig = EndpointPolicyConfig.fromCfgJson("core-test", testJson);
        registry.bindPolicyConfig(testConfig, Collections.singletonMap("service.pid", testConfig.getConfigPid()));

        // 1. /aemapi/test/dsl 의 모든 required 파라미터 등록 상태 확인
        when(request.getRequestURI()).thenReturn("/aemapi/test/dsl");
        ServletPolicyRule dslRule = securityFilter.getServletSecurityConfig().findMatchingPolicy(request);
        assertNotNull(dslRule);
        assertTrue(dslRule.getParams().get("userid").isRequired());
        assertTrue(dslRule.getParams().get("username").isRequired());
        assertTrue(dslRule.getParams().get("email").isRequired());
        assertTrue(dslRule.getParams().get("phone").isRequired());
        assertTrue(dslRule.getParams().get("code").isRequired());
        assertEquals("^[A-Z0-9]{4,10}$", dslRule.getParams().get("code").getPattern());
        assertTrue(dslRule.getParams().get("id").isRequired());

        // 2. /aemapi/test/json-array 의 JSON 객체 배열 및 requiredParams 등록 상태 확인
        when(request.getRequestURI()).thenReturn("/aemapi/test/json-array");
        ServletPolicyRule jsonArrayRule = securityFilter.getServletSecurityConfig().findMatchingPolicy(request);
        assertNotNull(jsonArrayRule);
        assertTrue(jsonArrayRule.getParams().get("accountno").isRequired());
        assertEquals(Integer.valueOf(10), jsonArrayRule.getParams().get("accountno").getMinLength());
        assertEquals(Integer.valueOf(14), jsonArrayRule.getParams().get("accountno").getMaxLength());
        assertFalse(jsonArrayRule.getParams().get("memo").isRequired());
        assertTrue(jsonArrayRule.getParams().get("txtoken").isRequired());

        // 3. ParamPolicyValidator 실제 필수 파라미터 누락 차단(SEC-40001) 검증
        com.example.security.validators.ParamPolicyValidator validator = new com.example.security.validators.ParamPolicyValidator();
        when(request.getParameterMap()).thenReturn(Collections.emptyMap());
        com.example.security.validators.ValidationResult missingResult =
                validator.validate(request, jsonArrayRule, securityFilter.getServletSecurityConfig());
        assertFalse(missingResult.isValid());
        assertEquals(400, missingResult.getStatusCode());
        assertEquals("SEC-40001", missingResult.getSubCode());
    }
}
