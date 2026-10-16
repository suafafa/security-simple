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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PathTraversalValidationTest {

    private ParamPolicyValidator validator;

    @Mock
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        validator = new ParamPolicyValidator();
    }

    private ServletPolicyRule createPolicyWithFileParam(boolean allowTraversal) {
        ServletPolicyRule policy = new ServletPolicyRule();
        policy.setTarget("/bin/export/file");

        ParamRule fileRule = new ParamRule();
        fileRule.setAllowPathTraversal(allowTraversal);

        Map<String, ParamRule> params = new HashMap<>();
        params.put("filename", fileRule);
        policy.setParams(params);
        policy.init();

        return policy;
    }

    @Test
    @DisplayName("정상적인 안전한 파일명은 검증 통과")
    void testSafeFileNamePasses() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"report_2026_q3.csv"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertTrue(result.isValid());
        assertEquals(200, result.getStatusCode());
    }

    @Test
    @DisplayName("표준 상위 디렉토리 이동 (../../etc/passwd) 차단")
    void testStandardPathTraversalBlocked() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"../../../../etc/passwd"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_PATH_TRAVERSAL, result.getErrorCode());
        assertEquals("SEC-40007", result.getSubCode());
    }

    @Test
    @DisplayName("윈도우 역슬래시 (..\\..\\windows) 경로 조작 차단")
    void testWindowsBackslashPathTraversalBlocked() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"..\\..\\windows\\system32\\cmd.exe"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_PATH_TRAVERSAL, result.getErrorCode());
    }

    @Test
    @DisplayName("URL 인코딩 (%2e%2e%2f) 우회 시도 차단")
    void testUrlEncodedPathTraversalBlocked() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"%2e%2e%2f%2e%2e%2fconfig.json"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_PATH_TRAVERSAL, result.getErrorCode());
    }

    @Test
    @DisplayName("이중 URL 인코딩 (%252e%252e%252f) 우회 시도 차단")
    void testDoubleUrlEncodedPathTraversalBlocked() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"%252e%252e%252fsecret.key"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_PATH_TRAVERSAL, result.getErrorCode());
    }

    @Test
    @DisplayName("세미콜론 우회 기법 (..;/..;/) 차단")
    void testSemicolonMatrixPathTraversalBlocked() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"..;/..;/conf/security.json"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_PATH_TRAVERSAL, result.getErrorCode());
    }

    @Test
    @DisplayName("널 바이트 인젝션 (%00) 차단")
    void testNullByteInjectionBlocked() {
        ServletPolicyRule policy = createPolicyWithFileParam(false);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"safe.png%00.jsp"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertFalse(result.isValid());
        assertEquals(400, result.getStatusCode());
        assertEquals(SecurityErrorCode.PARAM_PATH_TRAVERSAL, result.getErrorCode());
    }

    @Test
    @DisplayName("allowPathTraversal = true 설정 시 예외적 허용 확인")
    void testExplicitlyAllowedPathTraversalPasses() {
        ServletPolicyRule policy = createPolicyWithFileParam(true);

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put("filename", new String[]{"../relative/path.txt"});
        when(request.getParameterMap()).thenReturn(paramMap);

        ValidationResult result = validator.validate(request, policy, null);

        assertTrue(result.isValid());
        assertEquals(200, result.getStatusCode());
    }
}
