package com.example.security.validators;

import com.example.security.models.ParamRule;
import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 요청 파라미터의 보안 제약조건을 검증하는 모듈형 검증기입니다:
 * - 필수 파라미터(required) 누락 여부 검사
 * - 미정의 파라미터 허용 여부(allowUndefinedParams) 통제
 * - 경로 조작(Path Traversal, CWE-22) 공격 탐지 및 차단
 * - SQL / JCR-SQL2 / XPath 인젝션(CWE-89) 공격 탐지 및 차단
 * - 크로스 사이트 스크립팅(XSS, CWE-79) 공격 탐지 및 차단
 * - 최소/최대 글자 수(minLength, maxLength) 제한 검사
 * - 정규식 패턴(pattern) 일치 검사
 */
public class ParamPolicyValidator implements PolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(ParamPolicyValidator.class);

    /**
     * CWE-89: SQL / JCR-SQL2 / XPath 인젝션 공격 시그니처 정규식 목록
     */
    private static final List<Pattern> SQLI_PATTERNS = Arrays.asList(
            // 1. SQL 문법 키워드 결합 (UNION SELECT, SELECT FROM, INSERT INTO, UPDATE SET, DELETE FROM, DROP TABLE, ALTER TABLE)
            Pattern.compile("(?i)\\b(SELECT|UNION(\\s+ALL)?)\\b[\\s\\S]*?\\b(FROM|INTO)\\b"),
            Pattern.compile("(?i)\\b(INSERT\\s+INTO|UPDATE\\s+[\\s\\S]*?\\bSET|DELETE\\s+FROM|DROP\\s+(TABLE|DATABASE|VIEW)|ALTER\\s+TABLE|CREATE\\s+(TABLE|DATABASE))\\b"),

            // 2. 불리언 기반(Boolean-based) SQL 인젝션 (' OR '1'='1, ' OR 1=1--, admin'--)
            Pattern.compile("(?i)('|\")\\s*(OR|AND)\\s*('|\")?\\d+('|\")?\\s*=\\s*('|\")?\\d+"),
            Pattern.compile("(?i)('|\")\\s*(OR|AND)\\s+['\"\\w]+\\s*[=><!]"),
            Pattern.compile("(?i)\\bOR\\s+1\\s*=\\s*1\\b"),

            // 3. 주석을 이용한 쿼리 분기 우회 (-- , /* */, #)
            Pattern.compile("(?i)(--\\s+|;\\s*--|/\\*[\\s\\S]*?\\*/|#\\s+)"),

            // 4. 시간 지연 기반(Time-based Blind) SQL 인젝션 (SLEEP, BENCHMARK, WAITFOR DELAY)
            Pattern.compile("(?i)\\b(SLEEP|BENCHMARK|WAITFOR\\s+DELAY|PG_SLEEP)\\s*\\("),

            // 5. JCR-SQL2 Injection (AEM 전용 JCR 노드 쿼리 공격 패턴)
            Pattern.compile("(?i)\\bSELECT\\b[\\s\\S]*?\\bFROM\\s+\\[(nt|cq|rep|mix):[a-zA-Z0-9_-]+\\]"),
            Pattern.compile("(?i)\\b(ISDESCENDANTNODE|ISCHILDNODE|ISSAMENODE)\\s*\\("),

            // 6. XPath Injection (AEM JCR XPath 쿼리 공격 패턴)
            Pattern.compile("/jcr:root/|//element\\s*\\("),
            Pattern.compile("(?i)@jcr:(primaryType|mixinTypes|content|created|title|path)"),
            Pattern.compile("(?i)jcr:(contains|like|score|deref)\\s*\\(")
    );

    /**
     * CWE-79: Cross-Site Scripting (XSS) 공격 시그니처 정규식 목록 (범주별 고속 매칭)
     */
    private static final List<Pattern> XSS_TAG_PATTERNS = Arrays.asList(
            Pattern.compile("(?i)<\\s*script\\b[^>]*>"),
            Pattern.compile("(?i)<\\s*/\\s*script\\s*>"),
            Pattern.compile("(?i)<\\s*(iframe|object|embed|applet|meta|link|base)\\b[^>]*>"),
            Pattern.compile("(?i)<\\s*(svg|img|body|video|audio|input|form|details)\\b[^>]*?\\bon[a-zA-Z]+\\s*=")
    );

    private static final List<Pattern> XSS_SCHEME_PATTERNS = Arrays.asList(
            Pattern.compile("(?i)javascript\\s*:"),
            Pattern.compile("(?i)vbscript\\s*:"),
            Pattern.compile("(?i)data\\s*:\\s*text\\s*/\\s*html")
    );

    private static final List<Pattern> XSS_EVENT_PATTERNS = Arrays.asList(
            Pattern.compile("(?i)\\bon(load|error|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|focus|blur|keydown|keyup|keypress|submit|reset|change|input|pointerdown|pointerup)\\s*=")
    );

    private static final List<Pattern> XSS_FUNC_PATTERNS = Arrays.asList(
            Pattern.compile("(?i)\\b(eval|alert|prompt|confirm)\\s*\\(")
    );

    private static final List<Pattern> XSS_DOM_PATTERNS = Arrays.asList(
            Pattern.compile("(?i)document\\.(cookie|domain|write)"),
            Pattern.compile("(?i)(window|document)\\.location")
    );

    private static final Pattern HEX_LT_PATTERN = Pattern.compile("(?i)&#x3c;|&#60;");
    private static final Pattern HEX_GT_PATTERN = Pattern.compile("(?i)&#x3e;|&#62;");

    @Override
    public String getName() {
        return "PARAM";
    }

    @Override
    public ValidationResult validate(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        Map<String, ParamRule> configuredParams = policy.getParams();
        Map<String, String[]> parameterMap = request != null ? request.getParameterMap() : null;

        if ((configuredParams == null || configuredParams.isEmpty())
                && (parameterMap == null || parameterMap.isEmpty())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("ParamPolicyValidator PASSED for target [{}] | PassedConfig=[{}]",
                        policy.getTarget(), describePassedConfig(request, policy, rootConfig));
            }
            return ValidationResult.ok();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("ParamPolicyValidator evaluating target [{}] with {} configured params. allowUndefinedParams={}",
                    policy.getTarget(), configuredParams != null ? configuredParams.size() : 0, policy.isAllowUndefinedParams());
        }

        // 1. 필수 파라미터(required) 누락 여부 검사
        if (configuredParams != null && !configuredParams.isEmpty()) {
            for (Map.Entry<String, ParamRule> ruleEntry : configuredParams.entrySet()) {
                String paramName = ruleEntry.getKey();
                ParamRule rule = ruleEntry.getValue();

                if (rule.isEnabled() && rule.isRequired()) {
                    String[] values = getParameterValues(parameterMap, paramName);
                    if (values == null || values.length == 0 || StringUtils.isBlank(values[0])) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("ParamPolicyValidator: Required param [{}] is missing for target [{}]", paramName, policy.getTarget());
                        }
                        return ValidationResult.error(
                                SecurityErrorCode.PARAM_REQUIRED,
                                "Missing required parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] for target: " + SecurityUtils.sanitizeForLog(policy.getTarget()),
                                paramName
                        );
                    }
                }
            }
        }

        // 2. 유입된 요청 파라미터들의 보안 및 형식 유효성 검사
        if (parameterMap != null && !parameterMap.isEmpty()) {
            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                String paramName = entry.getKey();
                String[] paramValues = entry.getValue();

                // 빠른 조회(Fast-path): configuredParams는 init() 시점에 소문자 키로 인덱싱되어 있음
                ParamRule rule = null;
                if (configuredParams != null && !configuredParams.isEmpty()) {
                    rule = configuredParams.get(paramName);
                    if (rule == null) {
                        rule = configuredParams.get(paramName.toLowerCase());
                    }
                }

                if (rule == null) {
                    if (!policy.isAllowUndefinedParams()) {
                        return ValidationResult.error(
                                SecurityErrorCode.PARAM_UNDEFINED,
                                "Undefined parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] not permitted for target: " + SecurityUtils.sanitizeForLog(policy.getTarget()),
                                paramName
                        );
                    }
                    // 미정의 파라미터 허용 시에도 심층 보안 검사 (Path Traversal, SQLi, XSS 악성 페이로드 주입 원천 차단)
                    if (paramValues != null) {
                        for (String val : paramValues) {
                            if (val != null) {
                                if (isPathTraversalAttack(val)) {
                                    return ValidationResult.error(
                                            SecurityErrorCode.PARAM_PATH_TRAVERSAL,
                                            "Path Traversal attack pattern detected in undefined parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                            paramName
                                    );
                                }
                                if (policy.isBlockSqlInjection() && isSqlInjectionAttack(val)) {
                                    return ValidationResult.error(
                                            SecurityErrorCode.PARAM_SQL_INJECTION,
                                            "SQL/JCR Injection attack pattern detected in undefined parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                            paramName
                                    );
                                }
                                if (policy.isBlockXss() && isXssAttack(val)) {
                                    return ValidationResult.error(
                                            SecurityErrorCode.PARAM_XSS,
                                            "Cross-Site Scripting (XSS) attack pattern detected in undefined parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                            paramName
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }

                if (rule.isEnabled() && paramValues != null) {
                    for (String val : paramValues) {
                        if (val != null) {
                            // =========================================================================
                            // [보안 방어 계층 1] 경로 조작(Path Traversal / Directory Traversal) 자동 탐지
                            // CWE-22: 상위 디렉토리 이동(../, ..\), 2중 URL 인코딩(%252e%252e),
                            // 세미콜론 우회(..;), 널 바이트(%00) 주입 공격을 원천 차단합니다.
                            // rule.isAllowPathTraversal()이 true로 명시되지 않은 한 기본적으로 차단됩니다.
                            // =========================================================================
                            if (!rule.isAllowPathTraversal() && isPathTraversalAttack(val)) {
                                return ValidationResult.error(
                                        SecurityErrorCode.PARAM_PATH_TRAVERSAL,
                                        "Path Traversal attack pattern detected in parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                        paramName
                                );
                            }

                            // =========================================================================
                            // [보안 방어 계층 2] SQL / JCR-SQL2 / XPath 인젝션 자동 탐지
                            // CWE-89: DB 조작 쿼리, JCR-SQL2 노드 탐색 쿼리, XPath 인젝션 구문 차단
                            // rule.isAllowSqlInjection()이 true로 명시되지 않은 한 기본적으로 차단됩니다.
                            // =========================================================================
                            if (policy.isBlockSqlInjection() && !rule.isAllowSqlInjection() && isSqlInjectionAttack(val)) {
                                return ValidationResult.error(
                                        SecurityErrorCode.PARAM_SQL_INJECTION,
                                        "SQL/JCR Injection attack pattern detected in parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                        paramName
                                );
                            }

                            // =========================================================================
                            // [보안 방어 계층 3] XSS (Cross-Site Scripting) 악성 스크립트 태그 자동 차단
                            // CWE-79: <script>, onload=, onerror=, javascript: 등 악성 스크립트 실행 구문 차단
                            // rule.isAllowXss()이 true로 명시되지 않은 한 기본적으로 차단됩니다.
                            // =========================================================================
                            if (policy.isBlockXss() && !rule.isAllowXss() && isXssAttack(val)) {
                                return ValidationResult.error(
                                        SecurityErrorCode.PARAM_XSS,
                                        "Cross-Site Scripting (XSS) attack pattern detected in parameter [" + SecurityUtils.sanitizeForLog(paramName) + "]: " + SecurityUtils.sanitizeForLog(val),
                                        paramName
                                );
                            }

                            // 최소 글자 수(minLength) 제한 검사
                            if (rule.getMinLength() != null && val.length() < rule.getMinLength()) {
                                return ValidationResult.error(
                                        SecurityErrorCode.PARAM_TOO_SHORT,
                                        "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] length (" + val.length() + ") < min (" + rule.getMinLength() + ")",
                                        paramName, rule.getMinLength()
                                );
                            }

                            // 최대 글자 수(maxLength) 제한 검사
                            if (rule.getMaxLength() != null && val.length() > rule.getMaxLength()) {
                                return ValidationResult.error(
                                        SecurityErrorCode.PARAM_TOO_LONG,
                                        "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] length (" + val.length() + ") > max (" + rule.getMaxLength() + ")",
                                        paramName, rule.getMaxLength()
                                );
                            }

                            // 정규식 패턴(pattern) 일치 검사
                            if (rule.getCompiledPattern() != null && !rule.getCompiledPattern().matcher(val).matches()) {
                                return ValidationResult.error(
                                        SecurityErrorCode.PARAM_INVALID_FORMAT,
                                        "Parameter [" + SecurityUtils.sanitizeForLog(paramName) + "] format validation failed against pattern: " + rule.getPattern(),
                                        paramName
                                );
                            }
                        }
                    }
                }
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("ParamPolicyValidator PASSED for target [{}] | PassedConfig=[{}]",
                    policy.getTarget(), describePassedConfig(request, policy, rootConfig));
        }
        return ValidationResult.ok();
    }

    @Override
    public String describePassedConfig(HttpServletRequest request, ServletPolicyRule policy, ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return "NONE";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("allowUndefinedParams=").append(policy.isAllowUndefinedParams());
        sb.append(", blockSqlInjection=").append(policy.isBlockSqlInjection());
        sb.append(", blockXss=").append(policy.isBlockXss());
        Map<String, ParamRule> configuredParams = policy.getParams();
        if (configuredParams != null && !configuredParams.isEmpty()) {
            sb.append(", params={");
            boolean first = true;
            for (Map.Entry<String, ParamRule> entry : configuredParams.entrySet()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(entry.getKey()).append("=").append(entry.getValue() != null ? entry.getValue().toSummaryString() : "{}");
            }
            sb.append("}");
        } else {
            sb.append(", params={}");
        }
        return sb.toString();
    }

    /**
     * 파라미터 값 추출 헬퍼 (Zero-Allocation Fast Path):
     * 1차: 대소문자 정확히 일치 시 O(1) 해시 조회 (객체 생성 0개)
     * 2차: 불일치 시에만 대소문자 무시 순회 조회 (객체 생성 0개)
     */
    private static String[] getParameterValues(Map<String, String[]> parameterMap, String paramName) {
        if (parameterMap == null || paramName == null) {
            return null;
        }
        // 1. 빠른 경로: 정확히 일치 (대부분의 정상 웹 트래픽)
        String[] values = parameterMap.get(paramName);
        if (values != null) {
            return values;
        }
        // 2. 대체 경로: 대소문자 비구분 탐색
        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            if (paramName.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * 경로 조작(Path Traversal / Directory Traversal, CWE-22) 공격 시그니처를 정밀 검사합니다.
     * 
     * [방어 대상 공격 패턴]:
     * 1. 널 바이트 인젝션 (\0, %00): 파일 확장자 검증 우회 시도 차단
     * 2. 다중/중첩 URL 인코딩 (%2e%2e, %252e%252e): WAF/필터 탐지 우회 시도 차단
     * 3. 상위 디렉토리 이동 시퀀스:
     *    - ../, ..\ (표준 디렉토리 탈출)
     *    - /.., \.. (끝부분 탈출)
     *    - ..; (Tomcat / Spring / Sling 매트릭스 파라미터 세미콜론 우회 기법)
     *    - 단독 ".." 입력
     *
     * @param value 검증할 파라미터 값
     * @return 경로 조작 시그니처가 탐지되면 true (위험), 정상이면 false (안전)
     */
    public static boolean isPathTraversalAttack(String value) {
        if (StringUtils.isBlank(value)) {
            return false;
        }

        // 1. 널 바이트(Null Byte) 원본 검사 (\0 또는 %00)
        if (value.indexOf('\0') != -1 || value.contains("%00")) {
            return true;
        }

        // 2. URL 인코딩 해제 (1차 디코딩)
        String decoded = safeUrlDecode(value);

        // 3. 다중 인코딩(Double Encoding, e.g. %252e%252e) 우회 방지를 위한 2차 디코딩
        if (decoded.contains("%")) {
            decoded = safeUrlDecode(decoded);
        }

        // 디코딩 후 널 바이트 재검사
        if (decoded.indexOf('\0') != -1) {
            return true;
        }

        // 빠른 검사: 마침표 2개("..") 및 URL 인코딩 잔여물이 없는 정상 문자열은 즉시 통과 (Zero-allocation)
        if (decoded.indexOf("..") == -1 && decoded.indexOf('%') == -1) {
            return false;
        }

        // 4. 공백 및 제어문자 정규화 (소문자 변환)
        String lower = decoded.trim().toLowerCase();

        // 5. 상위 디렉토리 이동(..) 시그니처 정밀 검사
        if (lower.contains("..")) {
            // 표준 슬래시/역슬래시 경로 이동 (../ 또는 ..\)
            if (lower.contains("../") || lower.contains("..\\")) {
                return true;
            }
            // 끝부분 상위 이동 (/.. 또는 \..)
            if (lower.endsWith("/..") || lower.endsWith("\\..")) {
                return true;
            }
            // 세미콜론 우회 기법 (..;/)
            if (lower.contains("..;")) {
                return true;
            }
            // 값이 정확히 ".." 자체인 경우
            if (lower.equals("..")) {
                return true;
            }
            // URL 인코딩 잔여물 결합 형태 (..%2f, ..%5c)
            if (lower.contains("..%2f") || lower.contains("..%5c")) {
                return true;
            }
        }

        return false;
    }

    /**
     * UTF-8 기반으로 안전하게 URL 디코딩을 수행하며, 인코딩 특수문자(% 또는 +)가 없으면 원본을 즉시 반환합니다.
     */
    private static String safeUrlDecode(String input) {
        if (input == null || (input.indexOf('%') == -1 && input.indexOf('+') == -1)) {
            return input;
        }
        try {
            return java.net.URLDecoder.decode(input, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (Exception ignored) {
            // 잘못된 % 인코딩 형식일 경우 원본 반환
            return input;
        }
    }

    /**
     * CWE-89: SQL / JCR-SQL2 / XPath 인젝션 공격 시그니처를 정밀 검사합니다.
     *
     * [방어 대상 공격 유형]:
     * 1. 표준 SQL 인젝션: UNION SELECT, DROP TABLE, OR 1=1, 주석(--, /*) 우회
     * 2. Blind SQL 인젝션: SLEEP(), BENCHMARK(), WAITFOR DELAY
     * 3. AEM JCR-SQL2 인젝션: FROM [nt:base], ISDESCENDANTNODE(), CONTAINS()
     * 4. AEM JCR XPath 인젝션: /jcr:root/, //element(), @jcr:primaryType, jcr:contains()
     *
     * @param value 검증할 파라미터 값
     * @return SQL/JCR 인젝션 시그니처가 감지되면 true (위험), 정상이면 false (안전)
     */
    public static boolean isSqlInjectionAttack(String value) {
        if (StringUtils.isBlank(value)) {
            return false;
        }

        // 1. URL 인코딩 해제 (1차 및 다중 인코딩 우회 방지 2차 디코딩)
        String decoded = safeUrlDecode(value);
        if (decoded.contains("%")) {
            decoded = safeUrlDecode(decoded);
        }

        // 빠른 검사: SQLi 시그니처에 필수적인 특수문자나 공백이 없으면 12개 무거운 정규식 검사를 즉시 건너뜀
        if (!hasSqlInjectionIndicators(decoded)) {
            return false;
        }

        // 2. SQL / JCR 인젝션 정규식 일치 검사
        for (Pattern pattern : SQLI_PATTERNS) {
            if (pattern.matcher(decoded).find()) {
                return true;
            }
        }

        return false;
    }

    private static boolean hasSqlInjectionIndicators(String s) {
        final int len = s.length();
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c == '\'' || c == '"' || c == ';' || c == '-' || c == '/' || c == '*' || c == '#'
                    || c == '(' || c == ')' || c == '[' || c == ']' || c == '=' || c == '<'
                    || c == '>' || c == '@' || c == ':' || Character.isWhitespace(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * CWE-79: Cross-Site Scripting (XSS) 악성 스크립트 태그 및 이벤트 핸들러 시그니처를 정밀 검사합니다.
     *
     * [방어 대상 공격 유형]:
     * 1. Script 태그 주입: <script>, </script>, <script src="...">
     * 2. 인라인 이벤트 핸들러 주입: onload=, onerror=, onclick=, onmouseover= 등
     * 3. 가상 스키마 주입: javascript:, vbscript:, data:text/html
     * 4. 취약한 HTML 태그: <iframe, <object, <embed, <svg onload=, <img onerror=
     * 5. DOM 제어 및 쿠키 탈취 함수: document.cookie, window.location, eval()
     *
     * @param value 검증할 파라미터 값
     * @return XSS 공격 시그니처가 감지되면 true (위험), 정상이면 false (안전)
     */
    public static boolean isXssAttack(String value) {
        if (StringUtils.isBlank(value)) {
            return false;
        }

        // 1. URL 인코딩 해제 (다중 인코딩 우회 방지)
        String decoded = safeUrlDecode(value);
        if (decoded.contains("%")) {
            decoded = safeUrlDecode(decoded);
        }

        // 2. HTML 엔티티 정규화 (&lt; -> <, &#x3c; -> < 등)
        String normalized = unescapeHtml(decoded);

        // 빠른 지시자 검사: XSS에 필요한 핵심 트리거 문자 존재 여부 판별
        boolean hasLt = normalized.indexOf('<') != -1;
        boolean hasColon = normalized.indexOf(':') != -1;
        boolean hasEqual = normalized.indexOf('=') != -1;
        boolean hasParen = normalized.indexOf('(') != -1;
        boolean hasDot = normalized.indexOf('.') != -1;

        if (!hasLt && !hasColon && !hasEqual && !hasParen && !hasDot) {
            return false;
        }

        // 3. 지시자가 존재하는 범주에 한해서만 선별적 정규식 일치 검사 (불필요한 전체 정규식 스캔 방지)
        if (hasLt) {
            for (Pattern pattern : XSS_TAG_PATTERNS) {
                if (pattern.matcher(normalized).find()) return true;
            }
        }
        if (hasColon) {
            for (Pattern pattern : XSS_SCHEME_PATTERNS) {
                if (pattern.matcher(normalized).find()) return true;
            }
        }
        if (hasEqual) {
            for (Pattern pattern : XSS_EVENT_PATTERNS) {
                if (pattern.matcher(normalized).find()) return true;
            }
        }
        if (hasParen) {
            for (Pattern pattern : XSS_FUNC_PATTERNS) {
                if (pattern.matcher(normalized).find()) return true;
            }
        }
        if (hasDot) {
            for (Pattern pattern : XSS_DOM_PATTERNS) {
                if (pattern.matcher(normalized).find()) return true;
            }
        }

        return false;
    }

    /**
     * HTML 특수문자 및 숫자형/16진수 엔티티를 정규화하여 XSS 우회 인코딩을 무력화합니다.
     * 엔티티 시작 기호('&')가 없으면 문자열 생성 없이 즉시 반환합니다.
     */
    private static String unescapeHtml(String input) {
        if (input == null || input.indexOf('&') == -1) {
            return input;
        }
        String s = input;
        if (s.contains("&lt;")) s = s.replace("&lt;", "<");
        if (s.contains("&gt;")) s = s.replace("&gt;", ">");
        if (s.contains("&quot;")) s = s.replace("&quot;", "\"");
        if (s.contains("&apos;")) s = s.replace("&apos;", "'");
        if (s.contains("&amp;")) s = s.replace("&amp;", "&");
        if (s.contains("&#")) {
            s = HEX_LT_PATTERN.matcher(s).replaceAll("<");
            s = HEX_GT_PATTERN.matcher(s).replaceAll(">");
        }
        return s;
    }
}
