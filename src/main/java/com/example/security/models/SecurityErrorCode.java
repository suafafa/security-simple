package com.example.security.models;

/**
 * 경량 보안 필터(Method, Param, Referer)에서 사용하는 표준 보안 에러 코드(SEC-XXXXX),
 * HTTP 상태 코드 및 응답 메시지 템플릿을 정의하는 열거형입니다.
 */
public enum SecurityErrorCode {

    // 403 Forbidden (Referer 검증 실패)
    REFERER_UNTRUSTED(403, "SEC-40303", "Forbidden: Invalid or untrusted Referer"),

    // 405 Method Not Allowed (HTTP 메서드 제한)
    METHOD_NOT_ALLOWED(405, "SEC-40501", "Method Not Allowed: %s"),

    // 400 Bad Request (파라미터 제약조건 및 인젝션/XSS 방어)
    PARAM_REQUIRED(400, "SEC-40001", "Bad Request: Missing required parameter: %s"),
    PARAM_UNDEFINED(400, "SEC-40002", "Bad Request: Parameter [%s] is not permitted"),
    PARAM_TOO_SHORT(400, "SEC-40003", "Bad Request: Parameter [%s] is too short (min: %d)"),
    PARAM_TOO_LONG(400, "SEC-40004", "Bad Request: Parameter [%s] exceeds max length of %d"),
    PARAM_INVALID_FORMAT(400, "SEC-40005", "Bad Request: Parameter [%s] has invalid format"),

    /**
     * CWE-22: Path Traversal / Directory Traversal 방어 에러 코드
     * 파라미터 값에 상위 디렉토리 이동(../, ..\), 2중 URL 인코딩(%252e%252e), 널 바이트(%00) 주입이 감지되었을 때 반환
     */
    PARAM_PATH_TRAVERSAL(400, "SEC-40007", "Bad Request: Potential Path Traversal attack detected in parameter [%s]"),

    /**
     * CWE-89: SQL / JCR-SQL2 / XPath Injection 방어 에러 코드
     */
    PARAM_SQL_INJECTION(400, "SEC-40008", "Bad Request: Potential SQL/JCR Injection attack detected in parameter [%s]"),

    /**
     * CWE-79: Cross-Site Scripting (XSS) 방어 에러 코드
     */
    PARAM_XSS(400, "SEC-40009", "Bad Request: Potential Cross-Site Scripting (XSS) attack detected in parameter [%s]");

    private final int httpStatus;
    private final String subCode;
    private final String messageTemplate;

    SecurityErrorCode(int httpStatus, String subCode, String messageTemplate) {
        this.httpStatus = httpStatus;
        this.subCode = subCode;
        this.messageTemplate = messageTemplate;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getSubCode() {
        return subCode;
    }

    public String getMessageTemplate() {
        return messageTemplate;
    }

    public String format(Object... args) {
        if (args != null && args.length > 0) {
            try {
                return String.format(messageTemplate, args);
            } catch (Exception ignored) {
            }
        }
        return messageTemplate;
    }
}
