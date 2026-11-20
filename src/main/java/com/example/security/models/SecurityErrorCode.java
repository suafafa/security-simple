package com.example.security.models;

/**
 * 경량 보안 필터(Method, Param, Referer)에서 사용하는 표준 보안 에러 코드(SEC-XXXXX),
 * HTTP 상태 코드 및 응답 메시지 템플릿을 정의하는 열거형입니다.
 */
public enum SecurityErrorCode {

    // 401 Unauthorized (인증 필요)
    AUTH_REQUIRED(401, "SEC-40101", "Unauthorized: Authentication required"),

    // 403 Forbidden (권한, 보안 토큰, Referer 및 RunMode 검증 실패)
    AUTH_TYPE_FORBIDDEN(403, "SEC-40301", "Forbidden: Access denied for auth type: %s"),
    ROLE_INSUFFICIENT(403, "SEC-40302", "Forbidden: Insufficient role permissions"),
    REFERER_UNTRUSTED(403, "SEC-40303", "Forbidden: Invalid or untrusted Referer"),
    CSRF_TOKEN_REQUIRED(403, "SEC-40304", "Forbidden: CSRF token is required"),
    RUNMODE_NOT_ALLOWED(403, "SEC-40305", "Forbidden: Endpoint is not permitted in current runmode"),
    CSRF_TOKEN_INVALID(403, "SEC-40306", "Forbidden: Invalid CSRF token"),
    OAUTH_STATE_REQUIRED(403, "SEC-40307", "Forbidden: OAuth state is required for CSRF validation"),
    OAUTH_STATE_MISMATCH(403, "SEC-40308", "Forbidden: OAuth state mismatch"),
    GRANITE_CSRF_REQUIRED(403, "SEC-40309", "Forbidden: Granite CSRF token is required"),
    GRANITE_CSRF_INVALID(403, "SEC-40310", "Forbidden: Invalid Granite CSRF token"),

    // 405 Method Not Allowed (HTTP 메서드 제한)
    METHOD_NOT_ALLOWED(405, "SEC-40501", "Method Not Allowed: %s"),

    // 400 Bad Request (파라미터 제약조건, 경로 조작, 오픈 리다이렉트 방어)
    PARAM_REQUIRED(400, "SEC-40001", "Bad Request: Missing required parameter: %s"),
    PARAM_UNDEFINED(400, "SEC-40002", "Bad Request: Parameter [%s] is not permitted"),
    PARAM_TOO_SHORT(400, "SEC-40003", "Bad Request: Parameter [%s] is too short (min: %d)"),
    PARAM_TOO_LONG(400, "SEC-40004", "Bad Request: Parameter [%s] exceeds max length of %d"),
    PARAM_INVALID_FORMAT(400, "SEC-40005", "Bad Request: Parameter [%s] has invalid format"),
    RESPONSE_TYPE_JSONP_INVALID(400, "SEC-40006", "Bad Request: Invalid JSONP callback parameter: %s"),

    /**
     * CWE-22: Path Traversal / Directory Traversal 방어 에러 코드
     * 파라미터 값에 상위 디렉토리 이동(../, ..\), 2중 URL 인코딩(%252e%252e), 널 바이트(%00) 주입이 감지되었을 때 반환
     */
    PARAM_PATH_TRAVERSAL(400, "SEC-40007", "Bad Request: Potential Path Traversal attack detected in parameter [%s]"),

    /**
     * CWE-601: Open Redirect (오픈 리다이렉트) 방어 에러 코드
     */
    OPEN_REDIRECT_FORBIDDEN(400, "SEC-40010", "Bad Request: Untrusted or invalid redirect URL: %s"),

    // 406 Not Acceptable & Response Validation (응답 타입 제약조건)
    RESPONSE_TYPE_NOT_ACCEPTABLE(406, "SEC-40601", "Not Acceptable: Client Accept header [%s] incompatible with required responseType [%s]"),

    // 413 Payload Too Large (요청 페이로드 크기 초과)
    PAYLOAD_TOO_LARGE(413, "SEC-41301", "Payload Too Large: Request body exceeds maximum allowed size of %d bytes"),

    // 429 Too Many Requests (Rate Limiting 속도 제한 초과)
    RATE_LIMIT_EXCEEDED(429, "SEC-42901", "Too Many Requests: Rate limit exceeded for target [%s]. Retry after %d seconds");

    private final int httpStatus;
    private final String subCode;
    private final String messageTemplate;

    /**
     * 보안 에러 코드 열거형 상수를 초기화합니다.
     *
     * @param httpStatus      클라이언트에 반환할 HTTP 상태 코드
     * @param subCode         표준 보안 서브 에러 코드 (예: "SEC-40002")
     * @param messageTemplate 응답 에러 메시지 포맷 템플릿
     */
    SecurityErrorCode(int httpStatus, String subCode, String messageTemplate) {
        this.httpStatus = httpStatus;
        this.subCode = subCode;
        this.messageTemplate = messageTemplate;
    }

    /**
     * 이 에러 코드에 매핑된 HTTP 상태 코드를 반환합니다.
     *
     * @return HTTP 상태 코드 (400, 403, 405 등)
     */
    public int getHttpStatus() {
        return httpStatus;
    }

    /**
     * 표준 보안 서브 에러 코드 문자열(예: "SEC-40303")을 반환합니다.
     *
     * @return 표준 보안 서브 에러 코드
     */
    public String getSubCode() {
        return subCode;
    }

    /**
     * 메시지 템플릿에 인자를 대입하여 완성된 에러 메시지 문자열을 생성합니다.
     *
     * @param args 메시지 템플릿 포맷팅 인자 목록
     * @return 포맷팅된 에러 메시지 문자열
     */
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
