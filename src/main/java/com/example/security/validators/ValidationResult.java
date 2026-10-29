package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;

/**
 * 개별 보안 정책 검증 단계의 수행 결과를 담는 불변(Immutable) 결과 객체입니다.
 * 검증 성공 여부, HTTP 상태 코드, 표준 보안 에러 코드(SEC-XXXXX),
 * 차단을 유발한 구체적인 설정값(blockedConfig), 상세 위반 사유 및 클라이언트 응답 메시지를 보관합니다.
 */
public class ValidationResult {

    private static final ValidationResult OK = new ValidationResult(true, 200, null, null, "NONE", null, null);

    private final boolean valid;
    private final int statusCode;
    private final SecurityErrorCode errorCode;
    private final String customSubCode;
    private final String blockedConfig;
    private final String violationDetail;
    private final String responseMessage;

    /**
     * 검증 결과 객체를 생성합니다.
     *
     * @param valid           검증 통과 여부 (통과 시 true, 차단 시 false)
     * @param statusCode      HTTP 응답 상태 코드 (예: 200, 400, 403, 405)
     * @param errorCode       표준 보안 에러 코드 열거형
     * @param customSubCode   커스텀 서브 에러 코드 문자열 (errorCode가 null일 때 사용)
     * @param blockedConfig   차단 원인이 된 구체적인 보안 설정값 요약 문자열
     * @param violationDetail 서버 로그 기록용 상세 위반 사유
     * @param responseMessage 클라이언트에 반환할 JSON 에러 메시지
     */
    private ValidationResult(boolean valid, int statusCode, SecurityErrorCode errorCode,
                             String customSubCode, String blockedConfig,
                             String violationDetail, String responseMessage) {
        this.valid = valid;
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.customSubCode = customSubCode;
        this.blockedConfig = blockedConfig;
        this.violationDetail = violationDetail;
        this.responseMessage = responseMessage;
    }

    /**
     * 검증을 정상 통과했음을 나타내는 싱글턴 결과 객체를 반환합니다.
     *
     * @return 검증 성공 ValidationResult 인스턴스
     */
    public static ValidationResult ok() {
        return OK;
    }

    /**
     * 보안 정책 위반으로 인한 차단 결과 객체를 생성합니다.
     *
     * @param errorCode       표준 보안 에러 코드
     * @param violationDetail 서버 로그용 상세 위반 내용
     * @param messageArgs     에러 메시지 템플릿 포맷팅 인자
     * @return 검증 실패 ValidationResult 인스턴스
     */
    public static ValidationResult error(SecurityErrorCode errorCode, String violationDetail, Object... messageArgs) {
        return errorWithConfig(errorCode, violationDetail, violationDetail, messageArgs);
    }

    /**
     * 차단을 유발한 구체적인 설정값 정보(blockedConfig)를 포함하여 보안 정책 위반 결과 객체를 생성합니다.
     *
     * @param errorCode       표준 보안 에러 코드
     * @param blockedConfig   차단 원인이 된 설정값 및 입력값 상세 비교 문자열
     * @param violationDetail 서버 로그용 상세 위반 내용
     * @param messageArgs     에러 메시지 템플릿 포맷팅 인자
     * @return 검증 실패 ValidationResult 인스턴스
     */
    public static ValidationResult errorWithConfig(SecurityErrorCode errorCode, String blockedConfig,
                                                   String violationDetail, Object... messageArgs) {
        if (errorCode == null) {
            return new ValidationResult(false, 400, null, null, blockedConfig, violationDetail, violationDetail);
        }
        String message = errorCode.format(messageArgs);
        return new ValidationResult(false, errorCode.getHttpStatus(), errorCode, errorCode.getSubCode(), blockedConfig, violationDetail, message);
    }

    /**
     * 사용자 정의 HTTP 상태 코드와 메시지로 차단 결과 객체를 생성합니다.
     *
     * @param statusCode      HTTP 상태 코드
     * @param violationDetail 서버 로그용 상세 위반 내용
     * @param responseMessage 클라이언트에 반환할 응답 메시지
     * @return 검증 실패 ValidationResult 인스턴스
     */
    public static ValidationResult error(int statusCode, String violationDetail, String responseMessage) {
        return new ValidationResult(false, statusCode, null, null, violationDetail, violationDetail, responseMessage);
    }

    /**
     * {@link SecurityErrorCode} 열거형 수정 없이 커스텀 서브 에러 코드와 차단 설정 정보를 포함하여 차단 결과 객체를 생성합니다.
     *
     * @param statusCode      HTTP 상태 코드
     * @param customSubCode   표준 보안 서브 에러 코드 문자열 (예: "SEC-40305")
     * @param blockedConfig   차단 원인이 된 설정값 및 입력값 상세 비교 문자열
     * @param violationDetail 서버 로그용 상세 위반 내용
     * @param responseMessage 클라이언트에 반환할 응답 메시지
     * @return 검증 실패 ValidationResult 인스턴스
     */
    public static ValidationResult errorCustom(int statusCode, String customSubCode, String blockedConfig,
                                               String violationDetail, String responseMessage) {
        return new ValidationResult(false, statusCode, null, customSubCode, blockedConfig, violationDetail, responseMessage);
    }

    /**
     * 검증 통과 여부를 반환합니다.
     *
     * @return 통과 시 true, 차단 시 false
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * HTTP 응답 상태 코드를 반환합니다.
     *
     * @return HTTP 상태 코드 (예: 200, 400, 403, 405)
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * 표준 보안 에러 코드 열거형을 반환합니다.
     *
     * @return SecurityErrorCode 인스턴스 (없을 경우 null)
     */
    public SecurityErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * 표준 보안 서브 에러 코드 문자열(예: "SEC-40002")을 반환합니다.
     *
     * @return 에러 코드 문자열 (없을 경우 null)
     */
    public String getSubCode() {
        return errorCode != null ? errorCode.getSubCode() : customSubCode;
    }

    /**
     * 요청을 차단하게 만든 구체적인 설정값 및 입력값 정보를 반환합니다.
     *
     * @return 차단 설정 상세 문자열
     */
    public String getBlockedConfig() {
        return blockedConfig != null ? blockedConfig : "UNKNOWN";
    }

    /**
     * 서버 보안 감사 로그에 기록할 상세 위반 사유를 반환합니다.
     *
     * @return 상세 위반 사유 문자열
     */
    public String getViolationDetail() {
        return violationDetail;
    }

    /**
     * 클라이언트 JSON 응답 본문에 포함될 에러 메시지를 반환합니다.
     *
     * @return 클라이언트 응답 에러 메시지
     */
    public String getResponseMessage() {
        return responseMessage;
    }
}
