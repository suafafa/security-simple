package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;

/**
 * 개별 보안 정책 검증 단계의 수행 결과를 담는 불변 DTO 클래스입니다.
 */
public class ValidationResult {

    private static final ValidationResult OK = new ValidationResult(true, 200, null, null, null);

    private final boolean valid;
    private final int statusCode;
    private final SecurityErrorCode errorCode;
    private final String violationDetail;
    private final String responseMessage;

    private ValidationResult(boolean valid, int statusCode, SecurityErrorCode errorCode, String violationDetail, String responseMessage) {
        this.valid = valid;
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.violationDetail = violationDetail;
        this.responseMessage = responseMessage;
    }

    public static ValidationResult ok() {
        return OK;
    }

    public static ValidationResult error(SecurityErrorCode errorCode, String violationDetail, Object... messageArgs) {
        if (errorCode == null) {
            return new ValidationResult(false, 400, null, violationDetail, violationDetail);
        }
        String message = errorCode.format(messageArgs);
        return new ValidationResult(false, errorCode.getHttpStatus(), errorCode, violationDetail, message);
    }

    public static ValidationResult error(int statusCode, String violationDetail, String responseMessage) {
        return new ValidationResult(false, statusCode, null, violationDetail, responseMessage);
    }

    public boolean isValid() {
        return valid;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public SecurityErrorCode getErrorCode() {
        return errorCode;
    }

    public String getSubCode() {
        return errorCode != null ? errorCode.getSubCode() : null;
    }

    public String getViolationDetail() {
        return violationDetail;
    }

    public String getResponseMessage() {
        return responseMessage;
    }
}
