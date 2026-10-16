package com.example.security.utils;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * 클라이언트 IP 추출 및 로그 인젝션(CRLF) 방어를 위한 문자열 정제 유틸리티 클래스입니다.
 */
public final class SecurityUtils {

    private SecurityUtils() {
    }

    /**
     * 프록시/로드밸런서 환경(X-Forwarded-For 헤더)을 고려하여 요청 클라이언트의 실제 IP 주소를 추출합니다.
     *
     * @param request 유입된 HTTP 요청
     * @return 클라이언트 IP 주소 문자열
     */
    public static String getClientIp(final HttpServletRequest request) {
        if (request == null) {
            return "";
        }
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.isNotBlank(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "";
    }

    /**
     * 로그 인젝션(CRLF Injection) 공격을 방지하기 위해 문자열 내 개행 문자(\r, \n)를 언더스코어('_')로 치환합니다.
     *
     * @param value 정제할 원본 문자열
     * @return 개행 문자가 제거된 안전한 로그 출력용 문자열
     */
    public static String sanitizeForLog(final String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\n', '_').replace('\r', '_');
    }
}
