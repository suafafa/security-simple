package com.example.security.utils;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * 클라이언트 IP 추출 및 로그 인젝션(CRLF) 방어를 위한 문자열 정제 유틸리티 클래스입니다.
 */
public final class SecurityUtils {

    private SecurityUtils() {
    }

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

    public static String sanitizeForLog(final String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\n', '_').replace('\r', '_');
    }
}
