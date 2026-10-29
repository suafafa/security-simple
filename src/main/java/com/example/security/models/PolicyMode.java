package com.example.security.models;

import org.apache.commons.lang3.StringUtils;

/**
 * 보안 필터 및 개별 서블릿 정책, 개별 검증기의 동작 모드(차단 강제 vs 모니터링 로그 전용)를 정의하는 열거형입니다.
 * <ul>
 *   <li>{@link #ENFORCE} (기본값): 보안 정책 위반 시 즉시 요청을 차단하고 에러 응답(400/403/405 등)을 반환합니다.</li>
 *   <li>{@link #MONITOR}: 보안 검증 로직은 동일하게 수행하되, 위반 시 WARN 감사 로그만 기록하고 요청은 정상 통과시킵니다.</li>
 * </ul>
 */
public enum PolicyMode {

    /**
     * 위반 시 즉시 차단 및 JSON 에러 응답 반환 (기본값)
     */
    ENFORCE,

    /**
     * 위반 시 WARN 로그만 기록하고 다음 검증기 및 서블릿으로 통과 (Dry-Run / 모니터링 모드)
     */
    MONITOR;

    /**
     * 문자열 설정값(예: "ENFORCE", "MONITOR", "LOG_ONLY", "REPORT_ONLY", "BLOCK")을
     * {@link PolicyMode} 열거형으로 안전하게 변환합니다.
     *
     * @param value 파싱할 모드 문자열
     * @return 매칭된 {@link PolicyMode} (입력이 비어있거나 알 수 없는 값이면 null)
     */
    public static PolicyMode fromString(final String value) {
        if (StringUtils.isBlank(value)) {
            return null;
        }
        String normalized = value.trim().toUpperCase();
        if ("MONITOR".equals(normalized)
                || "MONITORING".equals(normalized)
                || "LOG_ONLY".equals(normalized)
                || "LOGONLY".equals(normalized)
                || "REPORT_ONLY".equals(normalized)
                || "REPORTONLY".equals(normalized)
                || "DRY_RUN".equals(normalized)
                || "DRYRUN".equals(normalized)) {
            return MONITOR;
        }
        if ("ENFORCE".equals(normalized)
                || "ENFORCED".equals(normalized)
                || "BLOCK".equals(normalized)
                || "STRICT".equals(normalized)) {
            return ENFORCE;
        }
        return null;
    }

    /**
     * 문자열 설정값을 파싱하되, 유효하지 않거나 null이면 지정된 기본값을 반환합니다.
     *
     * @param value       파싱할 모드 문자열
     * @param defaultMode 기본 모드
     * @return 파싱된 {@link PolicyMode} 또는 {@code defaultMode}
     */
    public static PolicyMode fromStringOrDefault(final String value, final PolicyMode defaultMode) {
        PolicyMode parsed = fromString(value);
        return parsed != null ? parsed : defaultMode;
    }

    /**
     * 현재 모드가 모니터링(로그 전용) 모드인지 여부를 반환합니다.
     *
     * @return {@link #MONITOR}이면 true, 아니면 false
     */
    public boolean isMonitor() {
        return this == MONITOR;
    }

    /**
     * 현재 모드가 차단 강제(ENFORCE) 모드인지 여부를 반환합니다.
     *
     * @return {@link #ENFORCE}이면 true, 아니면 false
     */
    public boolean isEnforce() {
        return this == ENFORCE;
    }
}
