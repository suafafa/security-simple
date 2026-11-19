package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * 요청 페이로드 크기 제한 검증기 (CWE-400 / CWE-770)
 * <p>
 * 본문(Stream)을 메모리에 버퍼링하기 전 {@code Content-Length} 헤더를 사전 검증하여 즉시 차단(Fail-Fast)합니다.
 * {@link ServletPolicyRule} 수정 없이 {@code extensions} 맵에서 {@code "maxPayloadSize"}
 * (예: {@code "5MB"}, {@code "500KB"}, {@code 2097152}) 설정을 읽어 동작합니다 (기본값: 2MB).
 */
@Component(service = PolicyValidator.class, immediate = true)
public class PayloadSizePolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "PAYLOAD_SIZE";
    public static final int ORDER = 25;
    public static final long DEFAULT_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024L; // 기본값 2MB

    private static final String[] PAYLOAD_SIZE_KEYS = {
            "maxPayloadSize", "max_payload_size", "maxBodySize", "maxContentLength", "security.maxPayloadSize"
    };

    public PayloadSizePolicyValidator() {
        super(NAME, ORDER);
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (request == null) {
            return pass();
        }

        String method = request.getMethod();
        // 본문(Body)을 수반할 수 있는 HTTP 메서드만 대상
        if (!"POST".equalsIgnoreCase(method) && !"PUT".equalsIgnoreCase(method) && !"PATCH".equalsIgnoreCase(method)) {
            return pass();
        }

        long maxAllowedBytes = resolveMaxPayloadSize(policy);

        long contentLength = request.getContentLengthLong();
        if (contentLength <= 0) {
            contentLength = request.getContentLength();
        }

        if (contentLength > maxAllowedBytes) {
            String blockedConfig = "maxPayloadSize=" + maxAllowedBytes + "B, requestContentLength=" + contentLength + "B";
            return block(
                    policy,
                    SecurityErrorCode.PAYLOAD_TOO_LARGE,
                    blockedConfig,
                    "Payload Too Large: Request body (" + contentLength + " bytes) exceeds maximum limit of " + maxAllowedBytes + " bytes",
                    maxAllowedBytes
            );
        }

        return pass();
    }

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        long maxAllowedBytes = resolveMaxPayloadSize(policy);
        String rawMax = policy != null ? policy.getExtensionString(PAYLOAD_SIZE_KEYS) : null;
        if (StringUtils.isBlank(rawMax)) {
            rawMax = maxAllowedBytes + "B";
        }
        long contentLength = -1;
        if (request != null) {
            contentLength = request.getContentLengthLong();
            if (contentLength <= 0) {
                contentLength = request.getContentLength();
            }
        }
        return "maxPayloadSize=" + rawMax + "(" + maxAllowedBytes + "B), requestContentLength=" + Math.max(0, contentLength) + "B";
    }

    public static long resolveMaxPayloadSize(final ServletPolicyRule policy) {
        if (policy == null) {
            return DEFAULT_MAX_PAYLOAD_BYTES;
        }
        String raw = policy.getExtensionString(PAYLOAD_SIZE_KEYS);
        if (StringUtils.isBlank(raw)) {
            return DEFAULT_MAX_PAYLOAD_BYTES;
        }
        return parsePayloadSize(raw);
    }

    public static long parsePayloadSize(final Object sizeObj) {
        if (sizeObj == null) {
            return DEFAULT_MAX_PAYLOAD_BYTES;
        }
        if (sizeObj instanceof Number) {
            return ((Number) sizeObj).longValue();
        }
        String str = sizeObj.toString().trim().toUpperCase();
        if (StringUtils.isBlank(str)) {
            return DEFAULT_MAX_PAYLOAD_BYTES;
        }
        try {
            if (str.endsWith("KB") || str.endsWith("K")) {
                String num = str.replaceAll("[^0-9.]", "");
                return (long) (Double.parseDouble(num) * 1024);
            } else if (str.endsWith("MB") || str.endsWith("M")) {
                String num = str.replaceAll("[^0-9.]", "");
                return (long) (Double.parseDouble(num) * 1024 * 1024);
            } else if (str.endsWith("GB") || str.endsWith("G")) {
                String num = str.replaceAll("[^0-9.]", "");
                return (long) (Double.parseDouble(num) * 1024 * 1024 * 1024);
            } else if (str.endsWith("B")) {
                String num = str.replaceAll("[^0-9.]", "");
                return (long) Double.parseDouble(num);
            } else {
                return (long) Double.parseDouble(str);
            }
        } catch (Exception e) {
            return DEFAULT_MAX_PAYLOAD_BYTES;
        }
    }
}
