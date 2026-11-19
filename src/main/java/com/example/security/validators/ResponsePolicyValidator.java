package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

/**
 * 서블릿의 응답 타입({@code responseType}) 사전 계약을 검증하는 모듈형 검증기입니다:
 * <ul>
 *   <li>클라이언트의 {@code Accept} 헤더가 대상 서블릿의 {@code responseType}과 호환되는지 검증 (불일치 시 406 SEC-40601 차단)</li>
 *   <li>{@code JSONP} 응답 시 콜백({@code callback}) 파라미터 식별자의 XSS 안전성을 사전 검증 (위반 시 400 SEC-40006 차단)</li>
 * </ul>
 * <p>
 * {@link ServletPolicyRule} 수정 없이 {@code extensions} 맵에서
 * {@code "responseType"}, {@code "defaultResponseType"}, {@code "callbackParam"} 설정을 읽어 동작합니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class ResponsePolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "RESPONSE";
    public static final int ORDER = 40;

    public static final String RESP_DEFAULT = "DEFAULT";
    public static final String RESP_JSON = "JSON";
    public static final String RESP_JSONP = "JSONP";
    public static final String RESP_HTML = "HTML";
    public static final String RESP_FILE = "FILE";
    public static final String RESP_REDIRECT = "REDIRECT";

    private static final Pattern VALID_CALLBACK_PATTERN = Pattern.compile("^[a-zA-Z_$][a-zA-Z0-9_$.]*$");

    private static final String[] RESPONSE_TYPE_KEYS = {
            "responseType", "response_type", "type", "security.responseType"
    };
    private static final String[] DEFAULT_RESPONSE_TYPE_KEYS = {
            "defaultResponseType", "default_response_type"
    };
    private static final String[] CALLBACK_PARAM_KEYS = {
            "callbackParam", "callback", "jsonpCallbackParam", "jsonpParam"
    };

    public ResponsePolicyValidator() {
        super(NAME, ORDER);
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        String expectedType = resolveExpectedResponseType(policy, rootConfig);
        if (expectedType == null || RESP_DEFAULT.equals(expectedType)) {
            return pass();
        }

        // 1. 클라이언트 Accept 헤더 호환성 검사
        String acceptHeader = request != null ? request.getHeader("Accept") : null;
        if (StringUtils.isNotBlank(acceptHeader)) {
            String lowerAccept = acceptHeader.toLowerCase().trim();
            if (!isAcceptCompatible(lowerAccept, expectedType)) {
                String blockedConfig = "responseType=" + expectedType + ", clientAccept=" + SecurityUtils.sanitizeForLog(acceptHeader);
                return block(
                        policy,
                        SecurityErrorCode.RESPONSE_TYPE_NOT_ACCEPTABLE,
                        blockedConfig,
                        "Client Accept header [" + SecurityUtils.sanitizeForLog(acceptHeader)
                                + "] is incompatible with responseType [" + expectedType + "] for target: "
                                + SecurityUtils.sanitizeForLog(policy != null ? policy.getTarget() : ""),
                        acceptHeader, expectedType
                );
            }
        }

        // 2. JSONP 콜백 파라미터 검증 (XSS 스크립트 주입 방지)
        if (RESP_JSONP.equals(expectedType)) {
            String callbackParam = resolveCallbackParam(policy);
            String callback = request != null ? request.getParameter(callbackParam) : null;
            if (StringUtils.isBlank(callback)) {
                String blockedConfig = "responseType=JSONP, callbackParam=" + callbackParam + ", actualValue=MISSING";
                return block(
                        policy,
                        SecurityErrorCode.PARAM_REQUIRED,
                        blockedConfig,
                        "Missing required JSONP callback parameter [" + callbackParam + "] for target: "
                                + SecurityUtils.sanitizeForLog(policy != null ? policy.getTarget() : ""),
                        callbackParam
                );
            }
            if (!VALID_CALLBACK_PATTERN.matcher(callback).matches()) {
                String blockedConfig = "responseType=JSONP, callbackParam=" + callbackParam
                        + ", invalidCallback=" + SecurityUtils.sanitizeForLog(callback);
                return block(
                        policy,
                        SecurityErrorCode.RESPONSE_TYPE_JSONP_INVALID,
                        blockedConfig,
                        "Invalid or unsafe JSONP callback parameter [" + SecurityUtils.sanitizeForLog(callback) + "] for target: "
                                + SecurityUtils.sanitizeForLog(policy != null ? policy.getTarget() : ""),
                        callback
                );
            }
        }

        return pass();
    }

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        String expectedType = resolveExpectedResponseType(policy, rootConfig);
        String acceptHeader = request != null ? StringUtils.defaultIfBlank(request.getHeader("Accept"), "*/*") : "*/*";
        if (RESP_JSONP.equals(expectedType)) {
            String callbackParam = resolveCallbackParam(policy);
            return "responseType=" + expectedType + ", callbackParam=" + callbackParam + ", clientAccept=" + acceptHeader;
        }
        return "responseType=" + expectedType + ", clientAccept=" + acceptHeader;
    }

    private String resolveExpectedResponseType(final ServletPolicyRule policy, final ServletSecurityConfig rootConfig) {
        if (policy != null) {
            String rt = policy.getExtensionString(RESPONSE_TYPE_KEYS);
            if (StringUtils.isNotBlank(rt) && !RESP_DEFAULT.equalsIgnoreCase(rt.trim())) {
                return rt.trim().toUpperCase();
            }
            String defRt = policy.getExtensionString(DEFAULT_RESPONSE_TYPE_KEYS);
            if (StringUtils.isNotBlank(defRt)) {
                return defRt.trim().toUpperCase();
            }
        }
        if (rootConfig != null && rootConfig.getDefaultPolicy() != null) {
            String rootRt = rootConfig.getDefaultPolicy().getExtensionString(DEFAULT_RESPONSE_TYPE_KEYS);
            if (StringUtils.isNotBlank(rootRt)) {
                return rootRt.trim().toUpperCase();
            }
        }
        return RESP_DEFAULT;
    }

    private String resolveCallbackParam(final ServletPolicyRule policy) {
        if (policy != null) {
            String cb = policy.getExtensionString(CALLBACK_PARAM_KEYS);
            if (StringUtils.isNotBlank(cb)) {
                return cb.trim();
            }
        }
        return "callback";
    }

    private boolean isAcceptCompatible(final String lowerAccept, final String expectedType) {
        if (lowerAccept.contains("*/*")) {
            return true;
        }
        if (RESP_JSON.equals(expectedType)) {
            return lowerAccept.contains("application/json") || lowerAccept.contains("text/json")
                    || lowerAccept.contains("application/*");
        }
        if (RESP_JSONP.equals(expectedType)) {
            return lowerAccept.contains("javascript") || lowerAccept.contains("application/json")
                    || lowerAccept.contains("*/*");
        }
        if (RESP_HTML.equals(expectedType)) {
            return lowerAccept.contains("text/html") || lowerAccept.contains("text/*");
        }
        return true;
    }
}
