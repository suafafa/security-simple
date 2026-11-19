package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * CSRF(사이트 간 요청 위조) 방어 메커니즘을 검증하는 모듈형 검증기입니다:
 * <ul>
 *   <li>{@code NONE}: CSRF 검증 비활성화(생략)</li>
 *   <li>{@code TOKEN}: 표준 일반 CSRF 토큰 검증 (요청 헤더 또는 파라미터)</li>
 *   <li>{@code OAUTH_STATE}: OAuth 2.0 / OIDC 인가 콜백 시 세션/쿠키와 state 파라미터 일치 여부 검증</li>
 *   <li>{@code GRANITE}: Adobe Granite CSRF 토큰 검증 ({@code :cq_csrf_token} 파라미터 또는 {@code CSRF-Token} 헤더)</li>
 * </ul>
 * <p>
 * {@link ServletPolicyRule} 클래스를 수정하지 않고 {@code extensions} 맵에서
 * {@code "csrf"} (또는 {@code "csrfType"}, {@code "csrfCheck"}) 설정을 읽어 동작합니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class CsrfPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "CSRF";
    public static final int ORDER = 15;

    public static final String CSRF_NONE = "NONE";
    public static final String CSRF_TOKEN = "TOKEN";
    public static final String CSRF_GRANITE = "GRANITE";
    public static final String CSRF_OAUTH_STATE = "OAUTH_STATE";

    private static final String[] CSRF_KEYS = {
            "csrf", "csrfType", "csrfCheck", "security.csrf"
    };

    private Object csrfTokenService;

    private volatile Method cachedIsValidRequestMethod;
    private volatile Method cachedIsValidMethod;
    private volatile Class<?> cachedServiceClass;

    public CsrfPolicyValidator() {
        super(NAME, ORDER);
    }

    public CsrfPolicyValidator(final Object csrfTokenService) {
        super(NAME, ORDER);
        this.csrfTokenService = csrfTokenService;
    }

    public void setCsrfTokenService(final Object csrfTokenService) {
        this.csrfTokenService = csrfTokenService;
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return pass();
        }

        String csrf = resolveCsrfMode(policy);
        if (CSRF_NONE.equals(csrf)) {
            return pass();
        }

        switch (csrf) {
            case CSRF_TOKEN:
                return validateGenericToken(request, policy);
            case CSRF_OAUTH_STATE:
                return validateOAuthState(request, policy);
            case CSRF_GRANITE:
                return validateGraniteToken(request, policy);
            default:
                return pass();
        }
    }

    @Override
    public String describePassedConfig(final HttpServletRequest request,
                                       final ServletPolicyRule policy,
                                       final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return "NONE";
        }
        return "csrf=" + resolveCsrfMode(policy);
    }

    private String resolveCsrfMode(final ServletPolicyRule policy) {
        if (policy == null) {
            return CSRF_NONE;
        }
        String raw = policy.getExtensionString(CSRF_KEYS);
        return StringUtils.isNotBlank(raw) ? raw.trim().toUpperCase() : CSRF_NONE;
    }

    /**
     * 요청 헤더(X-CSRF-Token, CSRF-Token, X-XSRF-TOKEN) 또는
     * 파라미터(_csrf, csrf_token, csrfToken, :cq_csrf_token, token)로부터 표준 CSRF 토큰을 검증합니다.
     */
    private ValidationResult validateGenericToken(final HttpServletRequest request, final ServletPolicyRule policy) {
        String token = request != null ? request.getHeader("X-CSRF-Token") : null;
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getHeader("CSRF-Token");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getHeader("X-XSRF-TOKEN");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getParameter("_csrf");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getParameter("csrf_token");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getParameter("csrfToken");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getParameter(":cq_csrf_token");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getParameter("token");
        }

        if (StringUtils.isBlank(token)) {
            return block(
                    policy,
                    SecurityErrorCode.CSRF_TOKEN_REQUIRED,
                    "csrf=TOKEN, token=MISSING",
                    "Missing CSRF token for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
            );
        }

        // 세션 또는 쿠키에 기대 토큰이 존재하는 경우 상수 시간 비교로 일치 여부 검증
        String expectedToken = getSessionAttribute(request, "CSRF_TOKEN");
        if (StringUtils.isBlank(expectedToken)) {
            expectedToken = getSessionAttribute(request, "_csrf");
        }
        if (StringUtils.isBlank(expectedToken)) {
            expectedToken = getCookieValue(request, "XSRF-TOKEN");
        }
        if (StringUtils.isBlank(expectedToken)) {
            expectedToken = getCookieValue(request, "CSRF-TOKEN");
        }

        if (StringUtils.isNotBlank(expectedToken)) {
            if (!constantTimeEquals(expectedToken, token)) {
                return block(
                        policy,
                        SecurityErrorCode.CSRF_TOKEN_INVALID,
                        "csrf=TOKEN, token=MISMATCH",
                        "CSRF token mismatch for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                );
            }
        }

        return pass();
    }

    /**
     * OAuth 2.0 / OIDC 인가 콜백 시 CSRF 방지를 위해 state 파라미터를 세션/쿠키 값과 대조 검증합니다.
     */
    private ValidationResult validateOAuthState(final HttpServletRequest request, final ServletPolicyRule policy) {
        String state = request != null ? request.getParameter("state") : null;
        if (StringUtils.isBlank(state) && request != null) {
            state = request.getHeader("X-OAuth-State");
        }

        if (StringUtils.isBlank(state)) {
            return block(
                    policy,
                    SecurityErrorCode.OAUTH_STATE_REQUIRED,
                    "csrf=OAUTH_STATE, state=MISSING",
                    "Missing OAuth state parameter for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
            );
        }

        // 세션 또는 쿠키에 저장된 기대 state 값과 대조 검증
        String expectedState = getSessionAttribute(request, "oauth_state");
        if (StringUtils.isBlank(expectedState)) {
            expectedState = getSessionAttribute(request, "state");
        }
        if (StringUtils.isBlank(expectedState)) {
            expectedState = getCookieValue(request, "oauth_state");
        }

        if (StringUtils.isNotBlank(expectedState)) {
            if (!constantTimeEquals(expectedState, state)) {
                return block(
                        policy,
                        SecurityErrorCode.OAUTH_STATE_MISMATCH,
                        "csrf=OAUTH_STATE, state=MISMATCH",
                        "OAuth state mismatch for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                );
            }
        }

        return pass();
    }

    /**
     * :cq_csrf_token 파라미터 또는 CSRF-Token 헤더를 통해 AEM Granite CSRF 토큰을 검증합니다.
     */
    private ValidationResult validateGraniteToken(final HttpServletRequest request, final ServletPolicyRule policy) {
        String token = request != null ? request.getHeader("CSRF-Token") : null;
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getHeader("X-CSRF-Token");
        }
        if (StringUtils.isBlank(token) && request != null) {
            token = request.getParameter(":cq_csrf_token");
        }

        if (StringUtils.isBlank(token)) {
            return block(
                    policy,
                    SecurityErrorCode.GRANITE_CSRF_REQUIRED,
                    "csrf=GRANITE, token=MISSING",
                    "Missing Granite CSRF token (:cq_csrf_token or CSRF-Token) for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
            );
        }

        // Granite CSRFTokenService OSGi 서비스가 바인딩되어 있는 경우 검증 위임
        if (csrfTokenService != null) {
            try {
                Boolean isValid = invokeCsrfTokenService(csrfTokenService, request, token);
                if (isValid != null && !isValid) {
                    return block(
                            policy,
                            SecurityErrorCode.GRANITE_CSRF_INVALID,
                            "csrf=GRANITE, token=REJECTED_BY_SERVICE",
                            "Granite CSRFTokenService rejected token for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                    );
                }
            } catch (Exception e) {
                log.debug("Error validating with Granite CSRFTokenService: {}", e.getMessage());
            }
        }

        // 기본 유효성 검사: 토큰 길이가 비정상적으로 짧은 경우 차단
        if (token.length() < 8) {
            return block(
                    policy,
                    SecurityErrorCode.GRANITE_CSRF_INVALID,
                    "csrf=GRANITE, tokenLength=" + token.length() + "(<8)",
                    "Malformed Granite CSRF token for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
            );
        }

        return pass();
    }

    private Boolean invokeCsrfTokenService(final Object service, final HttpServletRequest request, final String token) {
        if (service == null) return null;
        Class<?> clazz = service.getClass();
        if (clazz != cachedServiceClass) {
            cachedServiceClass = clazz;
            try {
                cachedIsValidRequestMethod = clazz.getMethod("isValidRequest", HttpServletRequest.class);
            } catch (NoSuchMethodException e) {
                cachedIsValidRequestMethod = null;
                try {
                    cachedIsValidMethod = clazz.getMethod("isValid", HttpServletRequest.class, String.class);
                } catch (Exception ignored) {
                    cachedIsValidMethod = null;
                }
            }
        }

        try {
            if (cachedIsValidRequestMethod != null) {
                return (Boolean) cachedIsValidRequestMethod.invoke(service, request);
            }
            if (cachedIsValidMethod != null) {
                return (Boolean) cachedIsValidMethod.invoke(service, request, token);
            }
        } catch (Exception e) {
            log.debug("Error invoking cached Granite CSRFTokenService method: {}", e.getMessage());
        }
        return null;
    }

    private String getCookieValue(final HttpServletRequest request, final String cookieName) {
        if (request == null || request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (cookieName.equalsIgnoreCase(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private String getSessionAttribute(final HttpServletRequest request, final String attrName) {
        if (request == null) {
            return null;
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object val = session.getAttribute(attrName);
            if (val != null) {
                return val.toString();
            }
        }
        return null;
    }

    private boolean constantTimeEquals(final String a, final String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
