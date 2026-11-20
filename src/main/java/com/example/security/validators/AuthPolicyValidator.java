package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * 요청의 사용자 인증 타입({@code ANONYMOUS}, {@code SA_USER}, {@code AEM_USER}, {@code SYSTEM}) 및
 * AEM 사용자 그룹({@code roles}) 소속 여부를 검증하는 모듈형 검증기입니다.
 * <p>
 * {@link ServletPolicyRule} 클래스를 수정하지 않고 {@code extensions} 맵에서
 * {@code "auth"} (또는 {@code "authType"})와 {@code "roles"} (또는 {@code "groups"}) 설정을 읽어 동작합니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class AuthPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "AUTH";
    public static final int ORDER = 12;

    public static final String AUTH_ANONYMOUS = "ANONYMOUS";
    public static final String AUTH_SA_USER = "SA_USER";
    public static final String AUTH_AEM_USER = "AEM_USER";
    public static final String AUTH_SYSTEM = "SYSTEM";

    private static final String[] AUTH_KEYS = {
            "auth", "authType"
    };
    private static final String[] ROLE_KEYS = {
            "roles", "groups"
    };

    public AuthPolicyValidator() {
        super(NAME, ORDER);
    }

    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        if (policy == null) {
            return pass();
        }

        String requiredAuth = resolveRequiredAuth(policy);
        Set<String> requiredRoles = policy.getExtensionLowerSet(ROLE_KEYS);

        if (StringUtils.isBlank(requiredAuth) && requiredRoles.isEmpty()) {
            return pass();
        }

        String currentAuthType = resolveAuthType(request);
        String uid = getUserId(request);

        // 1. 인증 타입(ANONYMOUS, SA_USER, AEM_USER, SYSTEM) 일치 여부 검사
        if (StringUtils.isNotBlank(requiredAuth) && !requiredAuth.equalsIgnoreCase(currentAuthType)) {
            String blockedConfig = "requiredAuth=" + requiredAuth + ", currentAuthType=" + currentAuthType;
            if (AUTH_ANONYMOUS.equals(currentAuthType)) {
                return block(
                        policy,
                        SecurityErrorCode.AUTH_REQUIRED,
                        blockedConfig,
                        "Authentication required for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                                + ". Required: " + requiredAuth
                );
            } else {
                return block(
                        policy,
                        SecurityErrorCode.AUTH_TYPE_FORBIDDEN,
                        blockedConfig,
                        "Forbidden: User [" + SecurityUtils.sanitizeForLog(uid)
                                + "] with AuthType [" + currentAuthType
                                + "] not allowed for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                                + ". Required: " + requiredAuth,
                        currentAuthType
                );
            }
        }

        // 2. 요구되는 역할(AEM 사용자 그룹)이 설정된 경우 그룹 소속 여부 검사
        if (!requiredRoles.isEmpty()) {
            if (AUTH_ANONYMOUS.equals(currentAuthType)) {
                String blockedConfig = "requiredRoles=" + requiredRoles + ", currentAuthType=ANONYMOUS";
                return block(
                        policy,
                        SecurityErrorCode.AUTH_REQUIRED,
                        blockedConfig,
                        "Authentication required for role-restricted target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                );
            }

            if (!isUserInRoles(request, uid, requiredRoles)) {
                String blockedConfig = "requiredRoles=" + requiredRoles + ", userId=" + SecurityUtils.sanitizeForLog(uid);
                return block(
                        policy,
                        SecurityErrorCode.ROLE_INSUFFICIENT,
                        blockedConfig,
                        "User [" + SecurityUtils.sanitizeForLog(uid) + "] does not belong to any required role/group: "
                                + requiredRoles + " for target: " + SecurityUtils.sanitizeForLog(policy.getTarget())
                );
            }
        }

        return pass();
    }

    private String resolveRequiredAuth(final ServletPolicyRule policy) {
        if (policy == null) {
            return null;
        }
        String raw = policy.getExtensionString(AUTH_KEYS);
        return StringUtils.isNotBlank(raw) ? raw.trim().toUpperCase() : null;
    }

    /**
     * 현재 요청의 인증 타입을 ANONYMOUS, SA_USER, AEM_USER, SYSTEM 중 하나로 판별합니다.
     */
    public String resolveAuthType(final HttpServletRequest request) {
        String userId = getUserId(request);
        if (StringUtils.isBlank(userId) || "anonymous".equalsIgnoreCase(userId)) {
            return AUTH_ANONYMOUS;
        }

        ResourceResolver resolver = getResourceResolver(request);
        Authorizable authorizable = null;
        if (resolver != null) {
            try {
                UserManager userManager = resolver.adaptTo(UserManager.class);
                if (userManager != null) {
                    authorizable = userManager.getAuthorizable(userId);
                }
            } catch (Exception e) {
                log.debug("Could not resolve authorizable for [{}]: {}", userId, e.getMessage());
            }
        }

        if (isSystemUser(authorizable, userId)) {
            return AUTH_SYSTEM;
        }

        if (isAemUser(authorizable, userId)) {
            return AUTH_AEM_USER;
        }

        return AUTH_SA_USER;
    }

    /**
     * Sling ResourceResolver, HttpServletRequest의 RemoteUser 또는 UserPrincipal로부터 사용자 ID를 추출합니다.
     */
    public String getUserId(final HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        if (request instanceof SlingHttpServletRequest) {
            ResourceResolver resolver = ((SlingHttpServletRequest) request).getResourceResolver();
            if (resolver != null && resolver.getUserID() != null) {
                return resolver.getUserID();
            }
        }
        Object resolverObj = request.getAttribute(ResourceResolver.class.getName());
        if (resolverObj instanceof ResourceResolver) {
            String uid = ((ResourceResolver) resolverObj).getUserID();
            if (uid != null) {
                return uid;
            }
        }
        if (request.getRemoteUser() != null) {
            return request.getRemoteUser();
        }
        if (request.getUserPrincipal() != null) {
            return request.getUserPrincipal().getName();
        }
        return null;
    }

    private ResourceResolver getResourceResolver(final HttpServletRequest request) {
        if (request instanceof SlingHttpServletRequest) {
            return ((SlingHttpServletRequest) request).getResourceResolver();
        }
        Object resolverObj = request.getAttribute(ResourceResolver.class.getName());
        if (resolverObj instanceof ResourceResolver) {
            return (ResourceResolver) resolverObj;
        }
        return null;
    }

    private boolean isSystemUser(final Authorizable authorizable, final String userId) {
        if (authorizable instanceof User) {
            User user = (User) authorizable;
            if (user.isSystemUser()) {
                return true;
            }
        }
        if (authorizable != null) {
            try {
                String path = authorizable.getPath();
                if (path != null && path.startsWith("/home/users/system")) {
                    return true;
                }
            } catch (Exception e) {
                log.debug("Error checking system authorizable for [{}]: {}", userId, e.getMessage());
            }
        }
        return isSystemUserId(userId);
    }

    private boolean isAemUser(final Authorizable authorizable, final String userId) {
        if ("admin".equalsIgnoreCase(userId)) {
            return true;
        }
        if (authorizable != null) {
            try {
                String path = authorizable.getPath();
                if (path != null && (path.startsWith("/home/users/aem") || path.startsWith("/home/users/mac"))) {
                    return true;
                }
                Iterator<Group> groups = authorizable.memberOf();
                while (groups != null && groups.hasNext()) {
                    Group group = groups.next();
                    String groupId = group.getID();
                    if ("administrators".equalsIgnoreCase(groupId)
                            || "authors".equalsIgnoreCase(groupId)
                            || "content-authors".equalsIgnoreCase(groupId)
                            || "contributor".equalsIgnoreCase(groupId)) {
                        return true;
                    }
                }
            } catch (Exception e) {
                log.debug("Error checking AEM author user authorizable for [{}]: {}", userId, e.getMessage());
            }
        }
        return isAemUserId(userId);
    }

    private boolean isSystemUserId(final String userId) {
        if (userId == null) {
            return false;
        }
        String lower = userId.toLowerCase();
        return lower.startsWith("system")
                || lower.startsWith("service-")
                || lower.endsWith("-service")
                || lower.contains("system-user");
    }

    private boolean isAemUserId(final String userId) {
        if (userId == null) {
            return false;
        }
        String lower = userId.toLowerCase();
        return "admin".equals(lower)
                || lower.startsWith("aem-")
                || lower.startsWith("aem_")
                || lower.startsWith("author-")
                || lower.startsWith("author_");
    }

    /**
     * 사용자가 정책에 요구된 AEM 역할/그룹(requiredRoles) 중 하나 이상에 속하는지 확인합니다.
     */
    public boolean isUserInRoles(final HttpServletRequest request, final String userId, final Set<String> requiredRoles) {
        if (requiredRoles == null || requiredRoles.isEmpty()) {
            return true;
        }

        if (StringUtils.isBlank(userId)) {
            return false;
        }

        // 'admin' 최고관리자 계정은 모든 그룹 권한을 통과
        if ("admin".equalsIgnoreCase(userId)) {
            return true;
        }

        // 요청 스코프(Request-Scoped) 역할 캐시 조회 (동일 요청 내 반복적인 JCR UserManager 탐색 방지)
        if (request != null) {
            Object cached = request.getAttribute("__aem_security_resolved_roles__");
            if (cached instanceof Set<?>) {
                @SuppressWarnings("unchecked")
                Set<String> cachedRoles = (Set<String>) cached;
                for (String r : requiredRoles) {
                    if (cachedRoles.contains(r)) {
                        return true;
                    }
                }
            }
        }

        // 1. Jackrabbit UserManager를 통한 직·간접 그룹 소속 여부 확인
        ResourceResolver resolver = getResourceResolver(request);
        if (resolver != null) {
            try {
                UserManager userManager = resolver.adaptTo(UserManager.class);
                if (userManager != null) {
                    Authorizable authorizable = userManager.getAuthorizable(userId);
                    if (authorizable != null) {
                        Set<String> resolvedRoles = new HashSet<>();
                        resolvedRoles.add(authorizable.getID().toLowerCase());

                        Iterator<Group> groups = authorizable.memberOf();
                        while (groups != null && groups.hasNext()) {
                            Group group = groups.next();
                            String groupId = group.getID();
                            if (groupId != null) {
                                resolvedRoles.add(groupId.trim().toLowerCase());
                            }
                        }

                        if (request != null) {
                            request.setAttribute("__aem_security_resolved_roles__", Collections.unmodifiableSet(resolvedRoles));
                        }

                        for (String r : requiredRoles) {
                            if (resolvedRoles.contains(r)) {
                                return true;
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("Error checking group membership for user [{}]: {}", userId, e.getMessage());
            }
        }

        // 2. 표준 서블릿 API isUserInRole(role) 검사 (Mock/테스트 환경 지원)
        if (request != null) {
            for (String role : requiredRoles) {
                try {
                    if (request.isUserInRole(role)) {
                        return true;
                    }
                } catch (Exception ignored) {
                }
            }

            // 3. 요청 속성(request attribute)의 roles/groups 목록 확인
            Object rolesAttr = request.getAttribute("roles");
            if (rolesAttr == null) {
                rolesAttr = request.getAttribute("groups");
            }
            if (rolesAttr instanceof Collection<?>) {
                for (Object item : (Collection<?>) rolesAttr) {
                    if (item != null && requiredRoles.contains(item.toString().trim().toLowerCase())) {
                        return true;
                    }
                }
            } else if (rolesAttr instanceof String[]) {
                for (String item : (String[]) rolesAttr) {
                    if (item != null && requiredRoles.contains(item.trim().toLowerCase())) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
