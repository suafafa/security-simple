package com.example.security.validators;

import com.example.security.models.SecurityErrorCode;
import com.example.security.models.ServletPolicyRule;
import com.example.security.models.ServletSecurityConfig;
import com.example.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Rate Limiting &amp; DoS 방어 검증기 (CWE-770 / CWE-400)
 * <p>
 * {@link ServletPolicyRule} 클래스를 수정하지 않고 {@code extensions} 맵에서
 * {@code "rateLimit"} (최대 요청 수), {@code "rateLimitWindow"} (윈도우 초, 기본 60초),
 * {@code "rateLimitKey"} ({@code "IP"}, {@code "IP_TARGET"}, {@code "USER"}) 설정을 읽어 동작합니다.
 */
@Component(service = PolicyValidator.class, immediate = true)
public class RateLimitPolicyValidator extends AbstractPolicyValidator {

    public static final String NAME = "RATE_LIMIT";
    public static final int ORDER = 8;

    private static final int MAX_TRACKED_BUCKETS = 10000;
    private static final int HARD_CAP_BUCKETS = 20000;
    private static final long BUCKET_EXPIRY_MILLIS = 5 * 60 * 1000L; // 5분 미사용 시 제거
    private static final long MIN_CLEANUP_INTERVAL_MILLIS = 30 * 1000L; // 청소 스톰 방지 최소 주기 (30초)

    private static final String[] RATE_LIMIT_KEYS = {
            "rateLimit"
    };
    private static final String[] WINDOW_KEYS = {
            "rateLimitWindow"
    };
    private static final String[] KEY_MODE_KEYS = {
            "rateLimitKey"
    };

    /**
     * 버킷 데이터 구조 (타임스탬프 큐 및 마지막 접근 시간 보관)
     */
    private static class RequestBucket {
        private final Deque<Long> timestamps = new ArrayDeque<>();
        private long lastAccessTime = System.currentTimeMillis();

        /**
         * 슬라이딩 윈도우 내에 요청 허용 한도가 남아있는지 확인하고, 허용 시 현재 타임스탬프를 기록합니다.
         */
        synchronized boolean tryAcquire(final int maxRequests, final long windowMillis, final long now) {
            this.lastAccessTime = now;
            long cutoff = now - windowMillis;

            // 윈도우 범위를 벗어난 오래된 타임스탬프 제거
            while (!timestamps.isEmpty() && timestamps.peekFirst() <= cutoff) {
                timestamps.pollFirst();
            }

            if (timestamps.size() >= maxRequests) {
                return false;
            }

            timestamps.addLast(now);
            return true;
        }

        /**
         * 다음 요청이 허용될 때까지 남은 대기 시간(초)을 계산합니다.
         */
        synchronized long getSecondsUntilNextAvailable(final long windowMillis, final long now) {
            if (timestamps.isEmpty()) {
                return 1;
            }
            long oldest = timestamps.peekFirst();
            long waitMillis = (oldest + windowMillis) - now;
            return waitMillis > 0 ? (waitMillis / 1000 + 1) : 1;
        }

        /**
         * 이 버킷이 만료 시간({@code BUCKET_EXPIRY_MILLIS}) 동안 미사용 상태인지 확인합니다.
         */
        synchronized boolean isExpired(final long now) {
            return (now - lastAccessTime) > BUCKET_EXPIRY_MILLIS;
        }
    }

    private final ConcurrentHashMap<String, RequestBucket> bucketMap = new ConcurrentHashMap<>();
    private final AtomicLong lastCleanupTime = new AtomicLong(0L);
    private final AtomicBoolean isCleaningUp = new AtomicBoolean(false);

    /** 기본 생성자입니다 (식별자: "RATE_LIMIT", 실행 순서: 8). */
    public RateLimitPolicyValidator() {
        super(NAME, ORDER);
    }

    /**
     * 클라이언트 IP 또는 사용자 기준의 요청 빈도가 설정된 임계치({@code rateLimit}/{@code rateLimitWindow})를 초과하는지 검증합니다.
     */
    @Override
    protected ValidationResult doValidate(final HttpServletRequest request,
                                          final ServletPolicyRule policy,
                                          final ServletSecurityConfig rootConfig) {
        Integer maxRequests = resolveRateLimit(policy);
        if (policy == null || maxRequests == null || maxRequests <= 0) {
            return pass();
        }

        int windowSeconds = resolveRateLimitWindow(policy);
        long windowMillis = windowSeconds * 1000L;
        long now = System.currentTimeMillis();

        String clientIp = SecurityUtils.getClientIp(request);
        String bucketKey = resolveBucketKey(request, policy, clientIp);

        // 주기적/온디맨드 메모리 누수 방지 청소 (스톰 방지 쓰로틀링 적용)
        if (bucketMap.size() > MAX_TRACKED_BUCKETS) {
            tryCleanupExpiredBuckets(now);
        }

        RequestBucket bucket = bucketMap.get(bucketKey);
        if (bucket == null) {
            ensureCapacity(now);
            bucket = bucketMap.computeIfAbsent(bucketKey, k -> new RequestBucket());
        }

        if (!bucket.tryAcquire(maxRequests, windowMillis, now)) {
            long retryAfterSeconds = bucket.getSecondsUntilNextAvailable(windowMillis, now);
            String blockedConfig = "rateLimit=" + maxRequests + "/" + windowSeconds + "s, bucket=" + bucketKey
                    + ", retryAfter=" + retryAfterSeconds + "s";

            return block(
                    policy,
                    SecurityErrorCode.RATE_LIMIT_EXCEEDED,
                    blockedConfig,
                    "Rate limit of " + maxRequests + " requests per " + windowSeconds + "s exceeded for [" + bucketKey + "]",
                    bucketKey, retryAfterSeconds
            );
        }

        return pass();
    }

    /**
     * 서블릿 정책에서 윈도우당 최대 허용 요청 수({@code rateLimit})를 추출합니다.
     */
    private Integer resolveRateLimit(final ServletPolicyRule policy) {
        if (policy == null) {
            return null;
        }
        String raw = policy.getExtensionString(RATE_LIMIT_KEYS);
        if (StringUtils.isBlank(raw)) {
            return null;
        }
        try {
            // Gson 숫자가 "10.0" 형태로 변환된 경우까지 안전하게 파싱
            return (int) Double.parseDouble(raw.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * 서블릿 정책에서 Rate Limit 측정 윈도우 시간(초, 기본값 60초)을 추출합니다.
     */
    private int resolveRateLimitWindow(final ServletPolicyRule policy) {
        if (policy != null) {
            String raw = policy.getExtensionString(WINDOW_KEYS);
            if (StringUtils.isNotBlank(raw)) {
                try {
                    int val = (int) Double.parseDouble(raw.trim());
                    if (val > 0) {
                        return val;
                    }
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return 60;
    }

    /**
     * 서블릿 정책에서 버킷 구분 기준 키 모드({@code IP}, {@code IP_TARGET}, {@code USER})를 추출합니다.
     */
    private String resolveRateLimitKey(final ServletPolicyRule policy) {
        if (policy != null) {
            String raw = policy.getExtensionString(KEY_MODE_KEYS);
            if (StringUtils.isNotBlank(raw)) {
                return raw.trim().toUpperCase();
            }
        }
        return "IP";
    }

    /**
     * 정책의 rateLimitKey 설정("IP", "IP_TARGET", "USER")에 따라 고유 카운터 키를 결정합니다.
     */
    private String resolveBucketKey(final HttpServletRequest request, final ServletPolicyRule policy, final String clientIp) {
        String keyMode = resolveRateLimitKey(policy);
        String target = StringUtils.defaultIfBlank(policy.getTarget(), "global");

        if ("IP_TARGET".equalsIgnoreCase(keyMode)) {
            return clientIp + "#" + target;
        } else if ("USER".equalsIgnoreCase(keyMode)) {
            String remoteUser = request != null ? request.getRemoteUser() : null;
            if (StringUtils.isNotBlank(remoteUser)) {
                return "user:" + remoteUser + "#" + target;
            }
            return clientIp + "#" + target;
        }
        return clientIp;
    }

    /**
     * 만료된 버킷 정리: 여러 스레드가 동시에 몰려도 단 1개의 스레드만 비차단(Non-blocking)으로 청소를 수행합니다.
     */
    private void tryCleanupExpiredBuckets(final long now) {
        long last = lastCleanupTime.get();
        if (now - last >= MIN_CLEANUP_INTERVAL_MILLIS) {
            if (isCleaningUp.compareAndSet(false, true)) {
                try {
                    lastCleanupTime.set(now);
                    cleanupExpiredBuckets(now);
                } finally {
                    isCleaningUp.set(false);
                }
            }
        }
    }

    /**
     * 만료 시간이 지난 미사용 버킷들을 맵에서 제거합니다.
     */
    private void cleanupExpiredBuckets(final long now) {
        for (Map.Entry<String, RequestBucket> entry : bucketMap.entrySet()) {
            if (entry.getValue().isExpired(now)) {
                bucketMap.remove(entry.getKey());
            }
        }
    }

    /**
     * 대규모 DDoS(IP 스푸핑 공격 등) 발생 시 JVM OOM을 방지하기 위한 안전장치
     */
    private void ensureCapacity(final long now) {
        if (bucketMap.size() >= HARD_CAP_BUCKETS) {
            cleanupExpiredBuckets(now);
            if (bucketMap.size() >= HARD_CAP_BUCKETS) {
                java.util.Iterator<Map.Entry<String, RequestBucket>> it = bucketMap.entrySet().iterator();
                int evicted = 0;
                while (it.hasNext() && evicted < 500) {
                    it.next();
                    it.remove();
                    evicted++;
                }
            }
        }
    }
}
