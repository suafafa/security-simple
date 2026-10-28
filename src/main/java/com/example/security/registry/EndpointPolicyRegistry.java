package com.example.security.registry;

import com.example.security.models.ServletPolicyRule;

import java.util.List;
import java.util.Map;

/**
 * 특정 config 폴더에 등록된 번들/도메인별 {@link EndpointPolicyConfig}({@code .cfg.json}) 인스턴스들을
 * 실시간으로 수집·통합 관리하는 OSGi 엔드포인트 보안 정책 레지스트리 서비스 인터페이스입니다.
 */
public interface EndpointPolicyRegistry {

    /**
     * 현재 활성화된 모든 {@code .cfg.json} 번들 설정으로부터 수집된 전체 서블릿 보안 정책 목록을 반환합니다.
     *
     * @return 통합된 {@link ServletPolicyRule} 리스트 (읽기 전용)
     */
    List<ServletPolicyRule> getAllPolicies();

    /**
     * 특정 타겟 경로 또는 resourceType에 해당하는 보안 정책 규칙을 조회합니다.
     *
     * @param target 조회할 타겟 문자열 (예: {@code "/aemapi/user/contact"})
     * @return 매칭된 {@link ServletPolicyRule} (없으면 null)
     */
    ServletPolicyRule getPolicy(String target);

    /**
     * 특정 타겟 정책이 어느 번들({@code .cfg.json})에서 등록되었는지 출처 식별자를 반환합니다.
     * 보안 차단 로그의 {@code source=...} 출력에 활용됩니다.
     *
     * @param target 조회할 타겟 문자열
     * @return 출처 라벨 (예: {@code "EndpointPolicyConfig~core-member"}, 미등록 시 null)
     */
    String getPolicySource(String target);

    /**
     * 번들 식별자({@code bundle.id})별로 그룹화된 서블릿 보안 정책 맵을 반환합니다.
     *
     * @return {@code bundleId -> List<ServletPolicyRule>} 맵 (읽기 전용)
     */
    Map<String, List<ServletPolicyRule>> getPoliciesByBundle();

    /**
     * {@code .cfg.json} 설정 파일이 추가·수정·삭제되어 정책 목록이 변경될 때 호출될 리스너를 등록합니다.
     *
     * @param listener 변경 시 실행할 콜백
     */
    void addChangeListener(Runnable listener);

    /**
     * 등록된 변경 리스너를 해제합니다.
     *
     * @param listener 해제할 콜백
     */
    void removeChangeListener(Runnable listener);
}
