package com.example.security.models;

import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 개별 파라미터의 필수 여부(required), 길이 제약조건(minLength, maxLength),
 * 정규식 패턴(pattern), 경로 조작 허용 여부 및 활성화 상태를 정의하는 모델 클래스입니다.
 */
public class ParamRule {

    @SerializedName("enabled")
    private Boolean enabled = true;

    @SerializedName("required")
    private Boolean required = false;

    @SerializedName("minLength")
    private Integer minLength;

    @SerializedName("maxLength")
    private Integer maxLength;

    @SerializedName("pattern")
    private String pattern;

    /**
     * 경로 조작(Path Traversal: ../ 등) 허용 여부 (기본값: false 차단)
     */
    @SerializedName("allowPathTraversal")
    private Boolean allowPathTraversal = false;

    private transient Pattern compiledPattern;

    /**
     * 설정된 정규식 문자열(pattern)을 사전 컴파일하여 런타임 캐시에 저장합니다.
     */
    public void init() {
        if (StringUtils.isNotBlank(pattern)) {
            this.compiledPattern = Pattern.compile(pattern.trim());
        }
    }

    /**
     * 현재 {@link ParamRule}의 모든 설정값을 깊은 복사(Deep Copy)한 새 인스턴스를 반환합니다.
     *
     * @return 복사된 {@link ParamRule} 객체
     */
    public ParamRule copy() {
        ParamRule cloned = new ParamRule();
        cloned.enabled = this.enabled;
        cloned.required = this.required;
        cloned.minLength = this.minLength;
        cloned.maxLength = this.maxLength;
        cloned.pattern = this.pattern;
        cloned.allowPathTraversal = this.allowPathTraversal;
        cloned.compiledPattern = this.compiledPattern;
        return cloned;
    }

    /**
     * 파라미터 규칙의 정규식 문법 및 최소/최대 길이 설정의 유효성을 검사합니다.
     *
     * @param paramName 파라미터 이름
     * @param target    서블릿 타겟 식별자
     * @param errors    검증 오류 메시지를 수집할 리스트
     */
    public void validate(final String paramName, final String target, final List<String> errors) {
        if (StringUtils.isNotBlank(pattern)) {
            try {
                this.compiledPattern = Pattern.compile(pattern.trim());
            } catch (Exception e) {
                errors.add("Target '" + target + "', Param '" + paramName + "': Invalid regex pattern '" + pattern + "' (" + e.getMessage() + ")");
            }
        }
        if (minLength != null && minLength < 0) {
            errors.add("Target '" + target + "', Param '" + paramName + "': minLength cannot be negative (" + minLength + ")");
        }
        if (maxLength != null && maxLength < 0) {
            errors.add("Target '" + target + "', Param '" + paramName + "': maxLength cannot be negative (" + maxLength + ")");
        }
        if (minLength != null && maxLength != null && minLength > maxLength) {
            errors.add("Target '" + target + "', Param '" + paramName + "': minLength (" + minLength + ") exceeds maxLength (" + maxLength + ")");
        }
    }

    /**
     * 이 파라미터 규칙이 활성화되어 있는지 반환합니다.
     *
     * @return 활성화 여부 (기본값 true)
     */
    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    /**
     * 파라미터 규칙의 활성화 여부를 설정합니다.
     *
     * @param enabled 활성화 여부
     */
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * 이 파라미터가 필수(required)인지 반환합니다.
     *
     * @return 필수 여부 (기본값 false)
     */
    public boolean isRequired() {
        return required != null && required;
    }

    /**
     * 파라미터의 필수 여부를 설정합니다.
     *
     * @param required 필수 여부
     */
    public void setRequired(Boolean required) {
        this.required = required;
    }

    /**
     * 허용되는 최소 글자 수(minLength)를 반환합니다.
     *
     * @return 최소 글자 수 (미설정 시 null)
     */
    public Integer getMinLength() {
        return minLength;
    }

    /**
     * 허용되는 최소 글자 수(minLength)를 설정합니다.
     *
     * @param minLength 최소 글자 수
     */
    public void setMinLength(Integer minLength) {
        this.minLength = minLength;
    }

    /**
     * 허용되는 최대 글자 수(maxLength)를 반환합니다.
     *
     * @return 최대 글자 수 (미설정 시 null)
     */
    public Integer getMaxLength() {
        return maxLength;
    }

    /**
     * 허용되는 최대 글자 수(maxLength)를 설정합니다.
     *
     * @param maxLength 최대 글자 수
     */
    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    /**
     * 파라미터 값 검증용 정규식 패턴 문자열을 반환합니다.
     *
     * @return 정규식 문자열 (미설정 시 null)
     */
    public String getPattern() {
        return pattern;
    }

    /**
     * 파라미터 값 검증용 정규식 패턴 문자열을 설정하고 즉시 컴파일합니다.
     *
     * @param pattern 정규식 문자열
     */
    public void setPattern(String pattern) {
        this.pattern = pattern;
        if (StringUtils.isNotBlank(pattern)) {
            try {
                this.compiledPattern = Pattern.compile(pattern.trim());
            } catch (Exception ignored) {}
        }
    }

    /**
     * 사전 컴파일된 정규식 Pattern 객체를 반환합니다.
     *
     * @return 컴파일된 Pattern 객체 (미설정 시 null)
     */
    public Pattern getCompiledPattern() {
        if (compiledPattern == null && StringUtils.isNotBlank(pattern)) {
            compiledPattern = Pattern.compile(pattern.trim());
        }
        return compiledPattern;
    }

    /**
     * 해당 파라미터에 대해 경로 조작(Path Traversal) 구문 허용 여부를 반환합니다.
     *
     * @return 허용 시 true, 차단 시 false (기본값 false)
     */
    public boolean isAllowPathTraversal() {
        return allowPathTraversal != null && allowPathTraversal;
    }

    /**
     * 해당 파라미터에 대해 경로 조작(Path Traversal) 구문 허용 여부를 설정합니다.
     *
     * @param allowPathTraversal 허용 여부
     */
    public void setAllowPathTraversal(Boolean allowPathTraversal) {
        this.allowPathTraversal = allowPathTraversal;
    }

    /**
     * 로그 출력을 위해 이 파라미터 규칙의 핵심 제약조건(필수 여부, 길이 범위, 정규식)을 요약 문자열로 반환합니다.
     *
     * @return 파라미터 규칙 요약 문자열
     */
    public String toSummaryString() {
        StringBuilder sb = new StringBuilder("{");
        sb.append("required=").append(isRequired());
        if (minLength != null || maxLength != null) {
            sb.append(", len=").append(minLength != null ? minLength : 0)
              .append("..").append(maxLength != null ? maxLength : "MAX");
        }
        if (StringUtils.isNotBlank(pattern)) {
            sb.append(", pattern=").append(pattern);
        }
        if (isAllowPathTraversal()) {
            sb.append(", allowPathTraversal=true");
        }
        sb.append("}");
        return sb.toString();
    }

    @Override
    public String toString() {
        return toSummaryString();
    }
}
