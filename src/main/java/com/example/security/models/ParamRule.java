package com.example.security.models;

import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 파라미터의 길이 제약조건, 정규식 패턴, 인젝션/XSS 허용 여부 및 활성화 상태를 정의하는 모델 클래스입니다.
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
     * 경로 조작(Path Traversal: ../ 등) 허용 여부.
     * 기본값은 false이며, 특별한 사유가 없는 한 상위 디렉토리 이동 시퀀스는 자동 차단됩니다.
     */
    @SerializedName("allowPathTraversal")
    private Boolean allowPathTraversal = false;

    /**
     * CWE-89: SQL / JCR-SQL2 / XPath 인젝션 구문 허용 여부.
     * 기본값은 false이며, DB/JCR 조작 공격 구문이 포함된 경우 400 Bad Request로 자동 차단됩니다.
     */
    @SerializedName("allowSqlInjection")
    private Boolean allowSqlInjection = false;

    /**
     * CWE-79: Cross-Site Scripting (XSS) 스크립트 태그 및 이벤트 핸들러 허용 여부.
     * 기본값은 false이며, <script>, onload=, javascript: 등의 악성 태그가 감지되면 400 Bad Request로 자동 차단됩니다.
     */
    @SerializedName("allowXss")
    private Boolean allowXss = false;

    private transient Pattern compiledPattern;

    public void init() {
        if (StringUtils.isNotBlank(pattern)) {
            this.compiledPattern = Pattern.compile(pattern.trim());
        }
    }

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

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    public boolean isRequired() {
        return required != null && required;
    }

    public void setRequired(Boolean required) {
        this.required = required;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Integer getMinLength() {
        return minLength;
    }

    public void setMinLength(Integer minLength) {
        this.minLength = minLength;
    }

    public Integer getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
        if (StringUtils.isNotBlank(pattern)) {
            try {
                this.compiledPattern = Pattern.compile(pattern.trim());
            } catch (Exception ignored) {}
        }
    }

    public Pattern getCompiledPattern() {
        return compiledPattern;
    }

    public boolean isAllowPathTraversal() {
        return allowPathTraversal != null && allowPathTraversal;
    }

    public void setAllowPathTraversal(Boolean allowPathTraversal) {
        this.allowPathTraversal = allowPathTraversal;
    }

    public boolean isAllowSqlInjection() {
        return allowSqlInjection != null && allowSqlInjection;
    }

    public void setAllowSqlInjection(Boolean allowSqlInjection) {
        this.allowSqlInjection = allowSqlInjection;
    }

    public boolean isAllowXss() {
        return allowXss != null && allowXss;
    }

    public void setAllowXss(Boolean allowXss) {
        this.allowXss = allowXss;
    }

    /**
     * 보안 위반 로그 출력용 파라미터 규칙 요약 문자열을 반환합니다.
     */
    public String toSummaryString() {
        StringBuilder sb = new StringBuilder("{");
        sb.append("required=").append(isRequired());
        if (minLength != null || maxLength != null) {
            sb.append(", len=")
              .append(minLength != null ? minLength : 0)
              .append("..")
              .append(maxLength != null ? maxLength : "MAX");
        }
        if (StringUtils.isNotBlank(pattern)) {
            sb.append(", pattern='").append(pattern).append("'");
        }
        if (isAllowPathTraversal()) {
            sb.append(", allowPathTraversal=true");
        }
        if (isAllowSqlInjection()) {
            sb.append(", allowSqlInjection=true");
        }
        if (isAllowXss()) {
            sb.append(", allowXss=true");
        }
        sb.append("}");
        return sb.toString();
    }

    @Override
    public String toString() {
        return toSummaryString();
    }
}
