# 🛡️ AEM 6.5 Lightweight Security Filter (`security-simple`)

AEM 6.5 서블릿을 위한 **경량 보안 필터(`SecurityFilter`)** 프로젝트입니다.  
가장 핵심적인 **3대 보안 검증기(`RefererPolicyValidator`, `MethodPolicyValidator`, `ParamPolicyValidator`)**와 해당 설정만 남겨 가볍고 직관적으로 구성한 버전입니다.

---

## 📊 0. 아키텍처 및 기능 기술서 (PPT / 프레젠테이션 문서)

전체 시스템 아키텍처, 6단계 정책 매칭, 3대 Validator 동작 원리, DSL 문법, 로깅(`BlockedByConfig` / `AppliedServletPolicy`) 및 에러 코드 규격을 설명하는 프레젠테이션 문서가 [`docs/`](docs/) 디렉토리에 포함되어 있습니다:

- 📑 **PowerPoint 문서 (`.pptx`)**: [`docs/AEM_Security_Simple_Architecture_Guide.pptx`](docs/AEM_Security_Simple_Architecture_Guide.pptx) (총 12슬라이드, 16:9 와이드스크린)
- 🌐 **웹 슬라이드 덱 (`.html`)**: [`docs/AEM_Security_Simple_Presentation.html`](docs/AEM_Security_Simple_Presentation.html) (브라우저에서 바로 열람 및 방향키 `←`/`→` 이동, `Cmd+P` PDF 인쇄 지원)

---

## 📌 1. 핵심 3대 Validator 구성 및 실행 순서

필터 체인은 `/aemapi/.*` 및 `/sysapi/.*` 요청에 대해 아래 3개 Validator를 순차 실행합니다:

| 순서 | Validator 클래스 | 검증기 코드명 | 주요 검증 내용 | 차단 시 응답 코드 |
| :---: | :--- | :---: | :--- | :--- |
| **1** | `RefererPolicyValidator` | `REFERER` | 요청 `Referer` / `Origin` 헤더가 기본 허용 도메인(`default.referrer`) 또는 서블릿의 `security.allowedReferrers`와 일치하는지 검증 | `403 Forbidden` (`SEC-40303`) |
| **2** | `MethodPolicyValidator` | `METHOD` | 요청 HTTP Method(`GET`, `POST` 등)가 허용된 `security.methods` 목록에 포함되는지 검증 | `405 Method Not Allowed` (`SEC-40501`) |
| **3** | `ParamPolicyValidator` | `PARAM` | 정의되지 않은 파라미터 차단(`allowUndefinedParams=false`), 필수 여부(`required`), 길이(`min..max`), 정규식(`pattern`), Path Traversal(`SEC-40007`), SQL/JCR 인젝션(`SEC-40008`), XSS(`SEC-40009`) 검증 | `400 Bad Request` (`SEC-40001` ~ `SEC-40009`) |

---

## ⚙️ 2. 전역 OSGi 설정 (`config/com.example.security.filters.SecurityFilter.config`)

```ini
enabled=B"true"
sling.filter.pattern="(/aemapi/.*|/sysapi/.*)"

validator.referer.enabled=B"true"
validator.method.enabled=B"true"
validator.param.enabled=B"true"

default.enabled=B"true"
default.referrer="abc.com"
default.methods=["GET","POST"]
default.blockSqlInjection=B"true"
default.blockXss=B"true"
default.allowUndefinedParams=B"false"
default.params=[ \
  "page:optional:digits:5", \
  "size:optional:digits:4", \
  "sort:optional:alnum:30", \
  "order:optional:asc|desc:4", \
  "lang:optional:pattern(^[a-zA-Z]{2}(?:-[a-zA-Z0-9]{2,})?$):10", \
  "keyword:optional:100" \
]
```

---

## 💻 3. 서블릿 보안 설정 적용 예제

### 3-1. 단일 경로(`sling.servlet.paths` 1개) 서블릿
```java
@Component(
    service = { Servlet.class },
    property = {
        "sling.servlet.paths=/aemapi/user/contact",
        "security.methods=POST",
        "security.allowedReferrers=partner.abc.com",
        "security.params=name:required:2..20:korean",
        "security.params=email:required:email:50",
        "security.params=phone:required:phone",
        "security.params=inquiryType:required:tech|billing|general"
    }
)
public class UserContactServlet extends SlingAllMethodsServlet { ... }
```

### 3-2. 복수 경로(`sling.servlet.paths` 여러 개) 서블릿 (경로별 Method/Param 차등 적용)
```java
@Component(
    service = { Servlet.class },
    property = {
        "sling.servlet.paths=/aemapi/order/list",
        "sling.servlet.paths=/aemapi/order/cancel",

        // 경로별 허용 HTTP Method 분리
        "security.methods=/aemapi/order/list:GET",
        "security.methods=/aemapi/order/cancel:POST",

        // 모든 경로 공통 파라미터 + 경로별 전용 파라미터 분리
        "security.params=lang:optional:alpha:5",
        "security.params=/aemapi/order/list:page:optional:digits:5",
        "security.params=/aemapi/order/cancel:orderId:required:alphanumeric:20"
    }
)
public class OrderMultiPathServlet extends SlingAllMethodsServlet { ... }
```

### 3-3. 복수 `sling.servlet.resourceTypes` 서블릿
```java
@Component(
    service = { Servlet.class },
    property = {
        "sling.servlet.resourceTypes=myproject/components/product/search",
        "sling.servlet.resourceTypes=myproject/components/product/review",

        "security.methods=myproject/components/product/search:GET",
        "security.methods=myproject/components/product/review:POST",

        "security.params=locale:optional:alpha:5",
        "security.params=myproject/components/product/search:keyword:required:2..50",
        "security.params=myproject/components/product/review:productId:required:alphanumeric:12",
        "security.params=myproject/components/product/review:rating:required:1|2|3|4|5"
    }
)
public class ProductComponentServlet extends SlingAllMethodsServlet { ... }
```

---

## 🔍 4. 심플 DSL 파라미터 문법 요약 (`security.params`)

형식: `"파라미터명:필수여부:타입또는정규식:길이제한"`

| 토큰 키워드 | 의미 및 변환 정규식 | 예시 |
| :--- | :--- | :--- |
| `required` / `optional` | 필수 여부 (생략 시 `optional`) | `userId:required:20` |
| `min..max` 또는 `숫자` | 최소~최대 글자 수 또는 최대 글자 수 | `name:required:2..20` |
| `digits` / `number` | 숫자만 허용 (`^[0-9]+$`) | `page:optional:digits:5` |
| `alnum` / `alphanumeric` | 영문+숫자+`_` (`^[a-zA-Z0-9_]+$`) | `userId:required:alnum:20` |
| `alpha` | 영문자만 허용 (`^[a-zA-Z]+$`) | `lang:optional:alpha:5` |
| `korean` / `hangul` | 한글+영문+공백 (`^[가-힣a-zA-Z\s]+$`) | `name:required:korean:2..20` |
| `email` | 이메일 표준 정규식 | `email:required:email:50` |
| `phone` | 휴대폰 번호 정규식 (`^01[016789]-?\d{3,4}-?\d{4}$`) | `phone:required:phone` |
| `date` / `datetime` / `uuid` | 날짜(`YYYY-MM-DD`), 일시, UUID 형식 | `startDate:optional:date` |
| `값1\|값2\|값3` | 허용 열거값(Enum) 지정 | `order:optional:asc\|desc` |
| `pattern(...)` | 사용자 정의 정규식 직접 입력 | `code:required:pattern(^[A-Z]{3}-\d{4}$)` |
