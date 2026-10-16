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

필터 체인은 `sling.filter.pattern`(기본값: `(/aemapi/.*|/sysapi/.*)`)과 일치하는 요청에 대해 아래 3개 Validator를 순차 실행합니다:

| 순서 | Validator 클래스 | 검증기 코드명 | 주요 검증 내용 | 차단 시 응답 코드 |
| :---: | :--- | :---: | :--- | :--- |
| **1** | `RefererPolicyValidator` | `REFERER` | 요청 `Referer` 헤더가 기본 허용 도메인(`default.referrer`) 또는 서블릿의 `security.allowedReferrers`와 일치하는지 검증 | `403 Forbidden` (`SEC-40303`) |
| **2** | `MethodPolicyValidator` | `METHOD` | 요청 HTTP Method(`GET`, `POST` 등)가 허용된 `security.methods` 목록에 포함되는지 검증 | `405 Method Not Allowed` (`SEC-40501`) |
| **3** | `ParamPolicyValidator` | `PARAM` | 필수 여부(`required`), 미정의 파라미터 차단(`allowUndefinedParams=false`), Path Traversal(`SEC-40007`), SQL/JCR 인젝션(`SEC-40008`), XSS(`SEC-40009`), 길이(`min..max`), 정규식(`pattern`) 검증 | `400 Bad Request` (`SEC-40001` ~ `SEC-40009`) |

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

## 🧩 3. 서블릿 파라미터(`security.params`) 설정 가이드 — 케이스별 상세 예제

서블릿 클래스 상단의 `@Component(property = { ... })` 안에서 콜론(`:`) 구분자 기반의 간편 DSL 문법(`"파라미터명:필수여부:타입또는패턴:길이"`)으로 모든 파라미터 검증 규칙을 선언할 수 있습니다.  
토큰 순서는 첫 번째 `파라미터명`만 고정이며, 나머지 토큰(`required`, `타입`, `길이`)은 순서에 관계없이 자유롭게 조합할 수 있습니다.

---

### Case 1. 글자 수 / 길이 제한 (`minLength`, `maxLength`) 설정 케이스

| 세부 케이스 | 서블릿 `property` 설정 예시 | 동작 설명 (`ParamRule`) | 위반 시 에러 코드 |
| :--- | :--- | :--- | :---: |
| **① 최소~최대 길이 동시 지정 (`min..max`)** | `"security.params=userId:required:alnum:4..20"` | 4자 이상 ~ 20자 이하 (`minLength=4, maxLength=20`) | 4자 미만: `SEC-40003`<br>20자 초과: `SEC-40004` |
| **② 최대 길이만 지정 (`숫자` 또는 `max:숫자`)** | `"security.params=title:required:50"`<br>`"security.params=title:required:max:50"` | 최소 길이 제한 없음, 최대 50자 이하 (`minLength=null, maxLength=50`) | 50자 초과: `SEC-40004` |
| **③ 최소 길이만 지정 (`min:숫자`)** | `"security.params=feedback:required:min:10"` | 최소 10자 이상, 최대 길이 제한 없음 (`minLength=10, maxLength=null`) | 10자 미만: `SEC-40003` |
| **④ 패턴 없이 길이만 제한 (자유 텍스트)** | `"security.params=message:required:10..500"`<br>`"security.params=keyword:optional:100"` | 정규식(`pattern`) 없이 글자 수만 제한 (단, SQLi/XSS/PathTraversal은 기본 차단됨) | `SEC-40003` / `SEC-40004` |
| **⑤ 길이 지정 생략 (`min/maxLength` 미지정)** | `"security.params=deptCode:required:alpha"` | `minLength=null, maxLength=null`로 길이 검사를 생략하고 영문자 정규식만 검사 | 형식 불일치: `SEC-40005` |

---

### Case 2. 내장 타입 별칭(Type Alias) 활용 케이스

정규식을 직접 작성하지 않고 내장 키워드만 적어도 자동으로 검증 정규식이 적용됩니다. 규격 길이가 정해진 일부 타입(`email`, `phone`, `date` 등)은 길이를 생략해도 기본 `maxLength`가 자동 적용되며, 별도 길이를 적으면 적은 값이 우선합니다.

```java
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/aemapi/member/register",
        "security.methods=POST",

        // 숫자만 허용 (^[0-9]+$)
        "security.params=age:optional:digits:3",

        // 영문 + 숫자 + 언더스코어 (^[a-zA-Z0-9_]+$)
        "security.params=memberId:required:alnum:4..20",

        // 영문자만 허용 (^[a-zA-Z]+$)
        "security.params=countryCode:optional:alpha:2",

        // 한글 + 영문 + 공백 허용 (^[가-힣a-zA-Z\s]+$)
        "security.params=userName:required:korean:2..20",

        // 이메일 형식 (길이 생략 시 기본 maxLength=100, 아래처럼 :50 지정 시 maxLength=50)
        "security.params=email:required:email:50",

        // 휴대폰 번호 형식 (^01[016789]-?\d{3,4}-?\d{4}$, 기본 maxLength=13)
        "security.params=mobile:required:phone",

        // 날짜/시간 형식 (date: YYYY-MM-DD [10자], datetime: YYYY-MM-DD HH:mm:ss [19자], time: HH:mm:ss [8자])
        "security.params=birthDate:optional:date",
        "security.params=reservedAt:optional:datetime",

        // 표준 식별자 및 네트워크 형식 (uuid [36자], zipcode [5자], ip [15자], url)
        "security.params=requestId:optional:uuid",
        "security.params=zip:optional:zipcode",
        "security.params=clientIp:optional:ip",
        "security.params=homepage:optional:url:200"
    }
)
public class MemberRegisterServlet extends SlingAllMethodsServlet { ... }
```

| 내장 타입 키워드 | 자동 변환되는 정규식 (`pattern`) | 길이 생략 시 기본 `maxLength` |
| :--- | :--- | :---: |
| `digits` / `number` / `numeric` | `^[0-9]+$` | `null` (제한 없음) |
| `alnum` / `alphanumeric` | `^[a-zA-Z0-9_]+$` | `null` (제한 없음) |
| `alpha` | `^[a-zA-Z]+$` | `null` (제한 없음) |
| `korean` / `hangul` | `^[가-힣a-zA-Z\s]+$` | `null` (제한 없음) |
| `email` | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` | `100` |
| `phone` | `^01[016789]-?\d{3,4}-?\d{4}$` | `13` |
| `date` | `^\d{4}-\d{2}-\d{2}$` | `10` |
| `datetime` | `^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?$` | `19` |
| `time` | `^\d{2}:\d{2}(?::\d{2})?$` | `8` |
| `uuid` | `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$` | `36` |
| `zipcode` / `postal` | `^\d{5}$` | `5` |
| `ip` / `ipv4` | IPv4 주소 정규식 | `15` |
| `url` | `^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:/[^\s<>"]*)?$` | `null` (제한 없음) |

---

### Case 3. 허용값 목록(Enum) 및 커스텀 정규식(`pattern(...)`) 케이스

정해진 코드값만 허용하거나 프로젝트 고유의 포맷(주문번호, 쿠폰코드 등)을 정규식으로 검증할 때 사용합니다.  
정규식 내부에 콜론(`:`)이나 괄호(`(?:...)`)가 포함되어 있어도 `splitPreservingParens` 파서가 괄호 깊이를 계산하여 안전하게 파싱합니다.

```java
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/aemapi/coupon/issue",
        "security.methods=POST",

        // 1. 파이프(|)로 허용할 Enum 값 나열 -> 대소문자 구분 없이 ^(?:(?i)(VIP|GOLD|SILVER))$ 로 변환됨
        "security.params=grade:required:VIP|GOLD|SILVER:10",
        "security.params=sortOrder:optional:asc|desc:4",

        // 2. pattern(...) 또는 regex(...)로 커스텀 정규식 직접 지정
        "security.params=couponCode:required:pattern(^CPN-[A-Z0-9]{4}-[A-Z0-9]{4}$):15",

        // 3. 정규식 내부에 비캡처 그룹 (?:...) 등 콜론(:)이 포함된 경우에도 안전하게 파싱됨
        "security.params=locale:optional:pattern(^[a-z]{2}(?:-[A-Z]{2})?$):5"
    }
)
public class CouponIssueServlet extends SlingAllMethodsServlet { ... }
```

---

### Case 4. 한 서블릿에서 여러 경로(`sling.servlet.paths`)를 처리할 때 경로별 차등 설정 케이스

하나의 서블릿이 조회(`/inquiry`)와 취소(`/cancel`) 등 여러 경로를 동시에 처리하는 경우, **`경로:파라미터규칙`** 또는 **`[경로]파라미터규칙`** 접두사를 붙여 경로마다 서로 다른 HTTP Method와 파라미터 규칙을 지정할 수 있습니다.

```java
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/aemapi/order/inquiry",
        "sling.servlet.paths=/aemapi/order/cancel",

        // 1. 경로별 허용 HTTP Method 분리
        "security.methods=/aemapi/order/inquiry:GET",
        "security.methods=/aemapi/order/cancel:POST",

        // 2. 경로별 허용 Referer 분리 (생략된 경로는 기본 abc.com 적용)
        "security.allowedReferrers=/aemapi/order/cancel:pay.abc.com",

        // 3. [공통 파라미터] 경로 접두사가 없으면 서블릿의 모든 경로(/inquiry, /cancel)에 공통 적용
        "security.params=orderId:required:pattern(^ORD_[0-9]{3,10}$):15",

        // 4. [경로 전용 파라미터] 특정 경로에만 적용되는 파라미터 규칙
        "security.params=/aemapi/order/inquiry:includeHistory:optional:true|false:5",
        "security.params=/aemapi/order/cancel:cancelReason:required:2..200",
        "security.params=/aemapi/order/cancel:refundAccount:optional:digits:10..16"
    }
)
public class MultiPathOrderServlet extends SlingAllMethodsServlet { ... }
```

> **참고**: `sling.servlet.resourceTypes`를 여러 개 사용하는 서블릿에서도 동일하게 `"security.params=myproject/components/product/review:rating:required:1|2|3|4|5"` 형태로 리소스 타입별 분리가 가능합니다.

---

### Case 5. 다양한 프로퍼티 선언 스타일 (개별 키 분리 / 단순 필수 목록 / JSON 예외 허용)

기본 `security.params` DSL 배열 외에도 상황에 따라 아래 3가지 방식을 혼용할 수 있습니다:

#### 5-1. 파라미터별 개별 프로퍼티 키로 분리 선언 (`security.param.<이름>`)
파라미터가 많거나 정규식이 길어서 별도 줄로 분리하고 싶을 때 유용합니다:
```java
property = {
    "sling.servlet.paths=/aemapi/board/write",
    "security.methods=POST",
    "security.param.title=required:2..100",
    "security.param.writer=required:korean:2..20",
    "security.param.customCode=required:4..12",
    "security.param.customCode.pattern=^[A-Z]{2}_[0-9]{2,9}$"
}
```

#### 5-2. 단순 필수 파라미터 이름만 빠르게 지정 (`security.requiredParams`)
형식이나 길이 제약 없이 필수 존재 여부(`required=true`)만 빠르게 선언할 때 사용합니다:
```java
property = {
    "sling.servlet.paths=/aemapi/auth/logout",
    "security.methods=POST",
    "security.requiredParams=sessionId,deviceId"
}
```

#### 5-3. 특정 파라미터에 SQLi / XSS / PathTraversal 예외 허용이 필요한 경우 (`security.params.json`)
에디터 리치 텍스트(HTML 본문)나 파일 경로 파라미터처럼 특정 파라미터에만 보안 필터 예외(`allowXss`, `allowSqlInjection`, `allowPathTraversal`)를 열어야 할 때는 `security.params.json`을 사용합니다:
```java
property = {
    "sling.servlet.paths=/aemapi/cms/article/save",
    "security.methods=POST",
    "security.params.json={"
        + "\"title\": {\"required\": true, \"minLength\": 2, \"maxLength\": 100},"
        + "\"htmlContent\": {\"required\": true, \"maxLength\": 10000, \"allowXss\": true},"
        + "\"templatePath\": {\"required\": false, \"maxLength\": 200, \"allowPathTraversal\": false}"
        + "}"
}
```

---

### Case 6. 미정의 파라미터 허용(`allowUndefinedParams`) 및 기본 정책(`default.params`) 상속 케이스

1. **기본 정책(`default.params`) 자동 상속**:
   - 서블릿에 `page`, `size`, `sort`, `order`, `lang`, `keyword`를 따로 적지 않아도 `SecurityFilter.config`의 `default.params`가 자동 상속되므로 페이징·정렬 파라미터를 바로 사용할 수 있습니다.
   - 만약 서블릿에서 `"security.params=keyword:required:2..50"`을 선언하면 기본 정책의 `keyword:optional:100` 대신 **서블릿에 선언한 규칙이 우선 적용(Override)**됩니다.
2. **정의되지 않은 파라미터 허용 (`security.allowUndefinedParams=true`)**:
   - 기본값은 `false`(화이트리스트에 없는 파라미터가 1개라도 들어오면 `SEC-40002` 차단)입니다.
   - 외부 웹훅 수신이나 가변 파라미터를 받는 서블릿의 경우 `security.allowUndefinedParams=true`로 설정하면 미정의 파라미터도 허용하되, **유입되는 모든 미정의 파라미터 값에 대해서도 Path Traversal / SQLi / XSS 검사는 자동으로 수행**하여 안전하게 보호합니다:
   ```java
   property = {
       "sling.servlet.paths=/aemapi/webhook/callback",
       "security.methods=POST",
       "security.allowUndefinedParams=true",
       "security.params=signature:required:64"
   }
   ```

---

## 🚨 4. 차단 시 로그 출력 예시 (`BlockedByConfig` & `AppliedServletPolicy`)

요청이 필터에 의해 차단되면 **어떤 설정 규칙과 입력값 때문에 막혔는지(`BlockedByConfig`)**와 **해당 서블릿에 적용된 전체 보안 설정(`AppliedServletPolicy`)**이 동시에 출력됩니다:

```text
SECURITY VIOLATION BLOCKED: Client IP=[127.0.0.1], Method=[POST], URI=[/aemapi/user/contact], Validator=[PARAM], Status=[400], ErrorCode=[SEC-40003], Reason=[Parameter [name] length (1) < min (2)]
  | BlockedByConfig=[param=name, minLength=2, actualLength=1, rule={required=true, len=2..20, pattern='^[가-힣a-zA-Z\s]+$'}]
  | AppliedServletPolicy=[source=com.example.security.servlets.UserContactServlet, target=/aemapi/user/contact, methods=[POST], allowedReferrers=[abc.com, partner.abc.com], blockSqlInjection=true, blockXss=true, allowUndefinedParams=false, params={page={required=false, len=0..5, pattern='^[0-9]+$'}, ..., name={required=true, len=2..20, pattern='^[가-힣a-zA-Z\s]+$'}, email={required=true, len=0..50, pattern='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'}}]
```
