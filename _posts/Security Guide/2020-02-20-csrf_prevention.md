---
layout: post
title: CSRF(Cross Site Request Forgery) Prevention
author: bindon
post_list: "current"
category: Security Guide
date: 2020-02-20
toc: true
home_btn: true
btn_text: true
footer: true
maximize: true
encrypted_text: true
toc_level: 6
excerpt: ""
abstract: ""
---

# Introduction

CSRF(Cross Site Request Forgery)이란 웹 취약점의 하나로 인터넷 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위를 요청하게 만드는 공격이다.

***

# Details

사용자의 입력을 받을 때 Form 또는 Ajax를 사용하는 경우 CSRF Token을 추가하여 사용자가 의도하지 않은 요청에 대해 대비해야 한다.

예를 들어 공격자는 사이트의 운영자에게 아래와 같은 이미지 태그가 포함된 메일을 전송한다.

```html
<img src="https://bindon.github.io/changeUserAcoount?id=admin&password=admin" width="0" height="0" />
```

이 때 만약 운영자가 사이트에 로그인 상태였다고 가정할 때 작성한 URI를 통해 id와 password가 admin으로 변경될 것이며, 운영자는 이미지의 width와 height가 0이기 때문에 자신의 패스워드가 변경되었다는 것을 눈치채지 못하고 공격자가 접속할 때 까지 조치하지 못 할 것이다.

이러한 공격을 방어하기 위해 CSRF Token을 사용하면, 공격자는 CSRF Token을 생성할 수 없기 때문에 매개변수로 만들어 전달할 수 없게 된다. 서버측에서는 CSRF Token이 같이 전송되지 않았기 때문에 해당 요청을 거절하게 된다.

만약 GET으로 토큰을 받은 후 POST로 전송하는 케이스가 아닌 경우 CSRF 토큰을 받을 수 없기 때문에, CSRF 토큰을 조회하는 API를 만들어 사용자의 정보를 입력하여 전송하기 전 CSRF 토큰을 받아 동일한 방식으로 서버에서 점검할 수 있도록 조치해야 한다.


## CSRF Prevention Technique

### Token Based Mitigation

* State: synchronizer token pattern
  - 현재 가장 많이 사용하고 있으며 가장 권장하는 방법
  - 요청 당 한 개의 토큰 발급을 권장하지만, 필요에 따라 세션 당 한 개의 토큰 발급을 수행할 수 있음
* Stateless: encrypted/hash based token pattern


#### Synchronizer Token Pattern

* CSRF 공격을 방지하기 위한 CSRF Token의 조건
  - 사용자 세션마다 고유한 CSRF Token 생성
  - 충분히 큰 Random 값: 32 bytes == 256 bits 권장
  - CSPRNG(Cryptographically Secure Pseudo-Random Number Generator) 사용: Java의 SecureRandom
* Hidden Field, HTTP Header에 추가할 수 있으며, Form 및 Ajax에 사용될 수 있음
* 보안성: HTTP Header > Hidden Field, 공격자가 XMLHttpRequest 헤더를 스푸핑하려고 할 때 브라우저의 CORS로 인하여 방지할 수 있음
* 높은 보안성이 요구될 때에는 하나의 요청 당 하나의 CSRF Token을 생성해야 하지만, 세션당 한 개의 CSRF Token을 발행할 수 있음


#### Encrypted Based Token Pattern

1. 서버에서 가지고 있는 키를 이용하여 Session ID와 Timestamp(for replay attack 방지)로 구성된 토큰을 생성하여 전달
  - AES256-GCM 권장
2. 클라이언트에서는 Hidden Field 또는 HTTP Header에 추가할 수 있으며, From 및 Ajax에 사용될 수 있음
3. 서버측에서 값을 다시 받아 자신의 키를 이용하여 복호화를 수행하고 검증을 수행
  - Session ID로 사용자를 검증
  - Timestamp로 만료 시간을 검증


#### HMAC Based Token Pattern

1. 서버에서 가지고 있는 키를 이용하여 토큰을 생성
  - CSRF Token = HMAC(sessionId + timestamp) || timestamp
2. 클라이언트에서는 Hidden Field 또는 HTTP Header에 추가할 수 있으며, From 및 Ajax에 사용될 수 있음
3. 서버측에서 값을 다시 받아 자신의 키를 이용하여 복호화를 수행하고 검증을 수행
  1. CSRF Token에서 timestamp를 떼어내고 만료 시간을 검증
  2. 유효한 시간 내로 요청이 왔다면, sessionId에 떼어낸 timestamp를 붙여 HMAC 생성
  3. HMAC이 동일한지 확인


#### Defense In Depth Techniques

* Set-Cookie의 SameSite 사용
  - SameSite=Strict를 적용
  - 사이트 간 요청과 함께 쿠키를 보낼지 여부를 결정


#### Double-Submit Cookie

* 서버에서 CSRF Token의 상태를 유지할 수 없을 경우 사용
* 동작 방식(매 요청 시 마다 생성)
  1. 서버에서 CSRF Token을 생성하여 Cookie(필수) 및 Parameter(선택)로 내려줌
  2. SameSite, Secure 속성 적용
    * 클라이언트에서는 Hidden Field 또는 HTTP Header에 추가할 수 있으며, From 및 Ajax에 사용될 수 있음
  3. 서버측에서 올라온 Cookie의 CSRF Token과 Form Parameter 또는 HTTP Header에 전송된 CSRF Token이 일치하는지 확인
    * 만약 다른 도메인에서 공격을 수행할 경우 CORS로 인해 Cookie에 접근할 수 없을 뿐만 아니라 Cookie 자체도 전송할 수 없음

***

# Examples

## 1. Generate CSRF Token in Back End

### Spring(Spring Security Compatible)

```java
/** CSRF Token Name */
private static final String CSRF_TOKEN_MAP_KEY        = "_csrf";
private static final String CSRF_TOKEN_PARAMETER_NAME = "_csrf";
private static final String CSRF_TOKEN_HEADER_NAME    = "X-CSRF-TOKEN";
 
// FIXME : REPOSITORY and USER_SESSION is example. DO NOT USE
/** @deprecated */
private static final Map<String, String> REPOSITORY = new HashMap<String, String>();
/** @deprecated */
private static final String USER_SESSION = "USER_SESSION";
 
@GetMapping("/csrf")
public ModelAndView getCsrfPage() {
    ModelAndView csrfModel = new ModelAndView("csrf");
 
    // Generate CSRF Token
    String currentUUID = UUID.randomUUID().toString();
    Map<String, String> csrfTokenMap = Map.of(
        "parameterName", CSRF_TOKEN_PARAMETER_NAME, 
        "headerName",    CSRF_TOKEN_HEADER_NAME,
        "token",         currentUUID);
 
    // FIXME : Map CSRF token and user identification data and store it in repository
    REPOSITORY.put(USER_SESSION, currentUUID);
 
    // Allocate csrfToken
    csrfModel.addObject(CSRF_TOKEN_MAP_KEY, csrfTokenMap);
 
    return csrfModel;
}
```

### Spring Security(Default: CSRF Enabled)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf();
    }
}
```

## 2. Receive CSRF Token and Send it in Front End

### HTML Form

```html
<form method="post">
    <div class="form-group">
        <div>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input type="text"   name="value" id="value" value="bindon" />
            <input type="submit" class="btn btn-primary" id="submit" value="Send using form" />
            <input type="button" class="btn btn-primary" id="button" value="Send using ajax" />
        </div>
    </div>
</form>
```

### Ajax

```javascript
$.ajax({
    url: "/csrf",
    type: "post",
    headers: {
        "${_csrf.headerName}": "${_csrf.token}"
    },
    data: {
        "value": $("#value").val()
    },
    success: function(response) {
        alert(response);
    }
});
```

## 3. Verify CSRF Token and Exception Handling in Back End

### Spring

```java
@PostMapping("/csrf")
@ResponseBody
public String checkCsrfToken(
        @RequestHeader(value=CSRF_TOKEN_HEADER_NAME, required=false)    String csrfTokenInHeader,
        @RequestParam (value=CSRF_TOKEN_PARAMETER_NAME, required=false) String csrfTokenInParameter,
        @RequestParam("value") String value) {
    String result = "Failed";
 
    // Compare csrf tokens(server and client)
    if(!REPOSITORY.get(USER_SESSION).equals(csrfTokenInHeader)
    && !REPOSITORY.get(USER_SESSION).equals(csrfTokenInParameter)) {
        // TODO : Exception logic(Invalid token)
        throw new SecurityException("CSRF Token is Invalid");
    }
 
    // TODO : Business Logic
    result = value;
 
    return result;
}
```

### Spring Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
     
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
    }
 
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .exceptionHandling()
            .accessDeniedPage("/")
            .accessDeniedHandler(new AccessDeniedHandler() {
                @Override
                public void handle(HttpServletRequest request, HttpServletResponse response,
                        AccessDeniedException accessDeniedException) throws IOException, ServletException {
                    if(accessDeniedException instanceof MissingCsrfTokenException) {
                        // handle missing CSRF Token case
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    } else if(accessDeniedException instanceof InvalidCsrfTokenException) {
                        // handle invalid CSRF Token case
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    }
                }
            }).and()
        .authorizeRequests()
            .anyRequest().authenticated()
            .and()
        .formLogin().and()
        .httpBasic();
    }
}
```
