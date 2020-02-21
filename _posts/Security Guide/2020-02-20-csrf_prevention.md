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

# Details

사용자의 입력을 받을 때 Form 또는 Ajax를 사용하는 경우 CSRF Token을 추가하여 사용자가 의도하지 않은 요청에 대해 대비해야 한다.

예를 들어 공격자는 사이트의 운영자에게 아래와 같은 이미지 태그가 포함된 메일을 전송한다.

```html
<img src="https://bindon.github.io/changeUserAcoount?id=admin&password=admin" width="0" height="0" />
```

이 때 만약 운영자가 사이트에 로그인 상태였다고 가정할 때 작성한 URI를 통해 id와 password가 admin으로 변경될 것이며, 운영자는 이미지의 width와 height가 0이기 때문에 자신의 패스워드가 변경되었다는 것을 눈치채지 못하고 공격자가 접속할 때 까지 조치하지 못 할 것이다.

이러한 공격을 방어하기 위해 CSRF Token을 사용하면, 공격자는 CSRF Token을 생성할 수 없기 때문에 매개변수로 만들어 전달할 수 없게 된다. 서버측에서는 CSRF Token이 같이 전송되지 않았기 때문에 해당 요청을 거절하게 된다.

만약 GET으로 토큰을 받은 후 POST로 전송하는 케이스가 아닌 경우 CSRF 토큰을 받을 수 없기 때문에, CSRF 토큰을 조회하는 API를 만들어 사용자의 정보를 입력하여 전송하기 전 CSRF 토큰을 받아 동일한 방식으로 서버에서 점검할 수 있도록 조치해야 한다.

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
            <input type="text"   name="value" id="value" value="LINE" />
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
