---
layout: post
title: HTTP Security Headers
author: bindon
post_list: "current"
category: Security Guide
date: 2020-02-21
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

웹 개발 시 HTTP Header를 통해 클라이언트의 행위를 제한할 수 있다. 일반 사용자가 외부의 공격(e.g. XSS)을 통해 중요한 데이터가 유출되거나 의도하지 않은 행위가 발생하지 않도록 예방할 수 있다.

Security Header는 필요한 리소스의 사용에 대해서는 권한을 설정하여 편의성(Usability)는 그대로 유지하되 의도하지 않은 리소스에 대해서 제한하는 방향으로 적용시킨다.

예를 들어 Javascript를 사용해야 하는 페이지가 있을 때 A.js, B.js와 따로 정의한 inline-javascript를 사용할 경우 CSP헤더를 이용하여 두 Javascript 파일과 inline-javascript를 등록하여 XSS와 같은 공격을 받게 되더라도 공격자에 의해 삽입된 Javascript를 실행할 수 없도록 설정한다.

***

# Set-Cookie
* 사용자 브라우저에 쿠키를 전송하기 위해 사용되는 HTTP Header(상세 정보 확인)
  - &lt;cookie-name&gt;=&lt;cookie-value&gt; 형태로 값을 지정함
  - SameSite의 경우 먼저 Strict를 적용한 후 문제가 있을 시 다른 옵션으로 변경하는 것을 권장

| Directives                     | Description                                                                                                                                                                  |
|:-------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *Secure*                       | HTTPS 프로토콜을 사용할 때에만 전송                                                                                                                                          |
| *HttpOnly*                     | JavaScript를 통해 쿠키에 접근할 수 없도록 함                                                                                                                                 |
| Path=&lt;path-value&gt;        | 쿠키 헤더를 보내기 요청 된 URL 경로를 나타냄<br />디렉토리 구분 기호(/)로 구분되며 하위 디렉토리도 허용                                                                      |
| Max-Age=&lt;number&gt;         | 쿠키가 만료될 때 까지의 시간(초)<br />0 또는 음수가 지정되면 즉시 만료<br />Expires와 Max-Age가 둘 다 설정될 경우 Max-Age로 적용                                             |
| Domain=&lt;domain-value&gt;    | 쿠키가 적용되어야 하는 호스트를 지정<br />도메인이 dot(".", %x2e)으로 시작되지 않아야 함(RFC 6265)<br />지정되어있지 않으면 현재 URI 기준으로 적용(서브도메인 미포함)<br />www.example.com (O)<br />www.foo.example.com (X)<br />도메인을 지정할 경우 서브도메인 포함<br />www.example.com (O)<br />www.foo.example.com (O) |
| Expires=&lt;date&gt;           | 타임스탬프로 키록된 쿠키의 최대 유지 시간<br />지정되지 않을 경우 세션 쿠키로 취급되며 클라이언트가 종료될 때 파기<br />maxAge를 설정하면 Expires가 자동으로 설정(RFC 6265)  |
| *SameSite={None, Strint, Lax}* | 허용된 사이트에만 쿠키를 보낼 수 있도록 설정<br />None: 제 3자에게 쿠키 전송 허용<br />Strict: 제 3자에게 쿠키가 전송되지 않음<br />Lax: GET으로 요청하는 일부에 대해서 허용 |

* Examples
  - Java

```java
package io.github.bindon.controller;
 
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/myinfo")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookieName", "cookieValue");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
         
        return "index";
    }
}
```

  - Result
![Cache-Control]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_set-cookie.png){:style="display: block; margin: 0 auto"}

***

# CSP(Content-Security-Policy)

* 특정 컨텐츠를 삽입할 수 있는 공격을 완화하기 위해 사용되는 헤더([상세 정보 확인](https://developers.google.com/web/fundamentals/security/csp?hl=ko))

| Resource                  | Description                                                                                                |
|:--------------------------|:-----------------------------------------------------------------------------------------------------------|
| base-uri                  | 페이지의 &lt;base&gt; 요소에 나타날 수 있는 URL을 제한                                                     |
| child-src                 | 작업자와 삽입된 프레임 콘텐츠에 대한 URL을 나열                                                            |
| connect-src	              | XHR, WebSockets, EventSource 등을 통해 연결할 수 있는 출처를 제한                                          |
| font-src                  | 웹 글꼴을 제공할 수 있는 출처 지정                                                                         |
| form-action               | &lt;form&gt; 태그의 action 속성에 사용되는 사이트를 관리                                                   |
| frame-ancestors           | 현재 페이지를 삽입할 수 있는 소스 지정 &lt;frame&gt;, &lt;iframe&gt;, &lt;embed&gt;, &lt;applet&gt;에 적용 |
| frame-src                 | 사용 안함, child-src로 변경                                                                                |
| img-src                   | 이미지 로드를 위한 소스 지정                                                                               |
| media-src                 | 동영상과 오디오를 위한 소스 지정                                                                           |
| object-src                | 플래시 등 기타 플러그인에 대한 제어 허용                                                                   |
| plugin-types              | 페이지가 호출할 수 있는 플러그인의 종류 제한                                                               |
| rerport-uri               | 콘텐츠 보안 정책 위반 시 브라우저가 보고서를 보낼 URL을 지정                                               |
| style-src                 | CSS를 위한 소스 지정                                                                                       |
| script-src                | Javascript를 위한 소스 지정                                                                                |
| upgrade-insecure-requests | HTTP를 HTTPS로 변경하도록 지시                                                                             |

| Source          | Description                      |
|:----------------|:---------------------------------|
| 'none'          | 아무것도 허용하지 않음           |
| 'self'          | 현재 소스와 일치하는 소스만 허용 |
| 'unsafe-inline' | Inline Javascript 및 CSS 허용    |
| 'unsafe-eval'   | eval()과 같은 Javascript 허용    |

* Examples
  - NGINX

```nginx
add_header Content-Security-Policy "
  script-src 'self' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com;
  frame-src  'self' *.youtube.com *.facebook.com;
  object-src 'self'
";
```

  - Java

```java
package io.github.bindon.controller;
 
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
 
@Controller
public class SecurityHeaderController {
    @GetMapping("/")
    public String getSecurityHeaderPage(HttpServletResponse response) {
        response.addHeader("Content-Security-Policy", new StringBuilder()
                .append("default-src")
                .append("  'self'")
                .append(";")
                .append("script-src")
                .append("  'self'")
                .append("  https://*.jquery.com")
                .append("  https://*.cloudflare.com")
                .append("  https://*.bootstrapcdn.com")
                .append("  'sha256-vdn82jIbifAhhDy5DUG3/XzBxBTs9agx15YRH4J3R0o='") // console.log("Hello CSP!");
                .append(";")
                .append("style-src")
                .append("  'self'")
                .append("  https://*.bootstrapcdn.com")
                .append("  https://*.getbootstrap.com")
                .append(";")
                .append("img-src")
                .append("  'self'")
                .append("  https://*.google.com")
                .append(";").toString());
         
        return "security_header";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;
 
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 
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
        .headers()
            // CSP Header
            .contentSecurityPolicy(new StringBuilder()
                    .append("default-src")
                    .append("  'self'")
                    .append(";")
                    .append("script-src")
                    .append("  'self'")
                    .append("  https://*.jquery.com")
                    .append("  https://*.cloudflare.com")
                    .append("  https://*.bootstrapcdn.com")
                    .append("  'sha256-vdn82jIbifAhhDy5DUG3/XzBxBTs9agx15YRH4J3R0o='") // console.log("Hello CSP!");
                    .append(";")
                    .append("style-src")
                    .append("  'self'")
                    .append("  https://*.bootstrapcdn.com")
                    .append("  https://*.getbootstrap.com")
                    .append(";")
                    .append("img-src")
                    .append("  'self'")
                    .append("  https://*.google.com")
                    .append(";").toString());
    }
}
```

  - Front End

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Security Header</title>
<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
<!-- Grant Script('sha256-vdn82jIbifAhhDy5DUG3/XzBxBTs9agx15YRH4J3R0o=') -->
<script type="text/javascript">
    console.log("Hello CSP!");
</script>
<!-- Deny Script(e.g. Injected Script) -->
<script type="text/javascript">
    console.log("Unknown Script!");
</script>
</head>
<body>
<table>
<tr><td>LINE Image(Trusted Source - 'self')</td><td><img src="/resources/static/img/line.png" /></td></tr>
<tr><td>Google Image(Trusted Source - 'https://*.google.com')</td><td><img src="https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png" /></td></tr>
<tr><td>Daum Image(Untrusted Source)</td><td><img src="https://t1.daumcdn.net/daumtop_chanel/op/20170315064553027.png" /></td></tr>
</table>
</body>
</html>
```

  - Result
![Content Security Policy]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_csp.png){:style="display: block; margin: 0 auto"}
![Content Security Policy Result]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_csp_result.png){:style="display: block; margin: 0 auto"}

***

# Cache Control

* 서버와 클라이언트 사이의 캐싱 정책으로 브라우저가 캐싱을 수행해야 하는지와 언제 서버에게 다시 요청하는지 결정([상세 정보 확인](https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/Cache-Control))
* 캐시 사용 시 동일한 프록시 서버를 이용하는 사용자 간의 세션이 공유 될 수 있음
* API 서버 또한 인증을 하지 않고 데이터를 받아오는 일이 발생할 수 있기 때문에 적용 필요
* 지시자 종류
  - 캐시 요청: max-age, max-stale, min-fresh, no-cache, no-store, no-transform, only-if-cached
  - 캐시 응답: must-revalidate, no-cache, no-store, no-transform, public, private, proxy-revalidate, max-age, s-maxage

| Cacheability | Description                                                |
|:-------------|:-----------------------------------------------------------|
| *no-cache*   | 캐시 페이지를 보여주기 전 재검증을 위한 요청을 서버로 보냄 |
| *no-store*   | 클라이언트 요청, 서버 응답에 관해 어떤 것도 저장하지 않음  |
| private      | 단일 사용자를 위한 캐시                                    |
| public       | 어떤 정보라도 캐시될 수 있음                               |

| Expiration                             | Description                                                                                                      |
|:---------------------------------------|:-----------------------------------------------------------------------------------------------------------------|
| *max-age=&lt;seconds&gt;*              | 리소스가 최신 상태라고 판단할 최대 시간(0으로 설정 권장)                                                         |
| s-maxage=&lt;seconds&gt;               | 공유 캐시에만 적용됨                                                                                             |
| max-stale\[=&lt;seconds&gt;\]          | 클라이언트가 캐시 만료 시간을 초과한 응답을 받아들일지 선택(seconds: 만료 되어서는 안되는 시간을 정의)           |
| min-fresh=&lt;seconds&gt;              | 클라이언트가 지정된 시간동안 최신 정보를 받도록 함                                                               |
| stale-while-revalidate=&lt;seconds&gt; | 비동기적으로 최신 정보를 얻어오는 동안 캐시 된 페이지를 보여줌(seconds: 오래된 정보를 얼마나 오래 허용할 것인지) |
| stale-if-error=&lt;seconds&gt;         | 오류가 발생했을 때 성공했던 이전 정보를 전달(seconds: 응답을 허용할 시간)                                        |

| Revalidation and Reloading | Description                                             |
|:---------------------------|:--------------------------------------------------------|
| *must-revalidate*          | 캐시를 사용하기 이전에 기존 리소스의 상태를 반드시 검증 |
| proxy-revalidate           | must-revalidate가 공유 캐시에만 적용                    |
| immutable                  | 응답이 시간이 지나도 변경되지 않음을 알림               |

| Other          | Description                   |
|:---------------|:------------------------------|
| no-transform   | 캐시 된 응답만 받도록 요청    |
| only-if-cached | 응답이 변경되지 못하도록 설정 |

* Examples
  - Java

```java
package io.github.bindon.controller;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0L);
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;
 
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 
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
        /* Cache Control is default(in Spring Security)
         * Cache-Control: no-cache, no-store, must-revalidate
         * Pragma: no-cache
         * Expires: 0
         */
        http.headers().cacheControl();
    }
}
```

  - Result
![Cache-Control]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_cache-control.png){:style="display: block; margin: 0 auto"}

***

# HSTS(HTTP Strict-Transport-Security)

* HTTP 대신 HTTPS만을 사용하여 통신해야한다고 웹사이트가 브라우저에 알리는 보안 기능([상세 정보 확인](https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/Strict-Transport-Security#Preloading_Strict_Transport_Security))
  - HTTP 요청은 MITM의 위험성이 존재하기 때문에 HTTPS로 변경되어야 한다고 알리는 헤더

| Directives          | Description                                                       |
|:--------------------|:------------------------------------------------------------------|
| *max-age*           | 이 사이트가 HTTPS 로만 접근되어야 한다고 기억되어야 하는 시간(초) |
| *includeSubDomains* | 하위 도메인에도 HTTPS로만 접속                                    |
| *preload*           | 브라우저 자체에 내장된 HSTS 설정 사용                             |

* Examples
  - Java

```java
package io.github.bindon.controller;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;
 
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 
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
            .headers()
                .httpStrictTransportSecurity()
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000); // 1 year : 365*24*60*60;
    }
}
```

  - Result

![HSTS]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_hsts.png){:style="display: block; margin: 0 auto"}

***

# X-XSS-Protection

* Reflected XSS와 같은 공격을 탐지
  - 탐지된다면 옵션에 따라서 해당 부분을 제거한 후 렌더링하거나 렌더링을 하지않고 경고문 출력
  - 해당 옵션은 데이터를 받아온 후 렌더링 시점에서 발생하는 공격을 막는 옵션이며 Ajax를 통해 조회한 데이터에 대해서는 다룰 수 없음(API 서버는 헤더 설정 필요 없음)
    * ex) 웹 서버 및 API 서버에 "1; mode=block"을 적용하더라도 Ajax로 조회한 데이터에 XSS가 존재하면 스크립트가 실행 됨

| Directives                                        | Description                                                      |
|:--------------------------------------------------|:-----------------------------------------------------------------|
| X-XSS-Protection: 0                               | 비활성                                                           |
| X-XSS-Protection: 1	                              | XSS 공격 감지 시 해당하는 부분을 제거하고 렌더링하여 페이지 출력 |
| *X-XSS-Protection: 1; mode=block*	                | XSS 공격 감지 시 페이지 렌더링 중단                              |
| X-XSS-Protection: 1; report=&lt;reporting-uri&gt;	| XSS 공격 탐지 시 해당 URI로 보고서 전송                          |

* Examples
  - NGINX

```nginx
add_header X-XSS-Protection "1; mode=block";
```

  - Java
  
```java
package io.github.bindon.controller;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("X-XSS-Protection", "1; mode=block");
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 
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
        // Spring Security Default Value : "X-XSS-Protection: 1; mode=block"
        http.headers().xssProtection();
    }
}
```

  - Result

![X-XSS-Protection]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_x-xss-protection.png){:style="display: block; margin: 0 auto"}

***

# X-Content-Type-Options

* Content-Type에 저장된 MIME Type을 검사하여 올바른 형태인 경우에만 허용
* 요청 차단
  - &lt;style&gt;태그를 사용할 경우 type="text/css"가 아니면 차단
  - &lt;script&gt;태그를 사용할 경우 type="text/javascript"가 아니면 차단
* MIME-type이 일치하지 않을 시 읽기 차단(Cross-Origin Read Blocking)
  - text/html
  - text/plain
  - text/json, application/json, */*+json
  - text/xml, application/xml, */*+xml(image/svg+xml 제외)

| Directives                        | Description                        |
|:----------------------------------|:-----------------------------------|
| *X-Content-Type-Options: nosniff*	| MITMTYPE이 일치하지 않을 경우 차단 |
| X-Content-Type-Options: sniff	    | MITMTYPE이 일치하지 않아도 허용    |

* Examples
  - NGINX

```nginx
add_header X-Content-Type-Options nosniff;
```

  - Java

```java
package io.github.bindon.controller;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("X-Content-Type-Options", "nosniff");
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

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
        http.headers().contentTypeOptions();
    }
}
```

  - Result

![X-Content-Type-Options]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_x-content-type-options.png){:style="display: block; margin: 0 auto"}

***

# Referrer-Policy

* Referer 헤더를 관리하는 정책
* strict-origin을 기본으로 적용하고 필요한 경우 다른 옵션으로 수정

| Directives                      | Description                                                    |
|:--------------------------------|:---------------------------------------------------------------|
| no-referrer                     | 모든 referer 헤더가 제거                                       |
| no-referrer-when-downgrade      | https에서 http로 변경될 때 referer가 제거                      |
| same-origin                     | 동일한 도메인에서만 referer 유지 (http, https도 동일해야 함)   |
| origin                          | 모든 경로가 제거된 URL만 referer로 설정                        |
| *strict-origin*                 | origin과 동일하지만, https에서 http로 변경될 때는 referer 제거 |
| origin-when-cross-origin        | 동일한 도메인이 아닐 경우에만 origin 적용                      |
| strict-origin-when-cross-origin | 동일한 도메인이 아닐 경우에만 strict-origin 적용               |
| unsafe-url                      | 모든 요청에 대해서 referer 허용                                |

* Examples
  - Java

```java
package io.github.bindon.controller;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Referrer Policy", "no-referrer-when-downgrade");
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
 
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
        http.headers().referrerPolicy(ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE);
    }
}
```

  - Result

![Referrer-Policy]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_referrer-policy.png){:style="display: block; margin: 0 auto"}

***

# X-Frame-Options

* 자신이 iframe 또는 object 태그로 인해 렌더링 될 때의 정책 정의

| Directives                                     | Description                                                      |
|:-----------------------------------------------|:-----------------------------------------------------------------|
| *X-Frame-Options: deny*                        | 해당 페이지를 iframe 또는 object 태그로 import 할 수 없도록 금지 |
| X-Frame-Options: sameorigin                    | 도메인이 동일한 경우에만 렌더링 가능                             |
| X-Frame-Options: allow-from https://bindon.com | https://bindon.com 도메인에서만 렌더링 가능                      |

* Examples
  - NGINX

```nginx
add_header X-Frame-Options deny;
```

  - Java

```java
package io.github.bindon.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("X-Frame-Options", "sameorigin");
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 
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
        http.headers().frameOptions().sameOrigin();
    }
}
```

  - Result

![X-Frame-Options]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_x-frame-options.png){:style="display: block; margin: 0 auto"}

***

# Access-Control-Allow-Origin

* 사용 가능한 Origin를 정의하고 해당 Origin으로만 접근 허용
* 헤더를 적용하지 않을 경우 기본값은 없으며, 응답과 요청이 동일한 도메인일 경우만 허용할 수 있도록 설정되기 때문에 기본적으로는 적용할 필요가 없음

| Directives                                  | Description                                    |
|:--------------------------------------------|:-----------------------------------------------|
| Access-Control-Allow-Origin: *              | 모든 origin에서 접근 허용                      |
| Access-Control-Allow-Origin: &lt;origin&gt; | 설정한 origin에서만 접근 허용(1개만 설정 가능) |
| Access-Control-Allow-Origin: null           | 접근 불가                                      |

***

# Access-Control-Allow-Methods

* 사용 가능한 Methods를 정의하고 해당 Methods로만 접근 허용
* POST, GET, OPTIONS와 같이 사용하는 메소드만 허용
* Preflight Request(사전 요청)에 'Access-Control-Allow-Methods'가 포함된 경우 사용

| Directives                                                        | Description                                             |
|:------------------------------------------------------------------|:--------------------------------------------------------|
| Access-Control-Allow-Methods: &lt;method&gt;, &lt;method&gt;, ... | 설정한 메소드만 허용 <method> : POST, GET, OPTIONS, ... |
| Access-Control-Allow-Methods: *                                   | 모든 메소드 허용                                        |

***

# Access-Control-Allow-Headers

* 사용 가능한 Header를 정의하고 해당 Header만 허용
* 추가하지 않아도 되는 헤더 : Accept, Accept-Language, Content-Language, Content-Type(application/x-www-form-urlencoded, multipart/form-data, text/plain)
* Preflight Request(사전 요청)에 'Access-Control-Allow-Headers'가 포함된 경우 사용

| Directives                                                                  | Description                   |
|:----------------------------------------------------------------------------|:------------------------------|
| Access-Control-Allow-Headers: &lt;header-name&gt;\[, &lt;header-name&gt;\]* | &lt;header-name&gt; 헤더 허용 |

***

# Access-Control-Allow-Credentials
* 표준 CORS는 요청을 전송할 때 쿠키를 전송하지 않음
* 쿠키를 요청에 포함하기 위한 옵션으로 해당 옵션을 설정하지 않을 경우 요청이 실패

| Directives                             | Description                 |
|:---------------------------------------|:----------------------------|
| Access-Control-Allow-Credentials: true | false일 경우 해당 요청 실패 |

* Examples
  - Ajax

```javascript
$.ajax({
  type: "POST",
  xhrFields: {withCredentials: true},
  dataType: "xml",
  contentType: "text/xml; charset=\"utf-8\"",
  url: "https://example.com",
});
```

  - XHR

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://example.com/', true);
xhr.withCredentials = true;
xhr.send(null);
```

  - Fetch

```javascript
fetch(url, {
  credentials: 'include'
})
```

***

# Feature Policy

* 브라우저에서 사용할 수 있는 기능에 대한 허용 및 거부할 수 있도록 제공
* CSP와 유사한 방법으로 정의할 수 있음

| Allow List | Description                                               |
|:-----------|:----------------------------------------------------------|
| *          | iframe을 포함한 현재 페이지에서 기능 허용                 |
| 'self'     | iframe이 현재 페이지와 동일한 도메인일 경우에만 기능 허용 |
| 'src'      | iframe이 src에 명시한 도메인인 경우에만 기능 허용         |
| 'none'     | iframe에서 해당 기능을 허용하지 않음                      |

| Features                        | Description                                                                           |
|:--------------------------------|:--------------------------------------------------------------------------------------|
| accelerometer                   | Accelerometer 인터페이스를 통해 장치의 가속도 정보를 수집할 것인지 설정               |
| ambient-light-sensor            | AmbientLightSensor 인터페이스를 통해 장치 주변 환경의 조도 정보를 수집할 것인지 설정  |
| autoplay                        | HTMLMediaElement 인터페이스를 통해 요청된 미디어를 자동 재생하도록 허용할 것인지 설정 |
| battery                         | Battery Status API를 사용 여부를 허용할 것인지 설정                                   |
| camera                          | 비디오 입력 장치를 사용할 것인지 설정                                                 |
| display-capture                 | getDisplayMedia()를 이용하여 화면 내용을 캡처할 것인지 설정                           |
| document-domain                 | document.domain을 사용할 것인지 설정                                                  |
| encrypted-media                 | EME(Encrypted Media Exstensions API)를 사용할 것인지 설정                             |
| execution-while-not-rendered    | 렌더링 되지 않는 동안 프레임에서 작업을 실행할 것인지 설정                            |
| execution-while-out-of-viewport | 볼 수 없는 영역에 있을 때 실행할 것인지 설정                                          |
| fullscreen                      | Element.requestFullScreen()을 이용한 전체화면을 사용할 것인지 설정                    |
| geolocation                     | Geolocation 인터페이스를 통해 GPS 위치 정보를 수집할 것인지 설정                      |
| gyroscope                       | Gyroscope 인터페이스를 통해 장치의 방향에 대한 정보를 수집할 것인지 설정              |
| magnetometer                    | Magnetometer 인터페이스를 통해 장치 방향에 대한 정보를 수집할 것인지 설정             |
| microphone                      | 오디오 입력 장치를 사용할 것인지 설정, MediaDevices.getUserMedia()                    |
| midi                            | Web MIDI API를 사용할 것인지 설정, Navigator.requestMIDIAccess()                      |
| payment                         | Payment Request API를 사용할 것인지 설정                                              |
| picture-in-picture              | API를 통해 Picture-in-Picture 모드에서 비디오를 재생할 것인지 설정                    |
| publickey-credentials           | Web Authentication API를 사용하여 공개 키 자격 증명을 생성, 저장, 검색할 것인지 설정  |
| speaker                         | 모든 방법을 통해 오디오를 재생할 것인지 설정                                          |
| sync-xhr                        | XMLHttpRequest 요청을 할 것인지 설정                                                  |
| usb                             | WebUSB API를 사용할 것인지 설정                                                       |
| vr                              | WebVR API를 사용할 것인지 설정, Navigator.getVRDisplays()                             |
| wake-lock                       | Wake Lock API를 사용하여 장치가 절전 모드로 들어가면 안됨을 나타낼 것인지 설정        |
| xr-spatial-tracking             | WebXR Device API를 사용하여 WebXR 세션과 상호 작용할 것인지 설정                      |

* Examples
  - Java

```java
package io.github.bindon.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
 
@Controller
public class IndexController {
    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Feature-Policy", "microphone 'none'; geolocation 'none'");
         
        return "index";
    }
}
```

  - Spring Security

```java
package io.github.bindon.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 
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
        http.headers().featurePolicy(new StringBuilder()
                .append("microphone 'none'")
                .append("; ")
                .append("geolocation 'none'").toString());
    }
}
```

  - Result

![Feature-Policy]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-21-security_headers/examples_feature-policy.png){:style="display: block; margin: 0 auto"}
