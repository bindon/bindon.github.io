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
- 사용자 브라우저에 쿠키를 전송하기 위해 사용되는 HTTP Header(상세 정보 확인)
  - <cookie-name>=<cookie-value> 형태로 값을 지정함
  - SameSite의 경우 먼저 Strict를 적용한 후 문제가 있을 시 다른 옵션으로 변경하는 것을 권장

| Directive                      | Description                     |
|:-------------------------------|:--------------------------------|
| *Secure*                       | * HTTPS 프로토콜을 사용할 때에만 전송                                                                                                                                                                                                                                                                                                 |
| *HttpOnly*                     | * JavaScript를 통해 쿠키에 접근할 수 없도록 함                                                                                                                                                                                                                                                                                         |
| Path=<path-value>              | * 쿠키 헤더를 보내기 요청 된 URL 경로를 나타냄<br>* 디렉토리 구분 기호(/)로 구분되며 하위 디렉토리도 허용                                                                                                                                                                                                                                            |
| Max-Age=<number>               | * 쿠키가 만료될 때 까지의 시간(초)<br>* 0 또는 음수가 지정되면 즉시 만료<br>* Expires와 Max-Age가 둘 다 설정될 경우 Max-Age로 적용                                                                                                                                                                                                                  |
| Domain=<domain-value>          | * 쿠키가 적용되어야 하는 호스트를 지정<br>  * 도메인이 dot(".", %x2e)으로 시작되지 않아야 함(RFC 6265)<br>    * 지정되어있지 않으면 현재 URI 기준으로 적용(서브도메인 미포함)<br>      * www.example.com (O)<br><br>      * www.foo.example.com (X)<br>    * 도메인을 지정하면할 경우 서브도메인 포함<br>      * www.example.com (O)<br>      * www.foo.example.com (O) |
| Expires=<date>                 | * 타임스탬프로 키록된 쿠키의 최대 유지 시간<br>* 지정되지 않을 경우 세션 쿠키로 취급되며 클라이언트가 종료될 때 파기<br>* maxAge를 설정하면 Expires가 자동으로 설정(RFC 6265)                                                                                                                                                                                   |
| *SameSite={None, Strint, Lax}* | * 허용된 사이트에만 쿠키를 보낼 수 있도록 설정<br>* None: 제 3자에게 쿠키 전송 허용<br>* Strict: 제 3자에게 쿠키가 전송되지 않음<br>* Lax: GET으로 요청하는 일부에 대해서 허용(하단 참조)                                                                                                                                                                        |
