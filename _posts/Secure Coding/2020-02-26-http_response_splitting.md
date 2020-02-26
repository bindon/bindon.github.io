---
layout: post
title: HTTP Response Splitting
author: bindon
post_list: "current"
category: Secure Coding
date: 2020-02-26
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

HTTP의 규격에 따르면 아래 예제와 같이 헤더의 각 필드는 CR(Carriage Return), LF(Line Feed)를 이용하여 구분되며, Header와 Body의 구분은 두 개의 CR, LF를 이용하여 구분된다.
만약 사용자로부터 받은 값을 헤더에 추가하는 로직이 있을 때 악의적인 입력으로 강제로 개행시켜 다른 Header를 추가하거나 잘못된 동작을 일으킬 수 있으며, Response Body또한 수정이 가능해진다.

* HTTP Response Example

```html
POST /rest/request HTTP/1.1
Host: bindon.github.io
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 355
Connection: close
Referer: https://bindon.github.io
Cookie: JSESSIONID=00112233445566778899AABBCCDDEEFF; mycookie=bindon;
 
<html>
<head><title>Example</title></head>
<body>Hello World!</body>
</html>
```

***

# Vulnerable Case

1. 사용자는 parameter을 통해 자신의 ID를 서버로 전송
  - https://example.com/?id=bindon%0d%0a%0d%0a&lt;script&gt;alert(document.domain)&lt;/script&gt;
2. 서버에서는 받은 ID를 Header의 X-ID라는 필드에 저장
3. CR(%0d), LF(%0a)로 인하여 &lt;script&gt;가 Body에 기록되므로 스크립트가 실행됨

* Result
  - HTTP Response 1

```html
POST /rest/request HTTP/1.1
Host: bindon.github.io
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/json
X-Requested-With: XMLHttpRequest
X-ID: bindon
 
<script>alert(1)</script>
Content-Length: 355
Connection: close
Referer: https://bindon.github.io
Cookie: JSESSIONID=00112233445566778899AABBCCDDEEFF; mycookie=bindon;
 
<html>
<head><title>Example</title></head>
<body>Hello World!</body>
</html>
```

***

# Good Practice

간단하게 저장하기 이전 URL Encoding, Base64 Encoding을 수행하고 값 사용 시 Decoding하여 사용하거나 값 자체에 개행문자가 들어오지 않도록 XSS Prevention을 참고하여 Sanitization을 수행
