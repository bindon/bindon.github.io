---
layout: post
title: XSS(Cross-Site Scripting) Prevention
author: bindon
post_list: "current"
category: Security Guide
date: 2020-02-17
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

XSS(Cross-Site Scripting)이란 웹 취약점의 하나로 권한이 없는 사용자가 스크립트를 삽입할 수 있는 취약점이다.

이 취약점은 관리자 또는 다른 사용자의 세션을 탈취하여 악의적인 행위를 추가적으로 수행하기도 하며, 다른 공격과 결합하여 사용하기도 한다.

[OWASP](https://owasp.org)에서는 XSS를 크게 아래 3가지로 분류했었으며, 다른 곳에서도 이러한 분류를 이용하여 설명하는 곳이 많다.

1. Stored XSS(AKA *Persistent* or *Type 1*)
2. Reflected XSS(AKA *Non-Persistent* or *Type 2*)
3. DOM based XSS(AKA *Type 0*)

하지만, 이 유형들은 서로 겹치는 내용이 존재하기 때문에 2012년부터 아래와 같이 분류하기로 하였다.

* Server XSS
  - *Server 측에 취약점이 존재*하며, 서버에서 내려준 HTTP Response에 스크립트가 포함되어 있는 경우
  - 예를 들어 DB에 저장된 내용을 front end로 전달하여 렌더링할 때 저장된 내용에 스크립트가 포함되어 있다면 렌더링 도중 XSS가 발생
* Client XSS
  - *Client 측에 취약점이 존재*하며, 외부에서 유입된 Javascript를 실행하도록 하는 경우
  - 예를 들어 URL의 매개변수로 스크립트를 전달하여 이를 클릭했을 때 XSS가 발생하는 경우

***

# Details

XSS를 방지하기 위해서는 입력 값에 대한 Sanitizing이 필요하며 이를 위해 Client와 Server로 나누어 작성하였다.

이러한 방어 기법을 적용하더라도 XSS는 다양한 케이스가 많기 때문에 모두 방지할 수는 없지만 기본적인 수준의 공격에 안전해질 수 있다.

## Client

Client에서 렌더링 되는 방어 기법의 경우 공격자의 입장에서 스크립트와 같은 방법으로 공격이 가능하기 때문에 큰 의미가 없으며, Client에서 작성할 내용은 *JSTL(JSP Standard Tag Library)*로 *EL(Expression Language)*처럼 Client 측에서 작성하되 Server에서 렌더링 된 다음 결과가 Client로 전송되어 출력된다.

XSS를 방지하기 위한 JSTL 태그는 &lt;c:out&gt;이며 *escapeXml* Attribute를 활용한다.

```html
<c:out value="${escapedValue}" escapeXml="true" />
```

## Server

Client는 우회될 수 있기 때문에 결국 Server에서는 반드시 Sanitizing을 수행해야 한다.

주의할 점은 Escaping이 두 번 이상 수행되어 서비스에 지장이 가지 않도록 공통적으로 적용할 수 있는 시점과 지점을 찾아 한 번만 Escaping 될 수 있도록 적용해야 한다.

Server에서 작성할 내용은 *Apache Commons Text Library*에 존재하는 *StringEscapeUtils*를 사용할 예정이며, 이는 `Apache Commons Lang` -> `Apache Commons Lang3` -> `Apache Commons Text`순으로 변경되었기 때문에 가장 최신 버전인 *Apache Commons Text*를 사용하는 것을 권장한다.

`StringEscapeUtils`는 보안 목적으로 만들어진 기능이 아니며, OWASP에서 보안 목적으로 제작한 [OWASP Java HTML Sanitizer](https://github.com/owasp/java-html-sanitizer)를 사용할 것을 고려해볼 수 있다.

```java
StringEscapeUtils.escapeEcmaScript(value)
```

***

# Examples

1. &lt;img&gt; tag
img 태그는 HTML 태그 중 하나로 XSS 공격에 자주 사용되기 때문에 JSTL의 escapeXml을 이용하여 태그를 사용할 수 없게 Escaping 해야 한다.

아래 예제는 Server에서 Escaping을 수행했음에도 불구하고 Client에서 escapeXml을 수행하지 않아 스크립트가 실행된 것을 나타낸다.

![Image Tag]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-17-xss_prevention/examples_img_tag.png){:style="display: block; margin: 0 auto"}

2. java\rscript
해당 문법은 다양한 곳에 삽입될 수 있으며 *javascript:alert(1)*과 같이 작성하여 뒤에 나오는 문자열이 javascript 라는 것을 명시하고 실행시킨다.

이 때 javascript 사이에 개행(carriage return, line feed), 공백과 같은 문자가 포함되어도 javascript로 인식하며 *javascript* 문자열을 Filtering 할 경우 우회가 가능하다.

아래 예제는 Client에서 escapeXml을 사용했음에도 불구하고 Server에서 Escaping을 수행하지 않아 스크립트가 실행된 것을 나타낸다.

![Image Tag]({{site.url}}{{site.baseurl}}{{site.assets_path}}/img/posts/Security Guide/2020-02-17-xss_prevention/examples_carriage_return.png){:style="display: block; margin: 0 auto"}

***

# Glossary

* Sanitizing
  - Escaping, Filtering, Validating을 포함한 개념으로 입력을 적절하게 처리하여 비정상 동작을 막는 작업
* Escaping
  - 특정 문자를 다른 문자로 치환하는 작업
  - e.g. "&gt;" -> "&amp;gt;"
* Filtering
  - 특정 문자를 제거하는 작업
  - e.g. "&lt;script&gt;" 문자열 제거
* Validating
  - 포맷에 맞추어 입력되었는지 확인하는 작업
  - e.g. 주민등록번호의 경우 "숫자 6자리" + "-" + "숫자 7자리" 인지 검사

***

# References

* [Types of XSS in OWASP](https://owasp.org/www-community/Types_of_Cross-Site_Scripting)