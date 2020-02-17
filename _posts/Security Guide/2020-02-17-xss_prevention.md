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
1. Stored XSS(AKA **Persistent** or **Type 1**)
2. Reflected XSS(AKA **Non-Persistent** or **Type 2**)
3. DOM based XSS(AKA **Type 0**)

하지만, 이 유형들은 서로 겹치는 내용이 존재하기 때문에 2012년부터 아래와 같이 분류하기로 하였다.
* Server XSS
  - **서버 측에 취약점이 존재**하며, 서버에서 내려준 HTTP Response에 스크립트가 포함되어 있는 경우
  - 예를 들어 DB에 저장된 내용을 front end로 전달하여 렌더링할 때 저장된 내용에 스크립트가 포함되어 있다면 렌더링 도중 XSS가 발생
* Client XSS
  - **클라이언트 측에 취약점이 존재**하며, 외부에서 유입된 Javascript를 실행하도록 하는 경우
  - 예를 들어 URL의 매개변수로 스크립트를 전달하여 이를 클릭했을 때 XSS가 발생하는 경우

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