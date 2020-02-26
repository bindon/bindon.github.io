---
layout: post
title: API Security
author: bindon
post_list: "current"
category: Security Guide
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

API Security는 클라이언트와 서버 간 인터페이스에서 발생할 수 있는 보안 조치들을 다루며, 인증 및 인가와 같은 내용과 밀접하게 관련이 있다.

***

# Security Design Principle

* HTTPS
  - Authenticate Server, Confidentiality, Integrity 지원
  - One-way SSL: 묵시적 인증, 서버만 인증 수행
  - Two-way SSL: 명시적 인증, 서버와 클라이언트 상호 인증 수행
* Authentication/Authorization 적용

| Server Authentication | Client Authentication | Authorization                                                      |
|:----------------------|:----------------------|:-------------------------------------------------------------------|
| One-way SSL           | API Key               | API Key                                                            |
| One-way SSL           | JWT                   | JWT                                                                |
| One-way SSL           | IP Filtering          | N/A                                                                |
| Two-way SSL           | Two-way SSL           | [Select authorization method](https://tools.ietf.org/html/rfc5755) |

* 인가(Authorization) 구현 방식과 장단점
  - API Key 기반 인가 
    1. 클라이언트는 API Key를 request에 실어보낸다. 서버측에서는 API Key를 기반으로 API 사용권한을 확인 한다. 
      - 장점 : 구현이 간단하다.
      - 단점 : https의 취약점이 발견된다면 API Key는 탈취될 수 있다.
    2. 클라이언트는 API Key를 통해서 request payload의 Signature를 생성하여 보낸다. 이 때 API Key는 전달되지 않는다. 서버 측에서는 등록된 Client의 API Key를 통해서 Signature를 검증한다. 
      - 장점 : API Key 를  request에 실어 보내지 않는다. https의 취약점이 발견 되더라도 API Key는 노출되지 않으므로 안전하다.
      - 단점 : 클라이언트 측에서 signature를 만드는 루틴이 있어야 하고, 서버 측에서는 signature를 검증하는 루틴이 필요하다.
  - JWT 기반 인가 
    * 서버로부터 받은 JWT 토큰을 Request header에 추가하여 보낸다.
      - 장점 : JWT 토큰 인증만으로 인증/인가를 수행할 수 있음. DB 접근 필요 없음.
      - 단점 : 토큰을 즉시 expire 시킬 수 없음. (secret key 사용 제한을 통해서만 제한할 수 있음)

* Sensitive Information in HTTP Requests
  - URL에 중요정보(password, security token, API key 등)를 노출하면 안된다. 이는 웹 서버 로그에 남아 공격에 사용될 수 있다.
  - POST/PUT request에는 민감한 데이터는 request body 또는 request header에 포함되어야 한다.
  - GET request에는 민감한 데이터는 HTTP Header에 포함 되어야 한다.

***

# API Security List

## Authentication

* Basic Authentication를 사용하지 말고 표준 인증방식(JWT, OAuth 등) 사용
* 인증, 토큰 생성, 패스워드 저장은 반드시 직접 구현하지 말고 잘 만들어져있는 표준을 사용
* 로그인 시 최대 시도 횟수 제한을 적용하고, 시도 횟수를 초과할 경우 계정 잠금
* 민감한 데이터의 경우 전부 암호화

## JWT(JSON Web Token)

* 무작위 대입 공격을 막기 위해 복잡한 랜덤 키(JWT Secret)를 사용
* 요청에서 정의한 알고리즘을 사용하지 말고, 백엔드에서 정의한 알고리즘을 강제로 적용(HS256 또는 RS256)
* 토큰 만료 기간(TTL, RTTL)은 되도록 짧게 설정
* JWT 페이로드는 디코딩이 가능하기 때문에 민감한 데이터를 저장하지 않아야 함

## OAuth

* redirect_uri는 화이트리스트로 관리되는 URL만 허용될 수 있도록 서버측에서 항상 검증
* response_type은 token을 사용하지 말고 code를 사용
  - 공격자가 쉽게 token을 변경하여 사용할 수 있음(RFC-6749)
* OAuth 인증 프로세스에서 CSRF를 방지하기 위해 state 파라미터를 이용
* 기본 범위를 지정하고, 각 애플리케이션마다 범위가 적절한지 검증

## Access

* DDoS, 무작위 대입 공격을 피하기 위해 요청 수를 제한(Throttling)
* MITM을 피하기 위해 HTTPS를 사용
  - Pinning 사용 권장
* SSL Strip 공격을 피하기 위해 HTTPS와 HSTS 헤더를 사용

## Input

* 각 요청 동작에 따른 적절한 HTTP Method 사용
  - GET(읽기), POST(생성), PUT(수정), DELETE(삭제)
  - 적합하지 않은 경우 "405 Method Not Allowed"로 응답
* 서버에서 제공하는 포맷(application/json 등)만 허용
  - 요청의 Accept 헤더에서 Content-Type과 비교
  - 일치하지 않는다면 "406 Not Acceptable"로 응답
* 일반적인 취약점을 피하기 위해 사용자 입력의 유효성 검증
* URL에 민감한 데이터 포함 금지
  - Credential, Password, PIN, Token, API Key 등

## Processing

* 인증이 필요한 비즈니스 로직들이 전부 인증 프로세스 이후 동작하고 있는지 확인
* Auto-Increment 대신 UUID 사용
* XML 파싱이 필요한 경우 XXE 방지를 위해 Entity 태그는 비활성화
* 파일 업로드는 CDN을 사용
* 큰 크기의 데이터를 다룰 때 HTTP 블록킹을 피하기 위해 백그라운드에서 처리하고 응답을 빠르게 반환
* 디버그 모드는 반드시 OFF

## Output

* Security Header 적용
* 각 동작에 맞는 적절한 상태 코드를 반환
  - 200 OK, 400 Bad Request, 401 Unauthorized, 405 Method Not Allowed 등

***

# References

* [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/blob/master/README-ko.md)
* [OWASP API Security](https://www2.owasp.org/www-project-api-security)
