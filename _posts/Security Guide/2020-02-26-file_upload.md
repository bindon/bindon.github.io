---
layout: post
title: File Upload
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

파일 업로드를 구현할 때에는 사용자가 악의적인 행위를 할 수 있는 파일을 업로드 하거나, 이미 업로드 된 파일을 이용하여 정보를 획득하는 등의 행위를 할 수 없도록 기본적인 사항을 지켜야 한다.
예를 들어, 사용자가 업로드하는 파일의 확장자를 제한하지 않을 경우 php 또는 jsp와 같은 파일을 업로드 하여 서버의 리소스를 활용할 수 있거나 다른 사용자에게 악의적인 행위를 추가적으로 수행할 수 있다.

***

# Upload Policy

* 정상적인 파일의 이름은 1,024자 이하로 구성
* 필요한 파일 확장자만 허용
    - 특히 실행 가능한 파일 확장자(exe, php, asp, jsp 등)
* 파일의 타입 검증
    - 확장자에 맞는 형태인지 검사
    - exe를 docx로 확장자만 변경하여 업로드 할 수 있음
* 맬웨어 및 취약점 검사
* 내장된 위협을 제거
    - Microsoft Office 파일의 경우 내부에 스크립트, 매크로 등을 포함할 수 있음
    - 실제 필요한 내용이 아닌 매크로 부분을 삭제하여 업로드
* 사용자 인증
    - 인증을 수행한 사용자만 파일 업로드를 수행할 수 있도록 관리
* 최대 이름 길이 및 최대 파일 크기 설정
    - DoS 공격을 방지하기 위해 최대 이름 길이와 최대 파일 크기를 설정해야 함
* 업로드 된 파일은 웹 루트 외부에 저장
    - 파일이 업로드 된 디렉토리 내에 업로드 될 경우 URL을 통해 해당 파일을 실행할 수 있음
* 오류메시지 최소화
    - 파일 업로드에 대한 오류를 표시할 때 상세한 정보(전체 경로, 서버 설정 등)를 포함하지 않아야 함
* 업로드 파일 이름을 임의로 변경
    - 공격자가 업로드 한 파일 이름으로 접근할 수 없도록 파일 이름을 임의로 변경
    - 변경하지 않으면 다른 사용자가 업로드 한 파일도 유추하여 열어볼 수 있음
* 파일 이름 생성 예제

```java
String toFileName = UUID.randomUUID().toString();
```

***

# Examples

* 중요 포인트 요약
    - 앞에 입력하는 PATH를 반드시 상수로 하여 절대경로로 접근할 수 없도록 해야 함
    - 뒤에 사용자로부터 입력되는 name 부분 중 ".."이 있는지 검사하여 상대경로로 상위 디렉토리로 이동하는 것을 제거
    - new File(dir+filename)과 new File(dir, filename)은 보안상 차이가 없으나 아래와 같은 예시 처럼 오동작을 방지할 수 있음

```java
String path = "/tmp/bindon";
String name = "tmp.log"
new File(path,  name); // [+] /tmp/bindon/tmp.log
new File(path + name); // [-] /tmp/bindontmp.log
```

* 일반 파일
    - 다른 디렉토리로 이동할 수 없도록 BASE_DIRECTORY를 반드시 설정
        * 설정하지 않을 경우 ".."을 필터하더라도 "/etc/passwd"와 같은 방법으로 접근 가능
    - ".."을 필터하기 때문에 "bindon..txt"와 같은 파일도 필터링 될 수 있으니 정상적인 파일명을 입력하여 업로드 필요

```java
static final String BASE_DIRECTORY = "/tmp/";
...
File file = new File(BASE_DIRECTORY, untrustedUserInput);
if (file.getAbsolutePath().contains("..")) {
    // SecurityException
}
```

* 압축 파일
    - 포함된 모든 파일에 대해 잘못된 문자열이 없는지 검사가 필요

```java
static final String BASE_DIRECTORY = "/tmp/";
...
File zipFile = new File(BASE_DIRECTORY, untrustedUserInput);
ZipInputStream zipInputStream = new ZipInputStream(new BufferedInputStream(new InputStream(zipFile)));
while((ZipEntry zipEntry = zipInputStream.getNextEntry()) != null) {
  File currentFile = new File(BASE_DIRECTORY, zipEntry.getName())
  if (currentFile.getAbsolutePath().contains("..")) {
    // SecurityException
  }
  // Finish unzipping…
}
```