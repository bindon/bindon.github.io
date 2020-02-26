---
layout: post
title: StringBuilder in Java
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

Java에서 사용하는 String 클래스는 Immutable 하기 때문에, 아래와 같이 Concatenate와 같이 문자열이 변경되는 경우, 새로운 String 클래스를 정의하여 할당된다.
따라서 Heap영역에 a, b를 할당 받고, a+b를 할당받는 시점에서 ab를 위한 새로운 String 객체가 생성되어 Garbage Collector에 의해 Free되기 전까지 메모리를 차지하게 된다.

```java
String a = "A";
String b = "B";
String ab = a+b;
```

이러한 Immutable의 단점을 해결하기 위해 StringBuffer(thread-safe) 및 StringBuilder(thread-unsafe)를 사용하며, 이를 사용하기 위해서는 다른 문제점을 같이 생각해야 한다.

***

# Details

StringBuilder는 간단하게 append() 함수를 이용하여 String을 Concatenation 할 수 있으며 Time-Complexity와 Space-Complexity에서 많은 이점을 가진다.
Java Compiler에서는 String의 + 연산자를 이용해서 연결하더라도 StringBuilder로 컴파일 해 주기도 한다.

## Initialize

StringBuilder를 사용할 때 대부분의 개발자는 new StringBuilder()를 그대로 사용하는데, 만약 연결하고자 하는 데이터의 크기를 가늠할 수 있다면 초기화 시 매개변수로 넣어 불필요한 연산을 줄여야 한다.
만약 매개변수 없이 초기화 할 경우 INITIAL_SIZE(16)으로 할당되며, new StringBuilder(String)으로 초기화 할 경우 (String.length + INITIAL_SIZE)로 초기화를 수행한다.

## Append

StringBuilder의 append() 메소드를 사용하면 아래와 같이 상황에 따라 다르게 동작한다.

1. String을 append할 capacity가 있을 때
    1. 매개변수로 입력받은 String을 빈 공간에 할당
2. String을 append할 capacity가 없을 때(DoS 위험 존재)
    1. max(2*capacity, 기존크기+입력받은 크기)로 char[] 배열을 다시 생성
    2. 생성된 새로운 배열에 값을 할당

***

# Vulnerable Case

StringBuilder의 취약점은 Append의 2-a에서 입력받은 크기의 검사가 없어 매우 긴 입력값이 들어오거나 반복해서 공간을 확장해야 하는 경우, Garbage Collector에 의해 메모리가 수거되기 전까지 남아있어 Heap 공간이 가득 찰 수 있다. 이러한 문제 때문에 외부에서 입력받는 값을 append 할 때에는 입력 값의 최대 길이를 제한해야 한다.

***

# Good Practice

사용자에게 입력되는 값이 고정 길이인 경우, 해당 길이가 일치하는지 확인하며 StringBuilder 초기화 시 예상하는 길이를 입력하여 성능을 최대화 한다.
사용자에게 입력되는 값이 가변 길이인 경우, 반드시 적당한 최대 길이(여기에서는 MAX_LENGTH)보다 길이가 짧은 경우에만 append 하도록 해야한다. StringBuilder 초기화 시 적당한(예제에서는 MIN_LENGTH)값을 입력하는 것은 성능을 위한 권장 사항이다.

```java
package io.github.bindon.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
 
@Controller
public class StringBuilderController {
    private static final int MIN_LENGTH = 256;
    private static final int MAX_LENGTH = 32768;
     
    @RequestMapping("/appendForFixed")
    public String appendForFixed(@RequestParam String original, @RequestParam String[] elements) throws Exception {
        StringBuilder stringBuilder = new StringBuilder(elements.length * MAX_LENGTH);
         
        for(String element: elements) {
            if(element.length() == MAX_LENGTH) {
                stringBuilder.append(element);
            } else {
                throw new Exception("Invalid Length");
            }
        }
         
        return stringBuilder.toString();
    }
     
    @RequestMapping("/appendForDynamic")
    public String appendForDynamic(@RequestParam String original, @RequestParam String[] elements) throws Exception {
        StringBuilder stringBuilder = new StringBuilder(elements.length * MIN_LENGTH);
         
        for(String element: elements) {
            if(stringBuilder.length() + element.length() < MAX_LENGTH) {
                stringBuilder.append(element);
            } else {
                throw new Exception("Invalid Length");
            }
        }
         
        return stringBuilder.toString();
    }
}
```