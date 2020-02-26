---
layout: post
title: Array Assignment in Java
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

Java에서 클래스 작성 시 생성자(Constructor) 또는 Setter를 통해 인스턴스의 값을 할당하게 되는데, 할당하려는 값이 Call by Reference로 동작하는 값(e.g. array)인 경우 assignment("=") 연산자를 이용하여 값을 할당하게 되면 외부에서 변조가 가능한 문제가 존재한다.
이는 클래스 작성에만 해당되는 내용은 아니며, 발생하는 메커니즘을 파악하면 어렵지 않게 대처할 수 있다.

***

# Vulnerable Case

1. main에서 String[] 배열을 정의하여 setArray를 통해 setterClass의 인스턴스에 값을 할당
2. 인스턴스에서 getArray의 첫 번째 값을 읽어오면 before가 출력됨
3. 다시 setArray()를 호출하는 것이 아닌, 처음 정의한 array 배열에 접근하여 문자열을 after로 수정
4. 인스턴스에서 getArray의 첫 번째 값을 읽어왔을 때 before가 출력되는 것이 아닌 after가 출력됨

```java
package io.github.bindon;
 
class SetterClass {
    private String[] array;
     
    public String[] getArray() {
        return array;
    }
     
    //          setArray(String... array)
    public void setArray(String[]  array) {
        this.array = array;
    }
}
 
public class SetterTest {
    public static void main(String[] args) {
        // Initialize
        String[] array = {"before"};
        SetterClass setterClass = new SetterClass();
         
        // Set array
        setterClass.setArray(array);
        System.out.println(setterClass.getArray()[0]);
         
        // Change array
        array[0] = "after";
        System.out.println(setterClass.getArray()[0]);
    }
}
```

* Result

```
before
after
```

***

# Good Practice

Vulnerable Case의 문제를 해결하기 위해서는 clone() 함수를 이용하여 내부의 데이터들을 복사하면 해당 문제가 발생하지 않는다.

```java
package io.github.bindon;
 
class SetterClass {
    private String[] array;
     
    public String[] getArray() {
        return array;
    }
     
    //          setArray(String... array)
    public void setArray(String[]  array) {
        this.array = array.clone();
    }
}
 
public class SetterTest {
    public static void main(String[] args) {
        // Initialize
        String[] array = {"before"};
        SetterClass setterClass = new SetterClass();
         
        // Set array
        setterClass.setArray(array);
        System.out.println(setterClass.getArray()[0]);
         
        // Change array
        array[0] = "after";
        System.out.println(setterClass.getArray()[0]);
    }
}
```

* Result

```
before
before
```