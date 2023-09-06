# Shellcoding and exploits

## Background

We often see references for memory bugs and might have encountered them ourselves while programming with some systems programming language, especially in C or C++.
Usually, you see `Segmentation fault` or other undefined behavior when you encounter them.


We fuzz test software to especially find memory bugs.
Why is this a big deal?
Historically, memory bugs have caused many security disasters.
In the worst case, memory bugs can be used to manipulate the execution flow of the program, allowing even arbitrary code execution, or reading unauthorized memory sections.

The first documented case of such misuse was documented already in 1988 [^0].
They were brought to public knowledge by Aleph One in his publication "Smashing The Stack For Fun And Profit" in 1996 [^1].
Recent research both from Microsoft and Google suggests that 70% of all security bugs in Microsoft products and Chrome browsers are still memory bugs, in 2019 [^2][^3].
In 2023, the most dangerous software weakness was still *Out-of-bounds Write* [^4].


In this exercise, we will examine the practical implications of memory bugs at a technical level and explore how they've been exploited, particularly through the technique of ***shellcoding***.

As a primary theoretical source, we use the online book "Low-Level Software Security for Compiler Developers" [^5]

# Introduction

What is a memory bug, or error?

> Memory access errors describe memory accesses that, although permitted by a program, were not intended by the programmer. [^5]

Memory access errors are often defined [^] as:

* buffer overflow
* null pointer dereference
* use after free
* use of uninitialized memory
* illegal free


There are usually two main reasons, why dangerous memory bugs are possible.
  * The software takes user-defined input
  * This input is not validated nor sanitized

Input validation and sanitization is one of the major challenges in software development.
You must ensure, that *every* unintended effect from the user-defined input is *prevented* or *handled*.

You want the user to provide a name that is 15 characters at maximum.
What if they provide 20 characters???

## Buffer overflows


[^0]: [The Internet Worm of 1988](https://web.archive.org/web/20070520233435/http://world.std.com/~franl/worm.html)
[^1]: [Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html)
[^2]: [A proactive approach to more secure code ](https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/)
[^3]: [Memory safety](https://www.chromium.org/Home/chromium-security/memory-safety/)
[^4]: [2023 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
[^5]: [Low-Level Software Security for Compiler Developers](https://llsoftsec.github.io/llsoftsecbook/)
[^6]: [SoK: Eternal War in Memory](https://ieeexplore.ieee.org/document/6547101?arnumber=6547101)