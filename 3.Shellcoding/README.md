# Shellcoding and exploits

## Pre-requisites

This exercise requires a deep understanding of how computer stack works, how underlying memory is managed and the basics of assembly language.

Before starting with the exercise, it is recommended to read the first two chapters from the book "Low-Level Software Security for Compiler Developers" [^5] and the paper "Smashing The Stack For Fun And Profit"  [^1].

Some concepts from there are also summarised here.



## Background

We often see references for memory errors and might have encountered them ourselves while programming with some systems programming language, especially in C or C++.
Usually, you see `Segmentation fault` or other undefined behavior when you encounter them.


We fuzz test software, to especially find memory errors (often called bugs).
Why is this a big deal?
Historically, memory bugs have caused many security disasters.
In the worst case, memory bugs can be used to manipulate the execution flow of the program, allowing even arbitrary code execution, or reading unauthorized memory sections.

The first documented case of such misuse was documented already in 1988 [^0].
They were brought to public knowledge by Aleph One in his publication "Smashing The Stack For Fun And Profit" in 1996 [^1].
Recent research both from Microsoft and Google suggests that 70% of all security bugs in Microsoft products and Chrome browsers are still memory bugs, in 2019 [^2][^3].
In 2023, the most dangerous software weakness was still *Out-of-bounds Write* [^4].


In this exercise, we will examine the practical implications of memory bugs at a technical level and explore how they've been exploited, particularly through the technique of ***shellcoding***.

As a primary theoretical source, we use the online book "Low-Level Software Security for Compiler Developers" [^5].

# Introduction

What is a memory error?

> Memory access errors describe memory accesses that, although permitted by a program, were not intended by the programmer. [^5]

Memory access errors are often defined [^6] as:

* buffer overflow
* null pointer dereference
* use after free
* use of uninitialized memory
* illegal free

The software is memory-safe if these errors never happen.

There are usually two main reasons, why dangerous memory bugs are possible.
  * The software takes user-defined input
  * This input is not validated nor sanitized, and therefore program flow can be controlled with the input

This input validation and sanitization is one of the major challenges in software development.
You must ensure, that *every* unintended effect from the user-defined input is *prevented* or *handled*.

You want the user to provide a name that is 15 characters long at maximum.
What if they provide 20 characters???

## Buffer overflows

If you don't handle the lengths larger than 15 characters from the previous example in your program, a so-called _buffer overflow_ could happen.

This error is usually the most dangerous type.
MITRE top one from 2023 (out-of-bounds write)[^4], goes to this category.


To understand why, we need to understand how a computer works on a stack level and the principles of programming languages.


The fundamental philosophy of C programming is that "trust the programmer".
Do not prevent the programmer from doing what needs to be done.
The programmer has ultimate control but also an ultimate responsibility.
It means, that they must use memory correctly as well.

In the naive example below, the software compiles so that it reserves a stack space of 15 characters for the `name` variable in a program.

It means, that at maximum, a name with 14 characters, (+ null terminator `\x00`) can fit into this buffer.
The programmer should know, that the null terminator also takes space.

```c
#include <stdio.h>

int main() {
    char name[15];

    printf("Please enter your name: ");
    scanf("%s", name);

    printf("Hello, %s!\n", name);
    return 0;
}
```

Since we trust the programmer, the program only does what it is programmed to do, it does not check the boundaries of the buffer in this case.

If the end-user provides inputs larger than 14 characters, the buffer will overflow and it takes space in the memory in the area, which was not reserved for it.

> "Buffer overflows are Mother Nature's little reminder of that law of physics that says: if you try to put more stuff into a container than it can hold, you're going to make a mess." [^7]

We mainly focus on buffer overflows in this exercise.

## Understanding the stack

The computer stack is like a stack of books.

1. You can only add (push) or remove (pop) a book from the top. (aka FILO (first in, last out))
2. It's used to keep track of operations like function calls: when a function starts, its details are added (pushed) to the stack, and when it ends, they are removed (popped).
3. If you add too many books beyond the stack's limit, they'll fall off, we have a buffer overflow, or more precisely, "stack overflow".

When an application runs, it uses the stack and registers to manage the program's execution flow. The stack is split into frames, each holding data from functions that haven't yet been completed. These frames store local variables, parameters of potential function calls, return addresses, and more. For instance, if a program has three nested function calls, it would generate three stack frames.

Below is a simplified example from a stackframe of a 32-bit program, where the function B is called before function A.

| Memory Address | Content                      | Description                             |
|:--------------:|:----------------------------:|:---------------------------------------:|
| `0xffbfe14c`   | `Local Variable of funcA()`  | A local variable from `funcA()`         |
| `0xffbfe148`   | `Local Variable of funcA()`  | Another local variable from `funcA()`   |
| `0xffbfe144`   | `Return Address for funcA()` | The return address after `funcA()` completes |
| `0xffbfe140`   | `EBP for funcA()`            | Base pointer (EBP) for `funcA()`        |
| `0xffbfe13c`   | `Local Variable of funcB()`  | A local variable from `funcB()`         |
| `0xffbfe138`   | `Return Address for funcB()` | The return address after `funcB()` completes |
| `0xffbfe134`   | `EBP for funcB()`            | Base pointer (EBP) for `funcB()`        |
| ...            | ...                          | ...                                     |


## Protection mechanics and general tips



At this point, you should have basic knowledge about how computer stack/memory and registers are working.

You have to use C/C++ programming language in cases when you want to create a program with buffer overflow vulnerability.

Tasks are possible to do in both 32 - and 64-bit machine instructions as long as the machine has support for them. Implementation will differ and be more challenging depending on the version. It's recommended to use the 32-bit version since you can find more examples from it.

Task 3A is not possible to do with the latest Ubuntu, Arch Linux or any mature Linux environment which is intended for daily use.

You might have to note following Linux protections

 * Stack canaries (SSP)
 * Non-executable pages or stacks (NX)
 * Address Space Layout Randomization (ASLR)
 * Less known, no need to note unless specified in the task: (ASCII ARMOR, RELRO, PIE, D_FORTIFY_SOURCE, PTR_MANGLE)

    Check from here for some compiler flags.

Find a way to disable them if needed. Most are compiler options.

More information about protections in Ubuntu (and overall) can be found here.

On later tasks, we try to bypass some of them: specifically mentioning not to disable them.

Encoding significantly matters in these tasks, for example, Python 2 print produces just data, whereas Python 3 print produces encoded string by default.


[^0]: [The Internet Worm of 1988](https://web.archive.org/web/20070520233435/http://world.std.com/~franl/worm.html)
[^1]: [Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html)
[^2]: [A proactive approach to more secure code ](https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/)
[^3]: [Memory safety](https://www.chromium.org/Home/chromium-security/memory-safety/)
[^4]: [2023 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
[^5]: [Low-Level Software Security for Compiler Developers](https://llsoftsec.github.io/llsoftsecbook/)
[^6]: [SoK: Eternal War in Memory](https://ieeexplore.ieee.org/document/6547101?arnumber=6547101)
[^7]: [2009 CWE/SANS Top 25 Most Dangerous Programming Errors](https://cwe.mitre.org/top25/archive/2009/2009_cwe_sans_top25.html)