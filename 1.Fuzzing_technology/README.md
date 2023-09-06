Software and Hardware Security Lab 1: Introduction to Software and Fuzz Testing
====

Responsible person/main contact: Asad Hasan

## Preliminary tasks

* Create a GitHub account if you don't already have one
* Create your answer repository from the provided link in [Moodle space](https://moodle.oulu.fi/course/view.php?id=18470), **as instructed [here](../README.md#instructions)**
* Check the instructions on how to download and use the course's Arch Linux virtual machine
    * Instructions are available [here](https://ouspg.org/resources/laboratories/). You will find the download link from the Moodle workspace.
    * If you want to use your own computer, download and install Virtualbox to run the virtual machine. VMWare Player should work also.
* Get familiar with the documentation for the following tools:
    * [Radamsa](https://gitlab.com/akihe/radamsa)
    * [AFL (American Fuzzy Lop)](http://lcamtuf.coredump.cx/afl/)
    * [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer)
    * [Valgrind](http://valgrind.org/docs/manual/quick-start.html)


## Prerequisites

A basic understanding of the Python and C programming language is required.

A small introduction to each tool used in this exercise is provided before its actual task. However, you need to make yourself familiar with their usage:

* **Radamsa** - https://gitlab.com/akihe/radamsa
* **AFL** (American Fuzzy Lop) - http://lcamtuf.coredump.cx/afl/
* **AddressSanitizer** (ASan) - https://github.com/google/sanitizers/wiki/AddressSanitizer
* **Valgrind** - http://valgrind.org/docs/manual/quick-start.html



## About the lab

* This document contains task descriptions and theory for the fuzz testing lab. If there are any differences between the return template and this file, consider this to be the up-to-date document.
* **You can use your own computer/virtual machine if you want.** Check the chapter "Prerequisites" for information on what you need to install. This lab has been made to be completed in a Linux environment and tested to work in the provided Arch Linux virtual machine.
* __Upper scores for this assignment require that all previous tasks in this assignment have been done as well__, so e.g. to get the fourth point you will have to complete tasks 1, 2, 3 & 4.
* Check the deadline from Moodle and __remember that you have to return your name (and possibly people you worked together with) and GitHub repository information to Moodle before the deadline.__


## Background

This week’s theme is software and fuzz testing. Tasks are designed to be done with the provided Arch Linux virtual machine, see the [course practical assignments page]([https://github.com/ouspg/CompSec](https://moodle.oulu.fi/course/view.php?id=18470&section=3#tabs-tree-start)) for instructions on how to run the virtual machine (VM). The provided Arch VM has all the required tools preinstalled, but if you have your own computer with some other Linux distribution, you are free to use it, just install all the required tools.


## Grading

<!-- <details><summary>Details</summary> -->

Task #|Points|Description|
-----|:---:|-----------|
Task 0 | 0 | Introduction to software testing (Optional. No points awarded)
Task 1 | 1 | Mutated test case generation with Radamsa
Task 2 | 2 | Analyzing a C-program with AddressSanitizer, fuzz testing with AFL
Task 3 | 3 | Library fuzzing
Task 4 | 4 | Creating your own fuzzer and fuzz test it
Task 5 | 5 | Contribute to an existing open-source project. Set up a fuzzer and report findings.

Total points accumulated by doing the exercises reflect the overall grade. You can acquire upto 5 points per exercise.
<!-- </details> -->

---

## INTRODUCTION TO SOFTWARE TESTING (Optional)

In this lab, we will explore the key concept of software testing. Software testing is done to check the intended functionality of a piece of code/function or software. We will go through a quick tutorial on software testing to give you an overview:

## Task 0

## Testing A Simple Square-Root Function

Consider a square root function implementation in Python (Jupyter notebook) below:

```python
def my_sqrt(x):
    """Computes the square root of x, using the Newton-Raphson method"""
    approx = None
    guess = x / 2
    while approx != guess:
        approx = guess
        guess = (approx + x / approx) / 2
    return approx
```
Your job is now to find out whether this function actually does what it claims to do.

**Record your answer with an explanation**

This type of testing is called manually checking the function.
Such a test is the bare minimum of quality assurance and there is a better method of performing such tasks automatically known as ‘Automated Testing’

Almost all programming languages do have means to automatically check whether a condition holds, and stop execution if it does not.
This is called an assertion, and it is immensely useful for testing.

In Python, the assert statement takes a condition, and if the condition is true, nothing happens.
(If everything works as it should, you should not be bothered.)
If the condition evaluates to false, though, assert raises an exception, indicating that a test just failed.


A test suite is a collection of test cases that are designed to validate the functionality, behavior, or performance of a software application or system.
It is a systematic approach to testing, where multiple test cases are grouped based on a common objective or feature set.
You can now design a suite of assert statements yourself to carry out a case.
An example could look like this:

assert my_sqrt(4) == 2

assert my_sqrt(9) == 3

**Design a test suite with multiple assert statements and provide a screenshot of your results**

For more reading [follow](https://www.fuzzingbook.org/html/Intro_Testing.html)

[Credits](https://www.fuzzingbook.org/html/Intro_Testing.html)


## INTRODUCTION TO FUZZ TESTING a.k.a. 'FUZZING'

In contrast to software testing, fuzz testing is quite the opposite.
Fuzzing is a process of feeding malformed, mutated or unexpected inputs to a program (device or a system) and observing its behavior.
The motivation behind this kind of testing is to discover bugs, vulnerabilities and memory leaks in a software (device or a system) for exploitation or quality improvement.
While fuzzing is primarily used to discover and fix bugs, it can potentially be used in denial of service (DoS) attacks if certain conditions are met.

The main goal of fuzzing is to make the target system behave *unexpectedly*. From the security perspective, the goal is to find and analyze those unexpected behaviors for possible exploits and figure out how to fix them.
The programs that are used to perform fuzz testing are commonly called "fuzzers".

Example of Resource Exhaustion with Fuzzing: Fuzzing can be used to send a large volume of specially crafted inputs to a target application, overwhelming its resources. As an example, an HTTP server could be bombarded with a flood of excessively long or malformed requests, causing it to consume excessive memory or CPU cycles, ultimately leading to a denial of service condition.

In this exercise you will learn:
- Basic usage of 2 common fuzzers; Radamsa and American Fuzzy Lop (AFL).
- Working with AddressSanitizer, a memory error detection tool, and
- Valgrind, a debugging tool (can detect memory errors as well). This tool is often used alongside other fuzzers.
- Making your own fuzzer in Jupyter Notebook and fuzzing it

---

## Task 1

### Generating mutated test cases with Radamsa

**A)** Make yourself familiar with [Radamsa](https://gitlab.com/akihe/radamsa). Try it out in a terminal and print 10 malformed samples of ```Fuzztest 1337``` using *echo*.

**Provide the command line you used to do this.**

Radamsa can also handle various types of files. Next, you have to generate a bunch of *.txt* test samples for later usage.

**B)** Create a *.txt* file that contains only the text ```12 EF``` and nothing more. Use Radamsa to generate 100 fuzzed samples of the file that are stored in a single file called ```fuzz.txt```. You should create a separate folder for the sample files.

**Provide the content of 5 different samples that Radamsa created**
**Add a screenshot**

**Provide the command-line command(s) used to create the samples**

---

## Task 2

### A) Analyzing C program with AddressSanitizer

AddressSanitizer (ASan) is a powerful tool for detecting memory-related bugs in software programs.
It is a runtime memory error detector designed to find issues like buffer overflows, uninitialized memory access etc.
ASan works by instrumenting the program at compile-time, adding additional checks and metadata to track memory allocations and deallocations.
When the instrumented program is executed, ASan monitors memory operations, quickly detecting errors that violate memory safety.
When a bug is detected, ASan provides a detailed report, including information about the memory access violation, such as the exact location, stack trace, and associated source code line.
We will now analyze an example C program with this tool.

This repository contains an example C program called [example.c](misc/example.c).
Your task is to analyze it using [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer).
Compile the code with ```clang``` and appropriate [sanitizer flags](https://github.com/google/sanitizers/wiki/AddressSanitizerFlags#compiler-flags). Run the compiled program and analyze what happens.

Hint: Compiling the C program with Clang and appropriate sanitizer flags means using the Clang compiler and specifying certain flags in the command line that enable the AddressSanitizer (ASan) feature during the compilation process of the program.

**Provide command-line command(s) used to compile the program**

**Screenshot of the result after running the program**

**What is the error and what is causing it in this program?**

---
### B) Fuzzing with AFL
AFL, short for American Fuzzy Lop, is a highly effective and popular fuzzer used for finding vulnerabilities and bugs in software programs.
Developed by Michal Zalewski, AFL is designed to automatically generate inputs to test programs and identify potential crashes or unexpected behaviors.
AFL uses a technique called "coverage-guided fuzzing," which means that it tracks the code coverage achieved during the fuzzing process.
It starts with an initial set of input files and then mutates and manipulates them to generate a large number of test cases.
AFL uses feedback from the coverage information to prioritize inputs that explore new and previously untested program paths.

In the following task, you will be using [American Fuzzy Lop (AFL)](http://lcamtuf.coredump.cx/afl/) to fuzz test a program called UnRTF. UnRTF is a tool that can be used to convert *.rtf* files to *HTML*, *LaTeX* etc.

AFL is already installed in the provided Arch Linux virtual machine and the target program's source code is included in this repository ([unrtf0.21.5.tar.xz](misc/unrtf-0.21.5.tar.xz)).
AFL needs to be installed if your provided virtual machine does not have it.

When the source code is available, you should instrument the program by using AFL's own wrappers that work as drop-in replacements for **gcc** and **clang** (NOTE: afl-gcc might not work properly in all systems, but it works with the provided Linux vm).

__Note:__ AFL provides its own modified versions of the gcc and clang compilers, which are called "afl-gcc" and "afl-clang" respectively.
These wrappers serve as drop-in replacements for the regular compilers and are specifically tailored to work with AFL's instrumentation and fuzzing techniques.

So, here's what you need to do:

1. **Extract** the source code package ([unrtf0.21.5.tar.xz](misc/unrtf-0.21.5.tar.xz)) and ```cd``` your way to the extracted directory.

__Note:__ Be careful on file paths. Keep in mind that unrtf file is actually unrtf-0.21.5.

2. **Configure** it to use AFL's wrappers:
    ```shell
    ~$ ./configure CC="<Path_to_afl-wrapper>" --prefix=$HOME/unrtf
    ```
    The ```--prefix=$HOME/unrtf``` flag sets the installation location of the binary file to be your home directory. This is recommended, so you don't have to give it access to the root directory.

3. **Compile and build** the program:
    ```shell
    ~$ make
    ~$ make install
    ```

    __Hint__: See AFL [documentation](http://lcamtuf.coredump.cx/afl/README.txt) to learn about instrumenting programs to use AFL compilers.

4. Use AFL's example *.rtf* file located at ```/usr/share/doc/afl++-doc/afl/testcases/others/rtf/small_document.rtf``` to test that your UnRTF works by converting it to HTML:
    ```shell
    ~$ ~/unrtf/bin/unrtf --html /<path>/<to>/<testfile>
    ```

5. Create two folders, one for input files and one for result output. Copy the ```small_document.rtf``` into your input folder.
    ```
    ~$ mkdir <input_folder> <output_folder>
    ~$ cp /<path>/<to>/<testfile> /<path>/<to>/<input_floder>
    ```


6. Start fuzzing UnRTF with AFL using the example ```small_document.rtf``` file as input:
    ```shell
    afl-fuzz -i <input_folder> -o <output_folder> /<path>/<to>/<target_program>
    ```

    __Hint__: See AFL [documentation](http://lcamtuf.coredump.cx/afl/README.txt) on how to start the fuzzer. You are fuzzing the UnRTF binary, which is located at ```~/unrtf/bin/unrtf```.

7. Run the fuzzer until you get at least 50 unique (saved) crashes and observe the status window to see what is happening. A good description of the status window can be found [here](http://lcamtuf.coredump.cx/afl/status_screen.txt).

**Command line used to configure unrtf**

**Command line used to run AFL**

**Screenshot of the AFL status screen after stopping the fuzzer**

**What do you think are the most significant pieces of information on the status screen? Why are they important?**

---
### C) Reproducing crashes with Valgrind
Valgrind is a powerful open-source framework that provides a suite of dynamic analysis tools for detecting memory errors and profiling programs.
By running the target program in a virtual environment and using dynamic binary instrumentation, Valgrind can monitor and analyze memory operations during runtime.
The most popular of these tools is called Memcheck.
It can detect many memory-related errors that are common in C and C++ programs which can lead to crashes and unpredictable behavior.

You should now have found some crashes with the AFL. Next, you need to reproduce one of them to see what exactly went wrong. You can find the crashes from the output folder you created previously. Make your way into the ```.../<output_folder>/crashes``` and take one of the *.rtf* files that caused a crash under inspection.

Run UnRTF with this file under Valgrind:

```shell
~$ valgrind --leak-check=yes ~/unrtf/bin/unrtf --html /<path>/<to>/<crashfile>
```

__Hint__: Make sure that you are actually running the UnRTF with a crash file! If you get "Error: Cannot open input file" before Valgrind's actual memory analysis output, you are trying to run the program without any input. See the Valgrind [documentation](http://valgrind.org/docs/manual/quick-start.html) for help.

> [!NOTE]
> If valgrind is not installed on your virtual machine, you can install it with: "sudo apt install valgrind" on Kali Linux and "sudo pacman -S valgrind" on Arch Linux
> You also need to install dependencies for it to work:

> o Kali Linux:
> sudo apt update

> sudo apt install valgrind automake autoconf libc6-dbg

> o Arch linux:
> sudo pacman -Syu valgrind automake autoconf glibc

**Take a screenshot of the Valgrind result after running the program**

**What can you tell about the crash?**

---

## Task 3

### Fuzzing libraries

[OpenSSL](https://www.openssl.org/) is a widely-used open-source cryptographic software library for Transport Layer Security and Secure Socket Layer protocols.
In 2014, a buffer over-read vulnerability [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) was found in the Heartbeat Extension of OpenSSL (up to version 1.0.1f) two years after the feature was introduced. The vulnerability allowed attackers to obtain memory contents from process memory remotely, and as a result, it compromised the integrity of secure communications.

Since this vulnerability is caused by a memory handling-related bug, it is possible to find it using fuzzing tools like AddressSanitizer and AFL.
To fuzz test the OpenSSL library, we have to have a binary file that uses the library as a fuzzing target. For that, we are going to use the provided [target.c](misc/target.c), which uses OpenSSL to simulate a server-client TLS handshake.

Your task is to do the following:
* **Download and extract the source code** for [OpenSSL 1.0.1f](misc/openssl-1.0.1f.tar.xz).
* **Instrument, compile and build OpenSSL and enable the AddressSanitizer**:
    ```shell
    ~$ AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./config -d -g
    ~$ make
    ```
* **Instrument and compile the fuzzing target** and enable AddressSanitizer:
    ```shell
    ~$ AFL_USE_ASAN=1 afl-clang-fast target.c -o target openssl/libssl.a openssl/libcrypto.a -I openssl/include -ldl
    ```
* **Create a dummy certificate**. Use OpenSSL to create for example a 512 bit RSA key. The certificate is only used during fuzzing, so it doesn't matter how secure it is:
    ```
    ~$ openssl req -x509 -newkey rsa:512 -keyout server.key -out server.pem -days 365 -nodes -subj /CN=a/
    ```
* After you have tested that the target program works, **start fuzzing the target program** with AFL:
    ```shell
    ~$ afl-fuzz -i in -o out -m none -t 5000 ./target
    ```
    The bug is rather easy to find, so you should be able to find a crash in less than 10 minutes. Use the ```clienthello``` file as seed for AFL. The file is just a standard SSL hello message that the client sends to the server to initialize a secure session. Create an input folder for AFL and place the file there. Download ([clienthello](misc/clienthello)) from this repository. TLS/SSL handshake takes longer than just reading input from stdin, so raise the memory limit with ```-m none``` and the timeout limit with ```-t 5000``` just in case.
* **Run the target program with the crash file** you got from the AFL:
    ```shell
    ./target < <crash_file>
    ```
* To see more clearly why the crash occurred, convert the crash file into a *.pcap* file using ```od``` and Wireshark's ```text2pcap```:
    ```shell
    ~$ od -A x -t x1z -v <input_file> | text2pcap -T 443,443 - <output_file>
    ```
    This command can also be used to convert ```clienthello``` to *.pcap*.

**What is the more widely recognized name for this CVE-2014-0160 vulnerability?**

**What can you tell about the crash based on ASAN results and the pcap file? What is causing the vulnerability?**

**Take a screenshot of the AFL/ASAN results**

---

## Task 4

### Creating your own fuzzer and fuzzing with it

This task is to be completed in a Jupyter notebook.

You can access an online notebook following this link: https://notebooks.rahtiapp.fi/welcome or use your own

Use your university credentials 'Haka' to log in.
Select the 'Introduction to Python' notebook to work with. Do note that these notebooks only have a lifetime of 4 hours, so make sure to download and save your work!

Attach your notebook file ```lab1_fuzzer_your_name.ipynb``` as a return to your Github return template.

**You will now create your own fuzzer and fuzz test with it. This task has four sub-parts:**

A) Design your own mutator that takes a valid URL as input and creates its mutations

B) Design a target URL validator program and fuzz test it with mutations generated in task 1.

C) Create your own fuzzer

D) Generating mutations with Radamsa and observing program execution

---

### A) Create a mutator
In the context of fuzzing, mutation refers to the process of generating new test inputs by modifying existing inputs in order to explore different program behaviors and potentially trigger software vulnerabilities or bugs.

Design a mutator that takes a valid URL as input and creates its mutations.
Sample seed input that could be used: http://www.google.com/search?q=fuzzing
Run your mutator for 4 minutes.

**How many mutated inputs were generated in 4 minutes?**

**Attach a screenshot**

**Paste sample of 20 mutations below**

---

### B) Create a target program
Create a simple URL validator. Your program should accept only valid URLs according to the following syntax:

scheme://netloc/path?query#fragment

where
* scheme is the protocol to be used, including http, https, ftp, file...
* netloc is the name of the host to connect to, such as www.google.com
* path is the path on that very host, such as search
* query is a list of key/value pairs, such as q=fuzzing
* fragment is a marker for a location in the retrieved document, such as #result

To keep things simple, you can make it accept http, https and ftp schemes only!

**Test your program by providing it mutations generated in task 1. Did the program run smoothly or did you encounter any errors? Paste screenshots and provide explanation below**

---

### C) Create a simple fuzzer
A simple fuzzer can be made with two main components - a mutation generator and an execution engine.
The execution engine contains a fuzz loop in which random data is fed to the program, again and again, to see if it crashes.
You will now create your own fuzzer and write a function to measure program execution.

**Write a simple fuzzer program that tests the URL validator you created in Task B)**

Your fuzzer should test url validator with mutated inputs generated and report crashes. You can use the mutation generator from Task A) or feel free to implement a new one.

Hint: A sample structure of your fuzzer could look like this. Feel free to implement it in any other way!
* Example URL validator function (python function)
* Example URL mutation generator (python function)
* Example URL tester that uses both the functions above (i.e. main fuzzer). A call to this function with a specified number of test cases to be performed would be a call to your fuzzer.
In this part of the code, you should also implement checks to keep the crash count and report those.


**Observe program execution and report crashes**

A good implementation should report crashes. It should also print/show inputs that caused the crash.

Test your fuzzer with 100, 1000 and 10,000 malformed inputs and observe how many crashes you get.

**Report Results of your fuzzing. You can add screenshots to justify the results**

---

### D) Generating mutations with Radamsa and observing program execution
Your final task is to utilize Radamsa to generate 100, 1000 and 10,000 malformed inputs using http://www.google.com/search?q=fuzzing as a seed input.
Save these inputs (for example in a .txt file) and use these as input to your fuzzer that you created in Task C).

**How did your fuzzer perform now? Compare crash count with Task (C) and provide explanations if you observe differences**

---

## Task 5

### Contribute to an existing open-source project. Set up a fuzzer and report the whole process and possible findings.

Contribute to some existing open-source software (OSS) projects by setting up a fuzzing environment and documenting the total process and results.
You can choose the target software by yourself and use one of the 2 fuzzers introduced during the lab exercise, or pick some other that you think serves the purpose better.
**You should do all the testing inside a virtual machine in case there are potentially malicious files being handled.**

You should read for example [this guide](https://github.com/ouspg/fuzz-testing-beginners-guide) to get started.
Please note that in case a real bug is found in the software, it is very important to document the findings in a way that the issue can be easily reproduced.
The guide has some good points about what information you should provide.
The student doesn't need to file a "real" bug report, but if you find something new, we highly recommend doing so.

You should grab the most recent version of the source code. Few open-source projects as an example:

 * [Chromium](https://www.chromium.org/Home/) - An open-source browser project started by Google.
 * [VLC media player](https://www.videolan.org/vlc/index.html) - A common open-source media player from VideoLAN. Vast attack surface as the player uses many different libraries to handle audio/video encoding. See [features](https://www.videolan.org/vlc/features.html).
 * [ImageMagick](https://www.imagemagick.org/script/index.php) - An open-source suite for displaying, converting, and editing images, supporting over 200 file formats.
 * See [American Fuzzy Lop](https://lcamtuf.coredump.cx/afl/) main page for a comprehensive list of tools it has found bugs on. Newer versions of software can spawn new bugs, but the most common tools are usually tested the most so they might not be the best to start with.

You should at minimum provide the following information in the documentation:

* Which fuzzer was used
* A brief explanation of the target software and why you chose it
* Are you fuzzing the whole software or some specific part of it?
* Is software using some libraries? Are those fuzzed as well?
* Operating system and version information. Version numbers of target software, target software libraries, fuzzer and operating system are very important! Can you explain why?
* Compiler and debugger flags
* Initial test case(s) and the one(s) producing a possible crash
* Necessary steps to reproduce the crash
* It is not necessary to find any bugs. It is enough if you can prove that you have fuzzed with good code coverage and the way how input was mutated (=what kind of input fuzzer created overall))








---

