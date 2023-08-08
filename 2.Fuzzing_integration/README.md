Computer Security Lab 2: Fuzz Automation
====

Responsible person/main contact: Asad Hasan,

## Preliminary tasks

* Create a Github account if you don't already have one
* Create your own fork of the CompSec-2021-AnswerTemplate **as instructed [here](../README.md#instructions)**
* Check the instructions on how to download and use the course's Arch Linux virtual machine
    * If you want to use your own computer, download and install Virtualbox to run the virtual machine. VMWare Player should work also.


## About the lab

* This document contains task descriptions and theory for the fuzz automation lab. If there are any differences between the return template and this file, consider this to be the up-to-date document.
* **You can use your own computer/virtual machine if you want.** Check the chapter "Prerequisities" for information on what you need to install. This lab has been made to be completed in a Linux environment and tested to work in the provided Kali Linux virtual machine.
* __Upper scores for this assignment require that all previous tasks in this assignment have been done as well__, so e.g. in order to get fourth point you will have to complete tasks 1, 2 & 3.
* Check the deadline from Moodle and __remember that you have to return your name (and possibly people you worked together with) and GitHub repository information to Moodle before the deadline.__


## Background

This week’s theme is fuzz automation. Tasks are designed to be done with the provided Arch Linux virtual machine, see the [course mainpage](https://github.com/ouspg/CompSec) for instructions on how to run the virtual machine (VM). The provided Arch VM has all the required tools preinstalled, but if you have your own computer with some other Linux distribution, you are free to use it, just install all the required tools.



## INTRODUCTION TO FUZZ AUTOMATION 
Fuzz automation is the buzz word for industry standard practice, where software production phases are monitored by fuzz testing jobs which run automatically whenever there are new code changes to look for bugs and vulnerabilities before the software is launched into production. 

In this lab, we will first explore the concept of Continuous Integration and Continuous Delivery (CI/CD). Students will learn how CI/CD pipeline works and how can they design fuzz testing jobs that can be incorporated into these pipelines.  
 

The concept of CI/CD pipeline 

 * Continuous integration (CI) automatically builds, tests, and integrates code changes within a shared repository; then  

 * Continuous delivery (CD) automatically delivers code changes to production-ready environments for approval; or  

 * Continuous deployment (CD) automatically deploys code changes to customers directly. 

The objective of deploying a CI/CD pipeline: A CI pipeline runs whenever there are code changes and is designed to make sure all of the changes work with the rest of the code when it’s integrated. It should also compile your code, run tests, and check that it’s functional. The CD pipeline goes one step further and deploys the built code into production. 

Now that we know the basics of CI/CD, let’s get into the lab task 

## Prerequisites

A basic understanding of C/C++ programming language is required. Github is required to complete this exercise

Make yourself familiar with github actions and cifuzz fuzzing tool.

* **CIFUZZ** - https://github.com/CodeIntelligenceTesting/cifuzz
* **CIFUZZ Documentation** https://docs.code-intelligence.com/ci-fuzz/ci-fuzz-overview
* **Github Actions** https://docs.github.com/en/actions/learn-github-actions/understanding-github-actions
* **Creating .yml or .yaml file in github actions** https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions


## Grading

<details><summary>Details</summary>

Task #|Points|Description|
-----|:---:|-----------|
Task 1 | 1 | Implement a fuzzer (CIFUZZ) into C++ project
Task 2 | 2 | Finding bugs in project with fuzzer and generating coverage report
Task 3 | 3 | Apply patch fix and fuzz again. Design a fuzz job with github actions
Task 4 | 5 | Implement CI pipeline and fuzz an existing software or a project w.r.t. automation 


Total points accumulated by doing the exercises reflect the overall grade. You can acquire upto 5 points per exercise.
</details>

---
## TASKS 1-3: CASE SCENARIO 

You are recently hired as a Cybersecurity person in TechnoTech – a software company which releases small software products. TechnoTech is an agile C/C++ software development company and utilizes modern tech stacks such as GitHub to deploy its code and track version changes. Moreover, TechnoTech follows the latest practices of DevOps. 

TechnoTech’s software team recently designed a calculator product for children, which allows to perform basic mathematical operations i.e. addition, multiplication, subtraction and division. TechnoTech intends to invoice a manufacturing order for 1000 physical calculators with their code at the back-end and incorporate it into mathematics teaching e-books.  

As a cybersecurity personnel you are given the source code of the project. Your first task is to setup a fuzzer in the project repository and look for bugs. Your first task is to correctly configure your fuzzer with the project's source code and report back to the developer team with your findings! 

You will use CIFUZZ as a fuzzing tool for tasks 1-3. To build your C++ project correctly with cifuzz, you will be using CMake. Documentation for CMake is widely available online for example:

https://cmake.org/cmake/help/latest/index.html

https://cmake.org/cmake/help/latest/guide/tutorial/A%20Basic%20Starting%20Point.html#exercise-1-building-a-basic-project

---

### CIFUZZ Installation

Update your package manager based on your linux distribution and install the following dependencies:

Cmake, LLVM clang, LCOV, bazel 

Sample install instructions for arch-linux below:

#### Install dependencies

      sudo pacman -S clang llvm lcov python jdk-openjdk zip 

#### Install bazelisk 

      sudo curl -L https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 -o /usr/local/bin/bazel 

      sudo chmod +x /usr/local/bin/bazel 

#### Install the tool by running the following script: 

      sh -c "$(curl -fsSL https://raw.githubusercontent.com/CodeIntelligenceTesting/cifuzz/main/install.sh)" 

#### Install docker 
      sudo pacman –S docker 

---

## Task 1

### A) Setting up CI Fuzz in the project repository locally

Developer team has pushed the code of the calculator into following github repository:
https://github.com/ouspg/ProjectX.git

The source code is present under the ```source``` branch. Clone it locally into your machine with the command:

    ~$ git clone -b source https://github.com/ouspg/ProjectX.git

Explore all files within the project to have a better understanding of project structure. Take a look at flowchart below.

![Flowchart Image](./Pictures/fuzzing_with_cifuzz.png)


Hints are left inside files as comments. 

Cifuzz works on two important files: 

**o _CMakelists.txt:_** 
Configuration file for CMake build system. It defines the build configuration, dependencies, and build instructions for the C++ project. For the scope of this project, two CMake files are present, one in root directory and the other in /src directory 

**o _cifuzz.yaml:_** 
Configuration file for CIFuzz. It specifies the fuzzing target, corpus location, and other fuzzing parameters for CIFuzz to execute the C++ fuzzing process. 
Go to your projects root folder and initialize it cifuzz. It will create a .yaml file for you which defines the fuzzer's configuration. You can make changes to this file according to your project needs.

**Provide the command line you used to do this.**

**What did you change in cifuzz.yaml and why? Provide explanations**

Once a project is initialized with cifuzz, it must be built with a build system like bazel, CMake. Also, project contains multiple c++ files such as source function, a header file and main. Your next task is to correctly configure CMake files
to link and build your project. 

**Configure CMake files**
Two CMakelists.txt files are present. Correctly configure them to build your project with cifuzz. Look for hints within CMake files

---

**B) Create an empty fuzz test file** Create an empty fuzz test file in folder <ProjectX/test> called ```test1```. You will use this file to write your fuzz test cases in task 2 to generate mutated inputs to test your calculator function.

**Provide the command line you used to do this.**

---

**C) Run fuzzer with empty test case** By now, your fuzzer should be correctly linked across the calculator project and initialized with an empty test case called ```test1```. Run your fuzzer with this test case! 

**Provide command used to run the fuzzer** 

**Paste screenshot** 

---

## Task 2 

### Write a fuzz test case and look for bugs in the project


**A) Update fuzz test file with correct code**

Go to your empty fuzz test file (test1.cpp) created in task 1 and update it with correct code to generate input mutations. Afterwards, you will call your function under test in the main program and fuzzer will automatically feed mutated inputs to it using this fuzz test file!  

Write your code in following function only:


    FUZZ_TEST(const uint8_t *data, size_t size) {
    /* Your code */
    }

Notes for fuzz test file:  

 o Fuzz test must include the header for the target function _<../src/calculator.h>_ and cifuzz _<cifuzz/cifuzz.h>_ 

 o Fuzz test uses the _<fuzzer/FuzzedDataProvider.h>_ header from LLVM. This should be included

 o Create input variables and define their mutation scheme. As an example, if one of the input variables is integer, it’s mutation scheme can be defined using LLVM’s _FuzzedDataProvide.h_ header as:  
 ```int num1 = fuzzed_data.ConsumeIntegral<int8_t>();``` 

 o After creating input variables (example: num1, num2, and operator), the fuzz test should call the target function under test within this file. Sample call to a function named _‘calculator’_: ```calculator(num1, operator, num2)```
 
**Copy contents of fuzz test file here**

**Screenshot of the fuzz test file**

---

**B) Update main**

Write unit test cases within your main file (as a call to calculator function). Carefully choose inputs to ensure all functionalities of calculator are covered alongside edge test cases.

**Provide screenshot of your test cases** 

**How many test cases did you write? Do you think they are enough for the scope of this project? Explain** 

---

**C) Run fuzzer**

By now, cifuzz should be correctly integrated with project and ready to find bugs. If you are still encontering issues, go through [this](https://docs.code-intelligence.com/getting-started/ci-fuzz-cpp-first-bug) tutorial:


Run your fuzzer and report your findings.

**Command used to run fuzzer** 

**Name of bugs, if found any** 

---

**D) Generate code-coverage report and write a brief summary about what it represents**

Code-coverage is an important concept in modern fuzzers and is utilized by cifuzz. It measures how much of the target program's code is exercised by the generated test cases.
Cifuzz has an option to generate coverage reports of fuzzer runs. Go-ahead and generate a report and document what it represents and why is it important.

**Command used to generate code-coverage** 

**Screenshot of your code-coverage report** 

**Brief Summary** 


---


## Task 3

### A) Apply patch fix and fuzz again

Based on your previous fuzzing efforts a bug identified was forwared to developer team for a fix. Developer team has fixed the reported bug and have created a patch fix for it. 

Your task is to do the following:
* **Download and extract the patch into your project's root directory** Download link: [Patch File](./files/0001-New-version-release.-Contains-previous-bug-fix.tar.xz)
.
* **Apply the patch using**:
    ```shell
    ~$ git apply --check /path/to/your/patch-file.patch
    ~$ git apply /path/to/your/patch-file.patch
    ```
* After successfully applying the patch, run fuzzer again

**What bugs did you discover now? Is the bug found in task 2 fixed in this patch?**

**Add screenshot**

---

### B) Design a fuzzer job

Your next task is to automate the process of fuzzing for the project calculator. Latest version of ProjectX has been packed into docker by the DevOps team and they have left following note

      **_Notes from DevOps_**
      ProjectX now comes packed into a docker container with a fuzzer integrated. Moreover, we changed the build system from CMake to bazel.
      
      Newer version of ProjectX contains following:
      * All ProjectX C++ files
      * Project built with bazel instead of CMake
      * Cifuzz integrated 
      * Fuzzer set to timeout after 10minutes to save resources
      * Docker container which conatins project + fuzzer


Here's the github link to latest version: INSERT LINKKK//TO BE FINALIZED. SOLUTION IS PRESENT HERE FOR REFERENCE: https://github.com/ouspg/ProjectX1.2 in master branch!!!

**Fork this project repository and using Github actions, design a fuzzing job which does the following:
* Triggers for master branch on every pull/commit request
* Calls the script to build dockerfile into a container
* Runs the docker container**

Test your fuzz job in github actions by making small changes to code such as adding an extra space line. Commit the changes and this should trigger your workflow run

**Investigate workflow run logs**

Inspect workflow run to locate fuzzing results. **Paste screenshot**

If workflow fails to run, try to debug it for errors. You might be doing something wrong. 


The idea behind fuzz automation is that the fuzzer runs automatically for a specified duration whenever there are code changes. Since TechnoTech utilizes Github, therefore your fuzzer should trigger on any latest commit. Fuzzing results can be gathered from workflow (actions) log files and can also be exported to an external file by including appropriate code in your worflow file.

---

## Task 4

### Implement CI pipeline and fuzz an existing software or a project w.r.t. automation 

This is a free-form task where you will integrate a fuzzer into an existing project and design a CI pipeline which triggers on each pull/commit request. 

Here's what you need to do:
* Find a project or use one of your own
* Create a repository in Github and upload your project there
* Clone the repository and work to integrate a fuzzer of your choice
* Push the changes and design a Github actions workflow
* Github actions workflow file should trigger fuzzer on each code changes and log results
* A better implemented workflow would store bugs found as artifacts

There is no restriction to the choice of software or platform that students use for this task. Main idea behind this task is to integrate fuzz automation into an existing software. **If you want to design a CI pipeline outside
Github you are free to do so, but discuss with TAs before-hand.**

This task can be completed with cifuzz or any other fuzzer which supports continuous integration (CI) such as:
- [OSS-fuzz](https://github.com/google/oss-fuzz)
   Sample guide: https://google.github.io/oss-fuzz/getting-started/continuous-integration/

- [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)

For CI, Gitlab can also be used:
- https://docs.gitlab.com/ee/user/application_security/coverage_fuzzing/



If you are unable to find any project for this task, you can utilize the source code of [ProjectX](https://github.com/ouspg/ProjectX). However, it is recommended to pick-up a project
from Github, fork it and try to fuzz automate it. 2 points will be awarded for a well implemented CI pipeline with fuzz automation.

**Document your work properly for this task and include necessary screenshots and commands used**

**You should state clearly which project and fuzzer you are going to use and on which platform CI pipeline would be implemented**

**Include link to your project repository/work. Make sure to test the pipeline and share fuzzing results and/or logs**

**In-case of partial implementation, write a brief report on issues and roadblocks encountered**


---

