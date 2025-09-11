Software and Hardware Security Lab 2: Fuzz Automation
====

## Preliminary tasks

* Create a GitHub account if you don't already have one
* Create your answer repository from the provided link in Moodle workspace, **as instructed [here](../README.md#instructions)**
* Optionally, check the instructions on how to download and use the course's Arch Linux virtual machine
    * You can use any Linux/Unix compatible system you want, either directly or with virtualization/WSL
    * Instructions are available [here](https://ouspg.org/resources/laboratories/). You will find the download link from the Moodle workspace.

## Background

In the first week, we only briefly touched on fuzzing at more abstract layers.
`cargo fuzz` introduced the concept of creating a fuzzing *harness*; we passed random bytes over a specific API interface of the software under test ("SUT"), which in this case was a YAML implementation in Rust.
The harness in this case was just a few lines of code and didn't require much adjustment.
The fuzzer magically handled the rest, and we likely didn't find a single bug.
We also may have seen a jump in the coverage ratings when we provided a custom input *corpus* for the fuzzer.

Both `libFuzzer` and `AFL++` use compiler-provided instrumentation to improve test coverage automatically.
In other words, instrumentation traces the code coverage reached by each input fed to a fuzz target.
When a new branch is detected as a result of input mutation, the input data is saved and stored into the corpus. [1]

Sometimes, API interfaces may require additional input translation to achieve more efficient testing.
There can also be multiple different interfaces available, where testing can be more efficient when compared to higher-level abstractions (e.g., testing through direct API calls versus testing only through a CLI interface).


## Grading

Task #|Points|Description|
-----|:---:|-----------|
Task 1 | 3+ | In-depth fuzzing integration
Task 2 | 2+ | Contribute to an existing open-source project. |

Total points accumulated by doing the exercises reflect the overall grade.

---

# Task 1: In-depth fuzzing integration (3p+)

We go slightly futher with integrating the fuzzing for the potential software project.
On this case, We have a simple C++ project demonstrating a custom binary protocol with intentional memory safety bugs for educational purposes.

At a high level, it implements a messaging protocol where users can send text messages to each other and transfer files through binary chunks. The implementation is deliberately simplified to focus on common vulnerability patterns.
We assume that you have some level knowledge of C/C++ programming languages.
You are required to briefly understand the code on this project as you need to describe the vulnerability and make a fix for it.

The project uses older C++ idioms that are prone to memory safety and integer-related bugs. While C++ is statically typed, it allows implicit conversions between different data types and provides manual memory management, both of which are common sources of security vulnerabilities in real-world systems.
For these reasons, C++ is sometimes described as having weak type safety despite being statically typed.
However, modern C++ provides strongly-typed alternatives and safer abstractions that address many of these issues, such as smart pointers (unique_ptr, shared_ptr) and stricter type checking features.

## Protocol overview

This project implements a binary communication protocol for messaging systems that defines three distinct message types:

- **Chat messages** (`CHAT_MESSAGE`): Text messages between users containing username, message content, timestamp for ordering, and priority level for routing decisions
- **User profiles** (`USER_INFO`): User metadata including identity information, email addresses, status indicators, and dynamically-sized tag arrays for user classification
- **File transfer chunks** (`FILE_CHUNK`): Binary data segments that enable file transmission through chunked transfer, supporting segmentation and reassembly of larger files

The protocol uses a fixed 16-byte header structure that includes protocol validation, version information, message type identification, payload size, and unique message identifiers. This design supports efficient parsing and maintains compatibility across protocol versions, while we don't need all that in the scope of this exercise.

The implementation contains several intentional memory safety bugs that current basic unit tests won't catch, but can be discovered through fuzzing and sanitizers.

### Project Structure

```
├── lib/
│   ├── protocol.h          # Protocol definitions and structures
│   └── protocol.cpp        # Implementation with bugs
├── examples/
│   └── demo.cpp           # Demo program showcasing functionality
├── tests/
│   └── test_protocol.cpp  # Basic unit tests (won't catch all bugs)
├── fuzzing/ (FILES ARE MISSING ON PURPOSE)
│   ├── fuzz_deserialize.cpp # libFuzzer target for deserialization
│   └── fuzz_roundtrip.cpp   # libFuzzer target for round-trip testing
├── patches/ (MISSING)
│   ├── 001-fix-memory-leak.patch     # A sample patch with a partial fix introducing new bugs
└── CMakeLists.txt         # Build configuration
```

## Building

We assume that you are using Linux-based system, which has `llvm` and `clang++` installed.

Build the demo and tests.

```bash
make
```
For the exact details and all options, see [Makefile](Makefile).

## Running

### Unit tests
```bash
make test
```
### Demo
```bash
make demo
```

The demo will showcase normal protocol operations and one operation that triggers a  memory bug (visible with sanitizers).

### Dynamic analysis

There are `Makefile` commands for both demo and test program to run the relevant tooling. You are likely familiar with different sanitizers already at this point.
E.g. see more in [here](https://llvm.org/docs/LibFuzzer.html#id24).

```bash
# Run demo with AddressSanitizer (replace demo with test for tests)
make demo-asan
# with MemorySanitizer
make demo-msan
# with UndefinedBehaviorSanitizer
make demo-ubsan
# Run with Valgrind
valgrind --leak-check=full ./build/demo
```


### Task 1A) Fuzzing with `libFuzzer` and creating fixes (2p)

> To get started - read the files in [lib](lib) folder and see the demo file [examples/demo.cpp](examples/demo.cpp) and test file [tests/test_protocol.cpp](tests/test_protocol.cpp) to get basic understanding of the protocol.

There is already a double-free bug in the copying of the message types.
You will find that by running the demo program with AddressSanitizer.
Then you can start by fixing that!
Afterwards, we try to find even more of them. There are plenty of them.

We ideally create at least two different [fuzzing targets](https://llvm.org/docs/LibFuzzer.html#fuzz-target).

A very simple target could look like:

```cpp
#include "../lib/protocol.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Path 1: Deserialize untrusted input
    auto* msg = MessagingProtocol::Serializer::deserialize(data, size);
    if (msg) {
        // Path 2: Serialize potentially corrupted object
        auto serialized = MessagingProtocol::Serializer::serialize(*msg);
        delete msg;
    }
    return 0;
}
```

The idea is to expand the logic of the fuzzing targets to be more efficient, while the complexity level of this project still doesn't provide that many opportunities.

The first target could be a optimized deserializer that also tries to access the type fields. Optimisations could include:
  - Return early if `MessageHeader` is too small to be meaningful message
  - Try a very large initial input data just once, and cut them off afterwards (e.g. bigger than 1024 * 1024), so we can speed up the fuzzer.
  - Access different fields based on the header type (`CHAT_MESSAGE`, `USER_INFO`, `FILE_CHUNK`) (can also trigger bugs)

E.g. the initial goal is to feed data for :
```cpp
Message* msg = Serializer::deserialize(data, size);
```

The second target implements round-trip testing that validates serialization consistency and data integrity. This approach creates structurally valid messages from fuzzer input by casting the data, serializes them, then deserializes to detect corruption or inconsistencies:

```cpp
// Parse fuzzer input to create valid message structure (Note the different message types! Try each.)
Message original = parse_fuzzer_input_to_message(data, size);
std::vector<uint8_t> serialized = Serializer::serialize(original);
Message* roundtrip = Serializer::deserialize(serialized.data(), serialized.size());
// Compare original vs roundtrip for data integrity
```
The parsing does not use deserialize here at first, rather it casts the data, for example:
```cpp
// Create username and email by taking length from the data and using data by length
size_t username_len = std::min((size_t)data[0], size / 4);
size_t email_len = std::min((size_t)data[1], size / 4);

if (username_len > 0 && size > username_len + 2) {
    std::string username(reinterpret_cast<const char*>(data + 2), username_len);
    msg->user_info->username.set_data(username);
}
```

Effective fuzzing often benefits from a well-crafted initial corpus. For this protocol, useful seed inputs might include:
- Valid messages of each type (chat, user info, file chunks)
- Edge cases like empty strings, maximum length fields, zero counts
- Malformed headers with incorrect magic numbers or versions
- Boundary conditions like messages at size limits

The fuzzer will mutate these seeds to explore edge cases and discover bugs that manual testing might miss.
In this case, the project isn't that complex, so just adding a round-trip loop where you deserialize first may find the most bugs already, but we can practice much more.

See also Google's post about [What makes a good fuzz target?](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md).

**What to return?**
> Once you find a bug, you need to fix it so that the current unit tests still work. Most time will likely go toward figuring out where the bug is. Add a new test based on the crashing data so we can prevent regression.
Classify each bug with a CWE marking, e.g. is it [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)?

For a simpler fixes, you can create also a [git `.patch` file](https://stackoverflow.com/questions/5159185/how-to-create-a-git-patch-from-the-uncommitted-changes-in-the-current-working-di) into `patches/` directory. This makes it easy to test how patches fix or add new bugs.

Apply patches with e.g.:
```bash
git apply patches/001-fix-uaf.patch
```

Write also a summary of the process - how hard it is to find the bugs, what bugs you found and other overall experiences.
If you don't find new bugs with either of the fuzz targes (e.g for 10 minutes), you are likely done with this exercise.

## Task 1B) Integrating `libFuzzer` with ClusterFuzzLite (1p+)

> 1 bonus point available from extra work, see the task ending.

[ClusterFuzz](https://github.com/google/clusterfuzz) is a known large-scale project by Google to fuzz test programs.
It is not suitable for every project and something smaller can fit as well.
[ClusterFuzzLite](https://github.com/google/clusterfuzzlite) is a smaller version of that.

How easy it could be to integrate continuous fuzzing for your project?
Many big projects, like `curl` or `systemd` use it on the [code review process](https://security.googleblog.com/2021/11/clusterfuzzlite-continuous-fuzzing-for.html).
We try to integrate to the previous message protocol project by using the fuzz targets we just created.
ClusterFuzzLite can be added to automatically run continuous fuzzing in CI, discovering new crashes over time and regression testing fixes.


The suggested workflow is to run the `CLusterFuzzLite` [locally in Docker](https://google.github.io/clusterfuzzlite/build-integration/) at first.
If we have correctly created the fuzzing targets in the previous steps, it shouldn't be hard to add if you just follow the build integration instructions.

> We only support the `code-change` mode!

For the sake of simplicity, we use GitHub and GitHub Actions, while `ClusterFuzzLite` supports other platforms as well.
The documentation for GitHub Actions is available in [here.](https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/)

After the local workflow works, we can use [act](https://github.com/nektos/act) to run GitHub Actions locally.

You can simply install it with `pacman -Syu act`. It requires that Docker is up and running.
If you are using other than Arch Linux, see other [installation methods](https://nektosact.com/installation/index.html).
You may also need to consult official GitHub Actions documentation and friendly LLM if you are not yet familiar with them.


> Return the files required for GitHub Actions (`.github`) and ClusterFuzzLite (`.clusterfuzzlite`). Demonstrate how it works in the end by submitting a pull request to your private GitHub repository with few code changes.
You can also intentioanlly modify the code to add an bug and see if it catches it automatically. It is OK if it does not work perfectly because of missing the existing coverage data.

It is recommended that you work locally until the very last point, since it saves CI/CD minutes.
If the CI/CD minutes end, you are allowed to create a new public repository.

You can also get a bonus point from this task if you manage to automate the storage of input corpus in GitHub, store the old coverage data, and expand the findings as automatic unit tests if a bug is found! Or if you demonstrate the other modes than `code-change` which are supported by `ClusterFuzzLite`.


**You can disable the pipeline after the logs are in GitHub.**


## Task 2: Contribute to an existing open-source project. Set up a fuzzer and report the whole process and possible findings (2p+).

> You can have extra points from this task and technically there is no upper limit for points for outstanding work, but 5 points is likely the maximum, and going beyond requires upstream contribution.
A simple fuzzing with afl maybe eligible only for one point, but going beyond 2 points likely requires substantial effort and findings.

Contribute to some existing open-source software (OSS) projects by setting up a fuzzing environment and documenting the total process and results.
You can choose the target software by yourself and use fuzzers introduced during the lab exercises earlier, or pick some other that you think serves the purpose better.

Projects which are using C/C++/Rust and Go are easiest to start with, if you plan to implement custom harness and fuzz test library interfaces.

*Additionally*, you can also integerate the CI/CD pipeline with [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) for the project as well. Depending on how far you go, **you can get more than two points** from this task, while it can be difficult.
 - You could add custom harness for different API endpoints which are excuted in the pipeline, depending of the code changed
 - You could even make a pull request to upstream but please consult the instrcutor at first if you are willing to do so.

Please note that in case a real bug is found in the software, it is very important to document the findings in a way that the issue can be easily reproduced.
The guide has some good points about what information you should provide.
The student doesn't need to file a "real" bug report, but if you find something new, we highly recommend doing so.
If you end up finding a real vulnerability, you must follow [responsible disclosure.](https://www.hackerone.com/knowledge-center/why-you-need-responsible-disclosure-and-how-get-started)

You should grab the most recent version of the source code. Few open-source projects as an example:

 * [Chromium](https://www.chromium.org/Home/) - An open-source browser project started by Google.
 * [VLC media player](https://www.videolan.org/vlc/index.html) - A common open-source media player from VideoLAN. Vast attack surface as the player uses many different libraries to handle audio/video encoding. See [features](https://www.videolan.org/vlc/features.html).
 * [ImageMagick](https://www.imagemagick.org/script/index.php) - An open-source suite for displaying, converting, and editing images, supporting over 200 file formats.
 * See [AFLplusplus](https://aflplus.plus/#trophies) and [afl CVE list](https://github.com/mrash/afl-cve) for a comprehensive list of tools they have found bugs on. Newer versions of software can spawn new bugs, but the most common tools are usually tested the most so they might not be the best to start with.

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
* All the code that creates the potential custom harness when fuzzing libraries
* All the necessary files needed to add useful CI/CD integration

## References

[1]: Wang, J., Chen, B., Wei, L., & Liu, Y. (2019). Be Sensitive and Collaborative: Analyzing Impact of Coverage Metrics in Greybox Fuzzing. *RAID 2019*. https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf
