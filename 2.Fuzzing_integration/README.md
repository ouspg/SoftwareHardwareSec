Software and Hardware Security Lab 2: Fuzz Automation
====

## Preliminary tasks

- Make sure that you have access to your private GitHub repository under https://github.com/IC00AJ74
- Optionally, check the instructions in [main README.md](../README.md#laboratory-environment) to see recommendations about Linux environment.
  - You can use any Linux/Unix compatible system you want, either directly or with virtualization/WSL

## Background

In the first week, we only briefly touched on fuzzing at a more abstract level.
The `cargo fuzz` exercise introduced the concept of a fuzzing _harness_. We passed random bytes over a specific API interface of the software under test ("SUT"), which in this case was a YAML implementation in Rust.
The harness in this case was just a few lines of code and didn't require much adjustment.
The fuzzer magically handled the rest, and we likely didn't find a single bug.
We also may have seen a jump in the coverage numbers when we provided a custom input _corpus_ for the fuzzer.

Both `libFuzzer` and `AFL++` use compiler-provided instrumentation to track code coverage, which guides the mutation of inputs.
In other words, the instrumentation measures the code coverage reached by each input fed to a fuzz target.
When a new branch is detected as a result of input mutation, the input data is stored in the corpus. [1]

Sometimes, API interfaces may require additional input translation to achieve more efficient testing.
Multiple different interfaces can also be available, and testing through a lower-level one (e.g., direct API calls versus a CLI interface) is often more efficient than testing through higher-level abstractions.

This week's work focuses on using `libFuzzer`, creating the fuzzing harness, and finally integrating fuzzing into the CI/CD pipeline.

## Grading

| Task # | Points | Description                                    |
| ------ | :----: | ---------------------------------------------- |
| Task 1 |   3+   | In-depth fuzzing integration                   |
| Task 2 |   2+   | Contribute to an existing open-source project. |

Total points accumulated by doing the exercises reflect the overall grade.

---

# Task 1: In-depth fuzzing integration (3p+)

We go slightly further with integrating fuzzing in a sample software project.
In this case, we have a simple C++ project that demonstrates a custom binary protocol with memory safety bugs intentionally planted for educational purposes.

At a high level, it implements a messaging protocol where users can send text messages to each other and transfer files through binary chunks.
The implementation is deliberately simplified to focus on common vulnerability patterns.
We assume that you have some knowledge of C/C++.
You are expected to get a working understanding of the project's code, since you will need to describe the vulnerabilities and write fixes for them.

The project uses older C++ idioms that are prone to memory safety and integer-related bugs.
While C++ is statically typed, it allows implicit conversions between different data types and provides manual memory management, both of which are common sources of security vulnerabilities in real-world systems.
For these reasons, C++ is sometimes described as having weak type safety despite being statically typed.
However, modern C++ provides strongly-typed alternatives and safer abstractions that address many of these issues, such as smart pointers (`unique_ptr`, `shared_ptr`) for memory management and stricter type-checking features for conversions.

## Protocol overview

This project implements a binary communication protocol for messaging systems that defines three distinct message types:

- **Chat messages** (`CHAT_MESSAGE`): Text messages between users containing username, message content, timestamp for ordering, and priority level for routing decisions
- **User profiles** (`USER_INFO`): User metadata including identity information, email addresses, status indicators, and dynamically-sized tag arrays for user classification
- **File transfer chunks** (`FILE_CHUNK`): Binary data segments that enable file transmission through chunked transfer, supporting segmentation and reassembly of larger files

The protocol uses a fixed 12-byte header structure that includes protocol validation, version information, message type identification, payload size, and unique message identifiers. This design supports efficient parsing and maintains compatibility across protocol versions — though we don't need all of this for this exercise.

The implementation contains several intentional memory safety bugs that the basic unit tests won't catch but which can be discovered through fuzzing and sanitizers.

### Project structure

```
├── lib/
│   ├── protocol.h          # Protocol definitions and structures
│   └── protocol.cpp        # Implementation with bugs
├── examples/
│   └── demo.cpp           # Demo program showcasing functionality
├── tests/
│   └── test_protocol.cpp  # Basic unit tests (won't catch all bugs)
├── fuzzing/ (intentionally missing)
│   ├── fuzz_deserialize.cpp # libFuzzer target for deserialization
│   └── fuzz_roundtrip.cpp   # libFuzzer target for round-trip testing
├── patches/ (intentionally missing)
│   ├── 001-fix-memory-leak.patch     # A sample patch with a partial fix introducing new bugs
└── CMakeLists.txt         # Build configuration
```

## Building

We assume you are using a Linux-based system with `llvm`, `make`, `cmake`, `afl++`, and `clang++` installed.

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

The demo will showcase normal protocol operations and one operation that triggers a memory bug (visible with sanitizers).

### Dynamic analysis

The `Makefile` provides commands to run the relevant tooling for both the demo and the test program. You are likely familiar with the sanitizers by now.
See [here](https://llvm.org/docs/LibFuzzer.html#id24) for more.

```bash
# Run demo with AddressSanitizer (replace demo with test for tests)
make demo-asan
# with MemorySanitizer
make demo-msan
# with UndefinedBehaviorSanitizer
make demo-ubsan
# Run with Valgrind
valgrind --leak-check=full --error-exitcode=1 ./build/demo
```

An initial `make demo-asan` failure is expected on the vulnerable starter. [MemorySanitizer](https://clang.llvm.org/docs/MemorySanitizer.html) is optional and requires a supported platform and instrumented dependencies, including the C++ standard library.

### Task 1A: Fuzzing with `libFuzzer` and creating fixes (2p)

To get started, read the files in the [lib](lib) folder, and look at the demo in [examples/demo.cpp](examples/demo.cpp) and the tests in [tests/test_protocol.cpp](tests/test_protocol.cpp) to build a basic understanding of the protocol.

The project already contains a double-free bug in the message copying.
You can find it by running the demo program with AddressSanitizer, and start by fixing it.
After that, the goal is to find more bugs with fuzzing - there are plenty.

Ideally, create at least two different [fuzzing targets](https://llvm.org/docs/LibFuzzer.html#fuzz-target).

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

The exercise is to expand the target logic to make it more effective, although a project of this size offers a limited set of opportunities.

The first target could be an optimized deserializer that also accesses the type-specific fields. Optimizations could include:

- Return early if `MessageHeader` is too small to be a meaningful message
- Try a very large initial input once (e.g., larger than 1024 × 1024 bytes) and cap its size afterwards (e.g., via `-max_len`), so the fuzzer can work faster in the future.
- Access different fields based on the header type (`CHAT_MESSAGE`, `USER_INFO`, `FILE_CHUNK`) (can also trigger bugs)

At a minimum, the goal is to feed fuzzer data into:

```cpp
Message* msg = Serializer::deserialize(data, size);
```

The second target implements round-trip testing that validates serialization consistency and data integrity. It constructs valid C++ messages from bounded slices of fuzzer input, serializes them, then deserializes to detect corruption or inconsistencies:

```cpp
// Parse fuzzer input to create valid message structure (Note the different message types! Try each.)
Message original = parse_fuzzer_input_to_message(data, size);
std::vector<uint8_t> serialized = Serializer::serialize(original);
Message* roundtrip = Serializer::deserialize(serialized.data(), serialized.size());
assert(roundtrip != nullptr); // Include <cassert>; keep assertions enabled.
// Compare original vs roundtrip for data integrity
delete roundtrip;
```

Construct objects normally and never cast arbitrary bytes to structures containing pointers. For example, inside `LLVMFuzzerTestOneInput` (with `<algorithm>` included):

```cpp
if (size < 2) return 0;
MessagingProtocol::Message msg(MessagingProtocol::USER_INFO);
size_t offset = 2;
size_t username_len = std::min(static_cast<size_t>(data[0]), size - offset);
msg.user_info->username.set_data(
    std::string(reinterpret_cast<const char*>(data + offset), username_len));
offset += username_len;
size_t email_len = std::min(static_cast<size_t>(data[1]), size - offset);
msg.user_info->email.set_data(
    std::string(reinterpret_cast<const char*>(data + offset), email_len));
```

This example only generates short strings. Extend the mapping for boundary lengths and nonempty tags/chunks, with bounded harness allocations.

Effective fuzzing often benefits from a well-crafted initial corpus. For this protocol, useful seed inputs might include:

- Valid messages of each type (chat, user info, file chunks)
- Edge cases like empty strings, maximum length fields, zero counts
- Malformed headers with incorrect magic numbers or versions
- Boundary conditions like messages at size limits

The fuzzer will mutate these seeds to explore edge cases and discover bugs that manual testing might miss.
A deserialize/serialize loop can expose parser memory errors, but does not cover copying, assignment, or rejection correctness by itself.

See also Google's post about [What makes a good fuzz target?](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md).

If you use the sample file names from the project structure, the Makefile already contains sections for building the fuzzing targets and running one of them — you just need to uncomment the code:

```
# To build
make fuzz-build
# To run fuzz_deserialize target
make fuzz-run
```

### There is a crash - now what?

After finding a crashing input or memory violation in your program, understanding the root cause is usually the most time-consuming part.
Once identified, implementing the fix is typically straightforward.

Many bugs are already hinted at in the source code - we just need to trigger them with fuzzing.

Several steps can make debugging easier:

- First, minimize the test case that causes the crash.
  You can run the fuzzer with the `-minimize_crash=1` flag and let it do that automatically. More details are [here](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md#minimizing-a-reproducer).
- Next, create a minimal unit test that runs the program using the data from the crash file.
  E.g., read the raw bytes from the crash file and pass them to the same function as in the fuzzing process.
- Run the program with a debugger (or if necessary, using print statements) to understand where the crash happens and identify which specific byte patterns trigger the failure.
- Finally, analyze the protocol specification, determine the expected behavior, and verify whether the input exceeds the protocol's defined boundaries. If it does, check whether the implementation properly handles these edge cases.

### What to return?

> We assume that you copy the C++ project from here and work on it in your private GitHub repository.

> Once you find a bug, you need to fix it so that the current unit tests still work. Most of the time will likely go toward figuring out where the bug is. Add a new test based on the crashing data to prevent regressions.
> Classify each bug using a CWE ID (e.g., is it [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)?)

For learning purposes, you can create patch files in the `patches/` directory to track your fixes and understand their impact. This helps demonstrate how each change affects the codebase and potentially introduces new bugs.

You can create [git patch files](https://stackoverflow.com/questions/5159185/how-to-create-a-git-patch-from-the-uncommitted-changes-in-the-current-working-di) before committing changes:

```bash
# Create a patch from unstaged changes
git diff > patches/001-fix-description.patch
# Create a patch from staged changes
git diff --cached > patches/001-fix-description.patch
```

This approach lets you:

- Document each fix separately
- Test fixes in isolation
- Observe if fixes introduce new issues
- Learn from the debugging process

Apply patches with, e.g.:

```bash
git apply patches/001-fix-uaf.patch
```

Also, write a summary of the process — how hard it was to find the bugs, which bugs you found, and your overall experience.

**You are done with Task 1A when all of the following hold:**

1. The initial double-free bug shown in the demo is fixed and all basic unit tests pass.
2. You have created at least two working fuzz targets (`fuzz_deserialize` and `fuzz_roundtrip`).
3. You have found and fixed all **7** planted bugs across the protocol implementation (they span double-frees, a memory leak, out-of-bounds reads during deserialization, an integer overflow, and missing bounds and validation checks), each accompanied by a regression test and a CWE classification.
4. The summary report described above is written.

On this codebase, bugs typically surface within a few minutes of fuzzing with AddressSanitizer enabled. Budget around 10–20 minutes of fuzzing time per target. If your fuzzer runs for 10 minutes without finding new issues, treat that as a signal to review your fuzz target logic and seed corpus before concluding your search.

The 7 bugs above are the guaranteed set. Real codebases rarely contain only deliberately planted defects - if your fuzzer surfaces additional issues beyond them, investigate and report those in your summary as well.

## Task 1B: Integrating `libFuzzer` with ClusterFuzzLite (1p+)

> **1 bonus point** is available for advanced CI integration (see details at the end of this task).

[ClusterFuzz](https://github.com/google/clusterfuzz) is Google's large-scale fuzzing infrastructure. While full ClusterFuzz can be heavy to set up, [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) is a lightweight version designed to run directly inside CI/CD pipelines. Prominent open-source projects like `curl` and `systemd` use it during their [code review process](https://security.googleblog.com/2021/11/clusterfuzzlite-continuous-fuzzing-for.html) to catch regressions before code lands in main branches.

In this task, you will integrate ClusterFuzzLite into the messaging protocol project using the fuzz targets created in Task 1A. Only the `code-change` (pull request) mode is required.

You need Docker running, [`act`](https://github.com/nektos/act) installed (with Docker up), and basic familiarity with GitHub Actions. See the [GitHub Actions documentation](https://docs.github.com/actions) if you are not yet familiar with them.

---

### Step-by-step integration workflow

#### 1. Create the `.clusterfuzzlite` configuration directory

ClusterFuzzLite builds and runs your fuzz targets inside a standardized container. Follow the [ClusterFuzzLite build integration guide](https://google.github.io/clusterfuzzlite/build-integration/) to create the required files:

```
├── .clusterfuzzlite/
│   ├── Dockerfile      # Base image definition & build dependencies
│   ├── build.sh        # Script that compiles libFuzzer targets using $CXX and $LIB_FUZZING_ENGINE
│   └── project.yaml    # Project metadata (language: c++)
└── .github/
    └── workflows/
        └── cflite_pr.yml # GitHub Actions workflow running code-change fuzzing
```

#### 2. Run ClusterFuzzLite locally (core validation)

Before touching GitHub, validate the entire setup locally. This is the layer that actually checks your configuration, and it is feasible without any GitHub involvement. The build integration guide includes a section on testing your integration locally. Work through that section until all of the following hold:

- The `.clusterfuzzlite/Dockerfile` builds, and `build.sh` compiles the fuzz targets cleanly with sanitizers.
- The targets actually execute inside the container.
- A known crashing input from Task 1A is detected and reported.

#### 3. Smoke-test the workflow with `act`

Before spending CI minutes, use [`act`](https://github.com/nektos/act) to catch workflow wiring problems, in particular YAML syntax, matrix definitions, expressions, and action input names.
Install it with `pacman -Syu act` on Arch or through the [official installation methods](https://nektosact.com/installation/index.html). Then, with Docker running, run the workflow with a pull request event payload. Add `--no-skip-checkout` so that the checkout step is exercised too, and use an x86_64 container if your machine architecture differs.

Keep in mind that this is not an environment-equivalence test. `act` emulates the runner, but the real CFLT run, including the runner's Docker behavior, `GITHUB_TOKEN`, PR references, and the artifact services, is validated only on GitHub Actions.

#### 4. Verify end-to-end on GitHub and open a pull request

Follow the [ClusterFuzzLite GitHub Actions guide](https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/) for the workflow configuration. Then run the final end-to-end test on your private GitHub repository. A private repository is enough, but if you run out of your monthly CI minutes you may temporarily use a public one.

1. Push the `.clusterfuzzlite` and `.github/workflows` files to the repository.
2. Create a branch, introduce a small code change, and submit a pull request. Feel free to plant a subtle bug intentionally and see whether the fuzzer catches it. Detection may be imperfect without existing coverage data, and that is OK.
3. Verify that the `cflite_pr` workflow triggers, runs fuzzing on the PR diff, and reports its status.

Once you have captured the logs and verified the run, you can disable or remove the workflow.

---

### What to return?

- The `.clusterfuzzlite/` directory (`Dockerfile`, `build.sh`, `project.yaml`).
- The `.github/workflows/` workflow file for ClusterFuzzLite.
- Evidence that the PR workflow executed successfully in GitHub Actions (link to PR / action run or log excerpt in your report).

---

### Bonus point opportunities (+1p)

You can earn up to 1 bonus point by doing any of the following:

- Persist the fuzzer corpus across CI runs (for example, with a GitHub Actions cache or artifact) so that later runs start from an established corpus instead of from scratch, and attach a coverage report from the run to the workflow log or as an artifact.
- Extend the workflow so that a reported crash is automatically turned into a regression test: save the crashing input, convert it into a small C++ test under `tests/` that feeds it to the target function, and show that the new test reproduces the failure with `make test`.
- Configure and document one further ClusterFuzzLite mode beyond the required `code-change` - `batch` (a scheduled deep-fuzzing run, for example triggered by a cron workflow) or `coverage` (continuous fuzzing with coverage reporting) - including its trigger configuration and the report it produces.

## Task 2: Contribute to an existing open-source project. Set up a fuzzer and report the whole process and possible findings (2p+).

> You can earn extra points on this task. Technically there is no upper limit for outstanding work, but 5 points is likely the maximum, and going beyond requires an upstream contribution.
> A simple fuzzing run with AFL may be eligible for only one point, but going beyond 2 points likely requires substantial effort and findings.

Contribute to some existing open-source software (OSS) projects by setting up a fuzzing environment and documenting the whole process and results.
You can choose the target software yourself and use one of the fuzzers introduced in the earlier lab exercises, or pick another one that you think serves the purpose better.

Projects written in C/C++, Rust, or Go are easiest to start with, if you plan to implement custom harnesses that fuzz library interfaces.

Note that you do not need to pick one of the large projects below - a small library with a parser or a narrow API is often a better target. Aim for something that builds and runs on your machine within a reasonable time; the example list shows the _kind_ of software that has been fuzzed before.

Additionally, you can integrate the project's CI/CD pipeline with [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/). Depending on how far you go, **you can get more than two points** from this task, while it can be difficult.

- You could add custom harnesses for different API endpoints that are executed in the pipeline, depending on the code that changed
- You could even make a pull request to upstream, but please consult the instructor first if you are willing to do so.

Do not submit pull requests or upstream reports just to demonstrate effort - submit one only if you believe it is a genuine contribution. Maintainers will notice the difference, and low-quality automated submissions ("AI slop") waste their time and harm the project's reputation. A well-documented local run is more than sufficient for this task; when in doubt, discuss the submission with the instructor before sending anything upstream.

Please note that if you find a real bug in the software, it is very important to document the findings in a way that the issue can be easily reproduced.
The guide has some good points about what information you should provide.
You don't need to file a "real" bug report, but if you find something new, we highly recommend doing so.
If you end up finding a real vulnerability, you must follow [responsible disclosure](https://www.hackerone.com/knowledge-center/why-you-need-responsible-disclosure-and-how-get-started).

You should grab the most recent version of the source code. A few open-source projects, as examples:

- [Chromium](https://www.chromium.org/Home/) - An open-source browser project started by Google.
- [VLC media player](https://www.videolan.org/vlc/index.html) - A common open-source media player from VideoLAN. It has a vast attack surface, as the player uses many different libraries to handle audio/video encoding. See [features](https://www.videolan.org/vlc/features.html).
- [ImageMagick](https://www.imagemagick.org/script/index.php) - An open-source suite for displaying, converting, and editing images, supporting over 200 file formats.
- See [AFLplusplus](https://aflplus.plus/#trophies) and [afl CVE list](https://github.com/mrash/afl-cve) for a comprehensive list of projects in which they have found bugs. Newer versions of software can spawn new bugs, but the most common tools are usually tested the most, so they might not be the best place to start.

You should at minimum provide the following information in the documentation:

1. Which fuzzer was used
2. A brief explanation of the target software and why you chose it
3. Whether you are fuzzing the whole software or a specific part of it
4. Which libraries the software uses, and whether those are fuzzed as well
5. Operating system and version information - version numbers for the target software, its libraries, the fuzzer, and the operating system are very important. Explain why
6. Compiler and debugger flags
7. Initial test case(s) and the one(s) producing a crash, if found
8. The necessary steps to reproduce the crash
9. A demonstration of fuzzing with good code coverage and how input was mutated (i.e., what kind of input the fuzzer created overall)
10. All the code implementing any custom harness when fuzzing libraries
11. All the files needed for the CI/CD integration

Finding bugs is not required - item 9 (a demonstration of good coverage and input mutation) is sufficient.

## References

[1]: Wang, J., Chen, B., Wei, L., & Liu, Y. (2019). Be Sensitive and Collaborative: Analyzing Impact of Coverage Metrics in Greybox Fuzzing. _RAID 2019_. https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf
