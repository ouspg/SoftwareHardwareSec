# IC00AJ74 Cyber Security III: Software and Hardware Security

Exercises for the course IC00AJ74 Cyber Security III: Software and Hardware Security at the University of Oulu.

## Course key content

This course handles key concepts and principles in software and hardware security. Especially in the topics of

- Software testing including fuzzing and fuzzing integration
- Memory errors and vulnerabilities
- Return-oriented programming exploits and shellcoding
- Malware analysis and reverse engineering
- Hardware glitching and side-channel attacks
- Hardware testing with physical interfaces and close-range wireless methods
- Remote attestation and Hardware Security Modules (HSMs)

The course is organized by Oulu University Secure Programming Group (OUSPG)

## Practicalities

The course consists of seven laboratory exercises and seven mandatory lectures.

Lectures cover topics from a high-level perspective and generally do not dive deep into technical details.
Make-up lecture exams (in case of a missed lecture) are based primarily on the lecture material.

Laboratory exercises are designed as self-contained packages: they combine theory with practical exercises and explore topics in much greater technical depth.

To pass this course with a grade of 1, you must attend all lectures (or complete the corresponding make-up exams).

To earn a higher grade, you must complete laboratory exercises.
You can somewhat choose your own grade in this course, as the amount of work required for each grade is outlined from the beginning.
All laboratory tasks are optional, and the total points earned from them will determine your final grade.

### Grading

<!-- <details><summary>Details (Click to collapse!)</summary> -->

As described earlier, you must attend all lectures (or pass their respective make-up exams) to pass the course.
You can earn a higher grade by completing laboratory exercises.

You can earn up to 5 points per lab (for a total of 35 points).
Your final grade is determined based on these points.
For example, 12 points earns a grade of 2.

| Total Points | Total Grade |
| :----------: | :---------: |
|     12+      |      2      |
|     18+      |      3      |
|     24+      |      4      |
|     30+      |      5      |

<!-- </details> -->

### Getting started

- Enroll in the course.
- Find the course page on the university's Moodle.
- Note that we will invite you to the course's GitHub organization using your student email.
- Create a GitHub account if you do not already have one. Your GitHub account must have a **linked and verified university email!** If you do not want to link your university email to an existing account, create a new one.
- After you accept the invitation, we will provision a private GitHub repository for you.
- Fill out the provided templates and commit all your work to this repository.
- Check Moodle for assignment deadlines. There may be exceptions for ChipWhisperer and FlipperZero (Weeks 6 and 7).
- Complete as many tasks as you wish and update your repository accordingly. Check the grading table in each lab's instructions to see what is required to earn the grade of your choice.
- Push your changes to your repository before the deadline, and submit the repository link in the corresponding Moodle submission box for each lab.

> [!NOTE]
> There will be an experimental system, where you can optionally return most of the week 3 and week 4 exercises, and tasks will also be automatically graded! Also possible bonus points available.

Check the [cheat sheet](https://training.github.com/downloads/github-git-cheat-sheet.pdf) if you need a refresher on how to use Git.
Some basic commands below:

```bash
git add </path/filename>
git commit -m "<message>"
git push
```

### Laboratory environment

The course requires extensive use of a Linux-based operating system.

#### Windows

On Windows machines, we recommend using [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install).
WSL is available in TS135 and TS137 as well

> [!NOTE]
> Don't try to update WSL in the classrooms, just install the desired Linux distribution if you haven't done that yet.

Follow the instructions to complete the WSL installation, and install Kali Linux, as [instructed here.](https://www.kali.org/docs/wsl/wsl-preparations/)

We recommend using the Windows Terminal to access the newly created Linux system.

#### Linux

If you are already using Linux, we recommend using Kali Linux or Black Arch as container images. Alternatively, install the tools directly on your machine.

See Kali example [here.](https://www.kali.org/docs/containers/using-kali-docker-images/)

#### macOS

On MacBooks, you can use [Homebrew](https://brew.sh) or pull the ARM-compatible Kali Linux [Docker image](https://hub.docker.com/u/kalilinux).

You can use any OS you prefer, but you may need to figure out how to install the tools on your own.

## License

Any information, guidelines, tutorials, examples, or code pieces here are for teaching purposes, under MIT license, unless otherwise declared.
