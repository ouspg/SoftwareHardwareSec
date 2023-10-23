# Software and Hardware Security Lab 7: Hardware Security Modules (HSMs), Trusted Platform Module (TPM), and remote attestation.


Almost every new computer and (high-end) mobile phone has a small piece of embedded hardware, called a Hardware Security Module (HSM) [^1], likely in your computer's or phone's motherboard/SoC, and contains one or more secure cryptoprocessors.

The main purpose of this module is to **safeguard and manage secrets**.
In most cases, the secret is a digital cryptographic private key.
The chip is designed in a way, that the plaintext key never leaves the chip; all cryptographic operations happen inside the secure cryptoprocessor.

Different manufacturers have different solutions, which usually extend the basic features of HSMs.
Google's latest Android phones use Titan chip [^2], Apple has so-called Secure Enclave [^3], and Microsoft has been the main contributor to open Trusted Platform Module (TPM) standard [^4][^5].

Currently, TPM is the de-facto security module on non-Apple manufactured mainstream desktop and laptop computers.
The purpose of TPM goes outside of just being HSM; it primarily attempts to guarantee *platform integrity*.
It can identify whether the state of the hardware and overall platform has changed, by having access to information about components' firmware data, OS boot process data, and other meta information.
When the assurances that define the trustworthiness of a system are at a certain level, then TPM can enable the boot process of the computer or grant access to cryptographic keys.
For more about the TPM, a good start is to explore [Microsoft's documentation](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-top-node) [^6].

This exercise will mainly focus on trying out TPM 2.0 standard implementation and its use cases.
The module is extremely complex and we will just briefly explore the high-level functionality.
Exploiting known TPM vulnerabilities or attempts of tampering might go outside of the time constraints in this course, so we will focus more on its benefits and usage.

> [!WARNING]
> During this exercise, only use the simulator and not the underlying TPM module of your computer, even if you think that you know what you are doing. In the worst case, your computer will become unbootable (and unfixable) and your encrypted disk can never be decrypted.

## Grading

You are eligible for the following grades in this exercise by doing tasks as defined. Great ideas and implementations could compensate for some poorly implemented ones.

***You don't have to do the tasks 2 and 3 in order!***


Task|Points|Description|
----|:---:|-----------|
[Task 1](#task-1-getting-started-with-tpm-20) | 1 | Getting started with TPM 2.0 |
[Task 2](#task-2-hardware-secured-end-to-end-encrypted-messenger) | 1-3 | Hardware-secured end-to-end encrypted messenger |
[Task 3](#task-3-risks-and-limitations-of-hardware-based-security-and-remote-attestation) | 1 | Risks and limitations of hardware-based security and remote attestation |

A total of 5 points can be obtained from this lab.


*Return completed tasks to your private GitHub repository!*

# Task 1: Getting started with TPM 2.0

You can directly access TPM by using specific interfaces to use the device.
However, this can be sometimes a bit dangerous and should be avoided when just learning.

For the exercise, we will use a custom Docker/OCI image, which uses Microsoft's official TPM 2.0 reference implementation and its simulator [^7].

The image contains a set of TPM-specific tools and some additional dependencies to do the exercise this week.
In the first task, we are mainly using `tpm2-tools` collection, and the docs are available [here.](https://tpm2-tools.readthedocs.io/en/latest/)

To start doing this task, simply run

```console
docker run -it --rm ghcr.io/ouspg/tpm2env
```

The image is available for both `x86_64` and `AArch64` platforms.


Use the instructions from [Nokia's TPM course](https://github.com/nokia/TPMCourse/blob/master/docs/STARTHERE.md) [^8] as help and answer the following questions.
If the object memory of the TPM simulator gets full, you can in this case clear it safely by using the command `tpm2_flushcontext`, or start from the beginning by using `tpm2_clear`.


 1. How you could generate 30 bytes of random data by using TPM? Can you increase the entropy of TPM's random number generator? Provide the commands.

 2. Create Owner-class Hierarchy Primary Key of elliptic-curve kind. What does the seed mean in this context and how does it affect key generation? Are we using the correct hierarchy if we want to generate keys for applications? Provide the commands.

 3. Create a usable key with the help of the primary key. Load the key into TPM. Print the public key in `PEM` format. Provide the commands.

 4. Let's use the key. At first, generate a symmetric key for AES encryption. Encrypt some string which is longer in bits than the asymmetric key size (256 bits). Sign the ciphertext with the ECC keys and verify the integrity. Provide the commands.


# Task 2: Hardware-secured end-to-end encrypted messenger

> [!NOTE]
> You can skip this task and do the final task, if you don't want to do tasks in order.

This task is a programming exercise, and you will likely need to use `Golang`, unless you are prepared to figure out many things yourself.
Following are being used as base libraries:
  * [go-tpm](https://github.com/google/go-tpm)
  * [go-tpm-tools](https://github.com/google/go-tpm-tools)

These include many subpackages.

We provide a base project, and you need to implement some missing features, to programmatically use TPM 2.0.

There are also [Python bindings](https://github.com/tpm2-software/tpm2-pytss), for example,  if you don't want to use Go, but you are on your own.

## Requirements

The idea is the following; we are going to implement a secure end-to-end messenger, where most of the cryptographic keys are stored, *sealed* inside the TPM.
In theory, only the untampered TPM devices can decrypt the message contents, and nobody else.

The messenger should do the following:
 * The same application is able to send and receive messages. (already in the base project)
 * Two users, Alice and Bob are sending messages. This is simulated with Unix sockets between two Docker containers. We need containers to provide two TPM 2.0 instances. (Compose file already provided)
 * Both Alice and Bob have their own public-private key pairs, and *private key is stored inside separate TPMs.* (Missing)
   * Simulated by running the same application twice in different containers.
   * All encryption functionality is missing
 * Application is expected to exchange public keys of the messaging parties before the messaging is started. 
 * TPM is responsible for generating session-based stream encryption key (e.g. AES) (Missing)
 * The public key of the receiver is used to encrypt the AES key, among the encrypted data, when the data is being sent.
 It means that the receiver then uses their private key from TPM to decrypt the AES key, and then further decrypts the message content with the derived symmetric key. (Missing)


### Advanced (required for full points)

The messenger should implement the following Signal Protocols to replace the encryption functionality of the simple version:
 * [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/#introduction)
 * [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)

For example,  Signal, Facebook Messenger, WhatsApp, Google Messages, and Matrix use these in order to provide E2E encryption.

When compared to the previous. this should have perfect forward secrecy.

There are libraries available, that abstract most of the complexity. It is not as difficult as it sounds!

  * [Xochimilco - both Double Ratchet and X3DH with examples](https://pkg.go.dev/github.com/oxzi/xochimilco#section-readme)

 TPM 2.0 simulator does not support `Curve25519` or `Curve448` elliptic curves, which are recommended and often used by Signal protocol implementations.
 Instead, we need to use other TPM 2.0-supported algorithms to encrypt the private keys of these curves.

 Check the [PCR section](https://github.com/nokia/TPMCourse/blob/master/docs/pcrs.md) and [NVMRAM sealing](https://github.com/nokia/TPMCourse/blob/master/docs/nvram.md#sealing) of the Nokia instructions.

 Create a PCR policy, define NVMRAM section, and write the required private key(s) in there, which is sealed by the policy. Do you have any idea, what your policy is about? It tells about the state, but what state?

Check Go go-tpm-tools package [client](https://pkg.go.dev/github.com/google/go-tpm-tools/client) which abstracts a lot.

> You can explore further other ways to utilise TPM on this task!

> [!IMPORTANT]
> Do not use the previous in production. It is more about practicing using TPM rather than the most secure implementation (or maybe it is, but no guarantees).


## Getting started

To start developing, all you need is `docker-compose` or `podman-compose` installed and working.


On this directory, run `docker-compose up`.

This will spawn two identical containers named as:
  * `tpm2fun_1`
  * `tpm2fun_2`

The base code is located on the directory `messenger` on this repository, which is automatically mounted to `/data` directory inside both containers.

It will also create a named volume, which is mounted to path `/var/run/messenger/` in both containers.
This directory is used for the UNIX socket, which is used for communication.

Then in different terminal windows, connect to containers as
```console
docker exec -it tpm2fun_1 bash
# On another window
docker exec -it tpm2fun_2 bash
```

For demo the purpose, on the second window you can set Netcat for listening mode:
```console
nc -lU /var/run/messenger/unix.sock
```
In the first window, once you are in `/data` folder, just run
```console
go run .
```
This will install Go dependencies and run the main program, which will send some data over `Unix` socket, and Netcat will show the data.
In this case, it is just random bytes from TPM.

## Additional help

If you haven't developed much with Go, you can get the development environment running rather fast.
Install VSCode if you haven't already, and the following extensions:
  * [`Dev Containers`](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) (To attach TPM container)
  * When you have run the compose file, attach either `tmp2fun_1` or `tmp2fun_2` container, and open `/data` directory.
  * Once attached to the container, install `Go by Go Team in Google` extension (install also popups)

For Golang simulator documentation, look [here](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.4.1/simulator#pkg-overview), however, you probably don't need it more than already has been provided.

We will use the [old API of `go-tpm`](https://pkg.go.dev/github.com/google/go-tpm@v0.9.0/legacy/tpm2), since the new one is still under development and is missing documentation.

Some examples are available [here.](https://github.com/google/go-tpm/tree/main/examples)

Also, [tests](https://github.com/google/go-tpm/blob/ee6cbcd136f878df2c2f36b4a085d2115330f379/legacy/tpm2/test/tpm2_test.go) can be an excellent way to find more examples.


When looking at tutorials, in most cases, you can replace the usage of the real device as follows:

```go
    //  We don't use real device
    // rwc, err := tpm2.OpenTPM(path)
    // Instead ->
	rwc, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
```

When building the simulator, you will see some `GCC`-related notes; you can suppress them by setting `export CGO_CFLAGS="-Wno-psabi"` environment variable.
On containers, this is already set by default.

To compile `ProtoBuff` files, if you modify them:
```console
protoc --go_out=. --go_opt=paths=source_relative message.proto
```

# Task 3: Risks and limitations of hardware-based security and remote attestation

> As the final task of the course, you need to write an essay.
The essay should be 1-2 A4 pages long at minimum, or more. (400-800 words)

You can discuss some of the following ideas from different perspectives, especially in the context of TPM and remote attestation.

If you are unfamiliar with remote attestation, read the [Wikipedia page of Trusted Computing](https://en.wikipedia.org/wiki/Trusted_Computing).

 * Security modules can be a single point of failure or a root level of trust. How does one recover if a TPM fails? Are there systems in place to restore trust without compromising security?
 * There is absolute trust for the TPM manufacturers and distribution of Endorsement Key (EK) [^10]. What if the TPM manufacturer is based in a politically contentious region?
 * Can we control the global supply chain properly when manufacturing TPMs?
 * Privacy issues of the usage of the Endorsement Key - can we do better?
 * TPM has become a complex all-capable device - what does this mean for security? The public API has over 1200 functions [^11]. Complexity is the enemy of security.
 * The TPM manufacturing process can be very slow or lagging. For example, Curve25519 is a widely used cryptographic curve, but it just appeared in the standard 2020 and still, no single TPM chip supports it. For example, [the Signal protocol usually is implemented with Curve25519 or Curve448 elliptic curves](https://signal.org/docs/specifications/doubleratchet/).
 * TPM might lead you to not own your own computer anymore.  Explore the implications for personal and enterprise users.
 * How might vulnerabilities in the TPM firmware itself be addressed?
 * Is there enough transparency in the design, manufacturing, and functioning of TPMs for the broader cybersecurity community to place trust in them?

Additionally, take a look at Google's Web Environment Integrity for Chrome, which attempts to bring remote attestation for websites.
 * [Web Environment Integrity Explainer](https://github.com/RupertBenWiser/Web-Environment-Integrity/blob/main/explainer.md)
 * [Your Computer Should Say What You Tell It To Say](https://www.eff.org/deeplinks/2023/08/your-computer-should-say-what-you-tell-it-say-1)

Also, take a look at Apple's Safari version:
  * [Challenge: Private Access Tokens](https://developer.apple.com/news/?id=huqjyh7k)
  * [Verify Apple devices with no installed software](https://blog.cloudflare.com/private-attestation-token-device-posture/)

You can also look for public opinions about the topic.

Think about the potential problems of this - do benefits beat the negative effects? Consider good use cases and bad use cases for remote attestation.



[^1]: [Hardware Security Module](https://en.wikipedia.org/wiki/Hardware_security_module)

[^2]: [Learn about Pixel security certifications on Android](https://support.google.com/pixelphone/answer/11062200)

[^3]: [Secure Enclave](https://support.apple.com/en-mn/guide/security/sec59b0b31ff/web)

[^4]: [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)

[^5]: [ISO/IEC 11889-1:2015](https://www.iso.org/standard/66510.html)

[^6]: [Trusted Platform Module](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-top-node)

[^7]: [Official TPM 2.0 Reference Implementation (by Microsoft)](https://github.com/microsoft/ms-tpm-20-ref)

[^8]: [Getting started with TPM, or, START HERE](https://github.com/nokia/TPMCourse/blob/master/docs/STARTHERE.md)


[^10]: [TPM Key Attestation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation)

[^11]: [Fixing the TPM: Hardware Security Modules Done Right](https://loup-vaillant.fr/articles/hsm-done-right)