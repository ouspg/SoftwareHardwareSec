# Software and Hardware Security Lab 7: Hardware Security Modules (HSMs), Trusted Platform Module (TPM), and remote attestation.


Almost every new computer and (high-end) mobile phone has a small piece of embedded hardware, called a Hardware Security Module (HSM) [^1], likely in your computer's or phone's motherboard/SoC, and contains one or more secure cryptoprocessors.

The main purpose of this module is to **safeguard and manage secrets**.
In most cases, the secret is a digital cryptographic private key.
The chip is designed in a way, that the key never leaves the chip; all cryptographic operations happen inside the secure cryptoprocessor.

Different manufacturers have different solutions, which usually extend the basic features of HSMs.
Google's latest Android phones use Titan chip [^2], Apple has so-called Secure Enclave [^3], and Microsoft has been the main contributor to open Trusted Platform Module (TPM) standard [^4][^5].

Currently, TPM is the de-facto security module on non-Apple manufactured mainstream desktop and laptop computers.
The purpose of TPM goes outside of just being HSM; it primarily attempts to guarantee *platform integrity*.
It can identify whether the state of the hardware has changed, by having access to information about components' firmware data, OS boot process data, and other meta information.
When the assurances that define the trustworthiness of a system are at a certain level, then TPM can enable the boot process of the computer or grant access to cryptographic keys.
For more about the TPM, a good start is to explore [Microsoft's documentation](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-top-node) [^6].

This exercise will mainly focus on trying out TPM 2.0 standard implementation and its use cases.
The module is extremely complex and we will just briefly explore the high-level functionality.

> [!WARNING]
> During this exercise, only use the simulator and not the underlying TPM module of your computer, even if you think that you know what you are doing. In the worst case, your computer will become unbootable (and unfixable) or your encrypted disk can never be decrypted.


# Task 1: Getting started with TPM 2.0




[^1]: [Hardware Security Module](https://en.wikipedia.org/wiki/Hardware_security_module)

[^2]: [Learn about Pixel security certifications on Android](https://support.google.com/pixelphone/answer/11062200)

[^3]: [Secure Enclave](https://support.apple.com/en-mn/guide/security/sec59b0b31ff/web)

[^4]: [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)

[^5]: [ISO/IEC 11889-1:2015](https://www.iso.org/standard/66510.html)

[^6]: [Trusted Platform Module](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-top-node)