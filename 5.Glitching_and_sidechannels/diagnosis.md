## Common connection errors

### ERROR 1
USB Ccompatibility: USB 1.1
OS: Windows 10 64-bit
Software: VMWare 17.6 Workstation Pro

When calling cw.scope()
```
OSError: 'This device has no langid' ValueError caught. This is usually caused by us trying to read the serial number of the chipwhisperer, but it failing. The device is here and we can see it, but we can't access it. This has a number of root causes, including:
-Not having permission to access the ChipWhisperer (this still crops up if you have permission for one ChipWhisperer, but another ChipWhisperer is connected that you don't have access to)
-Not having the correct libusb backend loaded (common on Windows with 64bit Python). We try to handle this by loading the correct backend on Windows
```
![image](https://github.com/user-attachments/assets/4fa9c27d-13bd-4765-a22d-d7c9def67873)

Modify the error handling logic at:
/home/vagrant/work/projects/chipwhisperer/software/chipwhisperer/hardware/naeusb/naeusb.py

In ref to article: https://github.com/newaetech/chipwhisperer/issues/199

Changing dev rules at hardware/99-newae.rules from # CW-Lite MODE = 0664 to MODE = 0666 leads to original error:
```
Warning: Could not connect to "NewAE USB (CWLite/CW1200)". It may have been disconnected, is in an error state, or is being used by another tool.
```

### ERROR 2

Changing USB compatibility to USB 1.1, USB 2.0, USB 3.1 did not work and resulted in error below

Test machines: Windows 10, VMware || Arch linux, VirtualBox

Seems like there is an issue with USB Passthrough due to version compatibility issue such that the device appears to be busy. I've tested to ensure that device was connected
to VM only (as can be verified from ERROR 1). Moreover, rules for permission have been tested.

Consistent and persistent error across VMware & VirtualBox
![image](https://github.com/user-attachments/assets/ef7c1f1b-f91c-4420-a4ed-c75ae7fab6dc)

