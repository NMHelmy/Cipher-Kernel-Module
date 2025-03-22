# Cipher-Kernel-Module

This is a Linux Kernel Module that implements a **cipher device** using the **RC4 encryption algorithm**. The module allows users to encrypt and decrypt messages using a key, and provides access to these functionalities through both a **character device** and `/proc` files.

## Features
* RC4 Encryption/Decryption: Implements the RC4 stream cipher for encrypting and decrypting messages.
* Character Device Interface: Provides a character device (/dev/cipher) for writing messages and keys, and reading encrypted messages.
* Proc File Interface: Exposes encrypted messages and key management through /proc/cipher and /proc/cipher_key.
* Kernel Logging: Logs key events (e.g., device open/close, message encryption/decryption) using pr_info.

## Prerequisites
* Linux Kernel Development Environment: Ensure you have the kernel headers and development tools installed.
* Root Privileges: Required to load and unload kernel modules.
* GCC: To compile the kernel module.

## Usage
### Compilation
1. Compile the module:
```
make
```
### Loading the Module
1. Load the module:
```
sudo insmod cipher_module.ko
```
2. Verify that the module is loaded:
```
dmesg | tail
```
You should see messages like:
```
Initializing cipher module
Allocated major number: 123
Cipher module loaded with major 123
```
3. Check the /dev and /proc files:
```
ls /dev/cipher*
ls /proc/cipher*
```
You should see:
```
/dev/cipher  /dev/cipher_key
/proc/cipher  /proc/cipher_key
```

### Using the Cipher Device
Write a Key:
```
echo "YOUR_SECRET_KEY" > /dev/cipher_key
```
Write a Message:
```
echo "YOUR_SECRET_MESSAGE" > /dev/cipher
```
Read the Encrypted Message:
```
sudo cat /dev/cipher
```
Retrieve the Original Message:
Write the key to /proc/cipher_key:
```
echo "YOUR_SECRET_KEY" > /proc/cipher_key
```
Read the decrypted message:
```
sudo cat /proc/cipher
```
