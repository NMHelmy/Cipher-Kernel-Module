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
  * You should see messages like:
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
  * You should see:
      ```
      /dev/cipher  /dev/cipher_key
      /proc/cipher  /proc/cipher_key
      ```

### Using the Cipher Device
1. Write a Key:
```
echo "YOUR_SECRET_KEY" > /dev/cipher_key
```
2. Write a Message:
```
echo "YOUR_SECRET_MESSAGE" > /dev/cipher
```
3. Read the Encrypted Message:
```
sudo cat /dev/cipher
```
4. Retrieve the Original Message:
* Write the key to /proc/cipher_key:
```
echo "YOUR_SECRET_KEY" > /proc/cipher_key
```
* Read the decrypted message:
```
sudo cat /proc/cipher
```
### Unloading the Module
1. Unload the module:
```
sudo rmmod cipher_module.ko
```
2. Verify that the module is unloaded:
```
dmesg | tail
```
* You should see:
```
Cipher module unloaded
```
## Code Overview
### Key Files
* cipher_module.c: The main kernel module implementation.
    * Character Device: Provides /dev/cipher for writing messages and keys, and reading encrypted messages.
    * Proc Files: Provides /proc/cipher for decrypted messages and /proc/cipher_key for setting the key.
    * RC4 Integration: Calls the RC4 algorithm for encryption and decryption.

* RC4.c: Implements the RC4 encryption algorithm.
    * rc4(): Encrypts or decrypts a message using the provided key.
* RC4.h: Header file for the RC4 implementation.

### Key Functions
* cipher_open(): Logs when the cipher device is opened.
* cipher_release(): Logs when the cipher device is closed.
* cipher_write(): Handles writing messages or keys to the device.
* cipher_read(): Returns the encrypted message or a warning for key access.
* proc_read_cipher(): Reads and decrypts the message from /proc/cipher.
* proc_write_cipher_key(): Writes the key to /proc/cipher_key.
* rc4(): Encrypts or decrypts a message using the RC4 algorithm.

## Proc Files
* /proc/cipher: Read the decrypted message.
* /proc/cipher_key: Write the encryption key.

## Character Device
* /dev/cipher: Write messages or keys, and read encrypted messages.

## Example Workflow
1. Set the Key:
```
echo "mysecretkey" > /dev/cipher_key
```
2. Encrypt a Message:
```
echo "Hello, World!" > /dev/cipher
```
3. Read the Encrypted Message:
```
sudo cat /dev/cipher
```
4. Decrypt the Message:

    * Write the key to /proc/cipher_key:
    ```
    echo "mysecretkey" > /proc/cipher_key
    ```
    * Read the decrypted message:
    ```
    sudo cat /proc/cipher
    ```
