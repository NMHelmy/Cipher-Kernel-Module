#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include "RC4.c"

// Define constants for device names, buffer sizes, and key sizes
#define DEVICE_NAME "cipher"
#define KEY_DEVICE_NAME "cipher_key"
#define BUFFER_SIZE 4096
#define KEY_SIZE 128

static int major;  // Major number assigned to the device
static char message[BUFFER_SIZE];  // Buffer to store the message
static char encrypted_message[BUFFER_SIZE]; // This will hold the encrypted message
static char key[KEY_SIZE];  // Buffer to store the encryption key

// Pointers to proc directory and proc files
static struct proc_dir_entry *proc_cipher, *proc_cipher_key;

// Function prototypes for device operations
static int cipher_open(struct inode *, struct file *);
static ssize_t cipher_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t cipher_write(struct file *, const char __user *, size_t, loff_t *);
static int cipher_release(struct inode *, struct file *);

// Function prototypes for proc operations
static ssize_t proc_read_cipher(struct file *file, char __user *buf, size_t len, loff_t *offset);
static ssize_t proc_write_cipher_key(struct file *file, const char __user *buf, size_t len, loff_t *offset);

// Open the cipher device (Logs when the device is opened)
static int cipher_open(struct inode *inode, struct file *file) {
    pr_info("Cipher device opened\n");
    return 0;
}

// Release the cipher device (Logs when the device is closed)
static int cipher_release(struct inode *inode, struct file *file) {
    pr_info("Cipher device closed\n");
    return 0;
}

// Write to the cipher device (either message or key)
static ssize_t cipher_write(struct file *file, const char __user *buf, size_t len, loff_t *offset) { // file offset indicates the current position in the file
    int ret;
    // If writing to the cipher device (message), copy the message from user space
    if (file->f_inode->i_rdev == MKDEV(major, 0)) {  // Cipher device
        if (len > BUFFER_SIZE) return -EINVAL;
        // copy data from user-space buffer (buf) to kernel-space buffer (message) with the num of bytes to copy (len)
        ret = copy_from_user(message, buf, len);
        if (ret) return -EFAULT;
        pr_info("Message written to cipher device\n");
    }
    // If writing to the key device (cipher key), copy the key from user space
    else if (file->f_inode->i_rdev == MKDEV(major, 1)) {  // Cipher key device
        if (len > KEY_SIZE) return -EINVAL;
        ret = copy_from_user(key, buf, len);
        if (ret) return -EFAULT;
        pr_info("Key written to cipher_key device\n");
    }
    return len;
}

// Read from the cipher device (returns the encrypted message)
static ssize_t cipher_read(struct file *file, char __user *buf, size_t len, loff_t *offset) {
    int ret;
    size_t message_len = strlen(message);

    // If reading from the key device, return a message about the key being hidden
    if (file->f_inode->i_rdev == MKDEV(major, 1)) {
        return simple_read_from_buffer(buf, len, offset, "Go away silly one, you cannot see my key >-:\n", strlen("Go away silly one, you cannot see my key >-:\n"));
    } 

    // Otherwise, read the encrypted message
    else {
        if (*offset >= BUFFER_SIZE) return 0;  // End of buffer
        // if len > the available space from the current offset to t he end of the buffer it limits len to the remaining space
        if (len > BUFFER_SIZE - *offset) len = BUFFER_SIZE - *offset; 

        pr_info("Before encrypting message: %s\n", message);

        // Encrypt the message using RC4
        rc4(message, key, encrypted_message, message_len, strlen(key));
        pr_info("Encrypted message: %s\n", encrypted_message);

        // Copy the encrypted message to user space
        ret = copy_to_user(buf, encrypted_message + *offset, len);
        if (ret) return -EFAULT;

        // update offset by the len that was just copied
        *offset += len;
        return len;
    }
}

// Read from the /proc/cipher file (returns decrypted message)
static ssize_t proc_read_cipher(struct file *file, char __user *buf, size_t len, loff_t *offset) {
    char decrypted_message[BUFFER_SIZE];
    size_t message_len;

    // Check if the key is set
    if (strlen(key) == 0) {
        pr_info("Key is not set, cannot decrypt.\n");
        return -EINVAL;
    }

    // Determine the actual length of the message
    message_len = strlen(encrypted_message);
    if (message_len == 0) {
        pr_info("No message to decrypt.\n");
        return 0;
    }

    // Ensure len does not exceed the remaining message length
    if (len > message_len - *offset) len = message_len - *offset;

    pr_info("Decrypting message...\n");
    pr_info("Encrypted message: %s\n", encrypted_message);

    // Perform RC4 decryption
    rc4(encrypted_message, key, decrypted_message, message_len, strlen(key));
    pr_info("Decrypted message: %s\n", decrypted_message);

    // Null-terminate the decrypted string
    decrypted_message[message_len] = '\0';

    // Copy the decrypted message to the user buffer
    return simple_read_from_buffer(buf, len, offset, decrypted_message, message_len);
}


// Write to the /proc/cipher_key file (sets the cipher key)
static ssize_t proc_write_cipher_key(struct file *file, const char __user *buf, size_t len, loff_t *offset) {
    int ret;

    // Check if the key length is valid
    if (len > KEY_SIZE) return -EINVAL;

    // Copy the key from user space to kernel space
    ret = copy_from_user(key, buf, len);
    if (ret) return -EFAULT;
    pr_info("Key written to /proc/cipher_key\n");
    return len;
}

// File operations structure for the cipher device
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = cipher_open,
    .read = cipher_read,
    .write = cipher_write,
    .release = cipher_release,
};

// File operations for the /proc/cipher file (read encrypted message)
static struct file_operations proc_cipher_fops = {
    .read = proc_read_cipher,
};

// File operations for the /proc/cipher_key file (write key)
static struct file_operations proc_cipher_key_fops = {
    .write = proc_write_cipher_key,
};

// Character device structure - stores info about the device (including ops like open, read, etc)
// cipher_cdev represent the cipher device
static struct cdev cipher_cdev;

// Module initialization function
static int __init cipher_init(void) {
    dev_t dev; // device num both major and minor
    pr_info("Initializing cipher module\n");

    // Allocate device numbers - assigns both major and minor nums for the character device
    // device name used in /sys/class/ dir
    if (alloc_chrdev_region(&dev, 0, 2, DEVICE_NAME) < 0) {
        pr_err("Failed to allocate character device region\n");
        return -1;
    }

    major = MAJOR(dev);  // Get the allocated major number
    pr_info("Allocated major number: %d\n", major);

    // Initialize the character device (interface) with the file operations
    cdev_init(&cipher_cdev, &fops);
    if (cdev_add(&cipher_cdev, dev, 2) < 0) { // register the character device with the kernel
        pr_err("Failed to add cdev\n");
        unregister_chrdev_region(dev, 2);
        return -1;
    }

    // Create /proc/cipher file for encrypted message
    proc_cipher = proc_create("cipher", 0666, NULL, &proc_cipher_fops);
    if (!proc_cipher) {
        pr_err("Failed to create /proc/%s/cipher\n", DEVICE_NAME);
        cdev_del(&cipher_cdev);
        unregister_chrdev_region(dev, 2);
        return -1;
    }

    // Create /proc/cipher_key file for cipher key
    proc_cipher_key = proc_create("cipher_key", 0666, NULL, &proc_cipher_key_fops);
    if (!proc_cipher_key) {
        pr_err("Failed to create /proc/%s/cipher_key\n", DEVICE_NAME);
        remove_proc_entry(DEVICE_NAME, NULL);
        cdev_del(&cipher_cdev);
        unregister_chrdev_region(dev, 2);
        return -1;
    }

    pr_info("Cipher module loaded with major %d\n", major);
    return 0;
}

// Module cleanup function
static void __exit cipher_exit(void) {
    // ensures no further interactions with these files can happen after the module is unloaded
    remove_proc_entry(KEY_DEVICE_NAME, NULL);
    remove_proc_entry(DEVICE_NAME, NULL);

    cdev_del(&cipher_cdev); // removes the character device from the system
    unregister_chrdev_region(MKDEV(major, 0), 2); // releases the range of device numbers that were allocated

    pr_info("Cipher module unloaded\n");
}

module_init(cipher_init);
module_exit(cipher_exit);

MODULE_LICENSE("GPL");