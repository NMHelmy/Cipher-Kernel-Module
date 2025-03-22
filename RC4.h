#ifndef RC4_H 
#define RC4_H

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <../kernel/sched/sched.h>

void rc4(unsigned char * p, unsigned char * k, unsigned char * c,size_t l,size_t kl);

#endif // RC4_H