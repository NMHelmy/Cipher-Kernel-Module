//#include "RC4.h"
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <../kernel/sched/sched.h>

#define RC_SIZE 256

void rc4(unsigned char * p, unsigned char * k, unsigned char * c,size_t l,size_t kl){
    unsigned char s [RC_SIZE];
    unsigned char t [RC_SIZE];
    unsigned char temp;
    unsigned char kk;
    size_t i,j,x;
    for ( i  = 0 ; i  < RC_SIZE ; i ++ ){
        s[i] = i;
        t[i]= k[i % kl];
    }
    j = 0 ;
    for ( i  = 0 ; i  < RC_SIZE ; i ++ ){
        j = (j+s[i]+t[i])%RC_SIZE;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    i = j = -1;
    for ( x = 0 ; x < l ; x++ ){
        i = (i+1) % RC_SIZE;
        j = (j+s[i]) % RC_SIZE;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        kk = (s[i]+s[j]) % RC_SIZE;
        c[x] = p[x] ^ s[kk];
    }
}

MODULE_LICENSE("GPL");