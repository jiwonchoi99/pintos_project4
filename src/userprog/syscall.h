#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include "vm/page.h"


void syscall_init (void);

struct lock filesys_lock;

#endif /* userprog/syscall.h */
