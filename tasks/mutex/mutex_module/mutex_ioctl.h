#ifndef _MUTEX_UAPI_H
#define _MUTEX_UAPI_H

#ifdef __KERNEL__
#include <asm/ioctl.h>
#include "shared_spinlock.h"
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <shared_spinlock.h>
#endif //__KERNEL__

#define MUTEX_IOCTL_MAGIC 'M'

typedef unsigned long mutex_id_t;

typedef struct mutex_ioctl_lock_create_arg {
    mutex_id_t id; // out param
    unsigned long mutex_splock_vaddr;
} mutex_ioctl_lock_create_arg_t;

typedef struct mutex_ioctl_lock_delete_arg {
    mutex_id_t id;
} mutex_ioctl_lock_delete_arg_t;

typedef struct mutex_ioctl_thread_putwait_arg {
    mutex_id_t id;
} mutex_ioctl_thread_putwait_arg_t;

typedef struct mutex_ioctl_thread_wakeup_arg {
    mutex_id_t id;
} mutex_ioctl_thread_wakeup_arg_t;

#define MUTEX_IOCTL_LOCK_CREATE \
    _IOW(MUTEX_IOCTL_MAGIC, 1, mutex_ioctl_lock_create_arg_t)
#define MUTEX_IOCTL_LOCK_DELETE \
    _IOW(MUTEX_IOCTL_MAGIC, 2, mutex_ioctl_lock_delete_arg_t)
#define MUTEX_IOCTL_THREAD_PUTWAIT \
    _IOW(MUTEX_IOCTL_MAGIC, 3, mutex_ioctl_thread_putwait_arg_t)
#define MUTEX_IOCTL_THREAD_WAKEUP \
    _IOW(MUTEX_IOCTL_MAGIC, 4, mutex_ioctl_thread_wakeup_arg_t)

#endif //_VSD_UAPI_H
