#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/types.h>

#include "mutex_ioctl.h"

#define LOG_TAG "[MUTEX_MODULE] "

typedef struct mutex_state {
    shared_spinlock_t __user *mutex_splock;
    wait_queue_head_t waiters; 
    mutex_id_t id;

    struct hlist_node mutex_node;
} mutex_state_t;

typedef struct tgroup_state {
    pid_t tgroup_id;
    spinlock_t wlock;
    struct hlist_head mutexes;
    mutex_id_t free_id;

    struct hlist_node tgstate_node;
} tgroup_state_t;

typedef struct system_mutex_state {
    // lock only when adding new tgroup
    spinlock_t wlock;
    struct hlist_head tgstates;
} system_mutex_state_t;

typedef struct mutex_dev {
    struct miscdevice mdev;
    system_mutex_state_t sysmstate;
} mutex_dev_t;

static mutex_dev_t *mutex_dev;

/*
 * Must be invoked with tgroup_state.wlock taken.
 */
mutex_id_t get_new_id(tgroup_state_t *state) {
    ++(state->free_id);
    return state->free_id;
} 

static pid_t get_current_tgid(void) {
    return task_pid_nr(current);
}

static void init_system_mutex_state(system_mutex_state_t *sysmstate)
{
    spin_lock_init(&sysmstate->wlock);
    INIT_HLIST_HEAD(&sysmstate->tgstates);
}

static void deinit_system_mutex_state(system_mutex_state_t *sysmstate)
{
    // This is called on module release. So no opened file descriptors
    // exist. Thus we have nothing to cleanup here
}

static tgroup_state_t* find_current_tgroupstate(void) {
    tgroup_state_t *item = NULL;
    pid_t value_to_find = get_current_tgid();

    rcu_read_lock();
    hlist_for_each_entry_rcu(item, &mutex_dev->sysmstate.tgstates, tgstate_node) {
        if (item->tgroup_id == value_to_find) {
            break;
        }
    }
    rcu_read_unlock();

    return item;
}

static int mutex_dev_open(struct inode *inode, struct file *filp)
{
    if (find_current_tgroupstate() != NULL) {
        return -EINVAL;
    }

    tgroup_state_t *new_group_state = 
        kmalloc(sizeof(*new_group_state), GFP_KERNEL);
    if (new_group_state == NULL) {
        return -ENOMEM;
    }

    new_group_state->tgroup_id = get_current_tgid();
    spin_lock_init(&new_group_state->wlock);
    INIT_HLIST_HEAD(&new_group_state->mutexes);
    INIT_HLIST_NODE(&new_group_state->tgstate_node);
    new_group_state->free_id = 0;

    spin_lock(&mutex_dev->sysmstate.wlock);
    hlist_add_head_rcu(&new_group_state->tgstate_node, 
            &mutex_dev->sysmstate.tgstates);
    spin_unlock(&mutex_dev->sysmstate.wlock);

    pr_notice(LOG_TAG " opened successfully\n");
    return 0;
}

static int mutex_dev_release(struct inode *inode, struct file *filp)
{
    rcu_read_lock();
    tgroup_state_t *item = find_current_tgroupstate();
    hlist_del_rcu(&item->tgstate_node);
    rcu_read_unlock();

    synchronize_rcu();
    kfree(item);

    pr_notice(LOG_TAG " closed\n");
    return 0;
}

static long mutex_ioctl_create(mutex_ioctl_lock_create_arg_t __user *uarg) {
    tgroup_state_t *tgstate = find_current_tgroupstate();

    mutex_state_t *mtstate = kmalloc(sizeof(*mtstate), GFP_KERNEL);
    if (mtstate == NULL) {
        return -ENOMEM;
    }
    mtstate->mutex_splock = (shared_spinlock_t __user *)uarg->mutex_splock_vaddr;
    init_waitqueue_head(&mtstate->waiters);
    INIT_HLIST_NODE(&mtstate->mutex_node);

    spin_lock(&tgstate->wlock);
    uarg->id = get_new_id(tgstate);
    mtstate->id = uarg->id;
    hlist_add_head_rcu(&mtstate->mutex_node, &tgstate->mutexes);
    spin_unlock(&tgstate->wlock);

    return 0;
}

static mutex_state_t* get_mutex_by_id(mutex_id_t id) {
    tgroup_state_t *tgstate = find_current_tgroupstate();
    mutex_state_t *item;

    rcu_read_lock();
    hlist_for_each_entry_rcu(item, &tgstate->mutexes, mutex_node) {
        if (item->id == id) {
            break;
        }
    }
    rcu_read_unlock();

    return item;
}

static long mutex_ioctl_delete(mutex_ioctl_lock_delete_arg_t __user *uarg) {
    rcu_read_lock();
    mutex_state_t *item = get_mutex_by_id(uarg->id);
    hlist_del_rcu(&item->mutex_node);
    rcu_read_unlock();

    synchronize_rcu();
    kfree(item);

    return 0;
}

/*
 * Return 1 if thread was put to sleep,
 *        0 otherwise
 */
static long mutex_ioctl_thread_putwait(mutex_ioctl_thread_putwait_arg_t __user *arg) {
    long ret = 1;

    rcu_read_lock();
    mutex_state_t *mutex = get_mutex_by_id(arg->id);

    if (!wait_event_interruptible_exclusive(mutex->waiters, 
                !shared_spin_islocked(mutex->mutex_splock))) {
        ret = 0;
    }

    rcu_read_unlock();
    return ret;
}

/*
 * Assume that some thread wakes up. Maybe it is not correct.
 */
static long mutex_ioctl_thread_wakeup(mutex_ioctl_thread_wakeup_arg_t __user *arg) {
    rcu_read_lock();
    mutex_state_t *mutex = get_mutex_by_id(arg->id);
    wake_up(&mutex->waiters);
    rcu_read_unlock();

    return 1;
}


static long mutex_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    switch (cmd) {
        case MUTEX_IOCTL_LOCK_CREATE:
            return mutex_ioctl_create((mutex_ioctl_lock_create_arg_t __user *)arg);
        case MUTEX_IOCTL_LOCK_DELETE:
            return mutex_ioctl_delete((mutex_ioctl_lock_delete_arg_t __user *)arg);
        case MUTEX_IOCTL_THREAD_PUTWAIT:
            return mutex_ioctl_thread_putwait((mutex_ioctl_thread_putwait_arg_t __user *)arg);
        case MUTEX_IOCTL_THREAD_WAKEUP:
            return mutex_ioctl_thread_wakeup((mutex_ioctl_thread_wakeup_arg_t __user *)arg);
        default:
            return -ENOTTY;
    }
    return 0;
}

static struct file_operations mutex_dev_fops = {
    .owner = THIS_MODULE,
    .open = mutex_dev_open,
    .release = mutex_dev_release,
    .unlocked_ioctl = mutex_dev_ioctl
};

static int __init mutex_module_init(void)
{
    int ret = 0;
    mutex_dev = (mutex_dev_t*)
        kzalloc(sizeof(*mutex_dev), GFP_KERNEL);
    if (!mutex_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    mutex_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    mutex_dev->mdev.name = "mutex";
    mutex_dev->mdev.fops = &mutex_dev_fops;
    mutex_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;
    init_system_mutex_state(&mutex_dev->sysmstate);

    if ((ret = misc_register(&mutex_dev->mdev)))
        goto error_misc_reg;

    pr_notice(LOG_TAG "Mutex dev with MINOR %u"
        " has started successfully\n", mutex_dev->mdev.minor);
    return 0;

error_misc_reg:
    kfree(mutex_dev);
    mutex_dev = NULL;
error_alloc:
    return ret;
}

static void __exit mutex_module_exit(void)
{
    pr_notice(LOG_TAG "Removing mutex device %s\n", mutex_dev->mdev.name);
    misc_deregister(&mutex_dev->mdev);
    deinit_system_mutex_state(&mutex_dev->sysmstate);
    kfree(mutex_dev);
    mutex_dev = NULL;
}

module_init(mutex_module_init);
module_exit(mutex_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU user space mutex kernel side support module");
MODULE_AUTHOR("Kernel hacker!");
