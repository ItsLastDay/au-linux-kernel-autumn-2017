#include <fcntl.h>
#include <unistd.h>

#include <mutex.h>

static int dev_fd;

mutex_err_t mutex_init(mutex_t *m)
{
    shared_spinlock_init(&m->spinlock);
    m->num_waiters = 0;

    mutex_ioctl_lock_create_arg_t arg;
    arg.mutex_splock_vaddr = &m->spinlock;
    mutex_err_t ret = ioctl(dev_fd, MUTEX_IOCTL_LOCK_CREATE, &arg) 
        ? MUTEX_INTERNAL_ERR : MUTEX_OK;

    m->internal_id = arg.id;

    return ret;
}

mutex_err_t mutex_deinit(mutex_t *m)
{
    mutex_ioctl_lock_delete_arg_t arg;
    arg.id = m->internal_id;
    return ioctl(dev_fd, MUTEX_IOCTL_LOCK_DELETE, &arg) 
        ? MUTEX_INTERNAL_ERR : MUTEX_OK;
}

mutex_err_t mutex_lock(mutex_t *m)
{
    if (!shared_spin_trylock(&m->spinlock)) {
        mutex_ioctl_thread_putwait_arg_t arg;
        arg.id = m->internal_id;
        long has_added_waiter = ioctl(dev_fd, MUTEX_IOCTL_THREAD_PUTWAIT, &arg);
        if (has_added_waiter < 0) {
            return MUTEX_INTERNAL_ERR;
        } 
        m->num_waiters += has_added_waiter;
    }

    return MUTEX_OK;
}

mutex_err_t mutex_unlock(mutex_t *m)
{
    shared_spin_unlock(&m->spinlock); 
    if (m->num_waiters) {
        mutex_ioctl_thread_wakeup_arg_t arg;
        arg.id = m->internal_id;
        long has_wokenup_waiter = ioctl(dev_fd, MUTEX_IOCTL_THREAD_WAKEUP, &arg);
        if (has_wokenup_waiter < 0) {
            return MUTEX_INTERNAL_ERR;
        }

        m->num_waiters -= has_wokenup_waiter; 
    }

    return MUTEX_OK;
}

mutex_err_t mutex_lib_init()
{
    long ret = open("/dev/mutex", O_WRONLY);
    if (ret < 0) {
        return MUTEX_INTERNAL_ERR;
    }

    dev_fd = ret;
    return MUTEX_OK;
}

mutex_err_t mutex_lib_deinit()
{
    return close(dev_fd) ? MUTEX_INTERNAL_ERR : MUTEX_OK;
}
