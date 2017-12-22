#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

#define VSD_DEV_CMD_QUEUE_MAX_LEN 10

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;
} vsd_dev_t;
static vsd_dev_t *vsd_dev;


static struct task_struct *kthread;

static DECLARE_WAIT_QUEUE_HEAD(waiters_for_nonfullness);
static DECLARE_WAIT_QUEUE_HEAD(kthread_waitqueue);
static spinlock_t queue_spinlock;

typedef struct work_result {
    ssize_t return_code;
    bool has_result;
    wait_queue_head_t result_waiter;
} work_result;

typedef struct work_element {
    vsd_hw_regs_t regs;
    work_result* result;
    bool need_wakeup;
} work_element;

static volatile bool work_done, kthread_should_sleep;
static uint8_t queue_size = 0;
static uint8_t q_read = 0, q_write = 0;
static work_element *cmd_queue[VSD_DEV_CMD_QUEUE_MAX_LEN];

static int cmd_queue_size(void) 
{
    return queue_size;
}

static bool cmd_queue_full(void) 
{
    return cmd_queue_size() == VSD_DEV_CMD_QUEUE_MAX_LEN;
}

static bool cmd_queue_empty(void) 
{
    return cmd_queue_size() == 0;
}

static void cmd_queue_push(work_element* work) 
{
    ++queue_size;
    cmd_queue[q_write] = work;
    wmb();
    q_write = (q_write + 1) % VSD_DEV_CMD_QUEUE_MAX_LEN;
    wmb();
    kthread_should_sleep = false;
    wmb();
    wake_up(&kthread_waitqueue);
}

static void cmd_queue_pop(void) 
{
    --queue_size;
    kfree(cmd_queue[q_read]);
    q_read = (q_read + 1) % VSD_DEV_CMD_QUEUE_MAX_LEN;
    wmb();
    wake_up(&waiters_for_nonfullness);
}

static void load_top_work(void) 
{
    rmb();
    work_element *work = cmd_queue[q_read];
    work_done = false;

    vsd_dev->hwregs->dma_paddr = work->regs.dma_paddr;
    vsd_dev->hwregs->dma_size = work->regs.dma_size;
    vsd_dev->hwregs->dev_offset = work->regs.dev_offset;
    vsd_dev->hwregs->tasklet_vaddr = work->regs.tasklet_vaddr;
    wmb();
    vsd_dev->hwregs->cmd = work->regs.cmd;
}

#define LOCAL_DEBUG 0
static void print_vsd_dev_hw_regs(vsd_dev_t *vsd_dev)
{
    if (!LOCAL_DEBUG)
        return;

    pr_notice(LOG_TAG "VSD dev hwregs: \n"
            "CMD: %x \n"
            "RESULT: %x \n"
            "TASKLET_VADDR: %llx \n"
            "dma_paddr: %llx \n"
            "dma_size:  %llx \n"
            "dev_offset: %llx \n"
            "dev_size: %llx \n",
            vsd_dev->hwregs->cmd,
            vsd_dev->hwregs->result,
            vsd_dev->hwregs->tasklet_vaddr,
            vsd_dev->hwregs->dma_paddr,
            vsd_dev->hwregs->dma_size,
            vsd_dev->hwregs->dev_offset,
            vsd_dev->hwregs->dev_size
    );
}

static int vsd_dev_open(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev opened\n");
    return 0;
}

static int vsd_dev_release(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev closed\n");
    return 0;
}

static void vsd_dev_dma_op_complete_tsk_func(unsigned long unused)
{
    (void)unused;
    work_done = true;
    wmb();
    wake_up(&kthread_waitqueue);
}

static work_element* create_work(uint8_t cmd, char* buf, 
        uint64_t size,
        uint64_t offset,
        bool can_sleep) 
{
    work_result* result = kmalloc(sizeof(*result), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!result)
        return NULL;

    work_element* work = kmalloc(sizeof(*work), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (work) {
        work->regs.cmd = cmd;
        work->regs.tasklet_vaddr = &vsd_dev->dma_op_complete_tsk;
        work->regs.dma_paddr = buf ? virt_to_phys(buf) : 0;
        work->regs.dma_size = size;
        work->regs.dev_offset = offset;

        work->need_wakeup = can_sleep;

        work->result = result;
        result->has_result = false;

        init_waitqueue_head(&result->result_waiter);
    } else {
        kfree(result);
    }

    return work;
}

static void push_work_locked(work_element *work) 
{
    bool placed_task = false;
    while (!placed_task) {
        spin_lock(&queue_spinlock);
        if (cmd_queue_full()) {
            spin_unlock(&queue_spinlock);
            wait_event_interruptible_exclusive(waiters_for_nonfullness, 
                    !cmd_queue_full());
        } else {
            placed_task = true;
            cmd_queue_push(work);
            spin_unlock(&queue_spinlock);
        }
    }
}

static bool trypush_work_locked(work_element *work) 
{
    spin_lock(&queue_spinlock);
    if (cmd_queue_full()) {
        spin_unlock(&queue_spinlock);
        return 0;
    }
    cmd_queue_push(work);
    spin_unlock(&queue_spinlock);
    return 1;
}

static void wait_work_completion(work_result* result) 
{
    rmb();
    while (!result->has_result) {
        wait_event_interruptible(result->result_waiter, result->has_result);
    }
}

static kthread_driver_queue_poll(void *data) 
{
    while (!kthread_should_stop()) {
        mb();

        spin_lock(&queue_spinlock);
        if (cmd_queue_empty()) {
            kthread_should_sleep = true;
            spin_unlock(&queue_spinlock);

            while (kthread_should_sleep) {
                wait_event_interruptible(kthread_waitqueue, !kthread_should_sleep);
            }
        } else {
            load_top_work();
            spin_unlock(&queue_spinlock);

            while (!work_done) {
                wait_event_interruptible(kthread_waitqueue, work_done);
            }

            spin_lock(&queue_spinlock);
            rmb();
            work_element* work = cmd_queue[q_read];
            work->result->return_code = vsd_dev->hwregs->result;
            wmb();
            work->result->has_result = true;
            wmb();

            if (work->need_wakeup) {
                wake_up(&work->result->result_waiter);
            } else {
                kfree(phys_to_virt(work->regs.dma_paddr));
                kfree(work->result);
            }

            cmd_queue_pop();

            spin_unlock(&queue_spinlock);
        }
    }
}

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    if (filp->f_flags & O_NONBLOCK)
        return -EAGAIN;

    char* buf = kmalloc(read_size, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    work_element* work = create_work(VSD_CMD_READ, buf, read_size, *fpos, true);
    if (!work) {
        kfree(buf);
        return -ENOMEM;
    }

    push_work_locked(work);
    work_result* result = work->result;
    wait_work_completion(result);

    ssize_t ret = result->return_code;
    if (ret >= 0) {
        if (copy_to_user(read_user_buf, buf, ret)) {
            ret = -EFAULT;
        } else {
            *fpos += ret;
        }
    }

    kfree(buf);
    kfree(result);

    return ret;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    bool can_sleep = !(filp->f_flags & O_NONBLOCK);

    char* buf = kmalloc(write_size, can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!buf)
        return -ENOMEM;

    work_element* work = create_work(VSD_CMD_WRITE, buf, write_size, *fpos, can_sleep);
    if (!work) {
        kfree(buf);
        return -ENOMEM;
    }

    pagefault_disable();
    if (copy_from_user(buf, write_user_buf, write_size)) {
        kfree(buf);
        kfree(work->result);
        kfree(work);
        pagefault_enable();
        return -EFAULT;
    }
    pagefault_enable();

    if (can_sleep) {
        push_work_locked(work);
    } else {
        if (!trypush_work_locked(work)) {
            kfree(buf);
            kfree(work->result);
            kfree(work);
            return -EAGAIN;
        }
    }

    if (!can_sleep) {
        *fpos += write_size;
        return write_size;
    } else {
        work_result* result = work->result;
        wait_work_completion(result);

        ssize_t ret = result->return_code;
        if (ret >= 0) {
            *fpos += ret;
        }

        kfree(buf);
        kfree(result);
        return ret;
    }

}

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos = 0;

    switch(whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = vsd_dev->hwregs->dev_size - off;
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    if (newpos >= vsd_dev->hwregs->dev_size)
        newpos = vsd_dev->hwregs->dev_size;

    filp->f_pos = newpos;
    return newpos;
}

static unsigned int vsd_dev_poll(struct file *filp, poll_table *wait) 
{
    poll_wait(filp, &waiters_for_nonfullness, wait);
    poll_wait(filp, &kthread_waitqueue, wait);

    unsigned int mask = 0;

    spin_lock(&queue_spinlock);
    // POLLIN and the like are not set, because I do not allow non-blocking read.
    
    if (!cmd_queue_full()) 
        mask |= POLLOUT | POLLWRNORM;

    spin_unlock(&queue_spinlock);

    return mask;
}

static long vsd_ioctl_get_size(vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;
    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    arg.size = vsd_dev->hwregs->dev_size;

    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    vsd_ioctl_set_size_arg_t arg;

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    work_element* work = create_work(VSD_CMD_SET_SIZE, NULL, 0, arg.size, true);
    push_work_locked(work);
    work_result* result = work->result;

    wait_work_completion(result);

    long ret = result->return_code;
    kfree(result);

    return ret;
}

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    switch(cmd) {
        case VSD_IOCTL_GET_SIZE:
            return vsd_ioctl_get_size((vsd_ioctl_get_size_arg_t __user*)arg);
            break;
        case VSD_IOCTL_SET_SIZE:
            return vsd_ioctl_set_size((vsd_ioctl_set_size_arg_t __user*)arg);
            break;
        default:
            return -ENOTTY;
    }
}

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .poll = vsd_dev_poll,
    .unlocked_ioctl = vsd_dev_ioctl
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct resource *vsd_control_regs_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    vsd_dev = (vsd_dev_t*)
        kzalloc(sizeof(*vsd_dev), GFP_KERNEL);
    if (!vsd_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }

    spin_lock_init(&queue_spinlock);
    init_waitqueue_head(&waiters_for_nonfullness);
    init_waitqueue_head(&kthread_waitqueue);
    work_done = false;
    kthread_should_sleep = false;
    kthread = kthread_create(kthread_driver_queue_poll, NULL, "vsd driver poll thread");
    if (IS_ERR_OR_NULL(kthread)) {
        goto error_misc_reg;
    }

    tasklet_init(&vsd_dev->dma_op_complete_tsk,
            vsd_dev_dma_op_complete_tsk_func, 0);
    vsd_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    vsd_dev->mdev.name = "vsd";
    vsd_dev->mdev.fops = &vsd_dev_fops;
    vsd_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;

    if ((ret = misc_register(&vsd_dev->mdev)))
        goto error_misc_reg;

    vsd_control_regs_res = platform_get_resource_byname(
            pdev, IORESOURCE_REG, "control_regs");
    if (!vsd_control_regs_res) {
        ret = -ENOMEM;
        goto error_get_res;
    }
    vsd_dev->hwregs = (volatile vsd_hw_regs_t*)
        phys_to_virt(vsd_control_regs_res->start);

    wake_up_process(kthread);
    print_vsd_dev_hw_regs(vsd_dev);
    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

error_get_res:
    misc_deregister(&vsd_dev->mdev);
error_misc_reg:
    kfree(vsd_dev);
    vsd_dev = NULL;
error_alloc:
    return ret;
}

static int vsd_driver_remove(struct platform_device *dev)
{
    // module can't be unloaded if its users has even single
    // opened fd
    pr_notice(LOG_TAG "removing device %s\n", dev->name);
    misc_deregister(&vsd_dev->mdev);
    kfree(vsd_dev);
    vsd_dev = NULL;
    return 0;
}

static struct platform_driver vsd_driver = {
    .probe = vsd_driver_probe,
    .remove = vsd_driver_remove,
    .driver = {
        .name = "au-vsd",
        .owner = THIS_MODULE,
    }
};

static int __init vsd_driver_init(void)
{
    return platform_driver_register(&vsd_driver);
}

static void __exit vsd_driver_exit(void)
{
    kthread_stop(kthread);
    // This indirectly calls vsd_driver_remove
    platform_driver_unregister(&vsd_driver);
}

module_init(vsd_driver_init);
module_exit(vsd_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device driver module");
MODULE_AUTHOR("Kernel hacker!");
