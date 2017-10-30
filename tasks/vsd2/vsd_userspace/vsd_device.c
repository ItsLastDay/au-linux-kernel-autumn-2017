#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "vsd_device.h"
#include "vsd_ioctl.h"

static int vsd_fd = -1;

int vsd_init()
{
    vsd_fd = open("/dev/vsd", O_RDWR);
    return vsd_fd == -1;
}

int vsd_deinit()
{
    return close(vsd_fd);
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t arg;
    if (ioctl(vsd_fd, VSD_IOCTL_GET_SIZE, &arg)) {
        return -1;
    }
    *out_size = arg.size;
    return 0;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t arg;
    arg.size = size;
    return ioctl(vsd_fd, VSD_IOCTL_SET_SIZE, &arg);
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
    if (lseek(vsd_fd, offset, SEEK_SET) == (off_t)-1) {
        return -1;
    }
    return read(vsd_fd, dst, size);
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
    if (lseek(vsd_fd, offset, SEEK_SET) == (off_t)-1) {
        return -1;
    }
    return write(vsd_fd, src, size);
}

void* vsd_mmap(size_t offset)
{
    size_t cur_vsd_size;
    if (vsd_get_size(&cur_vsd_size)) {
        return NULL;
    }
    if (offset > cur_vsd_size) {
        return NULL;
    }

    void* ret = mmap(NULL, cur_vsd_size - offset, 
            PROT_READ | PROT_WRITE, MAP_SHARED, vsd_fd, offset);
    return ret == (void *)-1 ? NULL : ret;
}

int vsd_munmap(void* addr, size_t offset)
{
    size_t cur_vsd_size;
    if (vsd_get_size(&cur_vsd_size)) {
        return -1;
    }
    return munmap(addr, cur_vsd_size - offset);
}
