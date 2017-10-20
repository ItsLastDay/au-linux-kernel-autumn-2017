#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "vsd_ioctl.h"
/*
 * TODO parse command line arguments and call proper
 * VSD_IOCTL_* using C function 'ioctl' (see man ioctl).
 */
void print_usage_and_exit() {
    printf("USAGE:\n\tvsd_userspace size_get -- prints current buffer size to stdout"
                  "\n\tvsd_userspace size_set SIZE_IN_BYTES -- attempts to change buffer size to SIZE_IN_BYTES\n");
    exit(EXIT_FAILURE);
}


int open_device() {
    int fd = open("/dev/vsd", O_RDWR);
    if (fd == -1) {
        printf("Error opening device\n");
        exit(EXIT_FAILURE);
    }

    return fd;
}

void fail_ioctl() {
    printf("ioctl failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

void set_size(int new_sz) {
    if (new_sz < 0) {
        printf("Only positive size is allowed, got %d\n", new_sz);
        exit(EXIT_FAILURE);
    }


    vsd_ioctl_set_size_arg_t arg;
    arg.size = new_sz;

    if (ioctl(open_device(), VSD_IOCTL_SET_SIZE, &arg)) {
        fail_ioctl();
    }
}

void get_size() {
    vsd_ioctl_get_size_arg_t arg;

    if (ioctl(open_device(), VSD_IOCTL_GET_SIZE, &arg)) {
        fail_ioctl();
    }

    printf("Current buffer size is %zd\n", arg.size);
}

int main(int argc, char **argv) {
    if (argc == 1)
        print_usage_and_exit();

    if (!strcmp(argv[1], "size_get")) {
        if (argc != 2) 
            print_usage_and_exit();

        get_size();
    } else if (!strcmp(argv[1], "size_set")) {
        if (argc != 3)
            print_usage_and_exit();

        set_size(atoi(argv[2]));
    } else {
        print_usage_and_exit();
    }

    return EXIT_SUCCESS;
}
