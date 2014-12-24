/*
 * This binary provides access to the guest's balloon driver
 * module.
 *
 * Copyright (C) 2007 Qumranet
 *
 * Author:
 *
 *  Dor Laor <dor.laor@qumranet.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#define __user
#include <linux/kvm.h>

#define PAGE_SIZE 4096ul


static int balloon_op(int *fd, int bytes)
{
	struct kvm_balloon_op bop;
        int r;

	bop.npages = bytes/PAGE_SIZE;
	r = ioctl(*fd, KVM_BALLOON_OP, &bop);
	if (r == -1)
		return -errno;
	printf("Ballon handled %d pages successfully\n", bop.npages);

	return 0;
}

static int balloon_init(int *fd)
{
	*fd = open("/dev/kvm_balloon", O_RDWR);
	if (*fd == -1) {
		perror("open /dev/kvm_balloon");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int fd;
	int r;
	int bytes;

	if (argc != 3) {
		perror("Please provide op=[i|d], bytes\n");
		return 1;
	}
	bytes = atoi(argv[2]);

	switch (*argv[1]) {
	case 'i':
		break;
	case 'd':
		bytes = -bytes;
		break;
	default:
		perror("Wrong op param\n");
		return 1;
	}

	if (balloon_init(&fd)) {
		perror("balloon_init failed\n");
		return 1;
	}

	if ((r = balloon_op(&fd, bytes))) {
		perror("balloon_op failed\n");
		goto out;
	}

out:
	close(fd);
        
	return r;
}

