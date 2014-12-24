/*
 * Kernel-based Virtual Machine test driver
 *
 * This test driver provides a simple way of testing kvm, without a full
 * device model.
 *
 * Copyright (C) 2006 Qumranet
 *
 * Authors:
 *
 *  Avi Kivity <avi@qumranet.com>
 *  Yaniv Kamay <yaniv@qumranet.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 */

#include "kvmctl.h"
#include "test/apic.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
//#include <linux/unistd.h>


/*static int gettid(void)
{
    return syscall(__NR_gettid);
}

static int tkill(int pid, int sig)
{
    return syscall(__NR_tkill, pid, sig);
}*/

kvm_context_t kvm;

#define MAX_VCPUS 4

#define IPI_SIGNAL (SIGRTMIN + 4)

static int ncpus = 1;
static sem_t init_sem;
static __thread int vcpu;
static int apic_ipi_vector = 0xff;
static sigset_t kernel_sigmask;
static sigset_t ipi_sigmask;

struct vcpu_info {
    pid_t tid;
    sem_t sipi_sem;
};

struct vcpu_info *vcpus;

static uint32_t apic_sipi_addr;

static int apic_range(unsigned addr)
{
    return (addr >= APIC_BASE) && (addr < APIC_BASE + APIC_SIZE);
}

static void apic_send_sipi(int vcpu)
{
    sem_post(&vcpus[vcpu].sipi_sem);
}

static void apic_send_ipi(int vcpu)
{
    struct vcpu_info *v;

    if (vcpu < 0 || vcpu >= ncpus)
	return;
    v = &vcpus[vcpu];
    //tkill(v->tid, IPI_SIGNAL);
}

static int apic_io(unsigned addr, int is_write, uint32_t *value)
{
    if (!apic_range(addr))
	return 0;

    if (!is_write)
	*value = -1u;

    switch (addr - APIC_BASE) {
    case APIC_REG_NCPU:
	if (!is_write)
	    *value = ncpus;
	break;
    case APIC_REG_ID:
	if (!is_write)
	    *value = vcpu;
	break;
    case APIC_REG_SIPI_ADDR:
	if (!is_write)
	    *value = apic_sipi_addr;
	else
	    apic_sipi_addr = *value;
	break;
    case APIC_REG_SEND_SIPI:
	if (is_write)
	    apic_send_sipi(*value);
	break;
    case APIC_REG_IPI_VECTOR:
	if (!is_write)
	    *value = apic_ipi_vector;
	else
	    apic_ipi_vector = *value;
	break;
    case APIC_REG_SEND_IPI:
	if (is_write)
	    apic_send_ipi(*value);
	break;
    }
    return 1;
}

static int test_inb(void *opaque, uint16_t addr, uint8_t *value)
{
    printf("inb 0x%x\n", addr);
    return 0;
}

static int test_inw(void *opaque, uint16_t addr, uint16_t *value)
{
    printf("inw 0x%x\n", addr);
    return 0;
}

static int test_inl(void *opaque, uint16_t addr, uint32_t *value)
{
    if (apic_io(addr, 0, value))
	return 0;
    printf("inl 0x%x\n", addr);
    return 0;
}

static int test_outb(void *opaque, uint16_t addr, uint8_t value)
{
    static int newline = 1;

    switch (addr) {
    case 0xff: // irq injector
	printf("injecting interrupt 0x%x\n", value);
	kvm_inject_irq(kvm, 0, value);
	break;
    case 0xf1: // serial
	if (newline)
	    fputs("GUEST: ", stdout);
	putchar(value);
	newline = value == '\n';
	break;
    default:
	printf("outb $0x%x, 0x%x\n", value, addr);
    }
    return 0;
}

static int test_outw(void *opaque, uint16_t addr, uint16_t value)
{
    printf("outw $0x%x, 0x%x\n", value, addr);
    return 0;
}

static int test_outl(void *opaque, uint16_t addr, uint32_t value)
{
    if (apic_io(addr, 1, &value))
	return 0;
    printf("outl $0x%x, 0x%x\n", value, addr);
    return 0;
}

static int test_debug(void *opaque, int vcpu)
{
    printf("test_debug\n");
    return 0;
}

static int test_halt(void *opaque, int vcpu)
{
    int n;

    sigwait(&ipi_sigmask, &n);
    kvm_inject_irq(kvm, vcpu, apic_ipi_vector);
    return 0;
}

static int test_io_window(void *opaque)
{
    return 0;
}

static int test_try_push_interrupts(void *opaque)
{
    return 0;
}

static void test_post_kvm_run(void *opaque, int vcpu)
{
}

static int test_pre_kvm_run(void *opaque, int vcpu)
{
    return 0;
}

static struct kvm_callbacks test_callbacks = {
    .inb         = test_inb,
    .inw         = test_inw,
    .inl         = test_inl,
    .outb        = test_outb,
    .outw        = test_outw,
    .outl        = test_outl,
    .debug       = test_debug,
    .halt        = test_halt,
    .io_window = test_io_window,
    .try_push_interrupts = test_try_push_interrupts,
    .post_kvm_run = test_post_kvm_run,
    .pre_kvm_run = test_pre_kvm_run,
};
 

static void load_file(void *mem, const char *fname)
{
    int r;
    int fd;

    fd = open(fname, O_RDONLY);
    if (fd == -1) {
	perror("open");
	exit(1);
    }
    while ((r = read(fd, mem, 4096)) != -1 && r != 0)
	mem += r;
    if (r == -1) {
	perror("read");
	exit(1);
    }
}

static void enter_32(kvm_context_t kvm)
{
    struct kvm_regs regs = {
	.rsp = 0x80000,  /* 512KB */
	.rip = 0x100000, /* 1MB */
	.rflags = 2,
    };
    struct kvm_sregs sregs = {
	.cs = { 0, -1u,  8, 11, 1, 0, 1, 1, 0, 1, 0, 0 },
	.ds = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
	.es = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
	.fs = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
	.gs = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
	.ss = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },

	.tr = { 0, 10000, 24, 11, 1, 0, 0, 0, 0, 0, 0, 0 },
	.ldt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
	.gdt = { 0, 0 },
	.idt = { 0, 0 },
	.cr0 = 0x37,
	.cr3 = 0,
	.cr4 = 0,
	.efer = 0,
	.apic_base = 0,
	.interrupt_bitmap = { 0 },
    };

    kvm_set_regs(kvm, 0, &regs);
    kvm_set_sregs(kvm, 0, &sregs);
}

static void init_vcpu(int n)
{
    /*sigemptyset(&ipi_sigmask);
    sigaddset(&ipi_sigmask, IPI_SIGNAL);
    sigprocmask(SIG_UNBLOCK, &ipi_sigmask, NULL);
    sigprocmask(SIG_BLOCK, &ipi_sigmask, &kernel_sigmask);*/
    vcpus[n].tid = getpid();
    vcpu = n;
    //kvm_set_signal_mask(kvm, n, &kernel_sigmask);
    sem_post(&init_sem);
}

static void *do_create_vcpu(void *_n)
{
    int n = (long)_n;
    struct kvm_regs regs;

    kvm_create_vcpu(kvm, n);
    init_vcpu(n);
    sem_wait(&vcpus[n].sipi_sem);
    kvm_get_regs(kvm, n, &regs);
    regs.rip = apic_sipi_addr;
    kvm_set_regs(kvm, n, &regs);
    kvm_run(kvm, n);
    return NULL;
}

static void start_vcpu(int n)
{
    pthread_t thread;

    sem_init(&vcpus[n].sipi_sem, 0, 0);
    pthread_create(&thread, NULL, do_create_vcpu, (void *)(long)n);
}

const char *progname;

static void usage()
{
    fprintf(stderr, "usage: %s [--smp n] [bootstrap] flatfile\n", progname);
    exit(1);
}

static int isarg(const char *arg, const char *longform, const char *shortform)
{
    if (longform && strcmp(arg, longform) == 0)
	return 1;
    if (shortform && strcmp(arg, shortform) == 0)
	return 1;
    return 0;
}

static void sig_ignore(int sig)
{
    write(1, "boo\n", 4);
}

int main(int ac, char **av)
{
	void *vm_mem;
	int i;

	progname = av[0];
	while (ac > 1 && av[1][0] =='-') {
	    if (isarg(av[1], "--smp", "-s")) {
		if (ac <= 2)
		    usage();
		ncpus = atoi(av[2]);
		if (ncpus < 1)
		    usage();
		++av, --ac;
	    } else
		usage();
	    ++av, --ac;
	}

	//signal(IPI_SIGNAL, sig_ignore);

	vcpus = calloc(ncpus, sizeof *vcpus);
	if (!vcpus) {
	    fprintf(stderr, "calloc failed\n");
	    return 1;
	}

	kvm = kvm_init(&test_callbacks, 0);
	if (!kvm) {
	    fprintf(stderr, "kvm_init failed\n");
	    return 1;
	}
  printf("kvm_init done\n");
	if (kvm_create(kvm, 128 * 1024 * 1024, &vm_mem) < 0) {
	    kvm_finalize(kvm);
	    fprintf(stderr, "kvm_create failed\n");
	    return 1;
	}
  printf("kvm_create done %p\n", vm_mem);

	if (ac > 1) {
	    if (strcmp(av[1], "-32") != 0)
		load_file(vm_mem + 0xf0000, av[1]);
	    else
		enter_32(kvm);
	}
	if (ac > 2)
	    load_file(vm_mem + 0x100000, av[2]);

  printf("load file done\n");
	sem_init(&init_sem, 0, 0);
	init_vcpu(0);
  printf("init vcpu done\n");
	for (i = 1; i < ncpus; ++i)
	    start_vcpu(i);
  printf("start vcpu done\n");
	for (i = 0; i < ncpus; ++i)
	    sem_wait(&init_sem);

  printf("kvm_run\n");
	kvm_run(kvm, 0);
  printf("kvm_run done\n");

	return 0;
}
