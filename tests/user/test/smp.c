

#include "smp.h"
#include "apic.h"
#include "printf.h"

#define IPI_VECTOR 0x20

static int apic_read(int reg)
{
    unsigned short port = APIC_BASE + reg;
    unsigned v;

    asm volatile ("in %1, %0" : "=a"(v) : "d"(port));
    return v;
}

static void apic_write(int reg, unsigned v)
{
    unsigned short port = APIC_BASE + reg;

    asm volatile ("out %0, %1" : : "a"(v), "d"(port));
}

static int apic_get_cpu_count()
{
    return apic_read(APIC_REG_NCPU);
}

static int apic_get_id()
{
    return apic_read(APIC_REG_ID);
}

static void apic_set_ipi_vector(int vector)
{
    apic_write(APIC_REG_IPI_VECTOR, vector);
}

static void apic_send_ipi(int cpu)
{
    apic_write(APIC_REG_SEND_IPI, cpu);
}

static struct spinlock ipi_lock;
static void (*ipi_function)(void *data);
static void *ipi_data;
static volatile int ipi_done;

static __attribute__((used)) void ipi()
{
    ipi_function(ipi_data);
    ipi_done = 1;
}

asm (
     "ipi_entry: \n"
     "   call ipi \n"
#ifndef __x86_64__
     "   iret"
#else
     "   iretq"
#endif
     );


static void set_ipi_descriptor(void (*ipi_entry)(void))
{
    unsigned short *desc = (void *)(IPI_VECTOR * sizeof(long) * 2);
    unsigned short cs;
    unsigned long ipi = (unsigned long)ipi_entry;

    asm ("mov %%cs, %0" : "=r"(cs));
    desc[0] = ipi;
    desc[1] = cs;
    desc[2] = 0x8e00;
    desc[3] = ipi >> 16;
#ifdef __x86_64__
    desc[4] = ipi >> 32;
    desc[5] = ipi >> 48;
    desc[6] = 0;
    desc[7] = 0;
#endif
}

void spin_lock(struct spinlock *lock)
{
    int v = 1;

    do {
	asm volatile ("xchg %1, %0" : "+m"(lock->v), "+r"(v));
    } while (v);
    asm volatile ("" : : : "memory");
}

void spin_unlock(struct spinlock *lock)
{
    asm volatile ("" : : : "memory");
    lock->v = 0;
}

int cpu_count(void)
{
    return apic_get_cpu_count();
}

int smp_id(void)
{
    return apic_get_id();
}

void on_cpu(int cpu, void (*function)(void *data), void *data)
{
    spin_lock(&ipi_lock);
    if (cpu == apic_get_id())
	function(data);
    else {
	ipi_function = function;
	ipi_data = data;
	apic_send_ipi(cpu);
	while (!ipi_done)
	    ;
	ipi_done = 0;
    }
    spin_unlock(&ipi_lock);
}

static void (*smp_main_func)(void);
static volatile int smp_main_running;

asm ("smp_init_entry: \n"
     "incl smp_main_running \n"
     "sti \n"
     "call *smp_main_func");

void smp_init(void (*smp_main)(void))
{
    int i;
    void smp_init_entry(void);
    void ipi_entry(void);

    apic_set_ipi_vector(IPI_VECTOR);
    set_ipi_descriptor(smp_init_entry);
    smp_main_func = smp_main;
    for (i = 1; i < cpu_count(); ++i) {
	apic_send_ipi(i);
	while (smp_main_running < i)
	    ;
    }
    set_ipi_descriptor(ipi_entry);
}
