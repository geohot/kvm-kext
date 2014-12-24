
#include "smp.h"
#include "printf.h"

static void ipi_test(void *data)
{
    int n = (long)data;

    printf("ipi called, cpu %d\n", n);
    if (n != smp_id())
	printf("but wrong cpu %d\n", smp_id());
}

static void smp_main(void)
{
    printf("smp main %d\n", smp_id());
    while (1)
	asm volatile ("hlt" : : : "memory");
}

int main()
{
    int ncpus;
    int i;

    smp_init(smp_main);
    ncpus = cpu_count();
    printf("found %d cpus\n", ncpus);
    for (i = 0; i < ncpus; ++i)
	on_cpu(i, ipi_test, (void *)(long)i);
    return 0;
}
