#ifndef __SMP_H
#define __SMP_H

struct spinlock {
    int v;
};

void smp_init(void (*smp_main)(void));

int cpu_count(void);
int smp_id(void);
void on_cpu(int cpu, void (*function)(void *data), void *data);
void spin_lock(struct spinlock *lock);
void spin_unlock(struct spinlock *lock);

#endif
