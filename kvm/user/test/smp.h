#ifndef __SMP_H
#define __SMP_H

struct spinlock {
    int v;
};

int cpu_count(void);
void on_cpu(int cpu, void (*function)(void *data), void *data);
void spin_lock(struct spinlock *lock);
void spin_unlock(struct spinlock *lock);

#endif
