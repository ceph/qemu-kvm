#ifndef QEMU_MIGRATION_H
#define QEMU_MIGRATION_H

/* migration commands */
void do_migration_listen(char *arg1, char *arg2);
void do_migration_connect(char *arg1, char *arg2);
void do_migration_getfd(int fd);
void do_migration_start(char *deadoralive);
void do_migration_cancel(void);
void do_migration_status(void);
void do_migration_set_rate(int min, int max, int offline);
void do_migration_set_total_time(int seconds);
void do_migration_show(void);

#endif /* QEMU_MIGRATION_H */
