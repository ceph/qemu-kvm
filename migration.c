#include "migration.h"

#define TO_BE_IMPLEMENTED term_printf("%s: TO_BE_IMPLEMENTED\n", __FUNCTION__)

#ifndef CONFIG_USER_ONLY
void do_migration_listen(char *arg1, char *arg2){ TO_BE_IMPLEMENTED; }
void do_migration_connect(char *arg1, char *arg2){ TO_BE_IMPLEMENTED; }
void do_migration_getfd(int fd) { TO_BE_IMPLEMENTED; }
void do_migration_start(char *deadoralive) { TO_BE_IMPLEMENTED; }
void do_migration_cancel(void){ TO_BE_IMPLEMENTED; }
void do_migration_status(void){ TO_BE_IMPLEMENTED; }
void do_migration_set(char *fmt, ...){ TO_BE_IMPLEMENTED; }
void do_migration_show(void){ TO_BE_IMPLEMENTED; }

#else /* CONFIG_USER_ONLY is defined */

void do_migration_listen(char *arg1, char *arg2) { TO_BE_IMPLEMENTED; }
void do_migration_connect(char *arg1, char *arg2) { TO_BE_IMPLEMENTED; }
void do_migration_getfd(int fd) { TO_BE_IMPLEMENTED; }
void do_migration_start(char *deadoralive) { TO_BE_IMPLEMENTED; }
void do_migration_cancel(void){ TO_BE_IMPLEMENTED; }
void do_migration_status(void){ TO_BE_IMPLEMENTED; }
void do_migration_set(char *fmt, ...){ TO_BE_IMPLEMENTED; }
void do_migration_show(void){ TO_BE_IMPLEMENTED; }

#endif /* of CONFIG_USER_ONLY is defined */
