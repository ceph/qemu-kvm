#ifndef MIGRATION_H
#define MIGRATION_H

void do_info_migration(void);
void do_migrate(int detach, const char *uri);
void do_migrate_cancel(void);
void do_migrate_set_speed(const char *value);
int migrate_incoming(const char *device);

#endif
