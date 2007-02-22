/*
 * QEMU migration support
 * 
 * Copyright (C) 2007 Anthony Liguori <anthony@codemonkey.ws>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "vl.h"
#include "qemu_socket.h"

#include <sys/wait.h>

#define MIN_FINALIZE_SIZE	(200 << 10)

typedef struct MigrationState
{
    int fd;
    int throttle_count;
    int bps;
    int updated_pages;
    int last_updated_pages;
    int iteration;
    int n_buffer;
    int throttled;
    int *has_error;
    char buffer[TARGET_PAGE_SIZE + 4];
    target_ulong addr;
    QEMUTimer *timer;
    void *opaque;
    int detach;
    int (*release)(void *opaque);
} MigrationState;

static uint32_t max_throttle = (32 << 20);
static MigrationState *current_migration;

/* QEMUFile migration implementation */

static void migrate_put_buffer(void *opaque, const uint8_t *buf, int64_t pos, int size)
{
    MigrationState *s = opaque;
    int offset = 0;

    if (*s->has_error)
	return;

    while (offset < size) {
	ssize_t len;

	len = write(s->fd, buf + offset, size - offset);
	if (len == -1) {
	    if (errno == EAGAIN || errno == EINTR)
		continue;
            term_printf("migration: write failed (%s)\n", strerror(errno));
	    *s->has_error = 10;
	    break;
	} else if (len == 0) {
            term_printf("migration: other side closed connection\n");
	    *s->has_error = 11;
	    break;
	}

	offset += len;
    }
}

static void migrate_close(void *opaque)
{
    MigrationState *s = opaque;

    if (s->release && s->release(s->opaque))
	*s->has_error = 12;

    qemu_free(s);
    current_migration = NULL;
}

/* Outgoing migration routines */

static void migrate_finish(MigrationState *s)
{
    QEMUFile *f;
    int ret = 0;
    int *has_error = s->has_error;

    fcntl(s->fd, F_SETFL, 0);

    if (! *has_error) {
        f = qemu_fopen(s, migrate_put_buffer, NULL, migrate_close);
        qemu_aio_flush();
        vm_stop(0);
        qemu_put_be32(f, 1);
        ret = qemu_live_savevm_state(f);
        qemu_fclose(f);
    }
    if (ret != 0 || *has_error) {
	term_printf("Migration failed! ret=%d error=%d\n", ret, *has_error);
	vm_start();
    }
    if (!s->detach)
	monitor_resume();
    qemu_free(has_error);
    cpu_physical_memory_set_dirty_tracking(0);
}

static int migrate_write_buffer(MigrationState *s)
{
    if (*s->has_error)
	return 0;

    if (s->n_buffer != sizeof(s->buffer)) {
	ssize_t len;
    again:
	len = write(s->fd, s->buffer + s->n_buffer, sizeof(s->buffer) - s->n_buffer);
	if (len == -1) {
	    if (errno == EINTR)
		goto again;
	    if (errno == EAGAIN)
		return 1;
	    *s->has_error = 13;
	    return 0;
	}
	if (len == 0) {
	    *s->has_error = 14;
	    return 0;
	}

	s->throttle_count += len;
	s->n_buffer += len;
	if (s->n_buffer != sizeof(s->buffer))
	    goto again;
    }

    if (s->throttle_count > max_throttle) {
	s->throttled = 1;
	qemu_set_fd_handler2(s->fd, NULL, NULL, NULL, NULL);
	return 1;
    }

    return 0;
}

static int migrate_check_convergence(MigrationState *s)
{
    target_ulong addr;
    int dirty_count = 0;

    for (addr = 0; addr < phys_ram_size; addr += TARGET_PAGE_SIZE) {
#ifdef USE_KVM
        if (kvm_allowed && (addr>=0xa0000) && (addr<0xc0000)) /* do not access video-addresses */
            continue;
#endif
	if (cpu_physical_memory_get_dirty(addr, MIGRATION_DIRTY_FLAG))
	    dirty_count++;
    }

    return ((dirty_count * TARGET_PAGE_SIZE) < MIN_FINALIZE_SIZE);
}

static void migrate_write(void *opaque)
{
    MigrationState *s = opaque;

    if (migrate_write_buffer(s))
	return;

    if (migrate_check_convergence(s) || *s->has_error) {
	qemu_del_timer(s->timer);
	qemu_free_timer(s->timer);
	qemu_set_fd_handler2(s->fd, NULL, NULL, NULL, NULL);
	migrate_finish(s);
	return;
    }	

    while (s->addr < phys_ram_size) {
#ifdef USE_KVM
        if (kvm_allowed && (s->addr>=0xa0000) && (s->addr<0xc0000)) /* do not access video-addresses */
            s->addr = 0xc0000;
#endif

	if (cpu_physical_memory_get_dirty(s->addr, MIGRATION_DIRTY_FLAG)) {
	    uint32_t value = cpu_to_be32(s->addr);

	    memcpy(s->buffer, &value, 4);
	    memcpy(s->buffer + 4, phys_ram_base + s->addr, TARGET_PAGE_SIZE);
	    s->n_buffer = 0;

	    cpu_physical_memory_reset_dirty(s->addr, s->addr + TARGET_PAGE_SIZE, MIGRATION_DIRTY_FLAG);

	    s->addr += TARGET_PAGE_SIZE;

	    s->updated_pages++;

	    if (migrate_write_buffer(s))
		return;
	} else
	    s->addr += TARGET_PAGE_SIZE;
    }

    s->last_updated_pages = s->updated_pages;
    s->updated_pages = 0;
    s->addr = 0;
    s->iteration++;
}

static void migrate_reset_throttle(void *opaque)
{
    MigrationState *s = opaque;

    s->bps = s->throttle_count;

    if (s->throttled) {
	s->throttled = 0;
	qemu_set_fd_handler2(s->fd, NULL, NULL, migrate_write, s);
    }
    s->throttle_count = 0;
    qemu_mod_timer(s->timer, qemu_get_clock(rt_clock) + 1000);
}

static int start_migration(MigrationState *s)
{
    uint32_t value = cpu_to_be32(phys_ram_size);
    target_phys_addr_t addr;
    size_t offset = 0;
	
    while (offset != 4) {
	ssize_t len = write(s->fd, ((char *)&value) + offset, 4 - offset);
	if (len == -1 && errno == EINTR)
	    continue;

	if (len < 1)
	    return -EIO;

	offset += len;
    }

    fcntl(s->fd, F_SETFL, O_NONBLOCK);

    for (addr = 0; addr < phys_ram_size; addr += TARGET_PAGE_SIZE) {
#ifdef USE_KVM
        if (kvm_allowed && (addr>=0xa0000) && (addr<0xc0000)) /* do not access video-addresses */
            continue;
#endif
	if (!cpu_physical_memory_get_dirty(addr, MIGRATION_DIRTY_FLAG))
	    cpu_physical_memory_set_dirty(addr);
    }

    cpu_physical_memory_set_dirty_tracking(1);

    s->addr = 0;
    s->iteration = 0;
    s->updated_pages = 0;
    s->last_updated_pages = 0;
    s->n_buffer = sizeof(s->buffer);
    s->timer = qemu_new_timer(rt_clock, migrate_reset_throttle, s);

    qemu_mod_timer(s->timer, qemu_get_clock(rt_clock));
    qemu_set_fd_handler2(s->fd, NULL, NULL, migrate_write, s);
}

static MigrationState *migration_init_fd(int detach, int fd)
{
    MigrationState *s;

    s = qemu_mallocz(sizeof(MigrationState));
    if (s == NULL) {
	term_printf("Allocation error\n");
	return NULL;
    }

    s->fd = fd;
    s->has_error = qemu_mallocz(sizeof(int));
    if (s->has_error == NULL) {
        term_printf("malloc failed (for has_error)\n");
        return NULL;
    }
    s->detach = detach;

    current_migration = s;
    
    if (start_migration(s) == -1) {
	term_printf("Could not start migration\n");
	return NULL;
    }

    if (!detach)
	monitor_suspend();

    return s;
}

typedef struct MigrationCmdState
{
    int fd;
    pid_t pid;
} MigrationCmdState;

static int cmd_release(void *opaque)
{
    MigrationCmdState *c = opaque;
    int status, ret;

    close(c->fd);

again:
    ret = waitpid(c->pid, &status, 0);
    if (ret == -1 && errno == EINTR)
	goto again;

    if (ret == -1) {
        term_printf("migration: waitpid failed (%s)\n", strerror(errno));
        return -1;
    }
    /* FIXME: check and uncomment
     * if (WIFEXITED(status))
     *     status = WEXITSTATUS(status);
     */
    return status;
}

static MigrationState *migration_init_cmd(int detach, const char *command, char **argv)
{
    int fds[2];
    pid_t pid;
    int i;
    MigrationState *s;

    if (pipe(fds) == -1) {
	term_printf("pipe() (%s)\n", strerror(errno));
	return NULL;
    }

    pid = fork();
    if (pid == -1) {
	close(fds[0]);
	close(fds[1]);
	term_printf("fork error (%s)\n", strerror(errno));
	return NULL;
    }
    if (pid == 0) {
	close(fds[1]);
	dup2(fds[0], STDIN_FILENO);
	execvp(command, argv);
	exit(1);
    } else
	close(fds[0]);

    for (i = 0; argv[i]; i++)
	qemu_free(argv[i]);
    qemu_free(argv);

    s = migration_init_fd(detach, fds[1]);
    if (s) {
	MigrationCmdState *c = qemu_mallocz(sizeof(*c));
	c->pid = pid;
	c->fd = fds[1];
	s->release = cmd_release;
	s->opaque = c;
    }

    return s;
}

static MigrationState *migration_init_exec(int detach, const char *command)
{
    char **argv = NULL;

    argv = qemu_mallocz(sizeof(char *) * 4);
    argv[0] = strdup("sh");
    argv[1] = strdup("-c");
    argv[2] = strdup(command);
    argv[3] = NULL;

    return migration_init_cmd(detach, "/bin/sh", argv);
}

static MigrationState *migration_init_ssh(int detach, const char *host)
{
    int qemu_argc, daemonize = 0, argc, i;
    char **qemu_argv, **argv;
    const char *incoming = NULL;
	
    qemu_get_launch_info(&qemu_argc, &qemu_argv, &daemonize, &incoming);

    argc = 3 + qemu_argc;
    if (!daemonize)
	argc++;
    if (!incoming)
	argc+=2;
    
    argv = qemu_mallocz(sizeof(char *) * (argc + 1));
    argv[0] = strdup("ssh");
    argv[1] = strdup("-XC");
    argv[2] = strdup(host);

    for (i = 0; i < qemu_argc; i++)
	argv[3 + i] = strdup(qemu_argv[i]);

    if (!daemonize)
	argv[3 + i++] = strdup("-daemonize");
    if (!incoming) {
	argv[3 + i++] = strdup("-incoming");
	argv[3 + i++] = strdup("stdio");
    }

    argv[3 + i] = NULL;

    return migration_init_cmd(detach, "ssh", argv);
}

static int tcp_release(void *opaque)
{
    MigrationState *s = opaque;
    uint8_t status = 0;
    ssize_t len;

again:
    len = read(s->fd, &status, 1);
    if (len == -1 && errno == EINTR)
	goto again;

    close(s->fd);

    return (len != 1 || status != 0);
}

static MigrationState *migration_init_tcp(int detach, const char *host)
{
    int fd;
    struct sockaddr_in addr;
    MigrationState *s;

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        term_printf("socket() failed %s\n", strerror(errno));
	return NULL;
    }

    addr.sin_family = AF_INET;
    if (parse_host_port(&addr, host) == -1) {
        term_printf("parse_host_port() FAILED for %s\n", host);
	close(fd);
	return NULL;
    }

again:
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        if (errno == EINTR)
            goto again;
        term_printf("connect() failed %s\n", strerror(errno));
	close(fd);
	return NULL;
    }

    s = migration_init_fd(detach, fd);
    if (s) {
	s->opaque = s;
	s->release = tcp_release;
    }
    return s;
}

/* Incoming migration */

static int migrate_incoming_fd(int fd)
{
    int ret;
    QEMUFile *f = qemu_fopen_fd(fd);
    uint32_t addr;
    extern void qemu_announce_self(void);

    if (qemu_get_be32(f) != phys_ram_size)
	return 101;

    do {
	int l;
	addr = qemu_get_be32(f);
	if (addr == 1)
	    break;
	l = qemu_get_buffer(f, phys_ram_base + addr, TARGET_PAGE_SIZE);
	if (l != TARGET_PAGE_SIZE)
	    return 102;
    } while (1);


    qemu_aio_flush();
    vm_stop(0);
    ret = qemu_live_loadvm_state(f);
    qemu_fclose(f);

    return ret;
}

static int migrate_incoming_tcp(const char *host)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int fd, sfd;
    ssize_t len;
    uint8_t status = 0;
    int reuse = 1;
    int rc;

    addr.sin_family = AF_INET;
    if (parse_host_port(&addr, host) == -1) {
        fprintf(stderr, "parse_host_port() failed for %s\n", host);
        rc = 201;
	goto error;
    }

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket failed");
        rc = 202;
	goto error;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        perror("setsockopt() failed");
        rc = 203;
	goto error_socket;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind() failed");
        rc = 204;
	goto error_socket;
    }

    if (listen(fd, 1) == -1) {
        perror("listen() failed");
        rc = 205;
	goto error_socket;
    }

again:
    sfd = accept(fd, (struct sockaddr *)&addr, &addrlen);
    if (sfd == -1) {
	if (errno == EINTR)
	    goto again;
        perror("accept() failed");
        rc = 206;
	goto error_socket;
    }

    rc = migrate_incoming_fd(sfd);
    if (rc != 0) {
        rc = 207;
        fprintf(stderr, "migrate_incoming_fd failed (rc=%d)\n", rc);
	goto error_accept;
    }

again1:
    len = write(sfd, &status, 1);
    if (len == -1 && errno == EAGAIN)
	goto again1;
    if (len != 1) {
        rc = 208;
	goto error_accept;

    }

error_accept:
    close(sfd);
error_socket:
    close(fd);
error:
    return rc;
}

int migrate_incoming(const char *device)
{
    const char *ptr;
    int ret = 0;

    if (strcmp(device, "stdio") == 0)
	ret = migrate_incoming_fd(STDIN_FILENO);
    else if (strstart(device, "tcp://", &ptr)) {
	char *host, *end;
	host = strdup(ptr);
	end = strchr(host, '/');
	if (end) *end = 0;
	ret = migrate_incoming_tcp(host);
	qemu_free(host);
    } else {
	errno = EINVAL;
	ret = -1;
    }

    return ret;
}

/* Migration monitor command */

/* TODO:
   1) audit all error paths
*/

void do_migrate(int detach, const char *uri)
{
    const char *ptr;

    if (strstart(uri, "exec:", &ptr)) {
	char *command = urldecode(ptr);
	migration_init_exec(detach, command);
	free(command);
    } else if (strstart(uri, "ssh://", &ptr)) {
	char *host, *end;

	host = strdup(ptr);
	end = strchr(host, '/');
	if (end) *end = 0;
	migration_init_ssh(detach, host);
	qemu_free(host);
    } else if (strstart(uri, "tcp://", &ptr)) {
	char *host, *end;

	host = strdup(ptr);
	end = strchr(host, '/');
	if (end) *end = 0;

	if (migration_init_tcp(detach, host) == NULL)
            term_printf("migration failed (migration_init_tcp for %s failed)\n", host);
	free(host);
    } else {
	term_printf("Unknown migration protocol '%s'\n", uri);
	return;
    }
}

void do_migrate_set_speed(const char *value)
{
    double d;
    char *ptr;

    d = strtod(value, &ptr);
    switch (*ptr) {
    case 'G': case 'g':
	d *= 1024;
    case 'M': case 'm':
	d *= 1024;
    case 'K': case 'k':
	d *= 1024;
    default:
	break;
    }

    max_throttle = (uint32_t)d;
}

void do_info_migration(void)
{
    MigrationState *s = current_migration;

    if (s) {
	term_printf("Migration active\n");
	if (s->bps < (1 << 20))
	    term_printf("Transfer rate %3.1f kb/s\n",
			(double)s->bps / 1024);
	else
	    term_printf("Transfer rate %3.1f mb/s\n",
			(double)s->bps / (1024 * 1024));
	term_printf("Iteration %d\n", s->iteration);
	term_printf("Transferred %d/%d pages\n", s->updated_pages, phys_ram_size >> TARGET_PAGE_BITS);
	if (s->iteration)
	    term_printf("Last iteration found %d dirty pages\n", s->last_updated_pages);
    } else
	term_printf("Migration inactive\n");

    term_printf("Maximum migration speed is ");
    if (max_throttle < (1 << 20))
	term_printf("%3.1f kb/s\n", (double)max_throttle / 1024);
    else
	term_printf("%3.1f mb/s\n", (double)max_throttle / (1024 * 1024));
}

void do_migrate_cancel(void)
{
    MigrationState *s = current_migration;

    if (s)
	*s->has_error = 20;
}
