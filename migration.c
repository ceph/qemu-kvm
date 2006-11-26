#include "vl.h"
#include "qemu_socket.h"
#include "migration.h"

#define TO_BE_IMPLEMENTED term_printf("%s: TO_BE_IMPLEMENTED\n", __FUNCTION__)

#ifndef CONFIG_USER_ONLY

/* defined in vl.c */
int parse_host_port(struct sockaddr_in *saddr, const char *str);

#define FD_UNUSED -1

typedef struct migration_state {
    int fd;
} migration_state_t;

static migration_state_t ms = {FD_UNUSED};

static const char *reader_default_addr="localhost:4455";
static const char *writer_default_addr="localhost:4456";


/* create a network address according to arg/default_addr */
static int parse_host_port_and_message(struct sockaddr_in *saddr,
                                       const char *arg,
                                       const char *default_addr,
                                       const char *name)
{
    if (!arg)
        arg = default_addr;
    if (parse_host_port(saddr, arg) < 0) {
        term_printf("%s: invalid argument '%s'", name, arg);
        return -1;
    }
    return 0;
}

static void migration_cleanup(migration_state_t *pms)
{
    if (pms->fd != FD_UNUSED) {
#ifdef USE_NONBLOCKING_SOCKETS
        qemu_set_fd_handler(pms->fd, NULL, NULL, NULL);
#endif
        close(pms->fd);
        pms->fd = FD_UNUSED;
    }
}

static void migration_accept(void *opaque)
{
    migration_state_t *pms = (migration_state_t *)opaque;
    socklen_t len;
    struct sockaddr_in sockaddr;
    int new_fd;

    for(;;) {
        len = sizeof(sockaddr);
        new_fd = accept(pms->fd, (struct sockaddr *)&sockaddr, &len);
        if (new_fd < 0 && errno != EINTR) {
            term_printf("migration listen: accept failed (%s)\n",
                        strerror(errno));
            return;
        } else if (new_fd >= 0) {
            break;
        }
    }

    /* FIXME: Need to be modified if we want to have a control connection
     *        e.g. cancel/abort
     */
    migration_cleanup(pms); /* clean old fd */
    pms->fd = new_fd;
#ifdef USE_NONBLOCKING_SOCKETS
    /* start handling I/O */
    qemu_set_fd_handler(pms->fd, migration_read_from_socket, NULL, NULL);
#endif

    term_printf("accepted new socket as fd %d\n", pms->fd);
}


void do_migration_listen(char *arg1, char *arg2)
{
    struct sockaddr_in local, remote;
    int val;

    if (ms.fd != FD_UNUSED) {
        term_printf("Already listening or connection established\n");
        return;
    }

    if (parse_host_port_and_message(&local,  arg1, reader_default_addr, "migration listen"))
        return;

    if (parse_host_port_and_message(&remote, arg2, writer_default_addr, "migration listen"))
        return;

    ms.fd = socket(PF_INET, SOCK_STREAM, 0);
    if (ms.fd < 0) {
        term_printf("migration listen: socket() failed (%s)\n",
                    strerror(errno));
        return;
    }

    /* fast reuse of address */
    val = 1;
    setsockopt(ms.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(val));
    
    if (bind(ms.fd, &local, sizeof local) < 0 ) {
        migration_cleanup(&ms);
        term_printf("migration listen: bind() failed (%s)\n", strerror(errno));
        return;
    }
    
    if (listen(ms.fd, 1) < 0) { /* allow only one connection */
        migration_cleanup(&ms);
        term_printf("migration listen: listen() failed (%s)\n", strerror(errno));
        return;
    }

#ifdef USE_NONBLOCKING_SOCKETS
    /* FIXME: should I allow BLOCKING socket after vm_stop() to get full bandwidth? */
    socket_set_nonblock(fd); /* do not block and delay the guest */

    qemu_set_fd_handler(fd, migration_accept, NULL, NULL); /* wait for connect() */
#else
    migration_accept(&ms);
#endif
}
void do_migration_connect(char *arg1, char *arg2)
{
    struct sockaddr_in local, remote;

    if (ms.fd != FD_UNUSED) {
        term_printf("Already connecting or connection established\n");
        return;
    }

    if (parse_host_port_and_message(&local,  arg1, writer_default_addr, "migration connect"))
        return;

    if (parse_host_port_and_message(&remote, arg2, reader_default_addr, "migration connect"))
        return;

    ms.fd = socket(PF_INET, SOCK_STREAM, 0);
    if (ms.fd < 0) {
        term_printf("migration connect: socket() failed (%s)\n",
                    strerror(errno));
        return;
    }
    
    if (connect(ms.fd, (struct sockaddr*)&remote, sizeof remote) < 0) {
        term_printf("migration connect: connect() failed (%s)\n",
                     strerror(errno));
        migration_cleanup(&ms);
        return;
    }
    
    term_printf("migration connect: connected through fd %d\n", ms.fd);
}
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
