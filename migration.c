#include "vl.h"
#include "qemu_socket.h"
#include "migration.h"

#define TO_BE_IMPLEMENTED term_printf("%s: TO_BE_IMPLEMENTED\n", __FUNCTION__)

#ifndef CONFIG_USER_ONLY

/* defined in vl.c */
int parse_host_port(struct sockaddr_in *saddr, const char *str);

#define FD_UNUSED -1

typedef enum {
    NONE   = 0,
    WRITER = 1,
    READER = 2
} migration_role_t;	

typedef struct migration_state {
    int fd;
#define BUFFSIZE (/* 256* */1024)
    char buff[BUFFSIZE]; /* FIXME: allocate dynamically; use mutli/double buffer */
    unsigned buffsize;
    unsigned head, tail;
    migration_role_t role;
} migration_state_t;

static migration_state_t ms = {
    .fd       = FD_UNUSED, 
    .buff     = { 0 },  
    .buffsize = BUFFSIZE, 
    .head = 0, 
    .tail = 0
};

static const char *reader_default_addr="localhost:4455";
static const char *writer_default_addr="localhost:4456";

/* circular buffer functions */
static int migration_buffer_empty(migration_state_t *pms)
{
    return (pms->head == pms->tail);
}

static int migration_buffer_bytes_filled(migration_state_t *pms)
{
    return (pms->head - pms->tail) % pms->buffsize;
}

static int migration_buffer_bytes_empty(migration_state_t *pms)
{
    return (pms->tail - pms->head -1) % pms->buffsize;
}

static void migration_state_inc_head(migration_state_t *pms, int n)
{
    pms->head = (pms->head + n) % pms->buffsize;
}

static void migration_state_inc_tail(migration_state_t *pms, int n)
{
    pms->tail = (pms->tail + n) % pms->buffsize;
}


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

static int migration_read_from_socket(void *opaque)
{
    migration_state_t *pms = (migration_state_t *)opaque;
    int size;

    if (pms->fd == FD_UNUSED) /* not connected */
        return 0;
    while (1) { /* breaking if O.K. */
        size = migration_buffer_bytes_empty(pms); /* available size */
        if (size > pms->buffsize - pms->head) /* read till end of buffer */
            size = pms->buffsize - pms->head;
        size = read(pms->fd, pms->buff + pms->head, size);
        if (size < 0) {
            if (socket_error() == EINTR)
                continue;
            perror("recv FAILED");
            term_printf("migration_read_from_socket: recv failed (%d: %s)\n", errno, strerror(errno) );
            return size;
        }
        if (size == 0) {
            /* connection closed */
            term_printf("migration_read_from_socket: CONNECTION CLOSED\n");
            migration_cleanup(pms);
            /* FIXME: call vm_start on A or B according to migration status ? */
            return size;
        }
        else /* we did read something */
            break;
    }

    migration_state_inc_head(pms, size);
    return size;
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

    ms.role = READER;

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

/* reads from the socket if needed 
 * returns 0  if connection closed
 *         >0 if buffer is not empty, number of bytes filled
 *         <0 if error occure
 */
static int migration_read_some(void)
{
    int size;

    if (migration_buffer_empty(&ms))
        size = migration_read_from_socket(&ms);
    else
        size = migration_buffer_bytes_filled(&ms);
    return size;
}


/* returns the byte read or 0 on error/connection closed */
int migration_read_byte(void)
{
    int val = 0;
    
    if (migration_read_some() > 0) {
        val = ms.buff[ms.tail];
        migration_state_inc_tail(&ms, 1);
    }
    return val;
}

/* returns >=0 the number of bytes actually read, 
 *       or <0 if error occured 
 */
int migration_read_buffer(char *buff, int len)
{
    int size, len_req = len;
    while (len > 0) {
        size = migration_read_some();
        if (size < 0)
            return size;
        else if (size==0)
            break;
        if (len < size)
            size = len;
        memcpy(buff, &ms.buff[ms.tail], size);
        migration_state_inc_tail(&ms, size);
        len -= size;
    }
    return len_req - len;
}


void do_migration_connect(char *arg1, char *arg2)
{
    struct sockaddr_in local, remote;

    if (ms.fd != FD_UNUSED) {
        term_printf("Already connecting or connection established\n");
        return;
    }

    ms.role = WRITER;

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
