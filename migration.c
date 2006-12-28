#include "vl.h"
#include "qemu_socket.h"
#include "migration.h"

#define TO_BE_IMPLEMENTED term_printf("%s: TO_BE_IMPLEMENTED\n", __FUNCTION__)
#define USE_NONBLOCKING_SOCKETS

#ifndef CONFIG_USER_ONLY

/* defined in vl.c */
int parse_host_port(struct sockaddr_in *saddr, const char *str);
#ifdef USE_NONBLOCKING_SOCKETS
void socket_set_block(int fd) /* should be in vl.c ? */
{
    int val;
    val = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, val & ~O_NONBLOCK);
}
#endif

#define FD_UNUSED -1

typedef enum {
    NONE   = 0,
    WRITER = 1,
    READER = 2
} migration_role_t;	

typedef enum {
    MIG_STAT_NONE   = 0, /* disconnected */
    MIG_STAT_LISTEN = 1, /* listening, waiting for the other to connect */
    MIG_STAT_CONN   = 2, /* connection established */
    MIG_STAT_START  = 3, /* migration started */
    MIG_STAT_SUCC   = 4, /* migration completed successfully */
    MIG_STAT_FAIL   = 5, /* migration failed */
    MIG_STAT_CANCEL = 6  /* migration canceled */
} migration_status_t;

typedef struct migration_bandwith_params {
    int min, max, offline, seconds;
} migration_bandwith_params_t;

typedef struct migration_state {
    int fd;
    migration_status_t status;
#define BUFFSIZE ( 256 * 1024)
    unsigned char buff[BUFFSIZE]; /* FIXME: allocate dynamically; use mutli/double buffer */
    unsigned buffsize;
    unsigned head, tail;
    migration_role_t role;
    int64_t  head_counter, tail_counter;
    migration_bandwith_params_t bw;
} migration_state_t;

static migration_state_t ms = {
    .fd       = FD_UNUSED, 
    .status   = MIG_STAT_NONE,
    .buff     = { 0 },  
    .buffsize = BUFFSIZE, 
    .head = 0, 
    .tail = 0,
    .head_counter = 0,
    .tail_counter = 0,
    .bw = {0, 0, 0, 0}
};

static const char *reader_default_addr="localhost:4455";
static const char *writer_default_addr="localhost:4456";

/* forward declarations */
static void migration_start_dst(int online);
static void migration_cleanup(migration_state_t *pms, migration_status_t stat);


static const char *mig_stat_str(migration_status_t mig_stat)
{
    struct {
        migration_status_t stat;
        const char *str;
    } stat_strs[] = {    
        {MIG_STAT_NONE,   "disconnected"},
        {MIG_STAT_LISTEN, "listening"},
        {MIG_STAT_CONN,   "connected"},
        {MIG_STAT_START,  "migration stared"},
        {MIG_STAT_SUCC,   "migration completed successfully"},
        {MIG_STAT_FAIL,   "migration failed"},
        {MIG_STAT_CANCEL, "migration canceled"}
    };

    int i;
    
    for (i=0 ; i<sizeof(stat_strs)/sizeof(stat_strs[0]) ; i++)
        if (stat_strs[i].stat == mig_stat)
            return stat_strs[i].str;
    
    return "unknown migration_status";
}

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

static int migration_buffer_bytes_head_end(migration_state_t *pms)
{
    return pms->buffsize - pms->head;
}

static int migration_buffer_bytes_tail_end(migration_state_t *pms)
{
    return pms->buffsize - pms->tail;
}

static void migration_state_inc_head(migration_state_t *pms, int n)
{
    pms->head = (pms->head + n) % pms->buffsize;
    pms->head_counter += n;
}

static void migration_state_inc_tail(migration_state_t *pms, int n)
{
    pms->tail = (pms->tail + n) % pms->buffsize;
    pms->tail_counter += n;
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
        term_printf("%s: invalid argument '%s'\n", name, arg);
        migration_cleanup(&ms, MIG_STAT_FAIL);
        return -1;
    }
    return 0;
}

static void migration_cleanup(migration_state_t *pms, migration_status_t stat)
{
    if (pms->fd != FD_UNUSED) {
#ifdef USE_NONBLOCKING_SOCKETS
        qemu_set_fd_handler(pms->fd, NULL, NULL, NULL);
#endif
        close(pms->fd);
        pms->fd = FD_UNUSED;
    }
    pms->status = stat;
}

static int migration_read_from_socket(void *opaque)
{
    migration_state_t *pms = (migration_state_t *)opaque;
    int size, toend;

    if (pms->status != MIG_STAT_START)
        return 0;
    if (pms->fd == FD_UNUSED) /* not connected */
        return 0;

    while (1) { /* breaking if O.K. */
        size = migration_buffer_bytes_empty(pms); /* available size */
        toend = migration_buffer_bytes_head_end(pms);
        if (size > toend) /* read till end of buffer */
            size = toend;
        size = read(pms->fd, pms->buff + pms->head, size);
        if (size < 0) {
            if (socket_error() == EINTR)
                continue;
            term_printf("migration_read_from_socket: read failed (%s)\n", strerror(errno) );
            migration_cleanup(pms, MIG_STAT_FAIL);
            return size;
        }
        if (size == 0) {
            /* connection closed */
            term_printf("migration_read_from_socket: CONNECTION CLOSED\n");
            migration_cleanup(pms, MIG_STAT_FAIL);
            /* FIXME: call vm_start on A or B according to migration status ? */
            return size;
        }
        else /* we did read something */
            break;
    }

    migration_state_inc_head(pms, size);
    return size;
}

static int migration_write_into_socket(void *opaque, int len)
{
    migration_state_t *pms = (migration_state_t *)opaque;
    int size, toend;

    if (pms->status != MIG_STAT_START)
        return 0;
    if (pms->fd == FD_UNUSED) /* not connected */
        return 0;
    while (1) { /* breaking if O.K. */
        size = migration_buffer_bytes_filled(pms); /* available size */
        toend = migration_buffer_bytes_tail_end(pms);
        if (size > toend) /* write till end of buffer */
            size = toend;
        if (size > len)
            size = len;
        size = write(pms->fd, pms->buff + pms->tail, size);
        if (size < 0) {
            if (socket_error() == EINTR)
                continue;
            term_printf("migration_write_into_socket: write failed (%s)\n", 
                        strerror(socket_error()) );
            migration_cleanup(pms, MIG_STAT_FAIL);
            return size;
        }
        if (size == 0) {
            /* connection closed */
            term_printf("migration_write_into_socket: CONNECTION CLOSED\n");
            migration_cleanup(pms, MIG_STAT_FAIL);
            return size;
        }
        else /* we did write something */
            break;
    }

    migration_state_inc_tail(pms, size);
    return size;
}

static void migration_start_now(void *opaque)
{
    migration_start_dst(0);
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
            migration_cleanup(pms, MIG_STAT_FAIL);
            return;
        } else if (new_fd >= 0) {
            break;
        }
    }

    /* FIXME: Need to be modified if we want to have a control connection
     *        e.g. cancel/abort
     */
    migration_cleanup(pms, MIG_STAT_CONN); /* clean old fd */
    pms->fd = new_fd;

    term_printf("accepted new socket as fd %d\n", pms->fd);

#ifdef USE_NONBLOCKING_SOCKETS
    /* start handling I/O */
    qemu_set_fd_handler(pms->fd, migration_start_now, NULL, pms);
#else 
    term_printf("waiting for migration to start...\n");
    migration_start_now(pms);
#endif
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
        migration_cleanup(&ms, MIG_STAT_FAIL);
        return;
    }

    /* fast reuse of address */
    val = 1;
    setsockopt(ms.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(val));
    
    if (bind(ms.fd, &local, sizeof local) < 0 ) {
        migration_cleanup(&ms, MIG_STAT_FAIL);
        term_printf("migration listen: bind() failed (%s)\n", strerror(errno));
        return;
    }
    
    if (listen(ms.fd, 1) < 0) { /* allow only one connection */
        migration_cleanup(&ms, MIG_STAT_FAIL);
        term_printf("migration listen: listen() failed (%s)\n", strerror(errno));
        return;
    }

    ms.status = MIG_STAT_LISTEN;
    term_printf("migration listen: listening on fd %d\n", ms.fd);

#ifdef USE_NONBLOCKING_SOCKETS
    /* FIXME: should I allow BLOCKING socket after vm_stop() to get full bandwidth? */
    socket_set_nonblock(ms.fd); /* do not block and delay the guest */

    qemu_set_fd_handler(ms.fd, migration_accept, NULL, &ms); /* wait for connect() */
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
    int size, toend, len_req = len;
    while (len > 0) {
        size = migration_read_some();
        if (size < 0)
            return size;
        else if (size==0)
            break;
        toend = migration_buffer_bytes_tail_end(&ms);
        if (size > toend)
            size = toend;
        if (size > len)
            size = len;
        memcpy(buff, &ms.buff[ms.tail], size);
        migration_state_inc_tail(&ms, size);
        len -= size;
        buff += size;
    }
    return len_req - len;
}



/*
 * buffer the bytes, and send when threshold reached
 * FIXME: bandwidth control can be implemented here
 * returns 0 on success, <0 on error
 */
static int migration_write_some(int force)
{
    int size, threshold = 1024;

    if (threshold >= ms.buffsize) /* if buffsize is small */
        threshold = ms.buffsize / 2;
    size = migration_buffer_bytes_filled(&ms);
    while (size && (force || (size > threshold))) {
        size = migration_write_into_socket(&ms, size);
        if (size < 0) /* error */
            return size;
        if (size == 0) { /* connection closed -- announce ERROR */
            term_printf("migration: other side closed connection\n");
            return -1;
        }
        size = migration_buffer_bytes_filled(&ms);
    }
    return 0;
}

static int migration_write_byte(int val)
{
    int rc;

    rc = migration_write_some(0);
    if ( rc == 0) {
        rc = 1;
        ms.buff[ms.head] = val;
        migration_state_inc_head(&ms, 1);
    }
    return rc;
}

static int migration_write_buffer(const char *buff, int len)
{
    int size, toend, len_req = len;

    while (len > 0) {
        if (migration_write_some(0) < 0)
            break;
        size = migration_buffer_bytes_empty(&ms);
        toend = migration_buffer_bytes_head_end(&ms);
        if (size > toend)
            size = toend;
        if (size > len)
            size = len;
        memcpy(&ms.buff[ms.head], buff, size);
        migration_state_inc_head(&ms, size);
        len -= size;
        buff += size;
    }
    return len_req - len;
}

static void migration_connect_check(void *opaque)
{
    migration_state_t *pms = (migration_state_t *)opaque;
    int err, rc;
    socklen_t len=sizeof(err);

    rc = getsockopt(pms->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);
    if (rc != 0) {
        term_printf("migration connect: getsockopt FAILED (%s)\n", strerror(errno));
        migration_cleanup(pms, MIG_STAT_FAIL);
        return;
    }
    if (err == 0) {
        term_printf("migration connect: connected through fd %d\n", pms->fd);
        pms->status = MIG_STAT_CONN;
    }
    else {
        term_printf("migration connect: failed to conenct (%s)\n", strerror(err));
        migration_cleanup(pms, MIG_STAT_FAIL);
        return;
    }

#ifdef USE_NONBLOCKING_SOCKETS
    qemu_set_fd_handler(pms->fd, migration_start_now, NULL, pms);
#endif
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
        migration_cleanup(&ms, MIG_STAT_FAIL);
        return;
    }

#ifdef USE_NONBLOCKING_SOCKETS
    socket_set_nonblock(ms.fd);
    qemu_set_fd_handler(ms.fd, NULL, migration_connect_check, &ms);
#endif
    
    while (connect(ms.fd, (struct sockaddr*)&remote, sizeof remote) < 0) {
        if (errno == EINTR)
            continue;
        if (errno != EINPROGRESS) {
            term_printf("migration connect: connect() failed (%s)\n",
                        strerror(errno));
            migration_cleanup(&ms, MIG_STAT_FAIL);
        }
        return;
    }
    
    migration_connect_check(&ms);
}

static void migration_disconnect(void *opaque)
{
    migration_state_t *pms = (migration_state_t*)opaque;
    migration_cleanup(pms, pms->status);
}

static void migration_start_common(int online,
                                   int (*migrate)(const char*, QEMUFile*),
                                   int cont_on_success)
{
    int rc;
    int64_t start_time, end_time;
    const char *dummy = "online_migration";
    migration_state_t *pms = &ms;

    if (pms->status != MIG_STAT_CONN) {
        switch (pms->status) {
        case MIG_STAT_NONE:
        case MIG_STAT_FAIL:
        case MIG_STAT_SUCC:
        case MIG_STAT_CANCEL:
            term_printf("migration start: not connected to peer\n");
            break;
        case MIG_STAT_START:
            term_printf("migration start: migration already running\n");
            break;
        default:
            term_printf("migration start: UNKNOWN state %d\n", pms->status);
        }
        return;
    }

#ifdef USE_NONBLOCKING_SOCKETS
    qemu_set_fd_handler(pms->fd, NULL, NULL, NULL);
    socket_set_block(pms->fd); /* read as fast as you can */
#endif

    pms->status = MIG_STAT_START;
    start_time = qemu_get_clock(rt_clock);
    term_printf("\nstarting migration (at %" PRIx64 ")\n", start_time);
    vm_stop(EXCP_INTERRUPT); /* FIXME: use EXCP_MIGRATION ? */
    rc = migrate(dummy, &qemu_savevm_method_socket);
    end_time = qemu_get_clock(rt_clock);
    term_printf("migration %s (at %" PRIx64 " (%" PRIx64 "))\n", 
                (rc)?"failed":"completed", end_time, end_time - start_time);
    if ((rc==0) && (pms->status == MIG_STAT_START))
        pms->status = MIG_STAT_SUCC;
    else
        if (pms->status == MIG_STAT_START)
            pms->status = MIG_STAT_FAIL;
    if (((pms->status == MIG_STAT_SUCC) && cont_on_success) ||
        ((pms->status != MIG_STAT_SUCC) && !cont_on_success)) {
        migration_cleanup(pms, pms->status);
        vm_start();
    }
    else
        if (pms->fd != FD_UNUSED)
            qemu_set_fd_handler(pms->fd, migration_disconnect, NULL, pms);
}

static void migration_start_src(int online)
{
    ms.role = WRITER;

    migration_start_common(online, qemu_savevm, 0);
}

static void migration_start_dst(int online)
{
    ms.role = READER;

    migration_start_common(online, qemu_loadvm, 1);
}

void do_migration_getfd(int fd) { TO_BE_IMPLEMENTED; }
void do_migration_start(char *deadoralive)
{ 
    migration_start_src(0);
}

void do_migration_cancel(void)
{
    migration_cleanup(&ms, MIG_STAT_CANCEL);
}
void do_migration_status(void){ 
    term_printf("migration status: %s\n", mig_stat_str(ms.status));
}
void do_migration_set_rate(int min, int max, int offline)
{
    if ((min<0) || (max<0) || (offline<0)) {
        term_printf("%s: positive values only please\n", __FUNCTION__);
        return;
    }
    ms.bw.min     = min;
    ms.bw.max     = max;
    ms.bw.offline = offline;
}

void do_migration_set_total_time(int seconds)
{
    if (seconds<0){
        term_printf("%s: positive values only please\n", __FUNCTION__);
        return;
    }
    ms.bw.seconds = seconds;
}
void do_migration_show(void)
{
    term_printf("%8s %8s %8s %8s\n%8d %8d %8d %8d\n",
                "min", "max", "offline", "seconds",
                ms.bw.min, ms.bw.max, ms.bw.offline, ms.bw.seconds); 
}



/* 
 * =============================================
 * qemu_savevm_method implementation for sockets 
 * =============================================
 */
static int qemu_savevm_method_socket_open(QEMUFile *f, const char *filename, 
                                  const char *flags)
{
    if (ms.fd == FD_UNUSED)
        return -1;
    f->opaque = (void*)&ms;
    return 0;
}

static void qemu_savevm_method_socket_close(QEMUFile *f)
{
    migration_state_t *pms = (migration_state_t*)f->opaque;
    if (pms->role == WRITER) {
        migration_write_some(1); /* sync */
    }
}

static void qemu_savevm_method_socket_put_buffer(QEMUFile *f, const uint8_t *buf, int size)
{
    migration_write_buffer(buf, size);
}

static void qemu_savevm_method_socket_put_byte(QEMUFile *f, int v)
{
    migration_write_byte(v);
}

static int qemu_savevm_method_socket_get_buffer(QEMUFile *f, uint8_t *buf, int size)
{
    return migration_read_buffer(buf, size);
}

static int qemu_savevm_method_socket_get_byte(QEMUFile *f)
{
    return migration_read_byte();
}

static int64_t qemu_savevm_method_socket_tell(QEMUFile *f)
{
    migration_state_t *pms = (migration_state_t*)f->opaque;
    int64_t cnt=-1;
    if (pms->role == WRITER)
        cnt = pms->head_counter;
    else if (pms->role == READER)
        cnt = pms->tail_counter;
    return cnt;
}

/* 
 * hack alert: written to overcome a weakness of our solution (not yet generic).
 * READER: read 4 bytes of the actual length (and maybe do something)
 * WRITER: ignore (or maybe do something)
 */
static int64_t qemu_savevm_method_socket_seek(QEMUFile *f, int64_t pos, int whence)
{
    migration_state_t *pms = (migration_state_t*)f->opaque;
    unsigned int record_len;

    if (pms->role == READER) {
        record_len = qemu_get_be32(f);
    }
    return 0;
}

static int qemu_savevm_method_socket_eof(QEMUFile *f)
{
    migration_state_t *pms = (migration_state_t*)f->opaque;

    return (pms->fd == FD_UNUSED);
}

QEMUFile qemu_savevm_method_socket = {
    .opaque       = NULL, 
    .open         = qemu_savevm_method_socket_open,
    .close        = qemu_savevm_method_socket_close,
    .put_byte     = qemu_savevm_method_socket_put_byte,
    .get_byte     = qemu_savevm_method_socket_get_byte,
    .put_buffer   = qemu_savevm_method_socket_put_buffer,
    .get_buffer   = qemu_savevm_method_socket_get_buffer,
    .tell         = qemu_savevm_method_socket_tell,
    .seek         = qemu_savevm_method_socket_seek,
    .eof          = qemu_savevm_method_socket_eof
};





#else /* CONFIG_USER_ONLY is defined */

void do_migration_listen(char *arg1, char *arg2) { TO_BE_IMPLEMENTED; }
void do_migration_connect(char *arg1, char *arg2) { TO_BE_IMPLEMENTED; }
void do_migration_getfd(int fd) { TO_BE_IMPLEMENTED; }
void do_migration_start(char *deadoralive) { TO_BE_IMPLEMENTED; }
void do_migration_cancel(void){ TO_BE_IMPLEMENTED; }
void do_migration_status(void){ TO_BE_IMPLEMENTED; }
void do_migration_set_rate(int min, int max, int offline) { TO_BE_IMPLEMENTED; }
void do_migration_set_total_time(int seconds) { TO_BE_IMPLEMENTED; }
void do_migration_show(void){ TO_BE_IMPLEMENTED; }

#endif /* of CONFIG_USER_ONLY is defined */
