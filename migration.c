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
#define QEMU_MIGRATION_MAGIC     0x5145564d /* FIXME: our own magic ??? */
#define QEMU_MIGRATION_VERSION   0x00000001

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


/* page types to be used when migrating ram pages */
enum {
    MIG_XFER_PAGE_TYPE_REGULAR     = 0,  /* regular page           */
    MIG_XFER_PAGE_TYPE_HOMOGENEOUS = 1,  /* all bytes are the same */
    MIG_XFER_PAGE_TYPE_END         = 15, /* go to the next phase   */
};

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
    int      phase;
    int      online;
    int      yield;
    QEMUFile *f;
    unsigned next_page;
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
    .bw = {0, 0, 0, 0},
    .phase = 0,
    .online = 0,
    .yield = 0,
    .f     = NULL,
};

static const char *reader_default_addr="localhost:4455";
static const char *writer_default_addr="localhost:4456";

/* forward declarations */
static void migration_cleanup(migration_state_t *pms, migration_status_t stat);
static void migration_start_src(migration_state_t *pms);
static void migration_phase_1_src(migration_state_t *pms);
static void migration_phase_2_src(migration_state_t *pms);
static void migration_phase_3_src(migration_state_t *pms);
static void migration_phase_4_src(migration_state_t *pms);
static void migration_start_dst(migration_state_t *pms);
static void migration_phase_1_dst(migration_state_t *pms);
static void migration_phase_2_dst(migration_state_t *pms);
static void migration_phase_3_dst(migration_state_t *pms);
static void migration_phase_4_dst(migration_state_t *pms);

static void migration_ram_send(migration_state_t *pms);
static void migration_ram_recv(migration_state_t *pms);

typedef void (*QemuMigrationPhaseCB)(migration_state_t *pms);
#define MIGRATION_NUM_PHASES 5
QemuMigrationPhaseCB migration_phase_funcs[2][MIGRATION_NUM_PHASES] = {
    {
        migration_start_src,
        migration_phase_1_src,
        migration_phase_2_src,
        migration_phase_3_src,
        migration_phase_4_src    },
    {
        migration_start_dst,
        migration_phase_1_dst,
        migration_phase_2_dst,
        migration_phase_3_dst,
        migration_phase_4_dst    }
};

/* MIG_ASSERT 
 * assuming pms is defined in the function calling MIG_ASSERT
 * retuns non-0 if the condition is false, 0 if all is OK 
 */
#define MIG_ASSERT(p) mig_assert(pms, !!(p), __FUNCTION__, __LINE__)
int mig_assert(migration_state_t *pms, int cond, const char *fname, int line)
{
    if (!cond) {
        term_printf("assertion failed at %s():%d\n", fname, line);
        migration_cleanup(&ms, MIG_STAT_FAIL);
    }
    return !cond;
}

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

static void migration_reset_buffer(migration_state_t *pms)
{
    memset(pms->buff, 0, pms->buffsize);
    pms->head = 0;
    pms->tail = 0;
    pms->head_counter = 0;
    pms->tail_counter = 0;
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
    migration_state_t *pms = (migration_state_t *)opaque;

    migration_start_dst(pms);
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

    if (ms.status != MIG_STAT_START)
        return -1;

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

static void migration_phase_set(migration_state_t *pms, int phase)
{
    int64_t t = qemu_get_clock(rt_clock);

    term_printf("migration: starting phase %d at %" PRId64 "\n",
                phase, t);
    pms->phase = phase;
}
static void migration_phase_inc(migration_state_t *pms)
{
    migration_phase_set(pms, pms->phase + 1);
}

/* four phases for the migration:
 * phase 0: initialization
 * phase 1: online or offline
 *    transfer all RAM pages
 *    enable dirty pages logging
 *
 * phase 2: online only
 *    repeat: transfer all dirty pages
 *    
 * phase 3: offline
 *    transfer whatever left (dirty pages + non-ram states)
 * 
 * phase 4: offline or online
 *    The grand finale: decide with host should continue
 *    send a "to whom it may concern..."
 *
 *
 * The function migration_main_loop just runs the appropriate function
 *     according to phase.
 */

void migration_main_loop(void *opaque)
{
    migration_state_t *pms = (migration_state_t *)opaque;
    
    pms->yield = 0;
    while (! pms->yield) {
        if (pms->status != MIG_STAT_START)
            pms->phase = MIGRATION_NUM_PHASES-1; /* last phase -- report */
        if (MIG_ASSERT(pms->phase < MIGRATION_NUM_PHASES))
            break;
        migration_phase_funcs[pms->role-1][pms->phase](pms);
    }
}

static void migration_start_common(migration_state_t *pms)
{
    int64_t start_time;

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

    start_time = qemu_get_clock(rt_clock);
    term_printf("\nstarting migration (at %" PRId64 ")\n", start_time);
    migration_phase_set(pms, 0);
    migration_reset_buffer(pms);
    pms->status = MIG_STAT_START;
    pms->next_page = 0;
    pms->f = &qemu_savevm_method_socket;
    pms->f->open(pms->f, NULL, NULL);

    migration_phase_inc(pms);
    migration_main_loop(pms);
}

static void migration_start_src(migration_state_t *pms)
{
    pms->role = WRITER;
    migration_start_common(pms);
}

static void migration_start_dst(migration_state_t *pms)
{
    pms->role = READER;
    migration_start_common(pms);
}


static void migration_phase_1_src(migration_state_t *pms)
{
    if (pms->next_page == 0) {
        qemu_put_be32(pms->f, QEMU_MIGRATION_MAGIC);
        qemu_put_be32(pms->f, QEMU_MIGRATION_VERSION);
        qemu_put_byte(pms->f, pms->online);
        qemu_set_fd_handler(pms->fd, NULL, migration_main_loop, pms);
    }

    migration_ram_send(pms);
    if (pms->next_page >=  (phys_ram_size >> TARGET_PAGE_BITS)) {
        migration_phase_inc(pms);
        qemu_set_fd_handler(pms->fd, NULL, NULL, pms);
    }
}
static void migration_phase_2_src(migration_state_t *pms)
{
    migration_phase_inc(pms);    
}

static void migration_phase_3_common(migration_state_t *pms, 
                                     int (*migrate)(const char*, QEMUFile*))
{
    const char *dummy = "migrating";
    int rc;

    vm_stop(EXCP_INTERRUPT); /* FIXME: use EXCP_MIGRATION ? */
    rc = migrate(dummy, &qemu_savevm_method_socket);
    if ((rc==0) && (pms->status == MIG_STAT_START))
        pms->status = MIG_STAT_SUCC;
    else
        if (pms->status == MIG_STAT_START)
            pms->status = MIG_STAT_FAIL;

    migration_phase_inc(pms);
}
static void migration_phase_3_src(migration_state_t *pms)
{
    migration_phase_3_common(pms, qemu_savevm);
}
static void migration_phase_4_common(migration_state_t *pms, int cont)
{
    int64_t end_time = qemu_get_clock(rt_clock);
    term_printf("migration %s at %" PRId64"\n",
                (pms->status!=MIG_STAT_SUCC)?"failed":"completed successfully",
                end_time);
    if (cont) {
        migration_cleanup(pms, pms->status);
        vm_start();
    }
    else 
        if (pms->fd != FD_UNUSED)
            qemu_set_fd_handler(pms->fd, migration_disconnect, NULL, pms);

    pms->yield = 1;
}

static void migration_phase_4_src(migration_state_t *pms)
{
    migration_phase_4_common(pms, pms->status != MIG_STAT_SUCC);
}

static void migration_phase_1_dst(migration_state_t *pms)
{
    uint32_t magic, version, online;

    if (pms->next_page == 0) {
        magic   = qemu_get_be32(pms->f);
        version = qemu_get_be32(pms->f);
        online  = qemu_get_byte(pms->f);

        if ((magic   != QEMU_MIGRATION_MAGIC)   ||
            (version != QEMU_MIGRATION_VERSION)) {
            term_printf("migration header: recv 0x%x 0x%x expecting 0x%x 0x%x\n",
                        magic, version, 
                        QEMU_MIGRATION_MAGIC, QEMU_MIGRATION_VERSION);
            migration_cleanup(pms, MIG_STAT_FAIL);
            return;
        }

        pms->online = online;
        term_printf("===>received online=%u\n", online);
    }

    migration_ram_recv(pms);

    if (pms->next_page  >= (phys_ram_size >> TARGET_PAGE_BITS)) {
        migration_phase_inc(pms);
    }
}
static void migration_phase_2_dst(migration_state_t *pms)
{
    migration_phase_inc(pms);    
}
static void migration_phase_3_dst(migration_state_t *pms)
{
    migration_phase_3_common(pms, qemu_loadvm);
}
static void migration_phase_4_dst(migration_state_t *pms)
{
    migration_phase_4_common(pms, pms->status == MIG_STAT_SUCC);
}


/* 
 * FIXME: make it share code in vl.c
 */
static int ram_page_homogeneous(const uint8_t *buf, const int len)
{
    int i, v;

    v = buf[0];
    for (i=1; i<len; i++)
        if (buf[i] != v)
            return 0;
    return 1;
}

static void mig_ram_dirty_reset_page(unsigned page_number)
{
    ram_addr_t start, end;
    start = page_number << TARGET_PAGE_BITS;
    end   = start + TARGET_PAGE_SIZE;
    cpu_physical_memory_reset_dirty(start, end, MIG_DIRTY_FLAG);
}

/*
 * Sends a single ram page
 * As in vl.c a single byte is being sent as data if page is "homogeneous"
 * Layout:
 *    header:
 *        byte   -- migration transfer page type
 *        uint32 -- page number
 *    data
 *        a single byte or the whole page (TARGET_PAGE_SIZE bytes).
 */
static void mig_send_ram_page(migration_state_t *pms, unsigned page_number)
{
    const uint8_t* ptr = (const uint8_t *)(unsigned long)phys_ram_base;
    uint8_t val;
    unsigned buflen;
    
    if (page_number >=  (phys_ram_size >> TARGET_PAGE_BITS)) {
        term_printf("mig_send_ram_page: page_number is too large: %u (max is %u)\n",
                    page_number, (phys_ram_size >> TARGET_PAGE_BITS));
        migration_cleanup(pms, MIG_STAT_FAIL);
        return;
    }

    ptr += (page_number << TARGET_PAGE_BITS);
    if (ram_page_homogeneous(ptr, TARGET_PAGE_SIZE)) {
        val = MIG_XFER_PAGE_TYPE_HOMOGENEOUS;
        buflen = 1;
    }
    else {
        val = MIG_XFER_PAGE_TYPE_REGULAR;
        buflen = TARGET_PAGE_SIZE;
    }
    qemu_put_byte(pms->f,   val);
    qemu_put_be32(pms->f,   page_number);
    qemu_put_buffer(pms->f, ptr, buflen);

    mig_ram_dirty_reset_page(page_number);
}

/* returns 0 on success,
 *         1 if this phase is over
 *        -1 on failure
 */
static int mig_recv_ram_page(migration_state_t *pms)
{
    uint8_t *ptr = (uint8_t *)(unsigned long)phys_ram_base;
    unsigned page_number;
    uint8_t val;
    unsigned buflen;

    val         = qemu_get_byte(pms->f);
    page_number = qemu_get_be32(pms->f);

    if ((pms->phase != 1) && (page_number != pms->next_page)) {
        term_printf("WARNING: page number mismatch: received %u expected %u\n",
                    page_number, pms->next_page);
        return -1;
    }

    if (page_number >=  (phys_ram_size >> TARGET_PAGE_BITS)) {
        term_printf("mig_recv_ram_page: page_number is too large: %u (max is %u)\n",
                    page_number, (phys_ram_size >> TARGET_PAGE_BITS));
        return -1;
    }

    switch(val) {
    case MIG_XFER_PAGE_TYPE_END: /* go to the next phase */;
        pms->next_page = phys_ram_size >> TARGET_PAGE_BITS;
        return 1;
    case MIG_XFER_PAGE_TYPE_REGULAR:
        buflen = TARGET_PAGE_SIZE;
        break;
    case MIG_XFER_PAGE_TYPE_HOMOGENEOUS:
        buflen = 1;
        break;
    default: 
        term_printf("mig_recv_ram_page: illegal val received %d\n", val); 
        migration_cleanup(pms, MIG_STAT_FAIL);
        return -1;
    }

    ptr += (page_number << TARGET_PAGE_BITS);
    qemu_get_buffer(pms->f, ptr, buflen);

    if (val == MIG_XFER_PAGE_TYPE_HOMOGENEOUS)
        memset(ptr, ptr[0], TARGET_PAGE_SIZE);

    return 0;
}


/* In order to enable the guest to run while memory is transferred, 
 *    the number of page continuously sent is limited by this constant.
 * When the limit is reached we take a break and continue to send pages
 *    upon another call to migration_ram_send (which would be when data can 
 *    be sent over the socket ( using qemu_set_fd_handler() ).
 */
#define PAGES_CHUNK ((phys_ram_size >> TARGET_PAGE_BITS) /16 )

/* Sends the whole ram in chunks, each call a few pages are being sent 
 *    (needs to be called multiple times).
 * State is kept in pms->next_page.
 */ 
static void migration_ram_send(migration_state_t *pms)
{
    unsigned num_pages = (phys_ram_size >> TARGET_PAGE_BITS);

    if (pms->next_page == 0) { /* send memory size */
        qemu_put_be32(pms->f, num_pages);
    }
    
    if (pms->next_page >= num_pages) /* finished already */
        return;

    /* send a few pages (or until network buffers full) */
    if (num_pages - pms->next_page > PAGES_CHUNK) {
        num_pages = pms->next_page + PAGES_CHUNK;
    }
    for ( /*none*/ ; pms->next_page < num_pages; pms->next_page++) {
        if ((pms->next_page >= (0xa0000 >> TARGET_PAGE_BITS)) && 
            (pms->next_page <  (0xc0000 >> TARGET_PAGE_BITS)))
            continue;
        mig_send_ram_page(pms, pms->next_page);
    }
}

/* recv the whole ram (first phase) */
static void migration_ram_recv(migration_state_t *pms)
{
    unsigned num_pages;
    int rc = 0;

    num_pages = qemu_get_be32(pms->f);
    if (num_pages != phys_ram_size >> TARGET_PAGE_BITS) {
        term_printf("phys_memory_mismatch: %uMB %uMB\n", 
                    num_pages >> (20-TARGET_PAGE_BITS), phys_ram_size>>20);
        migration_cleanup(pms, MIG_STAT_FAIL);
        return;
    }

    for (/* none */ ; rc==0 && pms->next_page < num_pages; pms->next_page++) {
        if ((pms->next_page >= (0xa0000 >> TARGET_PAGE_BITS)) && 
            (pms->next_page <  (0xc0000 >> TARGET_PAGE_BITS)))
            continue;
        rc = mig_recv_ram_page(pms); 
        if (rc < 0) {
            term_printf("mig_recv_ram_page FAILED after %u pages\n", pms->next_page);
            migration_cleanup(pms, MIG_STAT_FAIL);
            return;
        }
    }

    if (pms->next_page < num_pages)
        term_printf("migration_ram_recv: WARNING goto next phase after %u pages (of %u)\n",
                    pms->next_page, num_pages);
}

void do_migration_getfd(int fd) { TO_BE_IMPLEMENTED; }
void do_migration_start(char *deadoralive)
{ 
    if (strcmp(deadoralive, "online") == 0)
        ms.online = 1;
    else if (strcmp(deadoralive, "offline") == 0)
        ms.online = 0;
    else {
        term_printf("migration start: please specify 'online' or 'offline'\n");
        return;
    }
    migration_start_src(&ms);
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
