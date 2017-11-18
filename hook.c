#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include "allocated_string.h"
#include "span.h"
#include "countlog.h"

char* library_version = { "KOALA-LIBC-VERSION: 1.3.0" };

#define RTLD_NEXT	((void *) -1l)

#define HOOK_SYS_FUNC(name) if( !orig_##name##_func ) { orig_##name##_func = (name##_pfn_t)dlsym(RTLD_NEXT,#name); }

typedef ssize_t (*send_pfn_t)(int, const void *, size_t, int);
static send_pfn_t orig_send_func;

typedef ssize_t (*write_pfn_t)(int, const void *, size_t);
static write_pfn_t orig_write_func;

typedef ssize_t (*writev_pfn_t)(int, const struct iovec *, int);
static writev_pfn_t orig_writev_func;

typedef ssize_t (*recv_pfn_t)(int socket, void *, size_t, int);
static recv_pfn_t orig_recv_func;

typedef ssize_t (*read_pfn_t)(int socket, void *, size_t);
static read_pfn_t orig_read_func;

typedef ssize_t (*sendto_pfn_t)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static sendto_pfn_t orig_sendto_func;

typedef int (*connect_pfn_t)(int, const struct sockaddr *, socklen_t);
static connect_pfn_t orig_connect_func;

typedef int (*accept_pfn_t)(int, struct sockaddr *, socklen_t *);
static accept_pfn_t orig_accept_func;

typedef int (*accept4_pfn_t)(int, struct sockaddr *, socklen_t *, int);
static accept4_pfn_t orig_accept4_func;

typedef int (*bind_pfn_t)(int, const struct sockaddr *, socklen_t);
static bind_pfn_t orig_bind_func;

typedef FILE * (*fopen_pfn_t)(const char *filename, const char *opentype);
static fopen_pfn_t orig_fopen_func;

typedef FILE * (*fopen64_pfn_t)(const char *filename, const char *opentype);
static fopen64_pfn_t orig_fopen64_func;

typedef int (*open_pfn_t)(const char *filename, int flags, mode_t mode);
static open_pfn_t orig_open_func;

typedef int (*open64_pfn_t)(const char *filename, int flags, mode_t mode);
static open64_pfn_t orig_open64_func;

typedef void (*on_connect_pfn_t)(pid_t p0, int p1, struct sockaddr_in* p2);
static on_connect_pfn_t on_connect_func;

typedef void (*on_connect_unix_pfn_t)(pid_t p0, int p1, char* p2);
static on_connect_unix_pfn_t on_connect_unix_func;

typedef void (*on_bind_pfn_t)(pid_t p0, int p1, struct sockaddr_in* p2);
static on_bind_pfn_t on_bind_func;

typedef void (*on_bind_unix_pfn_t)(pid_t p0, int p1, char* p2);
static on_bind_unix_pfn_t on_bind_unix_func;

typedef void (*on_accept_pfn_t)(pid_t p0, int p1, int p2, struct sockaddr_in* p3);
static on_accept_pfn_t on_accept_func;

typedef void (*on_accept_unix_pfn_t)(pid_t p0, int p1, int p2, char* p3);
static on_accept_unix_pfn_t on_accept_unix_func;

typedef struct ch_allocated_string (*before_send_pfn_t)(pid_t p0, int p1, int p2, size_t *p3);
static before_send_pfn_t before_send_func;

typedef void (*on_send_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3, int p4);
static on_send_pfn_t on_send_func;

typedef struct ch_span (*on_recv_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3);
static on_recv_pfn_t on_recv_func;

typedef void (*on_sendto_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3, struct sockaddr_in* p4);
static on_sendto_pfn_t on_sendto_func;

typedef void (*send_to_koala_pfn_t)(pid_t p0, struct ch_span p1, int p2);
static send_to_koala_pfn_t send_to_koala_func;

typedef void (*on_opened_file_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3, mode_t p4);
static on_opened_file_pfn_t on_opened_file_func;

typedef void (*on_fopened_file_pfn_t)(pid_t p0, int p1, struct ch_span p2, struct ch_span p3);
static on_fopened_file_pfn_t on_fopened_file_func;

typedef void (*on_write_pfn_t)(pid_t p0, int p1, struct ch_span p2);
static on_write_pfn_t on_write_func;

typedef int (*is_tracing_pfn_t)();
static is_tracing_pfn_t is_tracing_func;

static void *koala_so_handle;

void hook_init (void) __attribute__ ((constructor));
void hook_init() {
    koala_so_handle = NULL;
    on_connect_func = NULL;
    on_connect_unix_func = NULL;
    on_bind_func = NULL;
    on_bind_unix_func = NULL;
    on_accept_func = NULL;
    on_accept_unix_func = NULL;
    before_send_func = NULL;
    on_send_func = NULL;
    on_recv_func = NULL;
    on_sendto_func = NULL;
    send_to_koala_func = NULL;
    on_opened_file_func = NULL;
    on_fopened_file_func = NULL;
    on_write_func = NULL;
    is_tracing_func = NULL;
}

static void load_koala_so() {
    if (koala_so_handle != NULL) {
        return;
    }
    char *koala_so_path = getenv("KOALA_SO");
    if (koala_so_path == NULL) {
        fprintf(stderr, "koala_libc.so find $KOALA_SO environment variable not set");
        fflush(stderr);
        return;
    }
    koala_so_handle = dlopen(koala_so_path, RTLD_LAZY);
    if (koala_so_handle == NULL) {
        fprintf(stderr, "koala_libc.so load $KOALA_SO failed: %s\n", koala_so_path);
        fflush(stderr);
        return;
    }
    load_koala_so_countlog(koala_so_handle);
    on_accept_func = (on_accept_pfn_t) dlsym(koala_so_handle, "on_accept");
    on_accept_unix_func = (on_accept_unix_pfn_t) dlsym(koala_so_handle, "on_accept_unix");
    on_connect_func = (on_connect_pfn_t) dlsym(koala_so_handle, "on_connect");
    on_connect_unix_func = (on_connect_unix_pfn_t) dlsym(koala_so_handle, "on_connect_unix");
    on_bind_func = (on_bind_pfn_t) dlsym(koala_so_handle, "on_bind");
    on_bind_unix_func = (on_bind_unix_pfn_t) dlsym(koala_so_handle, "on_bind_unix");
    before_send_func = (before_send_pfn_t) dlsym(koala_so_handle, "before_send");
    on_send_func = (on_send_pfn_t) dlsym(koala_so_handle, "on_send");
    on_recv_func = (on_recv_pfn_t) dlsym(koala_so_handle, "on_recv");
    on_sendto_func = (on_sendto_pfn_t) dlsym(koala_so_handle, "on_sendto");
    send_to_koala_func = (send_to_koala_pfn_t) dlsym(koala_so_handle, "send_to_koala");
    on_opened_file_func = (on_opened_file_pfn_t) dlsym(koala_so_handle, "on_opened_file");
    on_fopened_file_func = (on_fopened_file_pfn_t) dlsym(koala_so_handle, "on_fopened_file");
    on_write_func = (on_write_pfn_t) dlsym(koala_so_handle, "on_write");
    is_tracing_func = (is_tracing_pfn_t) dlsym(koala_so_handle, "is_tracing");
}

int is_tracing() {
    if (is_tracing_func == NULL) {
        return 0;
    }
    return is_tracing_func();
}

int bind (int socketFD, const struct sockaddr *addr, socklen_t length) {
    HOOK_SYS_FUNC( bind );
    int errno = orig_bind_func(socketFD,addr, length);
    int sslen = sizeof(struct sockaddr_un);
    struct sockaddr_un ss, *un;
    if (on_bind_func != NULL && errno == 0 && addr != NULL) {
        pid_t thread_id = get_thread_id();
        switch (addr->sa_family) {
            case AF_INET:
                on_bind_func(thread_id, socketFD, (struct sockaddr_in *)(addr));
                break;
            case AF_UNIX:
                if (getsockname(socketFD, (struct sockaddr *)&ss, &sslen) == 0) {
                    un = (struct sockaddr_un *)&ss;
                }
                on_bind_unix_func(thread_id, socketFD, un->sun_path);
                break;
        }
    }
    return errno;
}

ssize_t send(int socketFD, const void *buffer, size_t size, int flags) {
    HOOK_SYS_FUNC( send );
    ssize_t sent_size = orig_send_func(socketFD, buffer, size, flags);
    if (on_send_func != NULL && sent_size >= 0) {
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = sent_size;
        pid_t thread_id = get_thread_id();
        on_send_func(thread_id, socketFD, span, flags, 0);
    }
    return sent_size;
}

static void writev_call_on_write(int socketFD, const struct iovec *iov, int iovcnt, ssize_t sent_size) {
    ssize_t remaining_size = sent_size;
    pid_t thread_id = get_thread_id();
    for (int i = 0; i < iovcnt; i++) {
        struct ch_span span;
        span.Ptr = iov[i].iov_base;
        span.Len = iov[i].iov_len;
        if (remaining_size < iov[i].iov_len) {
            span.Len = remaining_size;
        }
        remaining_size -= span.Len;
        on_write_func(thread_id, socketFD, span);
        // len(span) == 0 should trigger the callback
        // so this check should be after on_write_func
        if (remaining_size <= 0) {
            break;
        }
    }
}

static void writev_call_on_send(int socketFD, const struct iovec *iov, int iovcnt, ssize_t sent_size) {
    ssize_t remaining_size = sent_size;
    pid_t thread_id = get_thread_id();
    for (int i = 0; i < iovcnt; i++) {
        struct ch_span span;
        span.Ptr = iov[i].iov_base;
        span.Len = iov[i].iov_len;
        if (remaining_size < iov[i].iov_len) {
            span.Len = remaining_size;
        }
        remaining_size -= span.Len;
        on_send_func(thread_id, socketFD, span, 0, 0);
        // len(span) == 0 should trigger the callback
        // so this check should be after on_write_func
        if (remaining_size <= 0) {
            break;
        }
    }
}

static ssize_t writev_in_tracing_mode(int socketFD, const struct iovec *iov, int iovcnt) {
    HOOK_SYS_FUNC( write ); // trace header is written out using write instead of writev
    pid_t thread_id = get_thread_id();
    size_t total_to_send_size;
    for (int i = 0; i < iovcnt; i++) {
        total_to_send_size += iov[i].iov_len;
    }
    struct ch_span span;
    // before send return the header to be sent, it might be the left over from last time
    // internally before_send/on_send has a finite-state-machine to handle the callback
    // might require send less data this time due to previous header sent
    // so span is passed as pointer
    size_t orig_total_to_send_size = total_to_send_size;
    struct ch_allocated_string extra_header = before_send_func(thread_id, socketFD, 0, &total_to_send_size);
    if (extra_header.Ptr != NULL) {
        // inject trace header into tcp stream
        char *remaining_ptr = extra_header.Ptr;
        size_t remaining_len = extra_header.Len;
        while (remaining_len > 0) {
            ssize_t sent_size = orig_write_func(socketFD, remaining_ptr, remaining_len);
            if (sent_size <= 0) {
                span.Ptr = NULL;
                span.Len = 0;
                // header not fully sent, remaining will be sent out next time 'send' being called
                on_send_func(thread_id, socketFD, span, 0, extra_header.Len - remaining_len);
                free(extra_header.Ptr);
                return sent_size;
            }
            remaining_ptr += sent_size;
            remaining_len -= sent_size;
        }
        free(extra_header.Ptr);
    }
    ssize_t sent_size;
    if (total_to_send_size < orig_total_to_send_size) {
        // limit the body size, as instructed by before_send
        struct iovec *shrink_iov = malloc(iovcnt * sizeof(struct iovec));
        memcpy(shrink_iov, iov, iovcnt * sizeof(struct iovec));
        for (int i = 0; i < iovcnt; i++) {
            if (shrink_iov[i].iov_len > total_to_send_size) {
                shrink_iov[i].iov_len = total_to_send_size;
                iovcnt = i + 1;
                break;
            }
            total_to_send_size -= shrink_iov[i].iov_len;
        }
        sent_size = orig_writev_func(socketFD, shrink_iov, iovcnt);
        free(shrink_iov);
    } else {
        // send out the body, without shrinking
        sent_size = orig_writev_func(socketFD, iov, iovcnt);
    }
    ssize_t remaining_size = sent_size;
    for (int i = 0; i < iovcnt; i++) {
        span.Ptr = iov[i].iov_base;
        span.Len = iov[i].iov_len;
        if (remaining_size < iov[i].iov_len) {
            span.Len = remaining_size;
        }
        remaining_size -= span.Len;
        if (i == 0) {
            on_send_func(thread_id, socketFD, span, 0, extra_header.Len);
        } else {
            on_send_func(thread_id, socketFD, span, 0, 0);
        }
        // len(span) == 0 should trigger the callback
        // so this check should be after on_write_func
        if (remaining_size <= 0) {
            break;
        }
    }
    return sent_size;
}

ssize_t writev(int socketFD, const struct iovec *iov, int iovcnt) {
    HOOK_SYS_FUNC( writev );
    if (!(on_send_func != NULL && on_write_func != NULL && before_send_func != NULL)) {
        return orig_writev_func(socketFD, iov, iovcnt);
    }
    struct stat statbuf;
    fstat(socketFD, &statbuf);
    if (!S_ISSOCK(statbuf.st_mode)) {
        ssize_t sent_size = orig_writev_func(socketFD, iov, iovcnt);
        if (sent_size >= 0) {
            writev_call_on_write(socketFD, iov, iovcnt, sent_size);
        }
        return sent_size;
    }
    if (is_tracing()) {
        return writev_in_tracing_mode(socketFD, iov, iovcnt);
    }
    ssize_t sent_size = orig_writev_func(socketFD, iov, iovcnt);
    if (sent_size >= 0) {
        writev_call_on_send(socketFD, iov, iovcnt, sent_size);
    }
    return sent_size;
}

ssize_t write(int socketFD, const void *buffer, size_t size) {
    HOOK_SYS_FUNC( write );
    ssize_t sent_size = orig_write_func(socketFD, buffer, size);
    if (on_send_func != NULL && on_write_func != NULL && sent_size >= 0) {
        struct stat statbuf;
        fstat(socketFD, &statbuf);
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = sent_size;
        pid_t thread_id = get_thread_id();
        if (S_ISSOCK(statbuf.st_mode)) {
            on_send_func(thread_id, socketFD, span, 0, 0);
        } else {
            on_write_func(thread_id, socketFD, span);
        }
    }
    return sent_size;
}

ssize_t recv (int socketFD, void *buffer, size_t size, int flags) {
    HOOK_SYS_FUNC( recv );
    ssize_t received_size = orig_recv_func(socketFD, buffer, size, flags);
    if (!(on_recv_func != NULL && received_size >= 0)) {
        return received_size; // not successful
    }
    pid_t thread_id = get_thread_id();
    if (!is_tracing()) { // not in tracing mode
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = received_size;
        on_recv_func(thread_id, socketFD, span, flags);
        return received_size;
    }
    // tracing mode
    for(;;) {
        if (received_size < 0) {
            return received_size;
        }
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = received_size;
        span = on_recv_func(thread_id, socketFD, span, flags);
        if (span.Ptr != NULL) {
            memmove((char *)buffer, span.Ptr, span.Len);
            return span.Len;
        }
        received_size = orig_recv_func(socketFD, buffer, size, flags);
    }
}

ssize_t read (int socketFD, void *buffer, size_t size) {
    HOOK_SYS_FUNC( read );
    ssize_t received_size = orig_read_func(socketFD, buffer, size);
    if (!(on_recv_func != NULL && received_size >= 0)) {
        return received_size; // not successful
    }
    struct stat statbuf;
    fstat(socketFD, &statbuf);
    if (!S_ISSOCK(statbuf.st_mode)) {
        return received_size; // not socket
    }
    pid_t thread_id = get_thread_id();
    if (!is_tracing()) { // not in tracing mode
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = received_size;
        on_recv_func(thread_id, socketFD, span, 0);
        return received_size;
    }
    // tracing mode
    for(;;) {
        if (received_size < 0) {
            return received_size;
        }
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = received_size;
        span = on_recv_func(thread_id, socketFD, span, 0);
        if (span.Ptr != NULL) {
            memmove((char *)buffer, span.Ptr, span.Len);
            return span.Len;
        }
        received_size = orig_read_func(socketFD, buffer, size);
    }
}

ssize_t sendto(int socketFD, const void *buffer, size_t buffer_size, int flags,
               const struct sockaddr *addr, socklen_t addr_size) {
    HOOK_SYS_FUNC( sendto );
    if (on_sendto_func != NULL && send_to_koala_func != NULL && addr != NULL && addr->sa_family == AF_INET) {
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = buffer_size;
        pid_t thread_id = get_thread_id();
        struct sockaddr_in *addr_in = (struct sockaddr_in *)(addr);
        if (addr_in->sin_addr.s_addr == 2139062143 /* 127.127.127.127 */ && addr_in->sin_port == 32512 /* 127 */) {
            send_to_koala_func(thread_id, span, flags);
            return 0;
        }
        on_sendto_func(thread_id, socketFD, span, flags, (struct sockaddr_in *)(addr));
    }
    return orig_sendto_func(socketFD, buffer, buffer_size, flags, addr, addr_size);
}

int connect(int socketFD, const struct sockaddr *remote_addr, socklen_t remote_addr_len) {
    HOOK_SYS_FUNC( connect );
    int sslen = sizeof(struct sockaddr_un);
    struct sockaddr_un ss, *un;
    if (on_connect_func != NULL && remote_addr != NULL) {
        pid_t thread_id = get_thread_id();
        switch (remote_addr->sa_family) {
            case AF_INET:
                on_connect_func(thread_id, socketFD, (struct sockaddr_in *)(remote_addr));
                break;
            case AF_UNIX:
                if (getsockname(socketFD, (struct sockaddr *)&ss, &sslen) == 0) {
                    un = (struct sockaddr_un *)&ss;
                }
                on_connect_unix_func(thread_id, socketFD, un->sun_path);
                break;
        }
    }
    return orig_connect_func(socketFD, remote_addr, remote_addr_len);
}

int accept4(int serverSocketFD, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    HOOK_SYS_FUNC( accept4 );
    int clientSocketFD = orig_accept4_func(serverSocketFD, addr, addrlen, flags);
    int sslen = sizeof(struct sockaddr_un);
    struct sockaddr_un ss, *un;
    load_koala_so();
    if (on_accept_func != NULL && clientSocketFD > 0 && addr != NULL) {
        pid_t thread_id = get_thread_id();
        switch (addr->sa_family) {
            case AF_INET:
                on_accept_func(thread_id, serverSocketFD, clientSocketFD, (struct sockaddr_in *)(addr));
                break;
            case AF_UNIX:
                if (getsockname(serverSocketFD, (struct sockaddr *)&ss, &sslen) == 0) {
                    un = (struct sockaddr_un *)&ss;
                }
                on_accept_unix_func(thread_id, serverSocketFD, clientSocketFD, un->sun_path);
                break;
        }
    }
    return clientSocketFD;
}

int accept(int serverSocketFD, struct sockaddr *addr, socklen_t *addrlen) {
    HOOK_SYS_FUNC( accept );
    int clientSocketFD = orig_accept_func(serverSocketFD, addr, addrlen);
    int sslen = sizeof(struct sockaddr_un);
    struct sockaddr_un ss, *un;
    load_koala_so();
    if (on_accept_func != NULL && clientSocketFD > 0 && addr != NULL) {
        pid_t thread_id = get_thread_id();
        switch (addr->sa_family) {
            case AF_INET:
                on_accept_func(thread_id, serverSocketFD, clientSocketFD, (struct sockaddr_in *)(addr));
                break;
            case AF_UNIX:
                if (getsockname(serverSocketFD, (struct sockaddr *)&ss, &sslen) == 0) {
                    un = (struct sockaddr_un *)&ss;
                }
                on_accept_unix_func(thread_id, serverSocketFD, clientSocketFD, un->sun_path);
                break;
        }
    }
    return clientSocketFD;
}

FILE * fopen(const char *filename, const char *opentype) {
    HOOK_SYS_FUNC( fopen );
    if (on_fopened_file_func == NULL) {
        return orig_fopen_func(filename, opentype);
    }
    pid_t thread_id = get_thread_id();
    struct ch_span filename_span;
    filename_span.Ptr = filename;
    filename_span.Len = strlen(filename);
    struct ch_span opentype_span;
    opentype_span.Ptr = opentype;
    opentype_span.Len = strlen(opentype);
    FILE *file = orig_fopen_func(filename, opentype);
    if (file != NULL) {
        on_fopened_file_func(thread_id, fileno(file), filename_span, opentype_span);
    }
    return file;
}

FILE * fopen64(const char *filename, const char *opentype) {
    HOOK_SYS_FUNC( fopen64 );
    if (on_fopened_file_func == NULL) {
        return orig_fopen64_func(filename, opentype);
    }
    pid_t thread_id = get_thread_id();
    struct ch_span filename_span;
    filename_span.Ptr = filename;
    filename_span.Len = strlen(filename);
    struct ch_span opentype_span;
    opentype_span.Ptr = opentype;
    opentype_span.Len = strlen(opentype);
    FILE *file = orig_fopen64_func(filename, opentype);
    if (file != NULL) {
        on_fopened_file_func(thread_id, fileno(file), filename_span, opentype_span);
    }
    return file;
}

int open(const char *filename, int flags, mode_t mode) {
    HOOK_SYS_FUNC( open );
    if (on_opened_file_func == NULL) {
        return orig_open_func(filename, flags, mode);
    }
    pid_t thread_id = get_thread_id();
    struct ch_span filename_span;
    filename_span.Ptr = filename;
    filename_span.Len = strlen(filename);
    int file = orig_open_func(filename, flags, mode);
    if (file != -1) {
        on_opened_file_func(thread_id, file, filename_span, flags, mode);
    }
    return file;
}

int open64(const char *filename, int flags, mode_t mode) {
    HOOK_SYS_FUNC( open64 );
    if (on_opened_file_func == NULL) {
        return orig_open64_func(filename, flags, mode);
    }
    pid_t thread_id = get_thread_id();
    struct ch_span filename_span;
    filename_span.Ptr = filename;
    filename_span.Len = strlen(filename);
    int file = orig_open64_func(filename, flags, mode);
    if (file != -1) {
        on_opened_file_func(thread_id, file, filename_span, flags, mode);
    }
    return file;
}
