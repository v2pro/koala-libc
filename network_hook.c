#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "span.h"

#define RTLD_NEXT	((void *) -1l)

#define HOOK_SYS_FUNC(name) if( !orig_##name##_func ) { orig_##name##_func = (name##_pfn_t)dlsym(RTLD_NEXT,#name); }

typedef ssize_t (*send_pfn_t)(int, const void *, size_t, int);
static send_pfn_t orig_send_func;

typedef ssize_t (*write_pfn_t)(int, const void *, size_t);
static write_pfn_t orig_write_func;

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

typedef int (*bind_pfn_t)(int, const struct sockaddr *, socklen_t);
static bind_pfn_t orig_bind_func;

typedef void (*on_connect_pfn_t)(pid_t p0, int p1, struct sockaddr_in* p2);
static on_connect_pfn_t on_connect_func;

typedef void (*on_bind_pfn_t)(pid_t p0, int p1, struct sockaddr_in* p2);
static on_bind_pfn_t on_bind_func;

typedef void (*on_accept_pfn_t)(pid_t p0, int p1, int p2, struct sockaddr_in* p3);
static on_accept_pfn_t on_accept_func;

typedef void (*on_send_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3);
static on_send_pfn_t on_send_func;

typedef void (*on_recv_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3);
static on_recv_pfn_t on_recv_func;

typedef void (*on_sendto_pfn_t)(pid_t p0, int p1, struct ch_span p2, int p3, struct sockaddr_in* p4);
static on_sendto_pfn_t on_sendto_func;

static void *koala_so_handle;

void network_hook_init (void) __attribute__ ((constructor));
void network_hook_init() {
    HOOK_SYS_FUNC( send );
    HOOK_SYS_FUNC( write );
    HOOK_SYS_FUNC( recv );
    HOOK_SYS_FUNC( read );
    HOOK_SYS_FUNC( sendto );
    HOOK_SYS_FUNC( connect );
    HOOK_SYS_FUNC( accept );
    HOOK_SYS_FUNC( bind );
    koala_so_handle = NULL;
    on_connect_func = NULL;
    on_bind_func = NULL;
    on_accept_func = NULL;
    on_send_func = NULL;
    on_recv_func = NULL;
    on_sendto_func = NULL;
}

int bind (int socketFD, const struct sockaddr *addr, socklen_t length) {
    int errno = orig_bind_func(socketFD,addr, length);
    if (on_bind_func != NULL && errno == 0 && addr->sa_family == AF_INET) {
        struct sockaddr_in *typed_addr = (struct sockaddr_in *)(addr);
        pid_t thread_id = syscall(__NR_gettid);
        on_bind_func(thread_id, socketFD, typed_addr);
    }
    return errno;
}

ssize_t send(int socketFD, const void *buffer, size_t size, int flags) {
    ssize_t sent_size = orig_send_func(socketFD, buffer, size, flags);
    if (on_send_func != NULL && sent_size >= 0) {
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = sent_size;
        pid_t thread_id = syscall(__NR_gettid);
        on_send_func(thread_id, socketFD, span, flags);
    }
    return sent_size;
}

ssize_t write(int socketFD, const void *buffer, size_t size) {
    ssize_t sent_size = orig_write_func(socketFD, buffer, size);
    if (on_send_func != NULL && sent_size >= 0) {
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = sent_size;
        pid_t thread_id = syscall(__NR_gettid);
        on_send_func(thread_id, socketFD, span, 0);
    }
    return sent_size;
}

ssize_t recv (int socketFD, void *buffer, size_t size, int flags) {
    ssize_t received_size = orig_recv_func(socketFD, buffer, size, flags);
    if (on_recv_func != NULL && received_size >= 0) {
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = received_size;
        pid_t thread_id = syscall(__NR_gettid);
        on_recv_func(thread_id, socketFD, span, flags);
    }
    return received_size;
}

ssize_t read (int socketFD, void *buffer, size_t size) {
    ssize_t received_size = orig_read_func(socketFD, buffer, size);
    if (on_recv_func != NULL && received_size >= 0) {
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = received_size;
        pid_t thread_id = syscall(__NR_gettid);
        on_recv_func(thread_id, socketFD, span, 0);
    }
    return received_size;
}

ssize_t sendto(int socketFD, const void *buffer, size_t buffer_size, int flags,
               const struct sockaddr *addr, socklen_t addr_size) {
    if (on_sendto_func != NULL && addr->sa_family == AF_INET) {
        struct sockaddr_in *typed_addr = (struct sockaddr_in *)(addr);
        struct ch_span span;
        span.Ptr = buffer;
        span.Len = buffer_size;
        pid_t thread_id = syscall(__NR_gettid);
        on_sendto_func(thread_id, socketFD, span, flags, typed_addr);
    }
    return orig_sendto_func(socketFD, buffer, buffer_size, flags, addr, addr_size);
}

int connect(int socketFD, const struct sockaddr *remote_addr, socklen_t remote_addr_len) {
    if (on_connect_func != NULL && remote_addr->sa_family == AF_INET) {
        struct sockaddr_in *typed_remote_addr = (struct sockaddr_in *)(remote_addr);
        pid_t thread_id = syscall(__NR_gettid);
        on_connect_func(thread_id, socketFD, typed_remote_addr);
    }
    return orig_connect_func(socketFD, remote_addr, remote_addr_len);
}

int accept(int serverSocketFD, struct sockaddr *addr, socklen_t *addrlen) {
    int clientSocketFD = orig_accept_func(serverSocketFD, addr, addrlen);
    if (koala_so_handle == NULL) {
        koala_so_handle = dlopen(getenv("KOALA_SO"), RTLD_LAZY);
        if (koala_so_handle != NULL) {
           on_accept_func = (on_accept_pfn_t) dlsym(koala_so_handle, "on_accept");
           on_connect_func = (on_connect_pfn_t) dlsym(koala_so_handle, "on_connect");
           on_bind_func = (on_bind_pfn_t) dlsym(koala_so_handle, "on_bind");
           on_send_func = (on_send_pfn_t) dlsym(koala_so_handle, "on_send");
           on_recv_func = (on_recv_pfn_t) dlsym(koala_so_handle, "on_recv");
           on_sendto_func = (on_sendto_pfn_t) dlsym(koala_so_handle, "on_sendto");
        }
    }
    if (on_accept_func != NULL && clientSocketFD > 0 && addr->sa_family == AF_INET) {
        struct sockaddr_in *typed_addr = (struct sockaddr_in *)(addr);
        pid_t thread_id = syscall(__NR_gettid);
        on_accept_func(thread_id, serverSocketFD, clientSocketFD, typed_addr);
    }
    return clientSocketFD;
}
