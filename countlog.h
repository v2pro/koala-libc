#ifndef __COUNTLOG_H__
#define __COUNTLOG_H__

typedef void (*countlog1_pfn_t)(int, struct ch_span, struct ch_span, struct ch_span);
static countlog1_pfn_t countlog1_func = NULL;

void load_koala_so_countlog(void *koala_so_handle) {
    countlog1_func = (countlog1_pfn_t) dlsym(koala_so_handle, "countlog1");
}

static pid_t get_thread_id() {
    return syscall(__NR_gettid);
}

static void countlog_info(const char *event) {
    if (countlog1_func == NULL) {
        return;
    }
    struct ch_span event_span;
    event_span.Ptr = event;
    event_span.Len = strlen(event);
    struct ch_span k1_span;
    k1_span.Ptr = "threadID";
    k1_span.Len = strlen("threadID");
    struct ch_span v1_span;
    char v1 [32];
    v1_span.Ptr = v1;
    v1_span.Len = sprintf(v1, "%d", get_thread_id());
    countlog1_func(30, event_span, k1_span, v1_span);
}

#endif