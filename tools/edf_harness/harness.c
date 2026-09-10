/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Periodic harness for the flow scheduler.
 * Each worker runs periodic jobs with start jitter
 * plus period plus execution.
 * All threads run with the default policy with no
 * realtime use. One probe thread wakes each 10ms and
 * records wake delay as a light baseline. The control
 * flag marks baseline runs for A and B comparison.
 * The scheduler never kills, the harness counts a
 * miss when wall completion passes release plus
 * deadline. Switch counts use voluntary switches
 * from thread resource use with no extra sampling.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
/* Least period in nanos. Matches the harness range. */
#define HARNESS_PERIOD_MIN_NS (120ULL * 1000ULL * 1000ULL)
/* Most period in nanos. Matches the harness range. */
#define HARNESS_PERIOD_MAX_NS (320ULL * 1000ULL * 1000ULL)
/* Least execution in nanos. Matches the harness range. */
#define HARNESS_AET_MIN_NS (2ULL * 1000ULL * 1000ULL)
/* Most execution in nanos. Matches the harness range. */
#define HARNESS_AET_MAX_NS (16ULL * 1000ULL * 1000ULL)
/* Most start jitter in nanos. Matches the range. */
#define HARNESS_JITTER_MAX_NS (1ULL * 1000ULL * 1000ULL)
/* Probe period in nanos at 10ms with no knob. */
#define HARNESS_PROBE_NS (10ULL * 1000ULL * 1000ULL)
/* Per thread counts for one run. */
struct thread_out {
    uint64_t released;
    uint64_t completed;
    uint64_t sum_released_ns;
    uint64_t sum_completed_ns;
    double sum_ratio;
    long nvcsw;
    long nivcsw;
};
/* Probe counts for one run with light wakeups. */
struct probe_out {
    uint64_t count;
    uint64_t sum_delay_ns;
    uint64_t max_delay_ns;
};
/* Shared run state for all threads. */
struct run_state {
    int nthreads;
    uint64_t duration_ns;
    unsigned int seed_base;
    int control;
    struct thread_out *outs;
    struct probe_out probe;
    pthread_barrier_t start_bar;
};
/* Time now in nanos on the boot clock. */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL +
        (uint64_t)ts.tv_nsec;
}
/* Keep the calling thread on the default policy. */
static void ensure_default(void)
{
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp);
}
/* Uniform nanos in closed range using thread seed. */
static uint64_t uniform_ns(unsigned int *seed, uint64_t lo,
    uint64_t hi)
{
    uint64_t span = hi - lo + 1ULL;
    uint64_t r = (uint64_t)rand_r(seed);
    uint64_t r2 = (uint64_t)rand_r(seed);
    r = (r << 32) | (r2 & 0xFFFFFFFFULL);
    return lo + (r % span);
}
/* Burn CPU for given nanos with no sleep. */
static void burn_ns(uint64_t ns)
{
    uint64_t start = now_ns();
    uint64_t end = start + ns;
    while (now_ns() < end) {
        __asm__ volatile("" ::: "memory");
    }
}
/* Sleep until target nanos, returns now after sleep. */
static uint64_t sleep_until(uint64_t target)
{
    uint64_t now = now_ns();
    if (target <= now)
        return now;
    for (;;) {
        uint64_t left = target - now;
        struct timespec req;
        struct timespec rem;
        req.tv_sec = (time_t)(left / 1000000000ULL);
        req.tv_nsec = (long)(left % 1000000000ULL);
        if (nanosleep(&req, &rem) == 0)
            return now_ns();
        if (errno != EINTR)
            return now_ns();
        now = now_ns();
        if (now >= target)
            return now;
    }
}
/* Worker arg carries run state plus thread index. */
struct worker_arg {
    struct run_state *st;
    int idx;
};
/* Probe arg carries run state with no index. */
struct probe_arg {
    struct run_state *st;
};
/* Periodic loop for one thread index. */
static void *worker_idx(void *arg)
{
    struct worker_arg *wa = (struct worker_arg *)arg;
    struct run_state *st = wa->st;
    int idx = wa->idx;
    struct thread_out *out = &st->outs[idx];
    unsigned int seed = st->seed_base +
        (unsigned int)idx * 7919U;
    uint64_t jitter;
    uint64_t t0;
    uint64_t wall_end;
    struct rusage ru_start;
    struct rusage ru_end;
    ensure_default();
    memset(out, 0, sizeof(*out));
    jitter = uniform_ns(&seed, 0, HARNESS_JITTER_MAX_NS);
    pthread_barrier_wait(&st->start_bar);
    t0 = now_ns();
    wall_end = t0 + st->duration_ns;
    if (jitter > 0) {
        struct timespec req;
        struct timespec rem;
        req.tv_sec = (time_t)(jitter / 1000000000ULL);
        req.tv_nsec = (long)(jitter % 1000000000ULL);
        while (nanosleep(&req, &rem) != 0 && errno == EINTR)
            req = rem;
    }
    getrusage(RUSAGE_THREAD, &ru_start);
    {
        uint64_t release = now_ns();
        uint64_t now;
        now = release;
        while (now < wall_end) {
            uint64_t period;
            uint64_t aet;
            uint64_t deadline;
            uint64_t burn_end;
            period = uniform_ns(&seed,
                HARNESS_PERIOD_MIN_NS,
                HARNESS_PERIOD_MAX_NS);
            aet = uniform_ns(&seed, HARNESS_AET_MIN_NS,
                HARNESS_AET_MAX_NS);
            deadline = release + period;
            burn_ns(aet);
            burn_end = now_ns();
            out->released += 1;
            out->sum_released_ns += aet;
            out->sum_ratio += (double)aet / (double)period;
            if (burn_end <= deadline) {
                out->completed += 1;
                out->sum_completed_ns += aet;
            }
            if (burn_end < release + period) {
                now = sleep_until(release + period);
                release = release + period;
            } else {
                now = burn_end;
                release = burn_end;
            }
            if (now >= wall_end)
                break;
        }
    }
    getrusage(RUSAGE_THREAD, &ru_end);
    out->nvcsw = (long)ru_end.ru_nvcsw -
        (long)ru_start.ru_nvcsw;
    out->nivcsw = (long)ru_end.ru_nivcsw -
        (long)ru_start.ru_nivcsw;
    return NULL;
}
/* Light probe loop with 10ms wakes and delay stats. */
static void *probe_idx(void *arg)
{
    struct probe_arg *pa = (struct probe_arg *)arg;
    struct run_state *st = pa->st;
    uint64_t t0;
    uint64_t wall_end;
    uint64_t expect;
    ensure_default();
    pthread_barrier_wait(&st->start_bar);
    t0 = now_ns();
    wall_end = t0 + st->duration_ns;
    expect = t0 + HARNESS_PROBE_NS;
    while (expect < wall_end) {
        uint64_t now;
        uint64_t delay;
        now = sleep_until(expect);
        if (now > expect)
            delay = now - expect;
        else
            delay = 0;
        st->probe.count += 1;
        st->probe.sum_delay_ns += delay;
        if (delay > st->probe.max_delay_ns)
            st->probe.max_delay_ns = delay;
        expect += HARNESS_PROBE_NS;
        if (now >= wall_end)
            break;
    }
    return NULL;
}
/* Read scheduler state with no change, unknown else. */
static void read_sched_state(char *buf, size_t len)
{
    FILE *f;
    if (len == 0)
        return;
    buf[0] = '\0';
    f = fopen("/sys/kernel/sched_ext/state", "r");
    if (!f) {
        snprintf(buf, len, "unknown");
        return;
    }
    if (!fgets(buf, (int)len, f))
        snprintf(buf, len, "unknown");
    else
        buf[strcspn(buf, "\r\n")] = '\0';
    fclose(f);
}
/* Print short use and exit with failure. */
static void usage(const char *prog)
{
    fprintf(stderr, "use %s -n N -d SECS -s SEED -o PREFIX\n",
        prog);
    fprintf(stderr, "    add -c 1 to mark a control run\n");
    exit(2);
}
/* Main. Parses args, runs threads, writes CSV plus JSON. */
int main(int argc, char **argv)
{
    int nthreads = 0;
    double duration_secs = 60.0;
    unsigned int seed_base = 1;
    const char *prefix = "harness";
    int control = 0;
    int opt;
    struct run_state st;
    struct worker_arg *wargs = NULL;
    struct probe_arg parg;
    pthread_t *threads = NULL;
    pthread_t probe;
    uint64_t wall_start = 0;
    uint64_t wall_end = 0;
    double wall_secs = 0.0;
    long ncpu = 0;
    uint64_t total_released = 0;
    uint64_t total_completed = 0;
    uint64_t total_released_ns = 0;
    uint64_t total_completed_ns = 0;
    double total_ratio = 0.0;
    long total_nvcsw = 0;
    long total_nivcsw = 0;
    double util_offered = 0.0;
    double util_exact = 0.0;
    double completion = 0.0;
    double util_effective = 0.0;
    double probe_avg_us = 0.0;
    double probe_max_us = 0.0;
    char sched_state[64];
    char csv_path[1024];
    char json_path[1024];
    FILE *csv = NULL;
    FILE *json = NULL;
    int i;
    while ((opt = getopt(argc, argv, "n:d:s:o:c:")) != -1) {
        switch (opt) {
        case 'n':
            nthreads = atoi(optarg);
            break;
        case 'd':
            duration_secs = atof(optarg);
            break;
        case 's':
            seed_base = (unsigned int)atoi(optarg);
            break;
        case 'o':
            prefix = optarg;
            break;
        case 'c':
            control = atoi(optarg) != 0;
            break;
        default:
            usage(argv[0]);
            break;
        }
    }
    if (nthreads <= 0)
        usage(argv[0]);
    if (duration_secs <= 0.0)
        usage(argv[0]);
    ensure_default();
    ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0)
        ncpu = 1;
    memset(&st, 0, sizeof(st));
    st.nthreads = nthreads;
    st.duration_ns =
        (uint64_t)(duration_secs * 1000000000.0);
    st.seed_base = seed_base;
    st.control = control;
    st.outs = calloc((size_t)nthreads,
        sizeof(struct thread_out));
    wargs = calloc((size_t)nthreads,
        sizeof(struct worker_arg));
    threads = calloc((size_t)nthreads, sizeof(pthread_t));
    if (!st.outs || !wargs || !threads) {
        fprintf(stderr, "no memory\n");
        return 1;
    }
    read_sched_state(sched_state, sizeof(sched_state));
    pthread_barrier_init(&st.start_bar, NULL,
        (unsigned)nthreads + 1U + 1U);
    for (i = 0; i < nthreads; i++) {
        wargs[i].st = &st;
        wargs[i].idx = i;
        if (pthread_create(&threads[i], NULL, worker_idx,
            &wargs[i]) != 0) {
            fprintf(stderr, "thread create failed\n");
            return 1;
        }
    }
    parg.st = &st;
    if (pthread_create(&probe, NULL, probe_idx,
        &parg) != 0) {
        fprintf(stderr, "probe create failed\n");
        return 1;
    }
    pthread_barrier_wait(&st.start_bar);
    wall_start = now_ns();
    for (i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(probe, NULL);
    wall_end = now_ns();
    wall_secs = (double)(wall_end - wall_start) /
        1000000000.0;
    if (wall_secs <= 0.0)
        wall_secs = duration_secs;
    for (i = 0; i < nthreads; i++) {
        total_released += st.outs[i].released;
        total_completed += st.outs[i].completed;
        total_released_ns += st.outs[i].sum_released_ns;
        total_completed_ns += st.outs[i].sum_completed_ns;
        total_ratio += st.outs[i].sum_ratio;
        total_nvcsw += st.outs[i].nvcsw;
        total_nivcsw += st.outs[i].nivcsw;
    }
    util_offered = (double)total_released_ns / wall_secs /
        1000000000.0 / (double)ncpu;
    if (total_released > 0)
        util_exact = (total_ratio /
            (double)total_released) *
            (double)nthreads / (double)ncpu;
    else
        util_exact = 0.0;
    if (total_released > 0)
        completion = (double)total_completed /
            (double)total_released;
    util_effective = (double)total_completed_ns / wall_secs /
        1000000000.0 / (double)ncpu;
    if (st.probe.count > 0) {
        probe_avg_us = (double)st.probe.sum_delay_ns /
            (double)st.probe.count / 1000.0;
        probe_max_us = (double)st.probe.max_delay_ns /
            1000.0;
    }
    snprintf(csv_path, sizeof(csv_path), "%s.csv", prefix);
    snprintf(json_path, sizeof(json_path), "%s.json", prefix);
    csv = fopen(csv_path, "w");
    if (!csv) {
        perror("csv open");
        return 1;
    }
    fprintf(csv, "nthreads,ncpu,wall_secs,released,completed,");
    fprintf(csv, "completion,offered_util,exact_util,");
    fprintf(csv, "effective_util,nvcsw,nivcsw,probe_count,");
    fprintf(csv, "probe_avg_us,probe_max_us,control,sched\n");
    fprintf(csv, "%d,%ld,%.3f,%" PRIu64 ",%" PRIu64 ",",
        nthreads, ncpu, wall_secs, total_released,
        total_completed);
    fprintf(csv, "%.6f,%.6f,%.6f,%.6f,%ld,%ld,",
        completion, util_offered, util_exact,
        util_effective, total_nvcsw, total_nivcsw);
    fprintf(csv, "%" PRIu64 ",%.3f,%.3f,%d,%s\n",
        st.probe.count, probe_avg_us,
        probe_max_us, control, sched_state);
    fclose(csv);
    json = fopen(json_path, "w");
    if (!json) {
        perror("json open");
        return 1;
    }
    fprintf(json, "{\n");
    fprintf(json, "  \"nthreads\": %d,\n", nthreads);
    fprintf(json, "  \"ncpu\": %ld,\n", ncpu);
    fprintf(json, "  \"wall_secs\": %.3f,\n", wall_secs);
    fprintf(json, "  \"released\": %" PRIu64 ",\n",
        total_released);
    fprintf(json, "  \"completed\": %" PRIu64 ",\n",
        total_completed);
    fprintf(json, "  \"completion\": %.6f,\n", completion);
    fprintf(json, "  \"offered_util\": %.6f,\n", util_offered);
    fprintf(json, "  \"exact_util\": %.6f,\n", util_exact);
    fprintf(json, "  \"effective_util\": %.6f,\n",
        util_effective);
    fprintf(json, "  \"nvcsw\": %ld,\n", total_nvcsw);
    fprintf(json, "  \"nivcsw\": %ld,\n", total_nivcsw);
    fprintf(json, "  \"probe_count\": %" PRIu64 ",\n",
        st.probe.count);
    fprintf(json, "  \"probe_avg_us\": %.3f,\n", probe_avg_us);
    fprintf(json, "  \"probe_max_us\": %.3f,\n", probe_max_us);
    fprintf(json, "  \"control\": %d,\n", control);
    fprintf(json, "  \"sched\": \"%s\",\n", sched_state);
    fprintf(json, "  \"seed\": %u,\n", seed_base);
    fprintf(json, "  \"duration_secs\": %.3f\n", duration_secs);
    fprintf(json, "}\n");
    fclose(json);
    printf("done n=%d released=%" PRIu64 " completed=%" PRIu64
        " completion=%.4f offered=%.4f exact=%.4f",
        nthreads, total_released, total_completed,
        completion, util_offered, util_exact);
    printf(" effective=%.4f nvcsw=%ld probe_avg=%.1fus",
        util_effective, total_nvcsw, probe_avg_us);
    printf(" probe_max=%.1fus control=%d sched=%s\n",
        probe_max_us, control, sched_state);
    pthread_barrier_destroy(&st.start_bar);
    free(st.outs);
    free(wargs);
    free(threads);
    return 0;
}
