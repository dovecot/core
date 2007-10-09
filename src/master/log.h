#ifndef LOG_H
#define LOG_H

struct log_io;

int log_create_pipe(struct log_io **log_r, unsigned int max_lines_per_sec);
void log_set_prefix(struct log_io *log, const char *prefix);
void log_set_pid(struct log_io *log, pid_t pid);

void log_ref(struct log_io *log_io);
void log_unref(struct log_io *log_io);

void log_init(void);
void log_deinit(void);

#endif
