#ifndef __LOG_H
#define __LOG_H

struct log_io;

int log_create_pipe(struct log_io **log_r, unsigned int max_lines_per_sec);
void log_set_prefix(struct log_io *log, const char *prefix);

void log_init(void);
void log_deinit(void);

#endif
