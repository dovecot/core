#ifndef __LOG_H
#define __LOG_H

int log_create_pipe(const char *prefix);
void log_init(void);
void log_deinit(void);

#endif
