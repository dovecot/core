#ifndef __SSL_INIT_H
#define __SSL_INIT_H

void ssl_parameter_process_destroyed(pid_t pid);

void ssl_init(void);
void ssl_deinit(void);

#endif
