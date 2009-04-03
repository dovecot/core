#ifndef LISTENER_H
#define LISTENER_H

void listeners_open_fds(struct master_server_settings *old_set, bool retry);
void listeners_close_fds(void);

#endif
