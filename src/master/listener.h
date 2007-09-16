#ifndef LISTENER_H
#define LISTENER_H

void listeners_open_fds(struct server_settings *old_set, bool retry);
void listeners_close_fds(void);

#endif
