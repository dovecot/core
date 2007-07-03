#ifndef __LISTENER_H
#define __LISTENER_H

void listeners_open_fds(struct server_settings *old_set, bool retry);
void listeners_close_fds(void);

#endif
