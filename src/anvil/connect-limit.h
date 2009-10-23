#ifndef CONNECT_LIMIT_H
#define CONNECT_LIMIT_H

struct connect_limit *connect_limit_init(void);
void connect_limit_deinit(struct connect_limit **limit);

unsigned int connect_limit_lookup(struct connect_limit *limit,
				  const char *ident);
void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const char *ident);
void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const char *ident);
void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid);
void connect_limit_dump(struct connect_limit *limit, struct ostream *output);

#endif
