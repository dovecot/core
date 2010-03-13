#ifndef USERDB_BLOCKING_H
#define USERDB_BLOCKING_H

void userdb_blocking_lookup(struct auth_request *request);

struct userdb_iterate_context *
userdb_blocking_iter_init(struct userdb_module *userdb,
			  userdb_iter_callback_t *callback, void *context);
void userdb_blocking_iter_next(struct userdb_iterate_context *ctx);
int userdb_blocking_iter_deinit(struct userdb_iterate_context **ctx);

#endif
