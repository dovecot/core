#ifndef ADMIN_CLIENT_H
#define ADMIN_CLIENT_H

/* Error is set and reply=NULL on internal errors. */
typedef void
admin_client_callback_t(const char *reply, const char *error, void *context);

struct admin_client *
admin_client_init(const char *base_dir, const char *service, pid_t pid);
void admin_client_unref(struct admin_client **client);

void admin_client_send_cmd(struct admin_client *client, const char *cmdline,
			   admin_client_callback_t *callback, void *context);
#define admin_client_send_cmd(client, cmd, callback, context) \
	admin_client_send_cmd(client, cmd, \
		(admin_client_callback_t *)callback, \
		TRUE ? context : CALLBACK_TYPECHECK(callback, \
				void (*)(const char *, const char *, \
					 typeof(context))))

void admin_clients_init(void);
void admin_clients_deinit(void);

#endif
