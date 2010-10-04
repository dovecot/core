#ifndef SUBSCRIPTION_FILE_H
#define SUBSCRIPTION_FILE_H

struct mailbox_list;

/* Initialize new subscription file listing. */
struct subsfile_list_context *
subsfile_list_init(struct mailbox_list *list, const char *path);

/* Deinitialize subscription file listing. Returns 0 if ok, or -1 if some
   error occurred while listing. */
int subsfile_list_deinit(struct subsfile_list_context *ctx);
/* Returns the next subscribed mailbox, or NULL. */
const char *subsfile_list_next(struct subsfile_list_context *ctx);

/* Returns 1 if subscribed, 0 if no changes done, -1 if error. */
int subsfile_set_subscribed(struct mailbox_list *list, const char *path,
			    const char *temp_prefix, const char *name,
			    bool set);

#endif
