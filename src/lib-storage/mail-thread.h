#ifndef __MAIL_THREAD_H
#define __MAIL_THREAD_H

#include "mail-storage.h"
#include "mail-sort.h"

struct mail_thread_context;

struct mail_thread_context *
mail_thread_init(enum mail_thread_type type, struct ostream *output,
		 const struct mail_sort_callbacks *callbacks,
		 void *callback_context);

/* id is either UID or sequence number of message, whichever is preferred
   in mail_thread_callbacks parameters. */
void mail_thread_input(struct mail_thread_context *ctx, unsigned int id,
		       const char *message_id, const char *in_reply_to,
		       const char *references);

void mail_thread_finish(struct mail_thread_context *ctx);

#endif
