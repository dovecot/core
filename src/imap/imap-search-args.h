#ifndef IMAP_SEARCH_ARGS_H
#define IMAP_SEARCH_ARGS_H

#include "mail-search.h"

struct imap_arg;
struct mailbox;
struct client_command_context;

/* Builds search arguments based on IMAP arguments. Returns -1 if search
   arguments are invalid, 0 if we have to wait for unambiguity,
   1 if we can continue. */
int imap_search_args_build(struct client_command_context *cmd,
			   const struct imap_arg *args, const char *charset,
			   struct mail_search_args **search_args_r);

/* Returns -1 if set is invalid, 0 if we have to wait for unambiguity,
   1 if we were successful. search_args_r is set to contain either a seqset
   or uidset. */
int imap_search_get_anyset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_args **search_args_r);
/* Like imap_search_get_anyset(), but always returns a seqset. */
int imap_search_get_seqset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_args **search_args_r);

void imap_search_add_changed_since(struct mail_search_args *search_args,
				   uint64_t modseq);

/* Iterate search_args in batches of messages. The search_args itself is
   modified each time imap_search_seqset_iter_next() is called. Note that
   search_args is expected to come from imap_search_get_anyset(), i.e. it
   must contain only SEARCH_SEQSET or SEARCH_ALL arg. */
struct imap_search_seqset_iter *
imap_search_seqset_iter_init(struct mail_search_args *search_args,
			     uint32_t messages_count, unsigned int batch_size);
/* Iterate the next batch. Returns TRUE if the batch was updated, FALSE if
   all the batches have been iterated. */
bool imap_search_seqset_iter_next(struct imap_search_seqset_iter *iter);
void imap_search_seqset_iter_deinit(struct imap_search_seqset_iter **iter);

#endif
