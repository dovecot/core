#ifndef MAILDIR_KEYWORDS_H
#define MAILDIR_KEYWORDS_H

#define MAILDIR_KEYWORDS_NAME "dovecot-keywords"

struct maildir_mailbox;
struct maildir_keywords;
struct maildir_keywords_sync_ctx;

struct maildir_keywords *maildir_keywords_init(struct maildir_mailbox *mbox);
void maildir_keywords_deinit(struct maildir_keywords **mk);

/* Initialize a read-only maildir_keywords instance. Mailbox needs to contain
   the dovecot-keywords file, but otherwise it doesn't have to be in maildir
   format. */
struct maildir_keywords *
maildir_keywords_init_readonly(struct mailbox *box);

struct maildir_keywords_sync_ctx *
maildir_keywords_sync_init(struct maildir_keywords *mk,
			   struct mail_index *index);
/* Don't try to add any nonexistent keywords */
struct maildir_keywords_sync_ctx *
maildir_keywords_sync_init_readonly(struct maildir_keywords *mk,
				    struct mail_index *index);
void maildir_keywords_sync_deinit(struct maildir_keywords_sync_ctx **ctx);

/* Returns keyword index. */
unsigned int maildir_keywords_char_idx(struct maildir_keywords_sync_ctx *ctx,
				       char keyword);
/* Returns keyword character for given index, or \0 if keyword couldn't be
   added. */
char maildir_keywords_idx_char(struct maildir_keywords_sync_ctx *ctx,
			       unsigned int idx);

#endif
