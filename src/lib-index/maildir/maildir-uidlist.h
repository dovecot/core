#ifndef __MAILDIR_UIDLIST_H
#define __MAILDIR_UIDLIST_H

#define INDEX_IS_UIDLIST_LOCKED(index) \
        ((index)->maildir_lock_fd != -1)

#define MAILDIR_UIDLIST_NAME "dovecot-uidlist"

struct maildir_uidlist {
	struct mail_index *index;
	char *fname;
	struct istream *input;

	unsigned int uid_validity, next_uid, last_read_uid;
	unsigned int rewrite:1;
};

struct maildir_uidlist_rec {
	unsigned int uid;
	const char *filename;
};

int maildir_uidlist_try_lock(struct mail_index *index);
void maildir_uidlist_unlock(struct mail_index *index);
int maildir_uidlist_rewrite(struct mail_index *index, time_t *mtime);

struct maildir_uidlist *maildir_uidlist_open(struct mail_index *index);
void maildir_uidlist_close(struct maildir_uidlist *uidlist);

/* Returns -1 if error, 0 if end of file or 1 if found.
   uid_rec.uid is also set to 0 at EOF. This function does sanity checks so
   you can be sure that uid_rec.uid is always growing and smaller than
   uidlist->next_uid. */
int maildir_uidlist_next(struct maildir_uidlist *uidlist,
			 struct maildir_uidlist_rec *uid_rec);

#endif
