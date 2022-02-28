#ifndef MAIL_DUPLICATE_H
#define MAIL_DUPLICATE_H

struct mail_duplicate_db;

enum mail_duplicate_check_result {
	/* The ID exists. The ID is not locked. */
	MAIL_DUPLICATE_CHECK_RESULT_EXISTS,
	/* The ID doesn't exist yet. The ID gets locked. */
	MAIL_DUPLICATE_CHECK_RESULT_NOT_FOUND,
	/* Internal I/O error (e.g. permission error) */
	MAIL_DUPLICATE_CHECK_RESULT_IO_ERROR,
	/* Locking timed out. */
	MAIL_DUPLICATE_CHECK_RESULT_LOCK_TIMEOUT,
	/* Too many locks held. */
	MAIL_DUPLICATE_CHECK_RESULT_TOO_MANY_LOCKS,
	/* Locking detected a deadlock. The caller should rollback the
	   transaction to release all locks, do a short random sleep, retry
	   and hope that the next attempt succeeds. */
	MAIL_DUPLICATE_CHECK_RESULT_DEADLOCK,
};

struct mail_duplicate_transaction *
mail_duplicate_transaction_begin(struct mail_duplicate_db *db);
void mail_duplicate_transaction_rollback(
	struct mail_duplicate_transaction **_trans);
void mail_duplicate_transaction_commit(
	struct mail_duplicate_transaction **_trans);

/* Check if id exists in the duplicate database. If not, lock the id. Any
   further checks for the same id in other processes will block until the first
   one's transaction is finished. Because checks can be done in different order
   by different processes, this can result in a deadlock. The caller should
   handle it by rolling back the transaction and retrying. */
enum mail_duplicate_check_result
mail_duplicate_check(struct mail_duplicate_transaction *trans,
		     const void *id, size_t id_size, const char *user);
/* Add id to the duplicate database. The writing isn't done until transaction
   is committed. There's no locking done by this call. If locking is needed,
   mail_duplicate_check() should be called first. */
void mail_duplicate_mark(struct mail_duplicate_transaction *trans,
			 const void *id, size_t id_size,
			 const char *user, time_t timestamp);

struct mail_duplicate_db *
mail_duplicate_db_init(struct mail_user *user, const char *name);
void mail_duplicate_db_deinit(struct mail_duplicate_db **db);

#endif
