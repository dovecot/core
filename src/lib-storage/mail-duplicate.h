#ifndef MAIL_DUPLICATE_H
#define MAIL_DUPLICATE_H

struct mail_duplicate_db;
struct mail_storage_settings;

enum mail_duplicate_check_result {
	/* The ID exists. The ID is not locked. */
	MAIL_DUPLICATE_CHECK_RESULT_EXISTS,
	/* The ID doesn't exist yet. The ID gets locked. */
	MAIL_DUPLICATE_CHECK_RESULT_NOT_FOUND,
};

#define MAIL_DUPLICATE_DEFAULT_KEEP (3600 * 24)

enum mail_duplicate_check_result
mail_duplicate_check(struct mail_duplicate_db *db,
		     const void *id, size_t id_size, const char *user);
void mail_duplicate_mark(struct mail_duplicate_db *db,
			 const void *id, size_t id_size,
			 const char *user, time_t timestamp);

void mail_duplicate_db_flush(struct mail_duplicate_db *db);

struct mail_duplicate_db *
mail_duplicate_db_init(struct mail_user *user, const char *name);
void mail_duplicate_db_deinit(struct mail_duplicate_db **db);

#endif
