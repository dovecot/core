#ifndef QUOTA_H
#define QUOTA_H

struct mail;
struct mailbox;
struct mail_user;

/* Message storage size kilobytes. */
#define QUOTA_NAME_STORAGE_KILOBYTES "STORAGE"
/* Message storage size bytes. This is used only internally. */
#define QUOTA_NAME_STORAGE_BYTES "STORAGE_BYTES"
/* Number of messages. */
#define QUOTA_NAME_MESSAGES "MESSAGE"

struct quota;
struct quota_settings;
struct quota_root_settings;
struct quota_root;
struct quota_root_iter;
struct quota_transaction_context;

struct quota_param_parser {
	char *param_name;
	void (* param_handler)(struct quota_root *_root, const char *param_value);
};

extern struct quota_param_parser quota_param_hidden;
extern struct quota_param_parser quota_param_ignoreunlimited;
extern struct quota_param_parser quota_param_noenforcing;
extern struct quota_param_parser quota_param_ns;

enum quota_recalculate {
	QUOTA_RECALCULATE_DONT = 0,
	/* We may want to recalculate quota because we weren't able to call
	   quota_free*() correctly for all mails. Quota needs to be
	   recalculated unless the backend does the quota tracking
	   internally. */
	QUOTA_RECALCULATE_MISSING_FREES,
	/* doveadm quota recalc called - make sure the quota is correct */
	QUOTA_RECALCULATE_FORCED
};

enum quota_alloc_result {
	QUOTA_ALLOC_RESULT_OK,
	QUOTA_ALLOC_RESULT_TEMPFAIL,
	QUOTA_ALLOC_RESULT_OVER_MAXSIZE,
	QUOTA_ALLOC_RESULT_OVER_QUOTA,
	/* Mail size is larger than even the maximum allowed quota. */
	QUOTA_ALLOC_RESULT_OVER_QUOTA_LIMIT,
	/* Blocked by ongoing background quota calculation. */
	QUOTA_ALLOC_RESULT_BACKGROUND_CALC,
};

/* Anything <= QUOTA_GET_RESULT_INTERNAL_ERROR is an error. */
enum quota_get_result {
	/* Ongoing background quota calculation */
	QUOTA_GET_RESULT_BACKGROUND_CALC,
	/* Quota resource name doesn't exist */
	QUOTA_GET_RESULT_UNKNOWN_RESOURCE,
	/* Internal error */
	QUOTA_GET_RESULT_INTERNAL_ERROR,

	/* Quota limit exists and was returned successfully */
	QUOTA_GET_RESULT_LIMITED,
	/* Quota is unlimited, but its value was returned */
	QUOTA_GET_RESULT_UNLIMITED,
};

const char *quota_alloc_result_errstr(enum quota_alloc_result res,
		struct quota_transaction_context *qt);

int quota_user_read_settings(struct mail_user *user,
			     struct quota_settings **set_r,
			     const char **error_r);
void quota_settings_deinit(struct quota_settings **quota_set);

/* Add a new rule too the quota root. Returns 0 if ok, -1 if rule is invalid. */
int quota_root_add_rule(struct quota_root_settings *root_set,
			const char *rule_def, const char **error_r);
/* Add a new warning rule for the quota root. Returns 0 if ok, -1 if rule is
   invalid. */
int quota_root_add_warning_rule(struct quota_root_settings *root_set,
				const char *rule_def, const char **error_r);

/* Initialize quota for the given user. Returns 0 and quota_r on success,
   -1 and error_r on failure. */
int quota_init(struct quota_settings *quota_set, struct mail_user *user,
	       struct quota **quota_r, const char **error_r);
void quota_deinit(struct quota **quota);

/* List all visible quota roots. They don't need to be freed. */
struct quota_root_iter *quota_root_iter_init_user(struct mail_user *user);
struct quota_root_iter *quota_root_iter_init(struct mailbox *box);
struct quota_root *quota_root_iter_next(struct quota_root_iter *iter);
void quota_root_iter_deinit(struct quota_root_iter **iter);

/* Return quota root or NULL. */
struct quota_root *quota_root_lookup(struct mail_user *user, const char *name);

/* Returns name of the quota root. */
const char *quota_root_get_name(struct quota_root *root);
/* Return a list of all resources set for the quota root. */
const char *const *quota_root_get_resources(struct quota_root *root);
/* Returns TRUE if quota root is marked as hidden (so it shouldn't be visible
   to users via IMAP GETQUOTAROOT command). */
bool quota_root_is_hidden(struct quota_root *root);

/* Returns 1 if values were successfully returned, 0 if resource name doesn't
   exist or isn't enabled, -1 if error. */
enum quota_get_result
quota_get_resource(struct quota_root *root, const char *mailbox_name,
		   const char *name, uint64_t *value_r, uint64_t *limit_r,
		   const char **error_r);
/* Returns 0 if OK, -1 if error (eg. permission denied, invalid name). */
int quota_set_resource(struct quota_root *root, const char *name,
		       uint64_t value, const char **client_error_r);

/* Start a new quota transaction. */
struct quota_transaction_context *quota_transaction_begin(struct mailbox *box);
/* Commit quota transaction. Returns 0 if ok, -1 if failed. */
int quota_transaction_commit(struct quota_transaction_context **ctx);
/* Rollback quota transaction changes. */
void quota_transaction_rollback(struct quota_transaction_context **ctx);

/* Allocate from quota if there's space. error_r is set when result is not
 * QUOTA_ALLOC_RESULT_OK. */
enum quota_alloc_result quota_try_alloc(struct quota_transaction_context *ctx,
					struct mail *mail, const char **error_r);
/* Like quota_try_alloc(), but don't actually allocate anything. */
enum quota_alloc_result quota_test_alloc(struct quota_transaction_context *ctx,
					 uoff_t size, const char **error_r);
/* Update quota by allocating/freeing space used by mail. */
void quota_alloc(struct quota_transaction_context *ctx, struct mail *mail);
void quota_free_bytes(struct quota_transaction_context *ctx,
		      uoff_t physical_size);
/* Mark the quota to be recalculated */
void quota_recalculate(struct quota_transaction_context *ctx,
		       enum quota_recalculate recalculate);

/* Execute quota_over_scripts if needed. */
void quota_over_flag_check_startup(struct quota *quota);

/* Common quota parameters parsing loop */
int quota_parse_parameters(struct quota_root *root, const char **args, const char **error_r,
			   const struct quota_param_parser *valid_params, bool fail_on_unknown);

#endif
