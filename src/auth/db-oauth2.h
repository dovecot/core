#ifndef DB_OAUTH2_H
#define DB_OAUTH2_H 1

struct db_oauth2;
struct oauth2_request;
struct db_oauth2_request;

typedef void db_oauth2_lookup_callback_t(struct db_oauth2_request *request,
					 enum passdb_result result,
					 const char *error,
					 void *context);
struct db_oauth2_request {
	pool_t pool;
	struct db_oauth2_request *prev,*next;

	struct db_oauth2 *db;
	struct oauth2_request *req;

	/* username to match */
	const char *username;
	/* token to use */
	const char *token;

	struct auth_request *auth_request;
	struct auth_fields *fields;

	db_oauth2_lookup_callback_t *callback;
	void *context;
	verify_plain_callback_t *verify_callback;
};


struct db_oauth2 *db_oauth2_init(const char *config_path);

void db_oauth2_ref(struct db_oauth2 *);
void db_oauth2_unref(struct db_oauth2 **);

bool db_oauth2_uses_password_grant(const struct db_oauth2 *db);

void db_oauth2_lookup(struct db_oauth2 *db, struct db_oauth2_request *req, const char *token, struct auth_request *request, db_oauth2_lookup_callback_t *callback, void *context);
#define db_oauth2_lookup(db, req, token, request, callback, context) \
	db_oauth2_lookup(db, req, token + \
		CALLBACK_TYPECHECK(callback, void(*)(struct db_oauth2_request *, enum passdb_result, const char*, typeof(context))), \
		request, (db_oauth2_lookup_callback_t*)callback, (void*)context)

#endif
