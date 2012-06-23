#ifndef CHECKPASSWORD_COMMON_H
#define CHECKPASSWORD_COMMON_H

#include "auth-request.h"

enum db_checkpassword_status {
	DB_CHECKPASSWORD_STATUS_INTERNAL_FAILURE = -1,
	/* auth unsuccessful / user not found */
	DB_CHECKPASSWORD_STATUS_FAILURE = 0,
	DB_CHECKPASSWORD_STATUS_OK = 1
};

typedef void db_checkpassword_callback_t(struct auth_request *request,
					 enum db_checkpassword_status status,
					 const char *const *extra_fields,
					 void (*request_callback)());

struct db_checkpassword *
db_checkpassword_init(const char *checkpassword_path,
		      const char *checkpassword_reply_path);
void db_checkpassword_deinit(struct db_checkpassword **db);

void db_checkpassword_call(struct db_checkpassword *db,
			   struct auth_request *request,
			   const char *auth_password,
			   db_checkpassword_callback_t *callback,
			   void (*request_callback)()) ATTR_NULL(3);

#endif
