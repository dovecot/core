#ifndef PASSDB_BLOCKING_H
#define PASSDB_BLOCKING_H

enum passdb_result
passdb_blocking_auth_worker_reply_parse(struct auth_request *request, const char *reply);
void passdb_blocking_verify_plain(struct auth_request *request);
void passdb_blocking_lookup_credentials(struct auth_request *request);
void passdb_blocking_set_credentials(struct auth_request *request,
				     const char *new_credentials);

#endif
