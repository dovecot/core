#ifndef __PASSDB_BLOCKING_H
#define __PASSDB_BLOCKING_H

void passdb_blocking_verify_plain(struct auth_request *request);
void passdb_blocking_lookup_credentials(struct auth_request *request);

#endif
