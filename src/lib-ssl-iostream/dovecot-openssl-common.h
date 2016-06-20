#ifndef DOVECOT_OPENSSL_COMMON_H
#define DOVECOT_OPENSSL_COMMON_H

/* Initialize OpenSSL if this is the first instance.
   Increase initialization reference count. */
void dovecot_openssl_common_global_ref(void);
/* Deinitialize OpenSSL if this is the last instance. Returns TRUE if there
   are more instances left. */
bool dovecot_openssl_common_global_unref(void);

/* Set OpenSSL engine if it's not already set. Returns 1 on success, 0 if engine
   is unknown, -1 on other error. error_r is set on 0/-1. */
int dovecot_openssl_common_global_set_engine(const char *engine,
					     const char **error_r);

#endif
