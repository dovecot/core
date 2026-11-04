#ifndef AUTH_SECRETS_H
#define AUTH_SECRETS_H

/* Returns TRUE if the value of the field key must not be logged: the key
   contains "pass", "pwd", "nonce", "hash" or "secret", or ends with "key",
   "key_file" or "token" (auth_token can be used to log in with
   DOVECOT-TOKEN, access_token is the OAuth2 bearer token). The match is
   case-insensitive. */
bool auth_field_key_is_secret(const char *key);
/* Same as auth_field_key_is_secret(), but for a "key=value" field. A field
   without '=' is not secret. */
bool auth_field_is_secret(const char *field);
/* Returns "key=<hidden>" if the field is secret, otherwise the field as-is.
   Allocated from data stack. */
const char *auth_field_hide_secret(const char *field);
/* Returns a line of tab-escaped "key=value" fields (e.g. an auth protocol
   reply) for logging, with the values of all secret fields replaced with
   "<hidden>". The tab-escaped fields inside userdb_fields are handled too.
   Allocated from data stack. */
const char *auth_field_line_hide_secrets(const char *line);

#endif
