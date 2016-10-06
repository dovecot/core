#ifndef IMAP_STATE_H
#define IMAP_STATE_H

/* Export the IMAP client state to the given buffer. Returns 1 if ok,
   0 if state couldn't be exported, -1 if temporary internal error error. */
int imap_state_export_internal(struct client *client, buffer_t *dest,
			       const char **error_r);
int imap_state_export_external(struct client *client, buffer_t *dest,
			       const char **error_r);

/* Returns 1 if ok, 0 if state was corrupted, -1 if other error. Internal state
   comes from another Dovecot component, which can override IP addresses,
   session IDs, etc. */
int imap_state_import_internal(struct client *client,
			       const unsigned char *data, size_t size,
			       const char **error_r);
int imap_state_import_external(struct client *client,
			       const unsigned char *data, size_t size,
			       const char **error_r);

/* INTERNAL API: Note that the "internal" flag specifies whether we're doing
   the import/export from/to another Dovecot component or an untrusted
   IMAP client. */
int imap_state_export_base(struct client *client, bool internal,
			   buffer_t *dest, const char **error_r);
ssize_t imap_state_import_base(struct client *client, bool internal,
			       const unsigned char *data, size_t size,
			       const char **error_r);
void imap_state_import_idle_cmd_tag(struct client *client, const char *tag);
#endif
