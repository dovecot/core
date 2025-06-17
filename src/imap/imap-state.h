#ifndef IMAP_STATE_H
#define IMAP_STATE_H

/* IMAP state import result codes */
enum imap_state_result {
	IMAP_STATE_OK, /* Success */
	IMAP_STATE_CORRUPTED, /* Data corruption or invalid state */
	IMAP_STATE_ERROR, /* General error (e.g., permission, resource issues) */
	IMAP_STATE_INCONSISTENT /* State inconsistency (e.g., mailbox not found) */
};

/* Export the IMAP client state to the given buffer. Returns 1 if ok,
   0 if state couldn't be exported, -1 if temporary internal error error. */
int imap_state_export_internal(struct client *client, buffer_t *dest,
			       const char **error_r);

/* Imports internal client state from another Dovecot component,
   which may override IP addresses, session IDs, etc. */
enum imap_state_result
imap_state_import_internal(struct client *client,
			   const unsigned char *data, size_t size,
			   const char **error_r);

/* Imports external client state from an untrusted source. */
enum imap_state_result
imap_state_import_external(struct client *client,
			   const unsigned char *data, size_t size,
			   const char **error_r);

/* INTERNAL API: Note that the "internal" flag specifies whether we're doing
   the import/export from/to another Dovecot component or an untrusted
   IMAP client. */
int imap_state_export_base(struct client *client, bool internal,
			   buffer_t *dest, const char **error_r);
enum imap_state_result imap_state_import_base(struct client *client,
				bool internal, const unsigned char *data,
				size_t size, size_t *skip_r, const char **error_r);
void imap_state_import_idle_cmd_tag(struct client *client, const char *tag);
#endif
