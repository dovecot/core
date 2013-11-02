#ifndef IMAP_METADATA_H
#define IMAP_METADATA_H

#define IMAP_METADATA_PRIVATE_PREFIX "/private"
#define IMAP_METADATA_SHARED_PREFIX "/shared"

bool imap_metadata_verify_entry_name(struct client_command_context *cmd,
				     const char *name);
void imap_metadata_entry2key(const char *entry, const char *key_prefix,
			     enum mail_attribute_type *type_r,
			     const char **key_r);

#endif
