/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-metadata.h"

bool imap_metadata_verify_entry_name(struct client_command_context *cmd,
				     const char *name)
{
	unsigned int i;
	bool ok;

	if (name[0] != '/') {
		client_send_command_error(cmd,
			"Entry name must begin with '/'");
		return FALSE;
	}
	for (i = 0; name[i] != '\0'; i++) {
		switch (name[i]) {
		case '/':
			if (i > 0 && name[i-1] == '/') {
				client_send_command_error(cmd,
					"Entry name can't contain consecutive '/'");
				return FALSE;
			}
			if (name[i+1] == '\0') {
				client_send_command_error(cmd,
					"Entry name can't end with '/'");
				return FALSE;
			}
			break;
		case '*':
			client_send_command_error(cmd,
				"Entry name can't contain '*'");
			return FALSE;
		case '%':
			client_send_command_error(cmd,
				"Entry name can't contain '%'");
			return FALSE;
		default:
			if (name[i] <= 0x19) {
				client_send_command_error(cmd,
					"Entry name can't contain control chars");
				return FALSE;
			}
			break;
		}
	}
	T_BEGIN {
		const char *prefix, *p = strchr(name+1, '/');

		prefix = p == NULL ? name : t_strdup_until(name, p);
		ok = strcasecmp(prefix, IMAP_METADATA_PRIVATE_PREFIX) == 0 ||
			strcasecmp(prefix, IMAP_METADATA_SHARED_PREFIX) == 0;
	} T_END;
	if (!ok) {
		client_send_command_error(cmd,
			"Entry name must begin with /private or /shared");
		return FALSE;
	}
	return TRUE;
}

void imap_metadata_entry2key(const char *entry, const char *key_prefix,
			     enum mail_attribute_type *type_r,
			     const char **key_r)
{
	if (strncmp(entry, IMAP_METADATA_PRIVATE_PREFIX,
		    strlen(IMAP_METADATA_PRIVATE_PREFIX)) == 0) {
		*key_r = entry + strlen(IMAP_METADATA_PRIVATE_PREFIX);
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
	} else {
		i_assert(strncmp(entry, IMAP_METADATA_SHARED_PREFIX,
				 strlen(IMAP_METADATA_SHARED_PREFIX)) == 0);
		*key_r = entry + strlen(IMAP_METADATA_SHARED_PREFIX);
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
	}
	if ((*key_r)[0] == '\0') {
		/* /private or /shared prefix has no value itself */
	} else {
		i_assert((*key_r)[0] == '/');
		*key_r += 1;
	}
	if (key_prefix != NULL)
		*key_r = t_strconcat(key_prefix, *key_r, NULL);
}
