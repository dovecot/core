/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-quote.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "acl-api.h"
#include "acl-storage.h"
#include "acl-plugin.h"
#include "imap-acl-plugin.h"


#define ERROR_NOT_ADMIN "["IMAP_RESP_CODE_NOPERM"] " \
	"You lack administrator privileges on this mailbox."

#define IMAP_ACL_ANYONE "anyone"
#define IMAP_ACL_AUTHENTICATED "authenticated"
#define IMAP_ACL_OWNER "owner"
#define IMAP_ACL_GROUP_PREFIX "$"
#define IMAP_ACL_GROUP_OVERRIDE_PREFIX "!$"
#define IMAP_ACL_GLOBAL_PREFIX "#"

struct imap_acl_letter_map {
	char letter;
	const char *name;
};

static const struct imap_acl_letter_map imap_acl_letter_map[] = {
	{ 'l', MAIL_ACL_LOOKUP },
	{ 'r', MAIL_ACL_READ },
	{ 'w', MAIL_ACL_WRITE },
	{ 's', MAIL_ACL_WRITE_SEEN },
	{ 't', MAIL_ACL_WRITE_DELETED },
	{ 'i', MAIL_ACL_INSERT },
	{ 'p', MAIL_ACL_POST },
	{ 'e', MAIL_ACL_EXPUNGE },
	{ 'k', MAIL_ACL_CREATE },
	{ 'x', MAIL_ACL_DELETE },
	{ 'a', MAIL_ACL_ADMIN },
	{ '\0', NULL }
};

const char *imap_acl_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_acl_module;
static imap_client_created_func_t *next_hook_client_created;

static struct mailbox *
acl_mailbox_open_as_admin(struct client_command_context *cmd, const char *name)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	enum mailbox_existence existence = MAILBOX_EXISTENCE_NONE;
	int ret;

	if (ACL_USER_CONTEXT(cmd->client->user) == NULL) {
		client_send_command_error(cmd, "ACLs disabled.");
		return NULL;
	}

	ns = client_find_namespace(cmd, &name);
	if (ns == NULL)
		return NULL;

	/* Force opening the mailbox so that we can give a nicer error message
	   if mailbox isn't selectable but is listable. */
	box = mailbox_alloc(ns->list, name, MAILBOX_FLAG_READONLY |
			    MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_exists(box, TRUE, &existence) == 0 &&
	    existence == MAILBOX_EXISTENCE_SELECT) {
		ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_ADMIN);
		if (ret > 0)
			return box;
	}

	/* mailbox doesn't exist / not an administrator. */
	if (existence != MAILBOX_EXISTENCE_SELECT ||
	    acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_LOOKUP) <= 0) {
		client_send_tagline(cmd, t_strdup_printf(
			"NO ["IMAP_RESP_CODE_NONEXISTENT"] "
			MAIL_ERRSTR_MAILBOX_NOT_FOUND, name));
	} else {
		client_send_tagline(cmd, "NO "ERROR_NOT_ADMIN);
	}
	mailbox_free(&box);
	return NULL;
}

static const struct imap_acl_letter_map *
imap_acl_letter_map_find(const char *name)
{
	unsigned int i;

	for (i = 0; imap_acl_letter_map[i].name != NULL; i++) {
		if (strcmp(imap_acl_letter_map[i].name, name) == 0)
			return &imap_acl_letter_map[i];
	}
	return NULL;
}

static void
imap_acl_write_rights_list(string_t *dest, const char *const *rights)
{
	const struct imap_acl_letter_map *map;
	unsigned int i;
	size_t orig_len = str_len(dest);
	bool append_c = FALSE, append_d = FALSE;

	for (i = 0; rights[i] != NULL; i++) {
		/* write only letters */
		map = imap_acl_letter_map_find(rights[i]);
		if (map != NULL) {
			str_append_c(dest, map->letter);
			if (map->letter == 'k' || map->letter == 'x')
				append_c = TRUE;
			if (map->letter == 't' || map->letter == 'e')
				append_d = TRUE;
		}
	}
	if (append_c)
		str_append_c(dest, 'c');
	if (append_d)
		str_append_c(dest, 'd');
	if (orig_len == str_len(dest))
		str_append(dest, "\"\"");
}

static void
imap_acl_write_right(string_t *dest, string_t *tmp,
		     const struct acl_rights *right, bool neg)
{
	const char *const *rights = neg ? right->neg_rights : right->rights;

	str_truncate(tmp, 0);
	if (neg) str_append_c(tmp,'-');
	if (right->global)
		str_append(tmp, IMAP_ACL_GLOBAL_PREFIX);
	switch (right->id_type) {
	case ACL_ID_ANYONE:
		str_append(tmp, IMAP_ACL_ANYONE);
		break;
	case ACL_ID_AUTHENTICATED:
		str_append(tmp, IMAP_ACL_AUTHENTICATED);
		break;
	case ACL_ID_OWNER:
		str_append(tmp, IMAP_ACL_OWNER);
		break;
	case ACL_ID_USER:
		str_append(tmp, right->identifier);
		break;
	case ACL_ID_GROUP:
		str_append(tmp, IMAP_ACL_GROUP_PREFIX);
		str_append(tmp, right->identifier);
		break;
	case ACL_ID_GROUP_OVERRIDE:
		str_append(tmp, IMAP_ACL_GROUP_OVERRIDE_PREFIX);
		str_append(tmp, right->identifier);
		break;
	case ACL_ID_TYPE_COUNT:
		i_unreached();
	}

	imap_append_astring(dest, str_c(tmp));
	str_append_c(dest, ' ');
	imap_acl_write_rights_list(dest, rights);
}

static bool
acl_rights_is_owner(struct acl_backend *backend,
		    const struct acl_rights *rights)
{
	switch (rights->id_type) {
	case ACL_ID_OWNER:
		return TRUE;
	case ACL_ID_USER:
		return acl_backend_user_name_equals(backend,
						    rights->identifier);
	default:
		return FALSE;
	}
}

static bool have_positive_owner_rights(struct acl_backend *backend,
				       struct acl_object *aclobj)
{
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	bool ret = FALSE;

	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) {
		if (acl_rights_is_owner(backend, &rights)) {
			if (rights.rights != NULL) {
				ret = TRUE;
				break;
			}
		}
	}
	(void)acl_object_list_deinit(&iter);
	return ret;
}

static int
imap_acl_write_aclobj(string_t *dest, struct acl_backend *backend,
		      struct acl_object *aclobj, bool convert_owner,
		      bool add_default)
{
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	string_t *tmp;
	const char *username;
	size_t orig_len = str_len(dest);
	bool seen_owner = FALSE, seen_positive_owner = FALSE;
	int ret;

	username = acl_backend_get_acl_username(backend);
	if (username == NULL)
		convert_owner = FALSE;

	tmp = t_str_new(128);
	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) {
		if (acl_rights_is_owner(backend, &rights)) {
			if (rights.id_type == ACL_ID_OWNER && convert_owner) {
				rights.id_type = ACL_ID_USER;
				rights.identifier = username;
			}
			if (seen_owner && convert_owner) {
				/* oops, we have both owner and user=myself.
				   can't do the conversion, so try again. */
				str_truncate(dest, orig_len);
				return imap_acl_write_aclobj(dest, backend,
							     aclobj, FALSE,
							     add_default);
			}
			seen_owner = TRUE;
			if (rights.rights != NULL)
				seen_positive_owner = TRUE;
		}

		if (rights.rights != NULL) {
			str_append_c(dest, ' ');
			imap_acl_write_right(dest, tmp, &rights, FALSE);
		}
		if (rights.neg_rights != NULL) {
			str_append_c(dest, ' ');
			imap_acl_write_right(dest, tmp, &rights, TRUE);
		}
	}
	ret = acl_object_list_deinit(&iter);

	if (!seen_positive_owner && username != NULL && add_default) {
		/* no positive owner rights returned, write default ACLs */
		i_zero(&rights);
		if (!convert_owner) {
			rights.id_type = ACL_ID_OWNER;
		} else {
			rights.id_type = ACL_ID_USER;
			rights.identifier = username;
		}
		rights.rights = acl_object_get_default_rights(aclobj);
		if (rights.rights != NULL) {
			str_append_c(dest, ' ');
			imap_acl_write_right(dest, tmp, &rights, FALSE);
		}
	}
	return ret;
}

static bool cmd_getacl(struct client_command_context *cmd)
{
	struct acl_backend *backend;
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *mailbox;
	string_t *str;
	int ret;

	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	box = acl_mailbox_open_as_admin(cmd, mailbox);
	if (box == NULL)
		return TRUE;

	str = t_str_new(128);
	str_append(str, "* ACL ");
	imap_append_astring(str, mailbox);

	ns = mailbox_get_namespace(box);
	backend = acl_mailbox_list_get_backend(ns->list);
	ret = imap_acl_write_aclobj(str, backend,
				    acl_mailbox_get_aclobj(box), TRUE,
				    ns->type == MAIL_NAMESPACE_TYPE_PRIVATE);
	if (ret > -1) {
		client_send_line(cmd->client, str_c(str));
		client_send_tagline(cmd, "OK Getacl completed.");
	} else {
		client_send_tagline(cmd, "NO "MAIL_ERRSTR_CRITICAL_MSG);
	}
	mailbox_free(&box);
	return TRUE;
}

static bool cmd_myrights(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *mailbox, *orig_mailbox;
	const char *const *rights;
	string_t *str;

	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	orig_mailbox = mailbox;

	if (ACL_USER_CONTEXT(cmd->client->user) == NULL) {
		client_send_command_error(cmd, "ACLs disabled.");
		return TRUE;
	}

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);
	if (acl_object_get_my_rights(acl_mailbox_get_aclobj(box),
				     pool_datastack_create(), &rights) < 0) {
		client_send_tagline(cmd, "NO "MAIL_ERRSTR_CRITICAL_MSG);
		mailbox_free(&box);
		return TRUE;
	}
	/* Post right alone doesn't give permissions to see if the mailbox
	   exists or not. Only mail deliveries care about that. */
	if (*rights == NULL ||
	    (strcmp(*rights, MAIL_ACL_POST) == 0 && rights[1] == NULL)) {
		client_send_tagline(cmd, t_strdup_printf(
			"NO ["IMAP_RESP_CODE_NONEXISTENT"] "
			MAIL_ERRSTR_MAILBOX_NOT_FOUND, mailbox));
		mailbox_free(&box);
		return TRUE;
	}

	str = t_str_new(128);
	str_append(str, "* MYRIGHTS ");
	imap_append_astring(str, orig_mailbox);
	str_append_c(str,' ');
	imap_acl_write_rights_list(str, rights);

	client_send_line(cmd->client, str_c(str));
	client_send_tagline(cmd, "OK Myrights completed.");
	mailbox_free(&box);
	return TRUE;
}

static bool cmd_listrights(struct client_command_context *cmd)
{
	struct mailbox *box;
	const char *mailbox, *identifier;
	string_t *str;

	if (!client_read_string_args(cmd, 2, &mailbox, &identifier))
		return FALSE;

	box = acl_mailbox_open_as_admin(cmd, mailbox);
	if (box == NULL)
		return TRUE;

	str = t_str_new(128);
	str_append(str, "* LISTRIGHTS ");
	imap_append_astring(str, mailbox);
	str_append_c(str, ' ');
	imap_append_astring(str, identifier);
	str_append_c(str, ' ');
	str_append(str, "\"\" l r w s t p i e k x a c d");

	client_send_line(cmd->client, str_c(str));
	client_send_tagline(cmd, "OK Listrights completed.");
	mailbox_free(&box);
	return TRUE;
}

static int
imap_acl_letters_parse(const char *letters, const char *const **rights_r,
		       const char **error_r)
{
	static const char *acl_k = MAIL_ACL_CREATE;
	static const char *acl_x = MAIL_ACL_DELETE;
	static const char *acl_e = MAIL_ACL_EXPUNGE;
	static const char *acl_t = MAIL_ACL_WRITE_DELETED;
	ARRAY_TYPE(const_string) rights;
	unsigned int i;

	t_array_init(&rights, 64);
	for (; *letters != '\0'; letters++) {
		for (i = 0; imap_acl_letter_map[i].name != NULL; i++) {
			if (imap_acl_letter_map[i].letter == *letters) {
				array_append(&rights,
					     &imap_acl_letter_map[i].name, 1);
				break;
			}
		}
		if (imap_acl_letter_map[i].name == NULL) {
			/* Handling of obsolete rights as virtual
			   rights according to RFC 4314 */
			switch (*letters) {
			case 'c':
				array_append(&rights, &acl_k, 1);
				array_append(&rights, &acl_x, 1);
				break;
			case 'd':
				array_append(&rights, &acl_e, 1);
				array_append(&rights, &acl_t, 1);
				break;
			default:
				*error_r = t_strdup_printf(
					"Invalid ACL right: %c", *letters);
				return -1;
			}
		}
	}
	array_append_zero(&rights);
	*rights_r = array_first(&rights);
	return 0;
}

static bool acl_anyone_allow(struct mail_user *user)
{
	const char *env;

	env = mail_user_plugin_getenv(user, "acl_anyone");
	return env != NULL && strcmp(env, "allow") == 0;
}

static int
imap_acl_identifier_parse(struct client_command_context *cmd,
			  const char *id, struct acl_rights *rights,
			  bool check_anyone, const char **error_r)
{
	struct mail_user *user = cmd->client->user;

	if (str_begins(id, IMAP_ACL_GLOBAL_PREFIX)) {
		*error_r = t_strdup_printf("Global ACLs can't be modified: %s",
					   id);
		return -1;
	}

	if (strcmp(id, IMAP_ACL_ANYONE) == 0) {
		if (check_anyone && !acl_anyone_allow(user)) {
			*error_r = "'anyone' identifier is disallowed";
			return -1;
		}
		rights->id_type = ACL_ID_ANYONE;
	} else if (strcmp(id, IMAP_ACL_AUTHENTICATED) == 0) {
		if (check_anyone && !acl_anyone_allow(user)) {
			*error_r = "'authenticated' identifier is disallowed";
			return -1;
		}
		rights->id_type = ACL_ID_AUTHENTICATED;
	} else if (strcmp(id, IMAP_ACL_OWNER) == 0)
		rights->id_type = ACL_ID_OWNER;
	else if (str_begins(id, IMAP_ACL_GROUP_PREFIX)) {
		rights->id_type = ACL_ID_GROUP;
		rights->identifier = id + strlen(IMAP_ACL_GROUP_PREFIX);
	} else if (str_begins(id, IMAP_ACL_GROUP_OVERRIDE_PREFIX)) {
		rights->id_type = ACL_ID_GROUP_OVERRIDE;
		rights->identifier = id +
			strlen(IMAP_ACL_GROUP_OVERRIDE_PREFIX);
	} else {
		rights->id_type = ACL_ID_USER;
		rights->identifier = id;
	}
	return 0;
}

static void imap_acl_update_ensure_keep_admins(struct acl_backend *backend,
					       struct acl_object *aclobj,
					       struct acl_rights_update *update)
{
	static const char *acl_admin = MAIL_ACL_ADMIN;
	const char *const *rights = update->rights.rights;
	const char *const *default_rights;
	ARRAY_TYPE(const_string) new_rights;
	unsigned int i;

	t_array_init(&new_rights, 64);
	for (i = 0; rights[i] != NULL; i++) {
		if (strcmp(rights[i], MAIL_ACL_ADMIN) == 0)
			break;
		array_append(&new_rights, &rights[i], 1);
	}

	switch (update->modify_mode) {
	case ACL_MODIFY_MODE_ADD:
		if (have_positive_owner_rights(backend, aclobj))
			return;

		/* adding initial rights for a user. we need to add
		   the defaults also. don't worry about duplicates. */
		for (; rights[i] != NULL; i++)
			array_append(&new_rights, &rights[i], 1);
		default_rights = acl_object_get_default_rights(aclobj);
		for (i = 0; default_rights[i] != NULL; i++)
			array_append(&new_rights, &default_rights[i], 1);
		break;
	case ACL_MODIFY_MODE_REMOVE:
		if (rights[i] == NULL)
			return;

		/* skip over the ADMIN removal and add the rest */
		for (i++; rights[i] != NULL; i++)
			array_append(&new_rights, &rights[i], 1);
		break;
	case ACL_MODIFY_MODE_REPLACE:
		if (rights[i] != NULL)
			return;

		/* add the missing ADMIN right */
		array_append(&new_rights, &acl_admin, 1);
		break;
	default:
		return;
	}
	array_append_zero(&new_rights);
	update->rights.rights = array_first(&new_rights);
}

static int
cmd_acl_mailbox_update(struct mailbox *box,
		       const struct acl_rights_update *update,
		       const char **error_r)
{
	struct mailbox_transaction_context *t;
	int ret;

	if (mailbox_open(box) < 0) {
		*error_r = mailbox_get_last_error(box, NULL);
		return -1;
	}

	t = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL,
				      __func__);
	ret = acl_mailbox_update_acl(t, update);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	*error_r = MAIL_ERRSTR_CRITICAL_MSG;
	return ret;
}

static bool cmd_setacl(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct acl_backend *backend;
	struct acl_object *aclobj;
	struct acl_rights_update update;
	struct acl_rights *r;
	const char *mailbox, *identifier, *rights, *error;
	bool negative = FALSE;

	if (!client_read_string_args(cmd, 3, &mailbox, &identifier, &rights))
		return FALSE;

	if (*identifier == '\0') {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	i_zero(&update);
	if (*identifier == '-') {
		negative = TRUE;
		identifier++;
	}

	switch (*rights) {
	case '-':
		update.modify_mode = ACL_MODIFY_MODE_REMOVE;
		rights++;
		break;
	case '+':
		update.modify_mode = ACL_MODIFY_MODE_ADD;
		rights++;
		break;
	default:
		update.modify_mode = ACL_MODIFY_MODE_REPLACE;
		break;
	}

	if (imap_acl_identifier_parse(cmd, identifier, &update.rights,
				      TRUE, &error) < 0) {
		client_send_command_error(cmd, error);
		return TRUE;
	}
	if (imap_acl_letters_parse(rights, &update.rights.rights, &error) < 0) {
		client_send_command_error(cmd, error);
		return TRUE;
	}
	r = &update.rights;

	box = acl_mailbox_open_as_admin(cmd, mailbox);
	if (box == NULL)
		return TRUE;

	ns = mailbox_get_namespace(box);
	backend = acl_mailbox_list_get_backend(ns->list);
	if (ns->type == MAIL_NAMESPACE_TYPE_PUBLIC &&
	    r->id_type == ACL_ID_OWNER) {
		client_send_tagline(cmd, "NO Public namespaces have no owner");
		mailbox_free(&box);
		return TRUE;
	}

	aclobj = acl_mailbox_get_aclobj(box);
	if (negative) {
		update.neg_modify_mode = update.modify_mode;
		update.modify_mode = ACL_MODIFY_MODE_REMOVE;
		update.rights.neg_rights = update.rights.rights;
		update.rights.rights = NULL;
	} else if (ns->type == MAIL_NAMESPACE_TYPE_PRIVATE &&
		   r->rights != NULL &&
		   ((r->id_type == ACL_ID_USER &&
		     acl_backend_user_name_equals(backend, r->identifier)) ||
		    (r->id_type == ACL_ID_OWNER &&
		     strcmp(acl_backend_get_acl_username(backend),
			    ns->user->username) == 0))) {
		/* make sure client doesn't (accidentally) remove admin
		   privileges from its own mailboxes */
		imap_acl_update_ensure_keep_admins(backend, aclobj, &update);
	}

	if (cmd_acl_mailbox_update(box, &update, &error) < 0)
		client_send_tagline(cmd, t_strdup_printf("NO %s", error));
	else
		client_send_tagline(cmd, "OK Setacl complete.");
	mailbox_free(&box);
	return TRUE;
}

static bool cmd_deleteacl(struct client_command_context *cmd)
{
	struct mailbox *box;
	struct acl_rights_update update;
	const char *mailbox, *identifier, *error;

	if (!client_read_string_args(cmd, 2, &mailbox, &identifier))
		return FALSE;
	if (*identifier == '\0') {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	i_zero(&update);
	if (*identifier != '-')
		update.modify_mode = ACL_MODIFY_MODE_CLEAR;
	else {
		update.neg_modify_mode = ACL_MODIFY_MODE_CLEAR;
		identifier++;
	}

	if (imap_acl_identifier_parse(cmd, identifier, &update.rights,
				      FALSE, &error) < 0) {
		client_send_command_error(cmd, error);
		return TRUE;
	}

	box = acl_mailbox_open_as_admin(cmd, mailbox);
	if (box == NULL)
		return TRUE;

	if (cmd_acl_mailbox_update(box, &update, &error) < 0)
		client_send_tagline(cmd, t_strdup_printf("NO %s", error));
	else
		client_send_tagline(cmd, "OK Deleteacl complete.");
	mailbox_free(&box);
	return TRUE;
}

static void imap_acl_client_created(struct client **client)
{
	if (mail_user_is_plugin_loaded((*client)->user, imap_acl_module)) {
		client_add_capability(*client, "ACL");
		client_add_capability(*client, "RIGHTS=texk");
	}

	if (next_hook_client_created != NULL)
		next_hook_client_created(client);
}

void imap_acl_plugin_init(struct module *module)
{
	command_register("LISTRIGHTS", cmd_listrights, 0);
	command_register("GETACL", cmd_getacl, 0);
	command_register("MYRIGHTS", cmd_myrights, 0);
	command_register("SETACL", cmd_setacl, 0);
	command_register("DELETEACL", cmd_deleteacl, 0);

	imap_acl_module = module;
	next_hook_client_created =
		imap_client_created_hook_set(imap_acl_client_created);
}

void imap_acl_plugin_deinit(void)
{
	command_unregister("GETACL");
	command_unregister("MYRIGHTS");
	command_unregister("SETACL");
	command_unregister("DELETEACL");
	command_unregister("LISTRIGHTS");

	imap_client_created_hook_set(next_hook_client_created);
}

const char *imap_acl_plugin_dependencies[] = { "acl", NULL };
const char imap_acl_plugin_binary_dependency[] = "imap";
