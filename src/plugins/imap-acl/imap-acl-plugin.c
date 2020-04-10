/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-quote.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "imapc-client.h"
#include "imapc-client-private.h"
#include "imapc-settings.h"
#include "imapc-storage.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "module-context.h"
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

#define IMAP_ACL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_acl_storage_module)
#define IMAP_ACL_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, imap_acl_storage_module)

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

struct imap_acl_storage {
	union mail_storage_module_context module_ctx;
	struct imapc_acl_context *iacl_ctx;
};

struct imap_acl_storage_module imap_acl_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

const char *imap_acl_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_acl_module;
static imap_client_created_func_t *next_hook_client_created;

enum imap_acl_cmd {
	IMAP_ACL_CMD_MYRIGHTS = 0,
	IMAP_ACL_CMD_GETACL,
	IMAP_ACL_CMD_SETACL,
	IMAP_ACL_CMD_DELETEACL,
};

const char *imapc_acl_cmd_names[] = {
	"MYRIGHTS", "GETACL", "SETACL", "DELETEACL"
};

struct imapc_acl_context {
	struct imapc_client *client;
	enum imap_acl_cmd proxy_cmd;
	struct mail_storage *storage;
	struct imapc_mailbox *expected_box;
	string_t *reply;
};

static int
acl_mailbox_open_as_admin(struct client_command_context *cmd,
			  struct mailbox *box, const char *name)
{
	enum mailbox_existence existence = MAILBOX_EXISTENCE_NONE;
	int ret;

	if (ACL_USER_CONTEXT(cmd->client->user) == NULL) {
		client_send_command_error(cmd, "ACLs disabled.");
		return 0;
	}

	if (mailbox_exists(box, TRUE, &existence) == 0 &&
	    existence == MAILBOX_EXISTENCE_SELECT) {
		ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_ADMIN);
		if (ret > 0)
			return ret;
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
	return 0;
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

static const char *
imapc_acl_get_mailbox_error(struct imapc_mailbox *mbox)
{
	enum mail_error err;
	const char *error = mailbox_get_last_error(&mbox->box, &err);
	const char *resp_code;
	string_t *str = t_str_new(128);

	if (imapc_mail_error_to_resp_text_code(err, &resp_code))
		str_printfa(str, "[%s] ", resp_code);
	str_append(str, error);

	return str_c(str);
}

static void
imapc_acl_myrights_untagged_cb(const struct imapc_untagged_reply *reply,
			       struct imapc_storage_client *client)
{
	struct imap_acl_storage *iacl_storage =
		IMAP_ACL_CONTEXT_REQUIRE(&client->_storage->storage);
	struct imapc_acl_context *ctx = iacl_storage->iacl_ctx;
	const char *value;

	if (!imap_arg_get_astring(&reply->args[0], &value) ||
	    ctx->expected_box == NULL)
		return;

	/* Untagged reply was not meant for this mailbox */
	if (!imapc_mailbox_name_equals(ctx->expected_box, value))
		return;

	/* copy rights from reply to string
	   <args[0](mailbox)> <args[1](rights)> */
	if (imap_arg_get_astring(&reply->args[1], &value)) {
		str_append(ctx->reply, value);
	} else {
		/* Rights could not been parsed mark this
		   failed and clear the prepared reply. */
		str_truncate(ctx->reply, 0);
	}
	/* Just handle one untagged reply. */
	ctx->expected_box = NULL;
}

static void
imapc_acl_getacl_untagged_cb(const struct imapc_untagged_reply *reply,
			     struct imapc_storage_client *client)
{
	struct imap_acl_storage *iacl_storage =
		IMAP_ACL_CONTEXT_REQUIRE(&client->_storage->storage);
	struct imapc_acl_context *ctx = iacl_storage->iacl_ctx;
	const char *key, *value;
	unsigned int i;

	if (!imap_arg_get_astring(&reply->args[0], &value) ||
	    ctx->expected_box == NULL)
		return;

	/* Untagged reply was not meant for this mailbox */
	if (!imapc_mailbox_name_equals(ctx->expected_box, value))
		return;

	/* Parse key:value pairs of user:right and append them
	   to the prepared reply. */
	for (i = 1; reply->args[i].type != IMAP_ARG_EOL; i += 2) {
		if (imap_arg_get_astring(&reply->args[i], &key) &&
		    imap_arg_get_astring(&reply->args[i+1], &value)) {
			str_append(iacl_storage->iacl_ctx->reply, key);
			str_append_c(iacl_storage->iacl_ctx->reply, ' ');
			str_append(iacl_storage->iacl_ctx->reply, value);
			str_append_c(iacl_storage->iacl_ctx->reply, ' ');
		}  else {
			/* Rights could not been parsed clear prepared reply. */
			str_truncate(ctx->reply, 0);
			break;
		}
	}
	/* Just handle one untagged reply. */
	ctx->expected_box = NULL;
}

static struct imapc_acl_context *
imap_acl_cmd_context_alloc(struct imapc_mailbox *mbox)
{
	struct imapc_acl_context *iacl_ctx =
		p_new(mbox->box.storage->pool, struct imapc_acl_context, 1);
	iacl_ctx->reply = str_new(mbox->box.storage->pool, 128);
	return iacl_ctx;
}

static void imap_acl_cmd_context_init(struct imapc_acl_context *iacl_ctx,
				      struct imapc_mailbox *mbox,
				      enum imap_acl_cmd proxy_cmd)
{
	iacl_ctx->client = mbox->storage->client->client;
	iacl_ctx->proxy_cmd = proxy_cmd;
	iacl_ctx->expected_box = mbox;
	str_truncate(iacl_ctx->reply, 0);
}

static struct imapc_acl_context *
imap_acl_cmd_context_register(struct imapc_mailbox *mbox, enum imap_acl_cmd proxy_cmd)
{
	struct mailbox *box = &mbox->box;
	struct imap_acl_storage *iacl_storage = IMAP_ACL_CONTEXT(box->storage);

	if (iacl_storage == NULL) {
		iacl_storage = p_new(box->storage->pool, struct imap_acl_storage, 1);
		MODULE_CONTEXT_SET(box->storage, imap_acl_storage_module, iacl_storage);
		iacl_storage->iacl_ctx = imap_acl_cmd_context_alloc(mbox);
	}

	imap_acl_cmd_context_init(iacl_storage->iacl_ctx, mbox, proxy_cmd);

	return iacl_storage->iacl_ctx;
}

static const char *imap_acl_get_mailbox_name(const struct mail_namespace *ns,
					     const char *mailbox)
{
	/* Strip namespace prefix from mailbox name or append "INBOX" if
	   mailbox is "" and mailbox is in shared namespace. */

	if (ns->prefix_len == 0)
		return mailbox;

	i_assert(ns->prefix_len >= 1);

	if ((mailbox[ns->prefix_len-1] == '\0' ||
	     mailbox[ns->prefix_len] == '\0') &&
	    strncmp(mailbox, ns->prefix, ns->prefix_len-1) == 0 &&
	    ns->type == MAIL_NAMESPACE_TYPE_SHARED) {
		/* Given mailbox name does not contain an actual mailbox name
		   but just the namespace prefix so default to "INBOX". */
		return "INBOX";
	}

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    strcasecmp(mailbox, "INBOX") == 0) {
		/* For user INBOX always use INBOX and ignore namespace
		   prefix. */
		return "INBOX";
	}

	i_assert(strncmp(mailbox, ns->prefix, ns->prefix_len-1) == 0);
	return mailbox+ns->prefix_len;
}

static const char *
imapc_acl_prepare_cmd(string_t *reply_r, const char *mailbox,
		      const struct mail_namespace *ns, const char *cmd_args,
		      const enum imap_acl_cmd proxy_cmd)
{
	string_t *proxy_cmd_str = t_str_new(128);
	/* Prepare proxy_cmd and untagged replies */
	switch (proxy_cmd) {
	case IMAP_ACL_CMD_MYRIGHTS:
		/* Prepare client untagged reply. */
		str_append(reply_r, "* MYRIGHTS ");
		imap_append_astring(reply_r, mailbox);
		str_append_c(reply_r, ' ');

		str_append(proxy_cmd_str, "MYRIGHTS ");
		/* Strip namespace prefix. */
		imap_append_astring(proxy_cmd_str,
				    imap_acl_get_mailbox_name(ns, mailbox));
		break;
	case IMAP_ACL_CMD_GETACL:
		/* Prepare client untagged reply. */
		str_append(reply_r, "* ACL ");
		imap_append_astring(reply_r, mailbox);
		str_append_c(reply_r, ' ');

		str_append(proxy_cmd_str, "GETACL ");
		imap_append_astring(proxy_cmd_str,
				    imap_acl_get_mailbox_name(ns, mailbox));
		break;
	case IMAP_ACL_CMD_SETACL:
		/* No contents in untagged replies for SETACL */
		str_append(proxy_cmd_str, "SETACL ");
		imap_append_astring(proxy_cmd_str,
				    imap_acl_get_mailbox_name(ns, mailbox));

		str_append_c(proxy_cmd_str, ' ');
		str_append(proxy_cmd_str, cmd_args);
		break;
	case IMAP_ACL_CMD_DELETEACL:
		/* No contents in untagged replies for DELETEACL */
		str_append(proxy_cmd_str, "DELETEACL ");
		imap_append_astring(proxy_cmd_str,
				    imap_acl_get_mailbox_name(ns, mailbox));

		str_append_c(proxy_cmd_str, ' ');
		str_append(proxy_cmd_str, cmd_args);
		break;
	default:
		i_unreached();
	}
	return str_c(proxy_cmd_str);
}

static struct imapc_command *
imapc_acl_simple_context_init(struct imapc_simple_context *ctx,
			      struct imapc_mailbox *mbox)
{
	imapc_simple_context_init(ctx, mbox->storage->client);
	return imapc_client_cmd(mbox->storage->client->client,
				imapc_simple_callback, ctx);
}

static void imapc_acl_send_client_reply(struct imapc_acl_context *iacl_ctx,
					struct client_command_context *orig_cmd,
					const char *success_tagged_reply)
{
	if (str_len(iacl_ctx->reply) == 0)
		client_send_tagline(orig_cmd, "NO "MAIL_ERRSTR_CRITICAL_MSG);
	else {
		client_send_line(orig_cmd->client, str_c(iacl_ctx->reply));
		client_send_tagline(orig_cmd, success_tagged_reply);
	}
}

static bool imap_acl_proxy_cmd(struct mailbox *box,
			       const char *mailbox,
			       const char *cmd_args,
			       const struct mail_namespace *ns,
			       struct client_command_context *orig_cmd,
			       const enum imap_acl_cmd proxy_cmd)
{
	struct imapc_acl_context *iacl_ctx;
	struct imapc_simple_context ctx;
	struct imapc_command *imapc_cmd;
	const char *proxy_cmd_str;

	if (strcmp(box->storage->name, "imapc") != 0) {
		/* Storage is not "imapc". */
		return FALSE;
	}

	struct imapc_mailbox *mbox = IMAPC_MAILBOX(box);
	if (!IMAPC_HAS_FEATURE(mbox->storage, IMAPC_FEATURE_ACL)) {
		/* Storage is "imapc" but no proxying of ACL commands should
		   be done. */
		return FALSE;
	}

	iacl_ctx = imap_acl_cmd_context_register(mbox, proxy_cmd);

	/* Register callbacks for untagged replies */
	imapc_storage_client_register_untagged(mbox->storage->client, "ACL",
					       imapc_acl_getacl_untagged_cb);
	imapc_storage_client_register_untagged(mbox->storage->client, "MYRIGHTS",
					       imapc_acl_myrights_untagged_cb);

	imapc_cmd = imapc_acl_simple_context_init(&ctx, mbox);

	/* Prepare untagged replies and return proxy_cmd */
	proxy_cmd_str = imapc_acl_prepare_cmd(iacl_ctx->reply, mailbox,
					      ns, cmd_args, proxy_cmd);

	imapc_command_send(imapc_cmd, proxy_cmd_str);
	imapc_simple_run(&ctx, &imapc_cmd);

	if (ctx.ret != 0) {
		/* If the remote replied BAD or NO send NO. */
		client_send_tagline(orig_cmd,
				    t_strdup_printf("NO %s", imapc_acl_get_mailbox_error(mbox)));
	} else {
		/* Command was OK on remote backend, send untagged reply from
		   ctx.str and tagged reply. */
		switch (iacl_ctx->proxy_cmd) {
		case IMAP_ACL_CMD_DELETEACL:
			client_send_tagline(orig_cmd, "OK Deleteacl complete.");
			break;
		case IMAP_ACL_CMD_GETACL:
			imapc_acl_send_client_reply(iacl_ctx,
						    orig_cmd,
						    "OK Getacl complete.");
			break;
		case IMAP_ACL_CMD_MYRIGHTS:
			imapc_acl_send_client_reply(iacl_ctx,
						    orig_cmd,
						    "OK Myrights complete.");
			break;
		case IMAP_ACL_CMD_SETACL:
			client_send_tagline(orig_cmd, "OK Setacl complete.");
			break;
		default:
			i_unreached();
		}
	}

	/* Unregister callbacks for untagged replies */
	imapc_storage_client_unregister_untagged(mbox->storage->client, "MYRIGHTS");
	imapc_storage_client_unregister_untagged(mbox->storage->client, "ACL");
	return TRUE;
}

static void imap_acl_cmd_getacl(struct mailbox *box, struct mail_namespace *ns,
				const char *mailbox,
				struct client_command_context *cmd)
{
	struct acl_backend *backend;
	string_t *str;
	int ret;

	if (acl_mailbox_open_as_admin(cmd, box, mailbox) <= 0)
		return;

	backend = acl_mailbox_list_get_backend(ns->list);

	str = t_str_new(128);
	str_append(str, "* ACL ");
	imap_append_astring(str, mailbox);

	ret = imap_acl_write_aclobj(str, backend,
				    acl_mailbox_get_aclobj(box), TRUE,
				    ns->type == MAIL_NAMESPACE_TYPE_PRIVATE);
	if (ret > -1) {
		client_send_line(cmd->client, str_c(str));
		client_send_tagline(cmd, "OK Getacl completed.");
	} else {
		client_send_tagline(cmd, "NO "MAIL_ERRSTR_CRITICAL_MSG);
	}
}

static bool cmd_getacl(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *mailbox, *orig_mailbox;

	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	orig_mailbox = mailbox;

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);
	/* If the location is remote and imapc_feature acl is enabled, proxy the
	   command to the configured imapc location. */
	if (!imap_acl_proxy_cmd(box, orig_mailbox, NULL, ns, cmd, IMAP_ACL_CMD_GETACL))
		imap_acl_cmd_getacl(box, ns, orig_mailbox, cmd);
	mailbox_free(&box);
	return TRUE;
}

static void imap_acl_cmd_myrights(struct mailbox *box, const char *mailbox,
                                  struct client_command_context *cmd)
{
       const char *const *rights;
       string_t *str = t_str_new(128);

       if (acl_object_get_my_rights(acl_mailbox_get_aclobj(box),
                                    pool_datastack_create(), &rights) < 0) {
               client_send_tagline(cmd, "NO "MAIL_ERRSTR_CRITICAL_MSG);
               return;
       }

       /* Post right alone doesn't give permissions to see if the mailbox
          exists or not. Only mail deliveries care about that. */
       if (*rights == NULL ||
           (strcmp(*rights, MAIL_ACL_POST) == 0 && rights[1] == NULL)) {
               client_send_tagline(cmd, t_strdup_printf(
                                       "NO ["IMAP_RESP_CODE_NONEXISTENT"] "
                                       MAIL_ERRSTR_MAILBOX_NOT_FOUND, mailbox));
               return;
       }

       str_append(str, "* MYRIGHTS ");
       imap_append_astring(str, mailbox);
       str_append_c(str, ' ');
       imap_acl_write_rights_list(str, rights);

       client_send_line(cmd->client, str_c(str));
       client_send_tagline(cmd, "OK Myrights completed.");
}

static bool cmd_myrights(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *mailbox, *orig_mailbox;

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

	/* If the location is remote and imapc_feature acl is enabled, proxy the
	   command to the configured imapc location. */
	if (!imap_acl_proxy_cmd(box, orig_mailbox, NULL, ns,
				cmd, IMAP_ACL_CMD_MYRIGHTS))
		imap_acl_cmd_myrights(box, orig_mailbox, cmd);
	mailbox_free(&box);
	return TRUE;
}

static bool cmd_listrights(struct client_command_context *cmd)
{
	struct mailbox *box;
	struct mail_namespace *ns;
	const char *mailbox, *orig_mailbox, *identifier;
	string_t *str;

	if (!client_read_string_args(cmd, 2, &mailbox, &identifier))
		return FALSE;
	orig_mailbox = mailbox;

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox,
                           MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);

	str = t_str_new(128);
	str_append(str, "* LISTRIGHTS ");
	imap_append_astring(str, orig_mailbox);
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
		       const char **client_error_r)
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
				array_push_back(&rights,
						&imap_acl_letter_map[i].name);
				break;
			}
		}
		if (imap_acl_letter_map[i].name == NULL) {
			/* Handling of obsolete rights as virtual
			   rights according to RFC 4314 */
			switch (*letters) {
			case 'c':
				array_push_back(&rights, &acl_k);
				array_push_back(&rights, &acl_x);
				break;
			case 'd':
				array_push_back(&rights, &acl_e);
				array_push_back(&rights, &acl_t);
				break;
			default:
				*client_error_r = t_strdup_printf(
					"Invalid ACL right: %c", *letters);
				return -1;
			}
		}
	}
	array_append_zero(&rights);
	*rights_r = array_front(&rights);
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
			  bool check_anyone, const char **client_error_r)
{
	struct mail_user *user = cmd->client->user;

	if (str_begins_with(id, IMAP_ACL_GLOBAL_PREFIX)) {
		*client_error_r = t_strdup_printf("Global ACLs can't be modified: %s",
					   id);
		return -1;
	}

	if (strcmp(id, IMAP_ACL_ANYONE) == 0) {
		if (check_anyone && !acl_anyone_allow(user)) {
			*client_error_r = "'anyone' identifier is disallowed";
			return -1;
		}
		rights->id_type = ACL_ID_ANYONE;
	} else if (strcmp(id, IMAP_ACL_AUTHENTICATED) == 0) {
		if (check_anyone && !acl_anyone_allow(user)) {
			*client_error_r = "'authenticated' identifier is disallowed";
			return -1;
		}
		rights->id_type = ACL_ID_AUTHENTICATED;
	} else if (strcmp(id, IMAP_ACL_OWNER) == 0)
		rights->id_type = ACL_ID_OWNER;
	else if (str_begins(id, IMAP_ACL_GROUP_PREFIX, &rights->identifier))
		rights->id_type = ACL_ID_GROUP;
	else if (str_begins(id, IMAP_ACL_GROUP_OVERRIDE_PREFIX,
			    &rights->identifier)) {
		rights->id_type = ACL_ID_GROUP_OVERRIDE;
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
		array_push_back(&new_rights, &rights[i]);
	}

	switch (update->modify_mode) {
	case ACL_MODIFY_MODE_ADD:
		if (have_positive_owner_rights(backend, aclobj))
			return;

		/* adding initial rights for a user. we need to add
		   the defaults also. don't worry about duplicates. */
		for (; rights[i] != NULL; i++)
			array_push_back(&new_rights, &rights[i]);
		default_rights = acl_object_get_default_rights(aclobj);
		for (i = 0; default_rights[i] != NULL; i++)
			array_push_back(&new_rights, &default_rights[i]);
		break;
	case ACL_MODIFY_MODE_REMOVE:
		if (rights[i] == NULL)
			return;

		/* skip over the ADMIN removal and add the rest */
		for (i++; rights[i] != NULL; i++)
			array_push_back(&new_rights, &rights[i]);
		break;
	case ACL_MODIFY_MODE_REPLACE:
		if (rights[i] != NULL)
			return;

		/* add the missing ADMIN right */
		array_push_back(&new_rights, &acl_admin);
		break;
	default:
		return;
	}
	array_append_zero(&new_rights);
	update->rights.rights = array_front(&new_rights);
}

static int
cmd_acl_mailbox_update(struct mailbox *box,
		       const struct acl_rights_update *update,
		       const char **client_error_r)
{
	struct mailbox_transaction_context *t;
	int ret;

	if (mailbox_open(box) < 0) {
		*client_error_r = mailbox_get_last_error(box, NULL);
		return -1;
	}

	t = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL,
				      __func__);
	ret = acl_mailbox_update_acl(t, update);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	*client_error_r = MAIL_ERRSTR_CRITICAL_MSG;
	return ret;
}

static void imap_acl_cmd_setacl(struct mailbox *box, struct mail_namespace *ns,
				const char *mailbox, const char *identifier,
				const char *rights,
				struct client_command_context *cmd)
{
	struct acl_backend *backend;
	struct acl_object *aclobj;
	struct acl_rights_update update;
	struct acl_rights *r;
	const char *client_error;
	bool negative = FALSE;

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
				      TRUE, &client_error) < 0) {
		client_send_command_error(cmd, client_error);
		return;
	}
	if (imap_acl_letters_parse(rights, &update.rights.rights, &client_error) < 0) {
		client_send_command_error(cmd, client_error);
		return;
	}
	r = &update.rights;

	if (acl_mailbox_open_as_admin(cmd, box, mailbox) <= 0)
		return;

	backend = acl_mailbox_list_get_backend(ns->list);
	if (ns->type == MAIL_NAMESPACE_TYPE_PUBLIC &&
	    r->id_type == ACL_ID_OWNER) {
		client_send_tagline(cmd, "NO Public namespaces have no owner");
		return;
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

	if (cmd_acl_mailbox_update(box, &update, &client_error) < 0)
		client_send_tagline(cmd, t_strdup_printf("NO %s", client_error));
	else
		client_send_tagline(cmd, "OK Setacl complete.");
}

static bool cmd_setacl(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *mailbox, *orig_mailbox, *identifier, *rights;
	string_t *proxy_cmd_args = t_str_new(64);

	if (!client_read_string_args(cmd, 3, &mailbox, &identifier, &rights))
		return FALSE;
	orig_mailbox = mailbox;

	if (*identifier == '\0') {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	/* Keep original identifer for proxy_cmd_args */
	imap_append_astring(proxy_cmd_args, identifier);
	str_append_c(proxy_cmd_args, ' ');
	/* Append original rights for proxy_cmd_args */
	imap_append_astring(proxy_cmd_args, rights);

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);
	/* If the location is remote and imapc_feature acl is enabled, proxy the
	   command to the configured imapc location. */
	if (!imap_acl_proxy_cmd(box, orig_mailbox, str_c(proxy_cmd_args),
				ns, cmd, IMAP_ACL_CMD_SETACL))
		imap_acl_cmd_setacl(box, ns, orig_mailbox, identifier, rights, cmd);
	mailbox_free(&box);
	return TRUE;
}

static void imap_acl_cmd_deleteacl(struct mailbox *box, const char *mailbox,
				   const char *identifier,
				   struct client_command_context *cmd)
{
	struct acl_rights_update update;
	const char *client_error;

	i_zero(&update);
	if (*identifier != '-')
		update.modify_mode = ACL_MODIFY_MODE_CLEAR;
	else {
		update.neg_modify_mode = ACL_MODIFY_MODE_CLEAR;
		identifier++;
	}

	if (imap_acl_identifier_parse(cmd, identifier, &update.rights,
				      FALSE, &client_error) < 0) {
		client_send_command_error(cmd, client_error);
		return;
	}

	if (acl_mailbox_open_as_admin(cmd, box, mailbox) <= 0)
		return;

	if (cmd_acl_mailbox_update(box, &update, &client_error) < 0)
		client_send_tagline(cmd, t_strdup_printf("NO %s", client_error));
	else
		client_send_tagline(cmd, "OK Deleteacl complete.");
}

static bool cmd_deleteacl(struct client_command_context *cmd)
{
	struct mailbox *box;
	struct mail_namespace *ns;
	const char *mailbox, *orig_mailbox, *identifier;
	string_t *proxy_cmd_args = t_str_new(64);

	if (!client_read_string_args(cmd, 2, &mailbox, &identifier))
		return FALSE;
	orig_mailbox = mailbox;

	if (*identifier == '\0') {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	/* Escaped identifer for proxy_cmd_args */
	imap_append_astring(proxy_cmd_args, identifier);

	box = mailbox_alloc(ns->list, mailbox,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);

	/* If the location is remote and imapc_feature acl is enabled, proxy the
	   command to the configured imapc location. */
	if (!imap_acl_proxy_cmd(box, orig_mailbox, str_c(proxy_cmd_args),
				ns, cmd, IMAP_ACL_CMD_DELETEACL))
		imap_acl_cmd_deleteacl(box, orig_mailbox, identifier, cmd);
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
