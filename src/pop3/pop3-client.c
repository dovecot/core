/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "pop3-common.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "iostream.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-rawlog.h"
#include "crc32.h"
#include "str.h"
#include "llist.h"
#include "hostpid.h"
#include "file-dotlock.h"
#include "var-expand.h"
#include "master-service.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-autoexpunge.h"
#include "pop3-commands.h"
#include "mail-search-build.h"
#include "mail-namespace.h"

#include <unistd.h>

/* max. length of input command line (spec says 512) */
#define MAX_INBUF_SIZE 2048

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)
/* If client starts idling for this many milliseconds, commit the current
   transaction. This allows the mailbox to become unlocked. */
#define CLIENT_COMMIT_TIMEOUT_MSECS (10*1000)

#define POP3_LOCK_FNAME "dovecot-pop3-session.lock"
#define POP3_SESSION_DOTLOCK_STALE_TIMEOUT_SECS (60*5)

extern struct pop3_client_vfuncs pop3_client_vfuncs;

struct pop3_module_register pop3_module_register = { 0 };

struct client *pop3_clients;
unsigned int pop3_client_count;

static enum mail_sort_type pop3_sort_program[] = {
	MAIL_SORT_POP3_ORDER,
	MAIL_SORT_END
};

static const struct dotlock_settings session_dotlock_set = {
	.timeout = 10,
	.stale_timeout = POP3_SESSION_DOTLOCK_STALE_TIMEOUT_SECS,
	.lock_suffix = "",
	.use_io_notify = TRUE
};

static void client_input(struct client *client);
static int client_output(struct client *client);

static void client_commit_timeout(struct client *client)
{
	if (client->cmd != NULL) {
		/* Can't commit while commands are running */
		return;
	}

	(void)mailbox_transaction_commit(&client->trans);
	client->trans = mailbox_transaction_begin(client->mailbox, 0, __func__);
}

static void client_idle_timeout(struct client *client)
{
	if (client->cmd != NULL) {
		client_destroy(client,
			"Disconnected for inactivity in reading our output");
	} else {
		client_send_line(client, "-ERR Disconnected for inactivity.");
		client_destroy(client, "Disconnected for inactivity");
	}
}

static int
pop3_mail_get_size(struct client *client, struct mail *mail, uoff_t *size_r)
{
	int ret;

	if (!client->set->pop3_fast_size_lookups)
		return mail_get_virtual_size(mail, size_r);

	/* first try to get the virtual size */
	mail->lookup_abort = MAIL_LOOKUP_ABORT_READ_MAIL;
	ret = mail_get_virtual_size(mail, size_r);
	mail->lookup_abort = MAIL_LOOKUP_ABORT_NEVER;
	if (ret == 0)
		return 0;

	if (mailbox_get_last_mail_error(mail->box) != MAIL_ERROR_LOOKUP_ABORTED)
		return -1;

	/* virtual size not available with a fast lookup.
	   fallback to trying the physical size */
	mail->lookup_abort = MAIL_LOOKUP_ABORT_READ_MAIL;
	ret = mail_get_physical_size(mail, size_r);
	mail->lookup_abort = MAIL_LOOKUP_ABORT_NEVER;
	if (ret == 0)
		return 0;

	if (mailbox_get_last_mail_error(mail->box) != MAIL_ERROR_LOOKUP_ABORTED)
		return -1;

	/* no way to quickly get the size. fallback to doing a slow virtual
	   size lookup */
	return mail_get_virtual_size(mail, size_r);
}

static void
msgnum_to_seq_map_add(ARRAY_TYPE(uint32_t) *msgnum_to_seq_map,
		      struct client *client, struct mail *mail,
		      unsigned int msgnum)
{
	uint32_t seq;

	if (mail->seq == msgnum+1)
		return;

	if (!array_is_created(msgnum_to_seq_map))
		i_array_init(msgnum_to_seq_map, client->messages_count);

	/* add any messages between this and the previous one that had
	   a POP3 order defined */
	seq = array_count(msgnum_to_seq_map) + 1;
	for (; seq <= msgnum; seq++)
		array_append(msgnum_to_seq_map, &seq, 1);
	array_append(msgnum_to_seq_map, &mail->seq, 1);
}

static int read_mailbox(struct client *client, uint32_t *failed_uid_r)
{
        struct mailbox_status status;
        struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_arg *sarg;
	struct mail_search_context *ctx;
	struct mail *mail;
	uoff_t size;
	ARRAY(uoff_t) message_sizes;
	ARRAY_TYPE(uint32_t) msgnum_to_seq_map = ARRAY_INIT;
	unsigned int msgnum;
	int ret = 1;

	*failed_uid_r = 0;

	mailbox_get_open_status(client->mailbox, STATUS_UIDVALIDITY, &status);
	client->uid_validity = status.uidvalidity;
	client->messages_count = status.messages;

	t = mailbox_transaction_begin(client->mailbox, 0, __func__);

	search_args = mail_search_build_init();
	if (client->deleted_kw != NULL) {
		sarg = mail_search_build_add(search_args, SEARCH_KEYWORDS);
		sarg->match_not = TRUE;
		sarg->value.str = p_strdup(search_args->pool,
					   client->set->pop3_deleted_flag);
		i_array_init(&client->all_seqs, 32);
	} else {
		mail_search_build_add_all(search_args);
	}
	mail_search_args_init(search_args, client->mailbox, TRUE, NULL);

	ctx = mailbox_search_init(t, search_args, pop3_sort_program,
				  client->set->pop3_fast_size_lookups ? 0 :
				  MAIL_FETCH_VIRTUAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	client->last_seen_pop3_msn = 0;
	client->total_size = 0;
	i_array_init(&message_sizes, client->messages_count);

	msgnum = 0;
	while (mailbox_search_next(ctx, &mail)) {
		if (pop3_mail_get_size(client, mail, &size) < 0) {
			ret = mail->expunged ? 0 : -1;
			*failed_uid_r = mail->uid;
			break;
		}
		if (array_is_created(&client->all_seqs))
			seq_range_array_add(&client->all_seqs, mail->seq);
		msgnum_to_seq_map_add(&msgnum_to_seq_map, client, mail, msgnum);

		if ((mail_get_flags(mail) & MAIL_SEEN) != 0)
			client->last_seen_pop3_msn = msgnum + 1;
		client->total_size += size;
		if (client->highest_seq < mail->seq)
			client->highest_seq = mail->seq;

		array_append(&message_sizes, &size, 1);
		msgnum++;
	}

	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;

	if (ret <= 0) {
		/* commit the transaction instead of rolling back to make sure
		   we don't lose data (virtual sizes) added to cache file */
		(void)mailbox_transaction_commit(&t);
		array_free(&message_sizes);
		if (array_is_created(&msgnum_to_seq_map))
			array_free(&msgnum_to_seq_map);
		return ret;
	}
	i_assert(msgnum <= client->messages_count);
	client->messages_count = msgnum;

	if (!array_is_created(&client->all_seqs)) {
		i_array_init(&client->all_seqs, 1);
		seq_range_array_add_range(&client->all_seqs, 1, msgnum);
	}

	client->trans = t;
	client->message_sizes =
		array_free_without_data(&message_sizes);
	if (array_is_created(&msgnum_to_seq_map)) {
		client->msgnum_to_seq_map_count =
			array_count(&msgnum_to_seq_map);
		client->msgnum_to_seq_map =
			array_free_without_data(&msgnum_to_seq_map);
	}
	return 1;
}

static int init_pop3_deleted_flag(struct client *client, const char **error_r)
{
	const char *deleted_keywords[2];

	if (client->set->pop3_deleted_flag[0] == '\0')
		return 0;

	deleted_keywords[0] = client->set->pop3_deleted_flag;
	deleted_keywords[1] = NULL;
	if (mailbox_keywords_create(client->mailbox, deleted_keywords,
				    &client->deleted_kw) < 0) {
		*error_r = t_strdup_printf(
			"pop3_deleted_flags: Invalid keyword '%s': %s",
			client->set->pop3_deleted_flag,
			mailbox_get_last_internal_error(client->mailbox, NULL));
		return -1;
	}
	return 0;
}

static int init_mailbox(struct client *client, const char **error_r)
{
	uint32_t failed_uid = 0, last_failed_uid = 0;
	int i, ret = -1;

	for (i = 0;; i++) {
		if (mailbox_sync(client->mailbox,
				 MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
			ret = -1;
			break;
		}

		ret = read_mailbox(client, &failed_uid);
		if (ret > 0)
			return 0;
		if (i == 2)
			break;

		/* well, sync and try again. maybe it works the second time. */
		last_failed_uid = failed_uid;
		failed_uid = 0;
	}

	if (ret < 0) {
		*error_r = mailbox_get_last_internal_error(client->mailbox, NULL);
		client_send_storage_error(client);
	} else {
		if (failed_uid == last_failed_uid && failed_uid != 0) {
			/* failed twice in same message */
			*error_r = t_strdup_printf(
				"Getting size of message UID=%u failed",
				failed_uid);
		} else {
			*error_r = "Can't sync mailbox: "
				"Messages keep getting expunged";
		}
		client_send_line(client, "-ERR [SYS/TEMP] Couldn't sync mailbox.");
	}
	return -1;
}

static enum uidl_keys parse_uidl_keymask(const char *format)
{
	enum uidl_keys mask = 0;

	for (; *format != '\0'; format++) {
		if (format[0] == '%' && format[1] != '\0') {
			switch (var_get_key(++format)) {
			case 'v':
				mask |= UIDL_UIDVALIDITY;
				break;
			case 'u':
				mask |= UIDL_UID;
				break;
			case 'm':
				mask |= UIDL_MD5;
				break;
			case 'f':
				mask |= UIDL_FILE_NAME;
				break;
			case 'g':
				mask |= UIDL_GUID;
				break;
			}
		}
	}
	return mask;
}

static void pop3_lock_session_refresh(struct client *client)
{
	if (file_dotlock_touch(client->session_dotlock) < 0) {
		client_send_line(client,
			"-ERR [SYS/TEMP] Couldn't update POP3 session lock.");
		client_destroy(client, "Couldn't lock POP3 session");
	}
}

int pop3_lock_session(struct client *client)
{
	const struct mail_storage_settings *mail_set =
		mail_storage_service_user_get_mail_set(client->service_user);
	struct dotlock_settings dotlock_set;
	enum mailbox_list_path_type type;
	const char *dir, *path;
	int ret;

	if (mailbox_list_get_root_path(client->inbox_ns->list,
				       MAILBOX_LIST_PATH_TYPE_INDEX, &dir)) {
		type = MAILBOX_LIST_PATH_TYPE_INDEX;
	} else if (mailbox_list_get_root_path(client->inbox_ns->list,
					      MAILBOX_LIST_PATH_TYPE_DIR, &dir)) {
		type = MAILBOX_LIST_PATH_TYPE_DIR;
	} else {
		i_error("pop3_lock_session: Storage has no root/index directory, "
			"can't create a POP3 session lock file");
		return -1;
	}
	if (mailbox_list_mkdir_root(client->inbox_ns->list, dir, type) < 0) {
		i_error("pop3_lock_session: Couldn't create root directory %s: %s",
			dir, mailbox_list_get_last_internal_error(client->inbox_ns->list, NULL));
		return -1;
	}
	path = t_strdup_printf("%s/"POP3_LOCK_FNAME, dir);

	dotlock_set = session_dotlock_set;
	dotlock_set.use_excl_lock = mail_set->dotlock_use_excl;
	dotlock_set.nfs_flush = mail_set->mail_nfs_storage;

	ret = file_dotlock_create(&dotlock_set, path, 0,
				  &client->session_dotlock);
	if (ret < 0)
		i_error("file_dotlock_create(%s) failed: %m", path);
	else if (ret > 0) {
		client->to_session_dotlock_refresh =
			timeout_add(POP3_SESSION_DOTLOCK_STALE_TIMEOUT_SECS*1000,
				    pop3_lock_session_refresh, client);
	}
	return ret;
}

struct client *client_create(int fd_in, int fd_out, const char *session_id,
			     struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct pop3_settings *set)
{
	struct client *client;
	pool_t pool;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	pool = pool_alloconly_create("pop3 client", 256);
	client = p_new(pool, struct client, 1);
	client->pool = pool;
	client->service_user = service_user;
	client->v = pop3_client_vfuncs;
	client->set = set;
	client->session_id = p_strdup(pool, session_id);
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->input = i_stream_create_fd(fd_in, MAX_INBUF_SIZE);
	client->output = o_stream_create_fd(fd_out, (size_t)-1);
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_set_flush_callback(client->output, client_output, client);

	if (set->rawlog_dir[0] != '\0') {
		(void)iostream_rawlog_create(set->rawlog_dir, &client->input,
					     &client->output);
	}

	p_array_init(&client->module_contexts, client->pool, 5);
	client->io = io_add_istream(client->input, client_input, client);
        client->last_input = ioloop_time;
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);
	client->to_commit = timeout_add(CLIENT_COMMIT_TIMEOUT_MSECS,
					client_commit_timeout, client);

	client->user = user;

	client->mail_set = mail_user_set_get_storage_set(user);
	client->uidl_keymask =
		parse_uidl_keymask(client->mail_set->pop3_uidl_format);
	if (client->uidl_keymask == 0)
		i_fatal("Invalid pop3_uidl_format");

	if (var_has_key(set->pop3_logout_format, 'u', "uidl_change")) {
		/* logging uidl_change. we need hashes of the UIDLs */
		client->message_uidls_save = TRUE;
	} else if (strcmp(set->pop3_uidl_duplicates, "allow") != 0) {
		/* UIDL duplicates aren't allowed, so we'll need to
		   keep track of them */
		client->message_uidls_save = TRUE;
	}

	pop3_client_count++;
	DLLIST_PREPEND(&pop3_clients, client);

	if (hook_client_created != NULL)
		hook_client_created(&client);

	return client;
}

int client_init_mailbox(struct client *client, const char **error_r)
{
        enum mailbox_flags flags;
	const char *ident, *errmsg;

	/* refresh proctitle before a potentially long-running init_mailbox() */
	pop3_refresh_proctitle();

	flags = MAILBOX_FLAG_POP3_SESSION;
	if (!client->set->pop3_no_flag_updates)
		flags |= MAILBOX_FLAG_DROP_RECENT;
	client->mailbox = mailbox_alloc(client->inbox_ns->list, "INBOX", flags);
	mailbox_set_reason(client->mailbox, "POP3 INBOX");
	if (mailbox_open(client->mailbox) < 0) {
		*error_r = t_strdup_printf("Couldn't open INBOX: %s",
			mailbox_get_last_internal_error(client->mailbox, NULL));
		client_send_storage_error(client);
		return -1;
	}

	if (init_pop3_deleted_flag(client, &errmsg) < 0 ||
	    init_mailbox(client, &errmsg) < 0) {
		*error_r = t_strdup_printf("Couldn't init INBOX: %s", errmsg);
		return -1;
	}

	if (!client->set->pop3_no_flag_updates && client->messages_count > 0)
		client->seen_bitmask = i_malloc(MSGS_BITMASK_SIZE(client));

	ident = mail_user_get_anvil_userip_ident(client->user);
	if (ident != NULL) {
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\tpop3/", ident, "\n", NULL));
		client->anvil_sent = TRUE;
	}
	return 0;
}

static const char *client_build_uidl_change_string(struct client *client)
{
	uint32_t i, old_hash, new_hash;
	unsigned int old_msg_count, new_msg_count;

	if (client->message_uidls == NULL) {
		/* UIDL command not given */
		return "";
	}

	/* 1..new-1 were probably left to mailbox by previous POP3 session */
	old_msg_count = client->lowest_retr_pop3_msn > 0 ?
		client->lowest_retr_pop3_msn - 1 : client->messages_count;
	for (i = 0, old_hash = 0; i < old_msg_count; i++)
		old_hash ^= crc32_str(client->message_uidls[i]);

	/* assume all except deleted messages were sent to POP3 client */
	if (!client->deleted) {
		for (i = 0, new_hash = 0; i < client->messages_count; i++)
			new_hash ^= crc32_str(client->message_uidls[i]);
	} else {
		for (i = 0, new_hash = 0; i < client->messages_count; i++) {
			if ((client->deleted_bitmask[i / CHAR_BIT] &
			     (1 << (i % CHAR_BIT))) != 0)
				continue;
			new_hash ^= crc32_str(client->message_uidls[i]);
		}
	}

	new_msg_count = client->messages_count - client->deleted_count;
	if (old_hash == new_hash && old_msg_count == new_msg_count)
		return t_strdup_printf("%u/%08x", old_msg_count, old_hash);
	else {
		return t_strdup_printf("%u/%08x -> %u/%08x",
				       old_msg_count, old_hash,
				       new_msg_count, new_hash);
	}
}

static const char *client_stats(struct client *client)
{
	const char *uidl_change = "";
	if (var_has_key(client->set->pop3_logout_format,
			'o', "uidl_change"))
		uidl_change = client_build_uidl_change_string(client);

	const struct var_expand_table logout_tab[] = {
		{ 'p', dec2str(client->top_bytes), "top_bytes" },
		{ 't', dec2str(client->top_count), "top_count" },
		{ 'b', dec2str(client->retr_bytes), "retr_bytes" },
		{ 'r', dec2str(client->retr_count), "retr_count" },
		{ 'd', !client->delete_success ? "0" :
		       dec2str(client->deleted_count), "deleted_count" },
		{ 'm', dec2str(client->messages_count), "message_count" },
		{ 's', dec2str(client->total_size), "message_bytes" },
		{ 'i', dec2str(client->input->v_offset), "input" },
		{ 'o', dec2str(client->output->offset), "output" },
		{ 'u', uidl_change, "uidl_change" },
		{ '\0', client->session_id, "session" },
		{ 'd', !client->delete_success ? "0" :
		       dec2str(client->deleted_size), "deleted_bytes" },
		{ '\0', NULL, NULL }
	};
	const struct var_expand_table *user_tab =
		mail_user_var_expand_table(client->user);
	const struct var_expand_table *tab =
		t_var_expand_merge_tables(logout_tab, user_tab);
	string_t *str;
	const char *error;

	str = t_str_new(128);
	if (var_expand_with_funcs(str, client->set->pop3_logout_format,
				  tab, mail_user_var_expand_func_table,
				  client->user, &error) < 0) {
		i_error("Failed to expand pop3_logout_format=%s: %s",
			client->set->pop3_logout_format, error);
	}
	return str_c(str);
}

void client_destroy(struct client *client, const char *reason)
{
	client->v.destroy(client, reason);
}

static void client_default_destroy(struct client *client, const char *reason)
{
	i_assert(!client->destroyed);

	client->destroyed = TRUE;

	if (client->seen_change_count > 0)
		(void)client_update_mails(client);

	if (!client->disconnected) {
		if (reason == NULL) {
			reason = io_stream_get_disconnect_reason(client->input,
								 client->output);
		}
		i_info("%s %s", reason, client_stats(client));
	}

	if (client->cmd != NULL) {
		/* deinitialize command */
		i_stream_close(client->input);
		o_stream_close(client->output);
		client->cmd(client);
		i_assert(client->cmd == NULL);
	}

	if (client->trans != NULL) {
		/* client didn't QUIT, but we still want to save any changes
		   done in this transaction. especially the cached virtual
		   message sizes. */
		(void)mailbox_transaction_commit(&client->trans);
	}
	if (array_is_created(&client->all_seqs))
		array_free(&client->all_seqs);
	if (client->deleted_kw != NULL)
		mailbox_keywords_unref(&client->deleted_kw);
	if (client->mailbox != NULL)
		mailbox_free(&client->mailbox);
	if (client->anvil_sent) {
		master_service_anvil_send(master_service, t_strconcat(
			"DISCONNECT\t", my_pid, "\tpop3/",
			mail_user_get_anvil_userip_ident(client->user),
			"\n", NULL));
	}

	if (client->session_dotlock != NULL)
		file_dotlock_delete(&client->session_dotlock);
	timeout_remove(&client->to_session_dotlock_refresh);

	pool_unref(&client->uidl_pool);
	i_free(client->message_sizes);
	i_free(client->deleted_bitmask);
	i_free(client->seen_bitmask);
	i_free(client->msgnum_to_seq_map);

	io_remove(&client->io);
	timeout_remove(&client->to_idle);
	timeout_remove(&client->to_commit);

	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	fd_close_maybe_stdio(&client->fd_in, &client->fd_out);

	/* Autoexpunging might run for a long time. Disconnect the client
	   before it starts, and refresh proctitle so it's clear that it's
	   doing autoexpunging. We've also sent DISCONNECT to anvil already,
	   because this is background work and shouldn't really be counted
	   as an active POP3 session for the user. */
	pop3_refresh_proctitle();
	mail_user_autoexpunge(client->user);
	mail_user_unref(&client->user);
	mail_storage_service_user_unref(&client->service_user);

	pop3_client_count--;
	DLLIST_REMOVE(&pop3_clients, client);
	pool_unref(&client->pool);

	master_service_client_connection_destroyed(master_service);
	pop3_refresh_proctitle();
}

static void client_destroy_timeout(struct client *client)
{
	client_destroy(client, NULL);
}

void client_disconnect(struct client *client, const char *reason)
{
	if (client->disconnected)
		return;

	client->disconnected = TRUE;
	i_info("Disconnected: %s %s", reason, client_stats(client));

	(void)o_stream_flush(client->output);

	i_stream_close(client->input);
	o_stream_close(client->output);

	timeout_remove(&client->to_idle);
	client->to_idle = timeout_add(0, client_destroy_timeout, client);
}

void client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;
	ssize_t ret;

	if (client->output->closed)
		return;

	va_start(va, fmt);

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, va);
		str_append(str, "\r\n");

		ret = o_stream_send(client->output,
				    str_data(str), str_len(str));
		i_assert(ret < 0 || (size_t)ret == str_len(str));
	} T_END;
	if (ret >= 0) {
		if (!POP3_CLIENT_OUTPUT_FULL(client))
			client->last_output = ioloop_time;
		else if (client->io != NULL) {
			/* no more input until client has read
			   our output */
			io_remove(&client->io);

			/* If someone happens to flush output, we want to get
			   our IO handler back in flush callback */
			o_stream_set_flush_pending(client->output, TRUE);
		}
	}
	va_end(va);
}

void client_send_storage_error(struct client *client)
{
	const char *errstr;
	enum mail_error error;

	if (mailbox_is_inconsistent(client->mailbox)) {
		client_send_line(client, "-ERR [SYS/TEMP] Mailbox is in inconsistent "
				 "state, please relogin.");
		client_disconnect(client, "Mailbox is in inconsistent state.");
		return;
	}

	errstr = mailbox_get_last_error(client->mailbox, &error);
	switch (error) {
	case MAIL_ERROR_TEMP:
	case MAIL_ERROR_NOQUOTA:
	case MAIL_ERROR_INUSE:
		client_send_line(client, "-ERR [SYS/TEMP] %s", errstr);
		break;
	default:
		client_send_line(client, "-ERR [SYS/PERM] %s", errstr);
		break;
	}
}

bool client_handle_input(struct client *client)
{
	char *line, *args;
	int ret;

	o_stream_cork(client->output);
	while (!client->output->closed &&
	       (line = i_stream_next_line(client->input)) != NULL) {
		args = strchr(line, ' ');
		if (args != NULL)
			*args++ = '\0';

		T_BEGIN {
			ret = client_command_execute(client, line,
						     args != NULL ? args : "");
		} T_END;
		if (ret >= 0) {
			client->bad_counter = 0;
			if (client->cmd != NULL) {
				o_stream_set_flush_pending(client->output,
							   TRUE);
				client->waiting_input = TRUE;
				break;
			}
		} else if (++client->bad_counter > CLIENT_MAX_BAD_COMMANDS) {
			client_send_line(client, "-ERR Too many bad commands.");
			client_disconnect(client, "Too many bad commands.");
		}
	}
	o_stream_uncork(client->output);

	if (client->output->closed) {
		client_destroy(client, NULL);
		return FALSE;
	}
	return TRUE;
}

static void client_input(struct client *client)
{
	if (client->cmd != NULL) {
		/* we're still processing a command. wait until it's
		   finished. */
		io_remove(&client->io);
		client->waiting_input = TRUE;
		return;
	}

	client->waiting_input = FALSE;
	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);
	if (client->to_commit != NULL)
		timeout_reset(client->to_commit);

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client, NULL);
		return;
	case -2:
		/* line too long, kill it */
		client_send_line(client, "-ERR Input line too long.");
		client_destroy(client, "Input line too long");
		return;
	}

	(void)client_handle_input(client);
}

static int client_output(struct client *client)
{
	if (o_stream_flush(client->output) < 0) {
		client_destroy(client, NULL);
		return 1;
	}

	client->last_output = ioloop_time;
	timeout_reset(client->to_idle);
	if (client->to_commit != NULL)
		timeout_reset(client->to_commit);

	if (client->cmd != NULL)
		client->cmd(client);

	if (client->cmd == NULL) {
		if (o_stream_get_buffer_used_size(client->output) <
		    POP3_OUTBUF_THROTTLE_SIZE/2 && client->io == NULL &&
		    !client->input->closed) {
			/* enable input again */
			client->io = io_add_istream(client->input, client_input,
						    client);
		}
		if (client->io != NULL && client->waiting_input) {
			if (!client_handle_input(client)) {
				/* client got destroyed */
				return 1;
			}
		}
	}

	if (client->cmd != NULL) {
		/* command not finished yet */
		return 0;
	} else if (client->io == NULL) {
		/* data still in output buffer, get back here to add IO */
		return 0;
	} else {
		return 1;
	}
}

void clients_destroy_all(void)
{
	while (pop3_clients != NULL) {
		if (pop3_clients->cmd == NULL) {
			client_send_line(pop3_clients,
				"-ERR [SYS/TEMP] Server shutting down.");
		}
		mail_storage_service_io_activate_user(pop3_clients->service_user);
		client_destroy(pop3_clients, "Server shutting down.");
	}
}

struct pop3_client_vfuncs pop3_client_vfuncs = {
	client_default_destroy
};
