/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "hostpid.h"
#include "str.h"
#include "file-create-locked.h"
#include "process-title.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "dsync-mailbox-tree.h"
#include "dsync-ibc.h"
#include "dsync-brain-private.h"
#include "dsync-mailbox-import.h"
#include "dsync-mailbox-export.h"

#include <sys/stat.h>

enum dsync_brain_title {
	DSYNC_BRAIN_TITLE_NONE = 0,
	DSYNC_BRAIN_TITLE_LOCKING,
};

static const char *dsync_state_names[] = {
	"master_recv_handshake",
	"slave_recv_handshake",
	"master_send_last_common",
	"slave_recv_last_common",
	"send_mailbox_tree",
	"send_mailbox_tree_deletes",
	"recv_mailbox_tree",
	"recv_mailbox_tree_deletes",
	"master_send_mailbox",
	"slave_recv_mailbox",
	"sync_mails",
	"finish",
	"done"
};

static void dsync_brain_mailbox_states_dump(struct dsync_brain *brain);

static const char *
dsync_brain_get_proctitle_full(struct dsync_brain *brain,
			       enum dsync_brain_title title)
{
	string_t *str = t_str_new(128);
	const char *import_title, *export_title;

	str_append_c(str, '[');
	if (brain->process_title_prefix != NULL)
		str_append(str, brain->process_title_prefix);
	str_append(str, brain->user->username);
	if (brain->box == NULL) {
		str_append_c(str, ' ');
		str_append(str, dsync_state_names[brain->state]);
	} else {
		str_append_c(str, ' ');
		str_append(str, mailbox_get_vname(brain->box));
		import_title = brain->box_importer == NULL ? "" :
			dsync_mailbox_import_get_proctitle(brain->box_importer);
		export_title = brain->box_exporter == NULL ? "" :
			dsync_mailbox_export_get_proctitle(brain->box_exporter);
		if (import_title[0] == '\0' && export_title[0] == '\0') {
			str_printfa(str, " send:%s recv:%s",
				    dsync_box_state_names[brain->box_send_state],
				    dsync_box_state_names[brain->box_recv_state]);
		} else {
			if (import_title[0] != '\0') {
				str_append(str, " import:");
				str_append(str, import_title);
			}
			if (export_title[0] != '\0') {
				str_append(str, " export:");
				str_append(str, export_title);
			}
		}
	}
	switch (title) {
	case DSYNC_BRAIN_TITLE_NONE:
		break;
	case DSYNC_BRAIN_TITLE_LOCKING:
		str_append(str, " locking "DSYNC_LOCK_FILENAME);
		break;
	}
	str_append_c(str, ']');
	return str_c(str);
}

static const char *dsync_brain_get_proctitle(struct dsync_brain *brain)
{
	return dsync_brain_get_proctitle_full(brain, DSYNC_BRAIN_TITLE_NONE);
}

static void dsync_brain_run_io(void *context)
{
	struct dsync_brain *brain = context;
	bool changed, try_pending;

	if (dsync_ibc_has_failed(brain->ibc)) {
		io_loop_stop(current_ioloop);
		brain->failed = TRUE;
		return;
	}

	try_pending = TRUE;
	do {
		if (!dsync_brain_run(brain, &changed)) {
			io_loop_stop(current_ioloop);
			break;
		}
		if (changed)
			try_pending = TRUE;
		else if (try_pending) {
			if (dsync_ibc_has_pending_data(brain->ibc))
				changed = TRUE;
			try_pending = FALSE;
		}
	} while (changed);
}

static struct dsync_brain *
dsync_brain_common_init(struct mail_user *user, struct dsync_ibc *ibc)
{
	struct dsync_brain *brain;
	const struct master_service_settings *service_set;
	pool_t pool;

	service_set = master_service_settings_get(master_service);
	mail_user_ref(user);

	pool = pool_alloconly_create("dsync brain", 10240);
	brain = p_new(pool, struct dsync_brain, 1);
	brain->pool = pool;
	brain->user = user;
	brain->ibc = ibc;
	brain->sync_type = DSYNC_BRAIN_SYNC_TYPE_UNKNOWN;
	brain->lock_fd = -1;
	brain->verbose_proctitle = service_set->verbose_proctitle;
	hash_table_create(&brain->mailbox_states, pool, 0,
			  guid_128_hash, guid_128_cmp);
	p_array_init(&brain->remote_mailbox_states, pool, 64);
	return brain;
}

static void
dsync_brain_set_flags(struct dsync_brain *brain, enum dsync_brain_flags flags)
{
	brain->mail_requests =
		(flags & DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS) != 0;
	brain->backup_send = (flags & DSYNC_BRAIN_FLAG_BACKUP_SEND) != 0;
	brain->backup_recv = (flags & DSYNC_BRAIN_FLAG_BACKUP_RECV) != 0;
	brain->debug = (flags & DSYNC_BRAIN_FLAG_DEBUG) != 0;
	brain->sync_visible_namespaces =
		(flags & DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES) != 0;
	brain->no_mail_sync = (flags & DSYNC_BRAIN_FLAG_NO_MAIL_SYNC) != 0;
	brain->no_backup_overwrite =
		(flags & DSYNC_BRAIN_FLAG_NO_BACKUP_OVERWRITE) != 0;
	brain->no_mail_prefetch =
		(flags & DSYNC_BRAIN_FLAG_NO_MAIL_PREFETCH) != 0;
	brain->no_mailbox_renames =
		(flags & DSYNC_BRAIN_FLAG_NO_MAILBOX_RENAMES) != 0;
	brain->no_notify = (flags & DSYNC_BRAIN_FLAG_NO_NOTIFY) != 0;
	brain->empty_hdr_workaround = (flags & DSYNC_BRAIN_FLAG_EMPTY_HDR_WORKAROUND) != 0;
}

static void
dsync_brain_open_virtual_all_box(struct dsync_brain *brain,
				 const char *vname)
{
	struct mail_namespace *ns;

	ns = mail_namespace_find(brain->user->namespaces, vname);
	brain->virtual_all_box =
		mailbox_alloc(ns->list, vname, MAILBOX_FLAG_READONLY);
}

struct dsync_brain *
dsync_brain_master_init(struct mail_user *user, struct dsync_ibc *ibc,
			enum dsync_brain_sync_type sync_type,
			enum dsync_brain_flags flags,
			const struct dsync_brain_settings *set)
{
	struct dsync_ibc_settings ibc_set;
	struct dsync_brain *brain;
	struct mail_namespace *const *nsp;
	string_t *sync_ns_str = NULL;
	const char *error;

	i_assert(sync_type != DSYNC_BRAIN_SYNC_TYPE_UNKNOWN);
	i_assert(sync_type != DSYNC_BRAIN_SYNC_TYPE_STATE ||
		 (set->state != NULL && *set->state != '\0'));
	i_assert(N_ELEMENTS(dsync_state_names) == DSYNC_STATE_DONE+1);

	brain = dsync_brain_common_init(user, ibc);
	brain->process_title_prefix =
		p_strdup(brain->pool, set->process_title_prefix);
	brain->sync_type = sync_type;
	if (array_count(&set->sync_namespaces) > 0) {
		sync_ns_str = t_str_new(128);
		p_array_init(&brain->sync_namespaces, brain->pool,
			     array_count(&set->sync_namespaces));
		array_foreach(&set->sync_namespaces, nsp) {
			str_append(sync_ns_str, (*nsp)->prefix);
			str_append_c(sync_ns_str, '\n');
			array_push_back(&brain->sync_namespaces, nsp);
		}
		str_delete(sync_ns_str, str_len(sync_ns_str)-1, 1);
	}
	brain->alt_char = set->mailbox_alt_char == '\0' ? '_' :
		set->mailbox_alt_char;
	brain->sync_since_timestamp = set->sync_since_timestamp;
	brain->sync_until_timestamp = set->sync_until_timestamp;
	brain->sync_max_size = set->sync_max_size;
	brain->sync_flag = p_strdup(brain->pool, set->sync_flag);
	brain->sync_box = p_strdup(brain->pool, set->sync_box);
	brain->exclude_mailboxes = set->exclude_mailboxes == NULL ? NULL :
		p_strarray_dup(brain->pool, set->exclude_mailboxes);
	memcpy(brain->sync_box_guid, set->sync_box_guid,
	       sizeof(brain->sync_box_guid));
	brain->lock_timeout = set->lock_timeout_secs;
	if (brain->lock_timeout != 0)
		brain->mailbox_lock_timeout_secs = brain->lock_timeout;
	else
		brain->mailbox_lock_timeout_secs =
			DSYNC_MAILBOX_DEFAULT_LOCK_TIMEOUT_SECS;
	brain->import_commit_msgs_interval = set->import_commit_msgs_interval;
	brain->master_brain = TRUE;
	brain->hashed_headers =
		(const char*const*)p_strarray_dup(brain->pool, set->hashed_headers);
	dsync_brain_set_flags(brain, flags);

	if (set->virtual_all_box != NULL)
		dsync_brain_open_virtual_all_box(brain, set->virtual_all_box);

	if (sync_type != DSYNC_BRAIN_SYNC_TYPE_STATE)
		;
	else if (dsync_mailbox_states_import(brain->mailbox_states, brain->pool,
					     set->state, &error) < 0) {
		hash_table_clear(brain->mailbox_states, FALSE);
		i_error("Saved sync state is invalid, "
			"falling back to full sync: %s", error);
		brain->sync_type = sync_type = DSYNC_BRAIN_SYNC_TYPE_FULL;
	} else {
		if (brain->debug) {
			i_debug("brain %c: Imported mailbox states:",
				brain->master_brain ? 'M' : 'S');
			dsync_brain_mailbox_states_dump(brain);
		}
	}
	dsync_brain_mailbox_trees_init(brain);

	i_zero(&ibc_set);
	ibc_set.hostname = my_hostdomain();
	ibc_set.sync_ns_prefixes = sync_ns_str == NULL ?
		NULL : str_c(sync_ns_str);
	ibc_set.sync_box = set->sync_box;
	ibc_set.virtual_all_box = set->virtual_all_box;
	ibc_set.exclude_mailboxes = set->exclude_mailboxes;
	ibc_set.sync_since_timestamp = set->sync_since_timestamp;
	ibc_set.sync_until_timestamp = set->sync_until_timestamp;
	ibc_set.sync_max_size = set->sync_max_size;
	ibc_set.sync_flags = set->sync_flag;
	memcpy(ibc_set.sync_box_guid, set->sync_box_guid,
	       sizeof(ibc_set.sync_box_guid));
	ibc_set.sync_type = sync_type;
	ibc_set.hdr_hash_v2 = TRUE;
	ibc_set.lock_timeout = set->lock_timeout_secs;
	ibc_set.import_commit_msgs_interval = set->import_commit_msgs_interval;
	ibc_set.hashed_headers = set->hashed_headers;
	/* reverse the backup direction for the slave */
	ibc_set.brain_flags = flags & ~(DSYNC_BRAIN_FLAG_BACKUP_SEND |
					DSYNC_BRAIN_FLAG_BACKUP_RECV);
	if ((flags & DSYNC_BRAIN_FLAG_BACKUP_SEND) != 0)
		ibc_set.brain_flags |= DSYNC_BRAIN_FLAG_BACKUP_RECV;
	else if ((flags & DSYNC_BRAIN_FLAG_BACKUP_RECV) != 0)
		ibc_set.brain_flags |= DSYNC_BRAIN_FLAG_BACKUP_SEND;
	dsync_ibc_send_handshake(ibc, &ibc_set);

	dsync_ibc_set_io_callback(ibc, dsync_brain_run_io, brain);
	brain->state = DSYNC_STATE_MASTER_RECV_HANDSHAKE;

	if (brain->verbose_proctitle)
		process_title_set(dsync_brain_get_proctitle(brain));
	return brain;
}

struct dsync_brain *
dsync_brain_slave_init(struct mail_user *user, struct dsync_ibc *ibc,
		       bool local, const char *process_title_prefix)
{
	struct dsync_ibc_settings ibc_set;
	struct dsync_brain *brain;

	brain = dsync_brain_common_init(user, ibc);
	brain->process_title_prefix =
		p_strdup(brain->pool, process_title_prefix);
	brain->state = DSYNC_STATE_SLAVE_RECV_HANDSHAKE;

	if (local) {
		/* both master and slave are running within the same process,
		   update the proctitle only for master. */
		brain->verbose_proctitle = FALSE;
	}

	i_zero(&ibc_set);
	ibc_set.hdr_hash_v2 = TRUE;
	ibc_set.hostname = my_hostdomain();
	dsync_ibc_send_handshake(ibc, &ibc_set);

	if (brain->verbose_proctitle)
		process_title_set(dsync_brain_get_proctitle(brain));
	dsync_ibc_set_io_callback(ibc, dsync_brain_run_io, brain);
	return brain;
}

static void dsync_brain_purge(struct dsync_brain *brain)
{
	struct mail_namespace *ns;
	struct mail_storage *storage;

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;

		storage = mail_namespace_get_default_storage(ns);
		if (mail_storage_purge(storage) < 0) {
			i_error("Purging namespace '%s' failed: %s", ns->prefix,
				mail_storage_get_last_internal_error(storage, NULL));
		}
	}
}

int dsync_brain_deinit(struct dsync_brain **_brain, enum mail_error *error_r)
{
	struct dsync_brain *brain = *_brain;
	int ret;

	*_brain = NULL;

	if (dsync_ibc_has_timed_out(brain->ibc)) {
		i_error("Timeout during state=%s%s",
			dsync_state_names[brain->state],
			brain->state != DSYNC_STATE_SYNC_MAILS ? "" :
			t_strdup_printf(" (send=%s recv=%s)",
				dsync_box_state_names[brain->box_send_state],
				dsync_box_state_names[brain->box_recv_state]));
	}
	if (dsync_ibc_has_failed(brain->ibc) ||
	    brain->state != DSYNC_STATE_DONE)
		brain->failed = TRUE;
	dsync_ibc_close_mail_streams(brain->ibc);

	if (brain->purge && !brain->failed)
		dsync_brain_purge(brain);

	if (brain->box != NULL)
		dsync_brain_sync_mailbox_deinit(brain);
	if (brain->virtual_all_box != NULL)
		mailbox_free(&brain->virtual_all_box);
	if (brain->local_tree_iter != NULL)
		dsync_mailbox_tree_iter_deinit(&brain->local_tree_iter);
	if (brain->local_mailbox_tree != NULL)
		dsync_mailbox_tree_deinit(&brain->local_mailbox_tree);
	if (brain->remote_mailbox_tree != NULL)
		dsync_mailbox_tree_deinit(&brain->remote_mailbox_tree);
	hash_table_iterate_deinit(&brain->mailbox_states_iter);
	hash_table_destroy(&brain->mailbox_states);

	pool_unref(&brain->dsync_box_pool);

	if (brain->lock_fd != -1) {
		/* unlink the lock file before it gets unlocked */
		i_unlink(brain->lock_path);
		if (brain->debug) {
			i_debug("brain %c: Unlocked %s",
				brain->master_brain ? 'M' : 'S',
				brain->lock_path);
		}
		file_lock_free(&brain->lock);
		i_close_fd(&brain->lock_fd);
	}

	ret = brain->failed ? -1 : 0;
	mail_user_unref(&brain->user);

	*error_r = !brain->failed ? 0 :
		(brain->mail_error == 0 ? MAIL_ERROR_TEMP : brain->mail_error);
	pool_unref(&brain->pool);
	return ret;
}

static int
dsync_brain_lock(struct dsync_brain *brain, const char *remote_hostname)
{
	const struct file_create_settings lock_set = {
		.lock_timeout_secs = brain->lock_timeout,
		.lock_method = FILE_LOCK_METHOD_FCNTL,
	};
	const char *home, *error, *local_hostname = my_hostdomain();
	bool created;
	int ret;

	if ((ret = strcmp(remote_hostname, local_hostname)) < 0) {
		/* locking done by remote */
		if (brain->debug) {
			i_debug("brain %c: Locking done by remote "
				"(local hostname=%s, remote hostname=%s)",
				brain->master_brain ? 'M' : 'S',
				local_hostname, remote_hostname);
		}
		return 0;
	}
	if (ret == 0 && !brain->master_brain) {
		/* running dsync within the same server.
		   locking done by master brain. */
		if (brain->debug) {
			i_debug("brain %c: Locking done by local master-brain "
				"(local hostname=%s, remote hostname=%s)",
				brain->master_brain ? 'M' : 'S',
				local_hostname, remote_hostname);
		}
		return 0;
	}

	if ((ret = mail_user_get_home(brain->user, &home)) < 0) {
		i_error("Couldn't look up user's home dir");
		return -1;
	}
	if (ret == 0) {
		i_error("User has no home directory");
		return -1;
	}

	if (brain->verbose_proctitle)
		process_title_set(dsync_brain_get_proctitle_full(brain, DSYNC_BRAIN_TITLE_LOCKING));
	brain->lock_path = p_strconcat(brain->pool, home,
				       "/"DSYNC_LOCK_FILENAME, NULL);
	brain->lock_fd = file_create_locked(brain->lock_path, &lock_set,
					    &brain->lock, &created, &error);
	if (brain->lock_fd == -1 && errno == ENOENT) {
		/* home directory not created */
		if (mail_user_home_mkdir(brain->user) < 0)
			return -1;
		brain->lock_fd = file_create_locked(brain->lock_path, &lock_set,
			&brain->lock, &created, &error);
	}
	if (brain->lock_fd == -1)
		i_error("Couldn't lock %s: %s", brain->lock_path, error);
	else if (brain->debug) {
		i_debug("brain %c: Locking done locally in %s "
			"(local hostname=%s, remote hostname=%s)",
			brain->master_brain ? 'M' : 'S',
			brain->lock_path, local_hostname, remote_hostname);
	}
	if (brain->verbose_proctitle)
		process_title_set(dsync_brain_get_proctitle(brain));
	return brain->lock_fd == -1 ? -1 : 0;
}

static void
dsync_brain_set_hdr_hash_version(struct dsync_brain *brain,
				 const struct dsync_ibc_settings *ibc_set)
{
	if (ibc_set->hdr_hash_v3)
		brain->hdr_hash_version = 3;
	else if (ibc_set->hdr_hash_v2)
		brain->hdr_hash_version = 3;
	else
		brain->hdr_hash_version = 1;
}

static bool dsync_brain_master_recv_handshake(struct dsync_brain *brain)
{
	const struct dsync_ibc_settings *ibc_set;

	i_assert(brain->master_brain);

	if (dsync_ibc_recv_handshake(brain->ibc, &ibc_set) == 0)
		return FALSE;

	if (brain->lock_timeout > 0) {
		if (dsync_brain_lock(brain, ibc_set->hostname) < 0) {
			brain->failed = TRUE;
			return FALSE;
		}
	}
	dsync_brain_set_hdr_hash_version(brain, ibc_set);

	brain->state = brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_STATE ?
		DSYNC_STATE_MASTER_SEND_LAST_COMMON :
		DSYNC_STATE_SEND_MAILBOX_TREE;
	return TRUE;
}

static bool dsync_brain_slave_recv_handshake(struct dsync_brain *brain)
{
	const struct dsync_ibc_settings *ibc_set;
	struct mail_namespace *ns;
	const char *const *prefixes;

	i_assert(!brain->master_brain);

	if (dsync_ibc_recv_handshake(brain->ibc, &ibc_set) == 0)
		return FALSE;
	dsync_brain_set_hdr_hash_version(brain, ibc_set);

	if (ibc_set->lock_timeout > 0) {
		brain->lock_timeout = ibc_set->lock_timeout;
		brain->mailbox_lock_timeout_secs = brain->lock_timeout;
		if (dsync_brain_lock(brain, ibc_set->hostname) < 0) {
			brain->failed = TRUE;
			return FALSE;
		}
	} else {
		brain->mailbox_lock_timeout_secs =
			DSYNC_MAILBOX_DEFAULT_LOCK_TIMEOUT_SECS;
	}

	if (ibc_set->sync_ns_prefixes != NULL) {
		p_array_init(&brain->sync_namespaces, brain->pool, 4);
		prefixes = t_strsplit(ibc_set->sync_ns_prefixes, "\n");
		if (prefixes[0] == NULL) {
			/* ugly workaround for strsplit API: there was one
			   prefix="" entry */
			static const char *empty_prefix[] = { "", NULL };
			prefixes = empty_prefix;
		}
		for (; *prefixes != NULL; prefixes++) {
			ns = mail_namespace_find(brain->user->namespaces,
						 *prefixes);
			if (ns == NULL) {
				i_error("Namespace not found: '%s'", *prefixes);
				brain->failed = TRUE;
				return FALSE;
			}
			array_push_back(&brain->sync_namespaces, &ns);
		}
	}
	brain->sync_box = p_strdup(brain->pool, ibc_set->sync_box);
	brain->exclude_mailboxes = ibc_set->exclude_mailboxes == NULL ? NULL :
		p_strarray_dup(brain->pool, ibc_set->exclude_mailboxes);
	brain->sync_since_timestamp = ibc_set->sync_since_timestamp;
	brain->sync_until_timestamp = ibc_set->sync_until_timestamp;
	brain->sync_max_size = ibc_set->sync_max_size;
	brain->sync_flag = p_strdup(brain->pool, ibc_set->sync_flags);
	memcpy(brain->sync_box_guid, ibc_set->sync_box_guid,
	       sizeof(brain->sync_box_guid));
	i_assert(brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_UNKNOWN);
	brain->sync_type = ibc_set->sync_type;

	dsync_brain_set_flags(brain, ibc_set->brain_flags);
	if (ibc_set->hashed_headers != NULL)
		brain->hashed_headers =
			p_strarray_dup(brain->pool, (const char*const*)ibc_set->hashed_headers);
	/* this flag is only set on the remote slave brain */
	brain->purge = (ibc_set->brain_flags &
			DSYNC_BRAIN_FLAG_PURGE_REMOTE) != 0;

	if (ibc_set->virtual_all_box != NULL)
		dsync_brain_open_virtual_all_box(brain, ibc_set->virtual_all_box);
	dsync_brain_mailbox_trees_init(brain);

	if (brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_STATE)
		brain->state = DSYNC_STATE_SLAVE_RECV_LAST_COMMON;
	else
		brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
	return TRUE;
}

static void dsync_brain_master_send_last_common(struct dsync_brain *brain)
{
	struct dsync_mailbox_state *state;
	uint8_t *guid;
	enum dsync_ibc_send_ret ret = DSYNC_IBC_SEND_RET_OK;

	i_assert(brain->master_brain);

	if (brain->mailbox_states_iter == NULL) {
		brain->mailbox_states_iter =
			hash_table_iterate_init(brain->mailbox_states);
	}

	for (;;) {
		if (ret == DSYNC_IBC_SEND_RET_FULL)
			return;
		if (!hash_table_iterate(brain->mailbox_states_iter,
					brain->mailbox_states, &guid, &state))
			break;
		ret = dsync_ibc_send_mailbox_state(brain->ibc, state);
	}
	hash_table_iterate_deinit(&brain->mailbox_states_iter);

	dsync_ibc_send_end_of_list(brain->ibc, DSYNC_IBC_EOL_MAILBOX_STATE);
	brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
}

static void dsync_mailbox_state_add(struct dsync_brain *brain,
				    const struct dsync_mailbox_state *state)
{
	struct dsync_mailbox_state *dupstate;
	uint8_t *guid_p;

	dupstate = p_new(brain->pool, struct dsync_mailbox_state, 1);
	*dupstate = *state;
	guid_p = dupstate->mailbox_guid;
	hash_table_insert(brain->mailbox_states, guid_p, dupstate);
}

static bool dsync_brain_slave_recv_last_common(struct dsync_brain *brain)
{
	struct dsync_mailbox_state state;
	enum dsync_ibc_recv_ret ret;
	bool changed = FALSE;

	i_assert(!brain->master_brain);

	while ((ret = dsync_ibc_recv_mailbox_state(brain->ibc, &state)) > 0) {
		dsync_mailbox_state_add(brain, &state);
		changed = TRUE;
	}
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
		changed = TRUE;
	}
	return changed;
}

static bool dsync_brain_finish(struct dsync_brain *brain)
{
	const char *error;
	enum mail_error mail_error;
	bool require_full_resync;
	enum dsync_ibc_recv_ret ret;

	if (!brain->master_brain) {
		dsync_ibc_send_finish(brain->ibc,
				      brain->failed ? "dsync failed" : NULL,
				      brain->mail_error,
				      brain->require_full_resync);
		brain->state = DSYNC_STATE_DONE;
		return TRUE;
	} 
	ret = dsync_ibc_recv_finish(brain->ibc, &error, &mail_error,
				    &require_full_resync);
	if (ret == DSYNC_IBC_RECV_RET_TRYAGAIN)
		return FALSE;
	if (error != NULL) {
		i_error("Remote dsync failed: %s", error);
		brain->failed = TRUE;
		if (mail_error != 0 &&
		    (brain->mail_error == 0 || brain->mail_error == MAIL_ERROR_TEMP))
			brain->mail_error = mail_error;
	}
	if (require_full_resync)
		brain->require_full_resync = TRUE;
	brain->state = DSYNC_STATE_DONE;
	return TRUE;
}

static bool dsync_brain_run_real(struct dsync_brain *brain, bool *changed_r)
{
	enum dsync_state orig_state = brain->state;
	enum dsync_box_state orig_box_recv_state = brain->box_recv_state;
	enum dsync_box_state orig_box_send_state = brain->box_send_state;
	bool changed = FALSE, ret = TRUE;

	if (brain->failed)
		return FALSE;

	switch (brain->state) {
	case DSYNC_STATE_MASTER_RECV_HANDSHAKE:
		changed = dsync_brain_master_recv_handshake(brain);
		break;
	case DSYNC_STATE_SLAVE_RECV_HANDSHAKE:
		changed = dsync_brain_slave_recv_handshake(brain);
		break;
	case DSYNC_STATE_MASTER_SEND_LAST_COMMON:
		dsync_brain_master_send_last_common(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_SLAVE_RECV_LAST_COMMON:
		changed = dsync_brain_slave_recv_last_common(brain);
		break;
	case DSYNC_STATE_SEND_MAILBOX_TREE:
		dsync_brain_send_mailbox_tree(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_RECV_MAILBOX_TREE:
		changed = dsync_brain_recv_mailbox_tree(brain);
		break;
	case DSYNC_STATE_SEND_MAILBOX_TREE_DELETES:
		dsync_brain_send_mailbox_tree_deletes(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_RECV_MAILBOX_TREE_DELETES:
		changed = dsync_brain_recv_mailbox_tree_deletes(brain);
		break;
	case DSYNC_STATE_MASTER_SEND_MAILBOX:
		dsync_brain_master_send_mailbox(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_SLAVE_RECV_MAILBOX:
		changed = dsync_brain_slave_recv_mailbox(brain);
		break;
	case DSYNC_STATE_SYNC_MAILS:
		changed = dsync_brain_sync_mails(brain);
		break;
	case DSYNC_STATE_FINISH:
		changed = dsync_brain_finish(brain);
		break;
	case DSYNC_STATE_DONE:
		changed = TRUE;
		ret = FALSE;
		break;
	}
	if (brain->verbose_proctitle) {
		if (orig_state != brain->state ||
		    orig_box_recv_state != brain->box_recv_state ||
		    orig_box_send_state != brain->box_send_state ||
		    ++brain->proctitle_update_counter % 100 == 0)
			process_title_set(dsync_brain_get_proctitle(brain));
	}
	*changed_r = changed;
	return brain->failed ? FALSE : ret;
}

bool dsync_brain_run(struct dsync_brain *brain, bool *changed_r)
{
	bool ret;

	*changed_r = FALSE;

	if (dsync_ibc_has_failed(brain->ibc)) {
		brain->failed = TRUE;
		return FALSE;
	}

	T_BEGIN {
		ret = dsync_brain_run_real(brain, changed_r);
	} T_END;
	return ret;
}

static void dsync_brain_mailbox_states_dump(struct dsync_brain *brain)
{
	struct hash_iterate_context *iter;
	struct dsync_mailbox_state *state;
	uint8_t *guid;

	iter = hash_table_iterate_init(brain->mailbox_states);
	while (hash_table_iterate(iter, brain->mailbox_states, &guid, &state)) {
		i_debug("brain %c: Mailbox %s state: uidvalidity=%u uid=%u modseq=%"PRIu64" pvt_modseq=%"PRIu64" messages=%u changes_during_sync=%d",
			brain->master_brain ? 'M' : 'S',
			guid_128_to_string(guid),
			state->last_uidvalidity,
			state->last_common_uid,
			state->last_common_modseq,
			state->last_common_pvt_modseq,
			state->last_messages_count,
			state->changes_during_sync ? 1 : 0);
	}
	hash_table_iterate_deinit(&iter);
}

void dsync_brain_get_state(struct dsync_brain *brain, string_t *output)
{
	struct hash_iterate_context *iter;
	struct dsync_mailbox_node *node;
	const struct dsync_mailbox_state *new_state;
	struct dsync_mailbox_state *state;
	const uint8_t *guid_p;
	uint8_t *guid;

	if (brain->require_full_resync)
		return;

	/* update mailbox states */
	array_foreach(&brain->remote_mailbox_states, new_state) {
		guid_p = new_state->mailbox_guid;
		state = hash_table_lookup(brain->mailbox_states, guid_p);
		if (state != NULL)
			*state = *new_state;
		else
			dsync_mailbox_state_add(brain, new_state);
	}

	/* remove nonexistent mailboxes */
	iter = hash_table_iterate_init(brain->mailbox_states);
	while (hash_table_iterate(iter, brain->mailbox_states, &guid, &state)) {
		node = dsync_mailbox_tree_lookup_guid(brain->local_mailbox_tree,
						      guid);
		if (node == NULL ||
		    node->existence != DSYNC_MAILBOX_NODE_EXISTS) {
			if (brain->debug) {
				i_debug("brain %c: Removed state for deleted mailbox %s",
					brain->master_brain ? 'M' : 'S',
					guid_128_to_string(guid));
			}
			hash_table_remove(brain->mailbox_states, guid);
		}
	}
	hash_table_iterate_deinit(&iter);

	if (brain->debug) {
		i_debug("brain %c: Exported mailbox states:",
			brain->master_brain ? 'M' : 'S');
		dsync_brain_mailbox_states_dump(brain);
	}
	dsync_mailbox_states_export(brain->mailbox_states, output);
}

enum dsync_brain_sync_type dsync_brain_get_sync_type(struct dsync_brain *brain)
{
	return brain->sync_type;
}

bool dsync_brain_has_failed(struct dsync_brain *brain)
{
	return brain->failed;
}

const char *dsync_brain_get_unexpected_changes_reason(struct dsync_brain *brain,
						      bool *remote_only_r)
{
	if (brain->changes_during_sync == NULL &&
	    brain->changes_during_remote_sync) {
		*remote_only_r = TRUE;
		return "Remote notified that changes happened during sync";
	}
	*remote_only_r = FALSE;
	return brain->changes_during_sync;
}

bool dsync_brain_want_namespace(struct dsync_brain *brain,
				struct mail_namespace *ns)
{
	struct mail_namespace *const *nsp;

	if (array_is_created(&brain->sync_namespaces)) {
		array_foreach(&brain->sync_namespaces, nsp) {
			if (ns == *nsp)
				return TRUE;
		}
		return FALSE;
	}
	if (ns->alias_for != NULL) {
		/* always skip aliases */
		return FALSE;
	}
	if (brain->sync_visible_namespaces) {
		if ((ns->flags & NAMESPACE_FLAG_HIDDEN) == 0)
			return TRUE;
		if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) != 0)
			return TRUE;
		return FALSE;
	} else {
		return strcmp(ns->unexpanded_set->location,
			      SETTING_STRVAR_UNEXPANDED) == 0;
	}
}

void dsync_brain_set_changes_during_sync(struct dsync_brain *brain,
					 const char *reason)
{
	if (brain->debug) {
		i_debug("brain %c: Change during sync: %s",
			brain->master_brain ? 'M' : 'S', reason);
	}
	if (brain->changes_during_sync == NULL)
		brain->changes_during_sync = p_strdup(brain->pool, reason);
}
