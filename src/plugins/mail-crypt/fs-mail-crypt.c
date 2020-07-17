/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */
#define FS_CLASS_CRYPT fs_class_mail_crypt
#include "fs-crypt-common.c"

static
int fs_crypt_load_keys(struct crypt_fs *fs, const char **error_r)
{
	struct mailbox_list *list = mailbox_list_fs_get_list(&fs->fs);
	const char *error;

	if (fs->keys_loaded)
		return 0;
	if (fs->public_key_path != NULL || fs->private_key_path != NULL) {
		/* overrides using settings */
		if (fs_crypt_load_keys_from_path(fs, error_r) < 0)
			return -1;
		fs->keys_loaded = TRUE;
		return 0;
	}
	if (list == NULL) {
		*error_r = "fs-mail-crypt can be used only via lib-storage";
		return -1;
	}

	if (mail_crypt_global_keys_load(mailbox_list_get_namespace(list)->user, 
					fs->set_prefix, &fs->keys, FALSE,
					&error) < 0) {
		*error_r = t_strdup_printf("%s: %s", fs->set_prefix, error);
		return -1;
	}
	fs->keys_loaded = TRUE;
	return 0;
}

const struct fs fs_class_mail_crypt = {
	.name = "mail-crypt",
	.v = {
		fs_crypt_alloc,
		fs_crypt_init,
		NULL,
		fs_crypt_free,
		fs_wrapper_get_properties,
		fs_crypt_file_alloc,
		fs_crypt_file_init,
		fs_crypt_file_deinit,
		fs_crypt_file_close,
		fs_wrapper_file_get_path,
		fs_wrapper_set_async_callback,
		fs_wrapper_wait_async,
		fs_wrapper_set_metadata,
		fs_wrapper_get_metadata,
		fs_wrapper_prefetch,
		fs_read_via_stream,
		fs_crypt_read_stream,
		fs_write_via_stream,
		fs_crypt_write_stream,
		fs_crypt_write_stream_finish,
		fs_wrapper_lock,
		fs_wrapper_unlock,
		fs_wrapper_exists,
		fs_wrapper_stat,
		fs_wrapper_copy,
		fs_wrapper_rename,
		fs_wrapper_delete,
		fs_wrapper_iter_alloc,
		fs_wrapper_iter_init,
		fs_wrapper_iter_next,
		fs_wrapper_iter_deinit,
		NULL,
		fs_wrapper_get_nlinks,
	}
};
