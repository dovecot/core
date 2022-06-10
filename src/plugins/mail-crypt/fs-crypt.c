/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */
#define FS_CLASS_CRYPT fs_class_crypt
#include "fs-crypt-common.c"

static
int fs_crypt_load_keys(struct crypt_fs *fs, const char **error_r)
{
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
	if (mail_crypt_global_keys_load_pluginenv(fs->set_prefix, &fs->keys,
	    &error) < 0) {
		*error_r = t_strdup_printf("%s: %s", fs->set_prefix, error);
		return -1;
	}
	fs->keys_loaded = TRUE;
	return 0;
}

const struct fs fs_class_crypt = {
	.name = "crypt",
	.v = {
		.alloc = fs_crypt_alloc,
		.init = fs_crypt_init,
		.deinit = NULL,
		.free = fs_crypt_free,
		.get_properties = fs_wrapper_get_properties,
		.file_alloc = fs_crypt_file_alloc,
		.file_init = fs_crypt_file_init,
		.file_deinit = fs_crypt_file_deinit,
		.file_close = fs_crypt_file_close,
		.get_path = fs_wrapper_file_get_path,
		.set_async_callback = fs_wrapper_set_async_callback,
		.wait_async = fs_wrapper_wait_async,
		.set_metadata = fs_wrapper_set_metadata,
		.get_metadata = fs_wrapper_get_metadata,
		.prefetch = fs_wrapper_prefetch,
		.read = fs_read_via_stream,
		.read_stream = fs_crypt_read_stream,
		.write = fs_write_via_stream,
		.write_stream = fs_crypt_write_stream,
		.write_stream_finish = fs_crypt_write_stream_finish,
		.lock = fs_wrapper_lock,
		.unlock = fs_wrapper_unlock,
		.exists = fs_wrapper_exists,
		.stat = fs_wrapper_stat,
		.copy = fs_wrapper_copy,
		.rename = fs_wrapper_rename,
		.delete_file = fs_wrapper_delete,
		.iter_alloc = fs_wrapper_iter_alloc,
		.iter_init = fs_wrapper_iter_init,
		.iter_next = fs_wrapper_iter_next,
		.iter_deinit = fs_wrapper_iter_deinit,
		.switch_ioloop = NULL,
		.get_nlinks = fs_wrapper_get_nlinks,
	}
};
