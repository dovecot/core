/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include "istream.h"
#include "istream-try.h"
#include "ostream.h"
#include "settings.h"
#include "dcrypt-iostream.h"
#include "istream-decrypt.h"
#include "ostream-encrypt.h"
#include "iostream-temp.h"
#include "mailbox-list.h"
#include "mail-namespace.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "dcrypt-iostream.h"
#include "fs-api-private.h"

#define FS_CRYPT_ISTREAM_MIN_BUFFER_SIZE 1024

struct crypt_fs {
	struct fs fs;
	struct mail_crypt_global_keys keys;
	bool keys_loaded;

	const struct crypt_settings *set;
};

struct crypt_fs_file {
	struct fs_file file;
	struct crypt_fs *fs;
	struct fs_file *super_read;
	enum fs_open_mode open_mode;
	struct istream *input;

	struct ostream *super_output;
	struct ostream *temp_output;
};

#define CRYPT_FS(ptr)	container_of((ptr), struct crypt_fs, fs)
#define CRYPT_FILE(ptr)	container_of((ptr), struct crypt_fs_file, file)

/* defined outside this file */
extern const struct fs fs_class_crypt;

static struct fs *fs_crypt_alloc(void)
{
	struct crypt_fs *fs;

	fs = i_new(struct crypt_fs, 1);
	fs->fs = fs_class_crypt;

	return &fs->fs;
}

static int
fs_crypt_init(struct fs *_fs, const struct fs_parameters *params,
	      const char **error_r)
{
	struct crypt_fs *fs = CRYPT_FS(_fs);
	const char *error;

	if (!dcrypt_initialize("openssl", NULL, &error))
		i_fatal("dcrypt_initialize(): %s", error);

	if (settings_get(_fs->event, &crypt_setting_parser_info, 0,
			 &fs->set, error_r) < 0)
		return -1;

	return fs_init_parent(_fs, params, error_r);
}

static void fs_crypt_free(struct fs *_fs)
{
	struct crypt_fs *fs = CRYPT_FS(_fs);

	mail_crypt_global_keys_free(&fs->keys);
	settings_free(fs->set);
	i_free(fs);
}

static struct fs_file *fs_crypt_file_alloc(void)
{
	struct crypt_fs_file *file = i_new(struct crypt_fs_file, 1);
	return &file->file;
}

static void
fs_crypt_file_init(struct fs_file *_file, const char *path,
		   enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct crypt_fs *fs = CRYPT_FS(_file->fs);
	struct crypt_fs_file *file = CRYPT_FILE(_file);

	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;

	/* avoid unnecessarily creating two seekable streams */
	flags &= ENUM_NEGATE(FS_OPEN_FLAG_SEEKABLE);

	file->file.parent = fs_file_init_parent(_file, path, mode, flags);
	if (mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for super, so fs_read_stream() won't create
		   another seekable stream needlessly */
		file->super_read = fs_file_init_parent(_file, path,
			mode, flags | FS_OPEN_FLAG_ASYNC |
			FS_OPEN_FLAG_ASYNC_NOQUEUE);
	} else {
		file->super_read = file->file.parent;
	}
}

static void fs_crypt_file_deinit(struct fs_file *_file)
{
	struct crypt_fs_file *file = CRYPT_FILE(_file);

	if (file->super_read != _file->parent)
		fs_file_deinit(&file->super_read);
	fs_file_free(_file);
	i_free(file->file.path);
	i_free(file);
}

static void fs_crypt_file_close(struct fs_file *_file)
{
	struct crypt_fs_file *file = CRYPT_FILE(_file);

	i_stream_unref(&file->input);
	fs_file_close(file->super_read);
	fs_file_close(_file->parent);
}

static void fs_crypt_set_metadata(struct fs_file *_file,
				  const char *key, const char *value)
{
	struct crypt_fs_file *file = CRYPT_FILE(_file);

	fs_set_metadata(_file->parent, key, value);
	if (file->super_read != NULL)
		fs_set_metadata(file->super_read, key, value);
}

static
int fs_crypt_load_keys(struct crypt_fs *fs, const char **error_r)
{
	if (fs->keys_loaded)
		return 0;
	if (mail_crypt_global_keys_load(fs->fs.event, fs->set,
					&fs->keys, error_r) < 0)
		return -1;
	fs->keys_loaded = TRUE;
	return 0;
}

static int
fs_crypt_istream_get_key(const char *pubkey_digest,
			 struct dcrypt_private_key **priv_key_r,
			 const char **error_r, void *context)
{
	struct crypt_fs_file *file = context;

	if (fs_crypt_load_keys(file->fs, error_r) < 0)
		return -1;

	*priv_key_r = mail_crypt_global_key_find(&file->fs->keys, pubkey_digest);
	if (*priv_key_r == NULL)
		return 0;
	dcrypt_key_ref_private(*priv_key_r);
	return 1;
}

static struct istream *
fs_crypt_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct crypt_fs_file *file = CRYPT_FILE(_file);
	struct istream *input;

	if (file->input != NULL) {
		i_stream_ref(file->input);
		i_stream_seek(file->input, 0);
		return file->input;
	}

	input = fs_read_stream(file->super_read,
		I_MAX(FS_CRYPT_ISTREAM_MIN_BUFFER_SIZE, max_buffer_size));

	if (file->fs->set->fs_crypt_read_plain_fallback) {
		struct istream *decrypted_input =
			i_stream_create_decrypt_callback(input,
					fs_crypt_istream_get_key, file);
		struct istream *plaintext_input =
			i_stream_create_noop(input);
		/* If the file is not encrypted, fall back to reading
		 * it as plaintext. */
		struct istream *inputs[] = {
			decrypted_input,
			plaintext_input,
			NULL
		};
		file->input = istream_try_create(inputs, max_buffer_size);
		i_stream_set_name(file->input, i_stream_get_name(inputs[0]));
		i_stream_unref(&decrypted_input);
		i_stream_unref(&plaintext_input);
	} else {
		file->input = i_stream_create_decrypt_callback(input,
					fs_crypt_istream_get_key, file);
	}
	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static void fs_crypt_write_stream(struct fs_file *_file)
{
	struct crypt_fs_file *file = CRYPT_FILE(_file);
	struct event *event = _file->event;
	const char *error;

	i_assert(_file->output == NULL);

	if (fs_crypt_load_keys(file->fs, &error) < 0) {
		_file->output = o_stream_create_error_str(EIO,
			"Couldn't read settings: %s", error);
		return;
	}

	if (file->fs->set->crypt_write_algorithm[0] == '\0') {
		e_debug(event, "Empty crypt_write_algorithm, "
			"NOT encrypting stream %s", fs_file_path(_file));
		file->super_output = fs_write_stream(_file->parent);
		_file->output = file->super_output;
		return;
	} else if (file->fs->keys.public_key == NULL) {
		_file->output = o_stream_create_error_str(EINVAL,
			"Encryption required, but no public key available");
		return;
	}

	enum io_stream_encrypt_flags flags;
	if (strstr(file->fs->set->crypt_write_algorithm, "gcm") != NULL ||
	    strstr(file->fs->set->crypt_write_algorithm, "ccm") != NULL ||
	    str_begins_with(file->fs->set->crypt_write_algorithm,
			    "chacha20-poly1305")) {
		flags = IO_STREAM_ENC_INTEGRITY_AEAD;
	} else {
		flags = IO_STREAM_ENC_INTEGRITY_HMAC;
	}

	file->temp_output =
		iostream_temp_create_named(_file->fs->temp_path_prefix,
					   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
					   fs_file_path(_file));
	_file->output = o_stream_create_encrypt(file->temp_output,
		file->fs->set->crypt_write_algorithm, file->fs->keys.public_key,
		flags);
}

static int fs_crypt_write_stream_finish(struct fs_file *_file, bool success)
{
	struct crypt_fs_file *file = CRYPT_FILE(_file);
	struct istream *input;
	int ret;

	if (_file->output != NULL) {
		if (_file->output == file->super_output)
			_file->output = NULL;
		else
			o_stream_unref(&_file->output);
	}
	if (!success) {
		if (file->super_output != NULL) {
			/* no encryption */
			i_assert(file->temp_output == NULL);
			fs_write_stream_abort_error(_file->parent, &file->super_output,
						    "write(%s) failed: %s",
						    o_stream_get_name(file->super_output),
						    o_stream_get_error(file->super_output));
		} else {
			o_stream_destroy(&file->temp_output);
		}
		return -1;
	}

	if (file->super_output != NULL) {
		/* no encrypt */
		i_assert(file->temp_output == NULL);
		return fs_write_stream_finish(_file->parent, &file->super_output);
	}
	if (file->temp_output == NULL) {
		/* finishing up */
		i_assert(file->super_output == NULL);
		return fs_write_stream_finish_async(_file->parent);
	}

	/* finish writing the temporary file */
	input = iostream_temp_finish(&file->temp_output, IO_BLOCK_SIZE);
	file->super_output = fs_write_stream(_file->parent);
	o_stream_nsend_istream(file->super_output, input);
	ret = fs_write_stream_finish(_file->parent, &file->super_output);
	i_stream_unref(&input);
	return ret;
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
		.set_metadata = fs_crypt_set_metadata,
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
