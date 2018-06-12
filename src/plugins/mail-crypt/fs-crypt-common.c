/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include "istream.h"
#include "ostream.h"
#include "istream-decrypt.h"
#include "ostream-encrypt.h"
#include "iostream-temp.h"
#include "mailbox-list.h"
#include "mail-namespace.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "dcrypt-iostream.h"
#include "fs-api-private.h"

struct crypt_fs {
	struct fs fs;
	struct mail_crypt_global_keys keys;
	bool keys_loaded;

	char *enc_algo;
	char *set_prefix;
	char *public_key_path;
	char *private_key_path;
	char *password;
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

/* defined outside this file */
extern const struct fs FS_CLASS_CRYPT;

static
int fs_crypt_load_keys(struct crypt_fs *fs, const char **error_r);

static struct fs *fs_crypt_alloc(void)
{
	struct crypt_fs *fs;

	fs = i_new(struct crypt_fs, 1);
	fs->fs = FS_CLASS_CRYPT;

	return &fs->fs;
}

static int
fs_crypt_init(struct fs *_fs, const char *args, const
	      struct fs_settings *set)
{
	struct crypt_fs *fs = (struct crypt_fs *)_fs;
	const char *enc_algo, *set_prefix;
	const char *p, *arg, *value, *error, *parent_name, *parent_args;
	const char *public_key_path = "", *private_key_path = "", *password = "";

	if (!dcrypt_initialize("openssl", NULL, &error))
		i_fatal("dcrypt_initialize(): %s", error);

	/* [algo=<s>:][set_prefix=<n>:][public_key_path=<s>:]
	   [private_key_path=<s>:[password=<s>:]]<parent fs> */
	set_prefix = "mail_crypt_global";
	enc_algo = "aes-256-gcm-sha256";
	for (;;) {
		p = strchr(args, ':');
		if (p == NULL) {
			fs_set_error(_fs, "Missing parameters");
			return -1;
		}
		arg = t_strdup_until(args, p);
		if ((value = strchr(arg, '=')) == NULL)
			break;
		arg = t_strdup_until(arg, value++);
		args = p+1;

		if (strcmp(arg, "algo") == 0)
			enc_algo = value;
		else if (strcmp(arg, "set_prefix") == 0)
			set_prefix = value;
		else if (strcmp(arg, "public_key_path") == 0)
			public_key_path = value;
		else if (strcmp(arg, "private_key_path") == 0)
			private_key_path = value;
		else if (strcmp(arg, "password") == 0)
			password = value;
		else {
			fs_set_error(_fs, "Invalid parameter '%s'", arg);
			return -1;
		}
	}

	parent_args = strchr(args, ':');
	if (parent_args == NULL) {
		parent_name = args;
		parent_args = "";
	} else {
		parent_name = t_strdup_until(args, parent_args);
		parent_args++;
	}
	if (fs_init(parent_name, parent_args, set, &_fs->parent, &error) < 0) {
		fs_set_error(_fs, "%s: %s", parent_name, error);
		return -1;
	}
	fs->enc_algo = i_strdup(enc_algo);
	fs->set_prefix = i_strdup(set_prefix);
	fs->public_key_path = i_strdup_empty(public_key_path);
	fs->private_key_path = i_strdup_empty(private_key_path);
	fs->password = i_strdup_empty(password);
	return 0;
}

static void fs_crypt_deinit(struct fs *_fs)
{
	struct crypt_fs *fs = (struct crypt_fs *)_fs;

	mail_crypt_global_keys_free(&fs->keys);
	fs_deinit(&_fs->parent);
	i_free(fs->enc_algo);
	i_free(fs->set_prefix);
	i_free(fs->public_key_path);
	i_free(fs->private_key_path);
	i_free(fs->password);
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
	struct crypt_fs *fs = (struct crypt_fs *)_file->fs;
	struct crypt_fs_file *file = (struct crypt_fs_file *)_file;

	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;

	/* avoid unnecessarily creating two seekable streams */
	flags &= ~FS_OPEN_FLAG_SEEKABLE;

	file->file.parent = fs_file_init_parent(_file, path, mode | flags);
	if (mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for super, so fs_read_stream() won't create
		   another seekable stream needlessly */
		file->super_read = fs_file_init_parent(_file, path,
			mode | flags | FS_OPEN_FLAG_ASYNC);
	} else {
		file->super_read = file->file.parent;
	}
}

static void fs_crypt_file_deinit(struct fs_file *_file)
{
	struct crypt_fs_file *file = (struct crypt_fs_file *)_file;

	if (file->super_read != _file->parent)
		fs_file_deinit(&file->super_read);
	fs_file_deinit(&_file->parent);
	i_free(file->file.path);
	i_free(file);
}

static void fs_crypt_file_close(struct fs_file *_file)
{
	struct crypt_fs_file *file = (struct crypt_fs_file *)_file;

	i_stream_unref(&file->input);
	fs_file_close(file->super_read);
	fs_file_close(_file->parent);
}

static int fs_crypt_read_file(const char *set_name, const char *path,
			      char **key_data_r, const char **error_r)
{
	struct istream *input;
	int ret;

	input = i_stream_create_file(path, (size_t)-1);
	while (i_stream_read(input) > 0) ;
	if (input->stream_errno != 0) {
		*error_r = t_strdup_printf("%s: read(%s) failed: %s",
			set_name, path, i_stream_get_error(input));
		ret = -1;
	} else {
		size_t size;
		const unsigned char *data = i_stream_get_data(input, &size);
		*key_data_r = i_strndup(data, size);
		ret = 0;
	}
	i_stream_unref(&input);
	return ret;
}

static int
fs_crypt_load_keys_from_path(struct crypt_fs *fs, const char **error_r)
{
	char *key_data;

	mail_crypt_global_keys_init(&fs->keys);
	if (fs->public_key_path != NULL) {
		if (fs_crypt_read_file("crypt:public_key_path",
					fs->public_key_path,
					&key_data, error_r) < 0)
			return -1;
		if (mail_crypt_load_global_public_key("crypt:public_key_path",
						      key_data, &fs->keys,
						      error_r) < 0) {
			i_free(key_data);
			return -1;
		}
		i_free(key_data);
	}
	if (fs->private_key_path != NULL) {
		if (fs_crypt_read_file("crypt:private_key_path",
					fs->private_key_path,
					&key_data, error_r) < 0)
			return -1;
		if (mail_crypt_load_global_private_key("crypt:private_key_path",
							key_data, "crypt:password",
							fs->password, &fs->keys,
							error_r) < 0) {
			i_free(key_data);
			return -1;
		}
		i_free(key_data);
	}
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
	struct crypt_fs_file *file = (struct crypt_fs_file *)_file;
	struct istream *input;

	if (file->input != NULL) {
		i_stream_ref(file->input);
		i_stream_seek(file->input, 0);
		return file->input;
	}

	input = fs_read_stream(file->super_read, max_buffer_size);

	file->input = i_stream_create_decrypt_callback(input,
				fs_crypt_istream_get_key, file);
	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static void fs_crypt_write_stream(struct fs_file *_file)
{
	struct crypt_fs_file *file = (struct crypt_fs_file *)_file;
	const char *error;

	i_assert(_file->output == NULL);

	if (fs_crypt_load_keys(file->fs, &error) < 0) {
		_file->output = o_stream_create_error_str(EIO,
			"Couldn't read settings: %s", error);
		return;
	}

	if (file->fs->keys.public_key == NULL) {
		if (_file->fs->set.debug)
			i_debug("No public key provided, "
				"NOT encrypting stream %s",
				 fs_file_path(_file));
		file->super_output = fs_write_stream(_file->parent);
		_file->output = file->super_output;
		return;
	}

	enum io_stream_encrypt_flags flags;
	if (strstr(file->fs->enc_algo, "gcm") != NULL ||
	    strstr(file->fs->enc_algo, "ccm") != NULL) {
		flags = IO_STREAM_ENC_INTEGRITY_AEAD;
	} else {
		flags = IO_STREAM_ENC_INTEGRITY_HMAC;
	}

	file->temp_output =
		iostream_temp_create_named(_file->fs->temp_path_prefix,
					   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
					   fs_file_path(_file));
	_file->output = o_stream_create_encrypt(file->temp_output,
		file->fs->enc_algo, file->fs->keys.public_key,
		flags);
}

static int fs_crypt_write_stream_finish(struct fs_file *_file, bool success)
{
	struct crypt_fs_file *file = (struct crypt_fs_file *)_file;
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
