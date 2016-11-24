#ifndef MAIL_CRYPT_PLUGIN_H
#define MAIL_CRYPT_PLUGIN_H

struct mailbox;
struct module;

struct mail_crypt_cache {
	struct timeout *to;
	struct mailbox *box;
	uint32_t uid;

	struct istream *input;
};

struct mail_crypt_user {
	union mail_user_module_context module_ctx;

	struct mail_crypt_global_keys global_keys;
	struct mail_crypt_cache cache;
	struct mail_crypt_key_cache_entry *key_cache;
	const char *curve;
	int save_version;
};

void mail_crypt_plugin_init(struct module *module);
void mail_crypt_plugin_deinit(void);

#define MAIL_CRYPT_MAIL_CACHE_EXPIRE_MSECS (60*1000)

struct mail_crypt_user *mail_crypt_get_mail_crypt_user(struct mail_user *user);

#endif
