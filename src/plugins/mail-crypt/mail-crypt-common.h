#ifndef MAIL_CRYPT_COMMON_H
#define MAIL_CRYPT_COMMON_H

#include "dcrypt.h"

#define MAIL_CRYPT_PW_CIPHER "aes-256-ctr"
#define MAIL_CRYPT_KEY_CIPHER "ecdh-aes-256-ctr"
#define MAIL_CRYPT_ENC_ALGORITHM "aes-256-gcm-sha256"
#define MAIL_CRYPT_KEY_ID_ALGORITHM "sha256"
#define MAIL_CRYPT_KEY_ATTRIBUTE_FORMAT DCRYPT_FORMAT_DOVECOT
#define MAIL_CRYPT_ACL_SECURE_SHARE_SETTING "mail_crypt_acl_require_secure_key_sharing"
#define MAIL_CRYPT_REQUIRE_ENCRYPTED_USER_KEY "mail_crypt_require_encrypted_user_key"
#define MAIL_CRYPT_HASH_BUF_SIZE 128
#define MAIL_CRYPT_KEY_BUF_SIZE 1024
#define ACTIVE_KEY_NAME "active"
#define PUBKEYS_PREFIX "pubkeys/"
#define PRIVKEYS_PREFIX "privkeys/"

#define BOX_CRYPT_PREFIX MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT"crypt/"
#define USER_CRYPT_PREFIX \
        MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
        MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT"crypt/"

#define MAIL_CRYPT_USERENV_PASSWORD "mail_crypt_private_password"
#define MAIL_CRYPT_USERENV_KEY "mail_crypt_private_key"
#define MAIL_CRYPT_USERENV_CURVE "mail_crypt_curve"

ARRAY_DEFINE_TYPE(dcrypt_private_key, struct dcrypt_private_key*);

#endif
