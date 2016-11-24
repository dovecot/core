#ifndef MAIL_CRYPT_KEY
#define MAIL_CRYPT_KEY

#include "mail-crypt-common.h"
#include "mail-crypt-global-key.h"
#include "mail-storage.h"

/*
   For mailboxes:

   shared/<mailbox GUID>/.../crypt/active = digest for the active public key
     that is used for encrypting new emails
   shared/<mailbox GUID>/.../crypt/pubkeys/<digest> = <key>
   private/<mailbox GUID>/.../crypt/privkeys/<digest> = <key>

   Similarly for users:

   shared/<INBOX GUID>/.../crypt/active = digest for the active public key that
     is used for encrypting new folder keys
   shared/<INBOX GUID>/.../crypt/pubkeys/<digest> = <key>
   private/<INBOX GUID>/.../crypt/privkeys/<digest> = <key>
*/

struct mail_crypt_key_cache_entry;

/**
 * key cache management functions
 */
void mail_crypt_key_cache_destroy(struct mail_crypt_key_cache_entry **cache);
void mail_crypt_key_register_mailbox_internal_attributes(void);

/* returns -1 on error, 0 not found, 1 = found */
int mail_crypt_get_private_key(struct mailbox *box, const char *pubid,
				bool user_key, bool shared,
				struct dcrypt_private_key **key_r,
				const char **error_r);
int mail_crypt_user_get_private_key(struct mail_user *user, const char *pubid,
				    struct dcrypt_private_key **key_r,
				    const char **error_r);
int mail_crypt_box_get_private_key(struct mailbox *box,
				   struct dcrypt_private_key **key_r,
				   const char **error_r);
int mail_crypt_box_get_private_keys(struct mailbox *box,
				    ARRAY_TYPE(dcrypt_private_key) *keys_r,
				    const char **error_r);
int mail_crypt_user_get_public_key(struct mail_user *user,
				   struct dcrypt_public_key **key_r,
				   const char **error_r);
int mail_crypt_box_get_public_key(struct mailbox *box,
				  struct dcrypt_public_key **key_r,
				  const char **error_r);
int mail_crypt_box_get_shared_key(struct mailbox *box,
				  const char *pubid,
				  struct dcrypt_private_key **key_r,
				  const char **error_r);
/* returns -1 on error, 0 no match , 1 = match */
int mail_crypt_private_key_id_match(struct dcrypt_private_key *key,
				     const char *pubid, const char **error_r);
int mail_crypt_public_key_id_match(struct dcrypt_public_key *key,
				   const char *pubid, const char **error_r);
/* returns -1 on error, 0 = ok */
int mail_crypt_user_set_private_key(struct mail_user *user, const char *pubid,
				    struct dcrypt_private_key *key,
				    const char **error_r);
int mail_crypt_box_set_private_key(struct mailbox *box, const char *pubid,
				   struct dcrypt_private_key *key,
				   struct dcrypt_public_key *user_key,
				   const char **error_r);
int mail_crypt_user_set_public_key(struct mail_user *user, const char *pubid,
				  struct dcrypt_public_key *key,
				  const char **error_r);
int mail_crypt_box_set_public_key(struct mailbox *box, const char *pubid,
				  struct dcrypt_public_key *key,
				  const char **error_r);
int mail_crypt_user_generate_keypair(struct mail_user *user,
				     struct dcrypt_keypair *pair,
				     const char **pubid_r,
				     const char **error_r);
int mail_crypt_box_generate_keypair(struct mailbox *box,
				    struct dcrypt_keypair *pair,
				    struct dcrypt_public_key *user_key,
				    const char **pubid_r,
				    const char **error_r);
/* returns -1 on error, 0 = ok */
int mail_crypt_box_set_shared_key(struct mailbox_transaction_context *t,
				  const char *pubid,
				  struct dcrypt_private_key *privkey,
				  const char *target_uid,
				  struct dcrypt_public_key *user_key,
				  const char **error_r);
int mail_crypt_box_unset_shared_key(struct mailbox_transaction_context *t,
				    const char *pubid,
				    const char *target_uid,
				    const char **error_r);
int mail_crypt_box_share_private_keys(struct mailbox_transaction_context *t,
					   struct dcrypt_public_key *dest_pub_key,
					   const char *dest_user,
					   const ARRAY_TYPE(dcrypt_private_key) *priv_keys,
					   const char **error_r);
/* returns -1 on error, 0 = ok
   these will also attempt to generate a keypair
*/
int mail_crypt_user_get_or_gen_public_key(struct mail_user *user,
					  struct dcrypt_public_key **pub_key_r,
					  const char **error_r);
int mail_crypt_box_get_or_gen_public_key(struct mailbox *box,
					 struct dcrypt_public_key **pub_key_r,
					 const char **error_r);

/* Lookup all private keys' digests. Returns 0 if ok, -1 on error. */
int mail_crypt_box_get_pvt_digests(struct mailbox *box, pool_t pool,
				   enum mail_attribute_type type,
				   ARRAY_TYPE(const_string) *digests,
				   const char **error_r);

/* is secure sharing enabled */
bool mail_crypt_acl_secure_sharing_enabled(struct mail_user *user);

#endif
