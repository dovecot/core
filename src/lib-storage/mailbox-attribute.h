#ifndef MAILBOX_ATTRIBUTE_H
#define MAILBOX_ATTRIBUTE_H

/*
 * Attribute Handling in Dovecot
 * =============================
 *
 * What IMAP & doveadm users see gets translated into one of several things
 * depending on if we're operating on a mailbox or on server metadata (""
 * mailbox in IMAP parlance).  Consider these examples:
 *
 *	/private/foo
 *	/shared/foo
 *
 * Here "foo" can be any RFC defined attribute name, or a vendor-prefixed
 * non-standard name.  (Our vendor prefix is "vendor/vendor.dovecot".)
 *
 * In all cases, the "/private" and "/shared" user visible prefixes get
 * replaced by priv/<GUID> and shared/<GUID>, respectively.  (Here, <GUID>
 * is the GUID of the mailbox with which the attribute is associated.)  This
 * way, attributes for all mailboxes can be stored in a single dict.  For
 * example, the above examples would map to:
 *
 *	priv/<GUID>/foo
 *	shared/<GUID>/foo
 *
 * More concrete examples:
 *
 *	/private/comment
 *	/private/vendor/vendor.dovecot/abc
 *
 * turn into:
 *
 *	priv/<GUID>/comment
 *	priv/<GUID>/vendor/vendor.dovecot/abc
 *
 * Server attributes, that is attributes not associated with a mailbox, are
 * stored in the INBOX mailbox with a special prefix -
 * vendor/vendor.dovecot/pvt/server.  For example, the server attribute
 * /private/comment gets mapped to:
 *
 *	priv/<INBOX GUID>/vendor/vendor.dovecot/pvt/server/comment
 *
 * This means that if we set a /private/comment server attribute as well as
 * /private/comment INBOX mailbox attribute, we'll see the following paths
 * used in the dict:
 *
 *	priv/<INBOX GUID>/comment                                   <- mailbox attr
 *	priv/<INBOX GUID>/vendor/vendor.dovecot/pvt/server/comment  <- server attr
 *
 * The case of vendor specific server attributes is a bit confusing, but
 * consistent.  For example, this server attribute:
 *
 *	/private/vendor/vendor.dovecot/abc
 *
 * It will get mapped to:
 *
 *	priv/<INBOX GUID>/vendor/vendor.dovecot/pvt/server/vendor/vendor.dovecot/abc
 *	                  |                              | |                       |
 *	                  \----- server attr prefix -----/ \-- server attr name ---/
 *
 *
 * Internal Attributes
 * -------------------
 *
 * The final aspect of attribute handling in Dovecot are the so called
 * "internal attributes".
 *
 * The easiest way to explain internal attributes is to summarize attributes
 * in general.  Attributes are just <key,value> pairs that are stored in a
 * dict.  The key is mangled according to the above rules before passed to
 * the dict code.  That is, the key already encodes whether the attribute is
 * private or shared, the GUID of the mailbox (or of INBOX for server
 * attributes), etc.  There is no processing of the value.  It is stored and
 * returned to clients verbatim.
 *
 * Internal attributes, on the other hand, are special cased attributes.
 * That is, the code contains a list of specific attribute names and how to
 * handle them.  Each internal attribute is defined by a struct
 * mailbox_attribute_internal.  It contains the pre-parsed name of the
 * attribute (type, key, and flags), and how to handle getting and setting
 * of the attribute (rank, get, and set).
 *
 * The values for these attributes may come from two places - from the
 * attributes dict, or from the get function pointer.  Which source to use
 * is identified by the rank (MAIL_ATTRIBUTE_INTERNAL_RANK_*).
 *
 *
 * Access
 * ------
 *
 * In general, a user (IMAP or doveadm) can access all attributes for a
 * mailbox.  The one exception are attributes under:
 *
 *	/private/vendor/vendor.dovecot/pvt
 *	/shared/vendor/vendor.dovecot/pvt
 *
 * Which as you may recall map to:
 *
 *	priv/<GUID>/vendor/vendor.dovecot/pvt
 *	shared/<GUID>/vendor/vendor.dovecot/pvt
 *
 * These are deemed internal to Dovecot, and therefore of no concern to the
 * user.
 *
 * Server attributes have a similar restriction.  That is, attributes
 * beginning with the following are not accessible:
 *
 *	/private/vendor/vendor.dovecot/pvt
 *	/shared/vendor/vendor.dovecot/pvt
 *
 * However since server attributes are stored under the INBOX mailbox, these
 * paths map to:
 *
 *	priv/<INBOX GUID>/vendor/vendor.dovecot/pvt/server/vendor/vendor.dovecot/pvt
 *	shared/<INBOX GUID>/vendor/vendor.dovecot/pvt/server/vendor/vendor.dovecot/pvt
 *
 * As a result, the code performs access checks via the
 * MAILBOX_ATTRIBUTE_KEY_IS_USER_ACCESSIBLE() macro to make sure that the
 * user is allowed access to the attribute.
 *
 *
 * Nicknames
 * ---------
 *
 * Since every path stored in the dict begins with priv/<GUID> or
 * shared/<GUID>, these prefixes are often omitted.  This also matches the
 * internal implementation where the priv/ or shared/ prefix is specified
 * using an enum, and only the path after the GUID is handled as a string.
 * For example:
 *
 *	priv/<GUID>/vendor/vendor.dovecot/pvt/server/foo
 *
 * would be referred to as:
 *
 *	vendor/vendor.dovecot/pvt/server/foo
 *
 * Since some of the generated paths are very long, developers often use a
 * shorthand to refer to some of these paths.  For example,
 *
 *	pvt/server/pvt
 *
 * is really:
 *
 *	vendor/vendor.dovecot/pvt/server/vendor/vendor.dovecot/pvt
 *
 * Which when fully specified with a type and INBOX's GUID would turn into
 * one of the following:
 *
 *	priv/<GUID>/vendor/vendor.dovecot/pvt/server/vendor/vendor.dovecot/pvt
 *	shared/<GUID>/vendor/vendor.dovecot/pvt/server/vendor/vendor.dovecot/pvt
 */

struct mailbox;
struct mailbox_transaction_context;

/* RFC 5464 specifies that this is vendor/<vendor-token>/. The registered
   vendor-tokens always begin with "vendor." so there's some redundancy.. */
#define MAILBOX_ATTRIBUTE_PREFIX_DOVECOT "vendor/vendor.dovecot/"
/* Prefix used for attributes reserved for Dovecot's internal use. Normal
   users cannot access these in any way. */
#define MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT"pvt/"
/* Server attributes are currently stored in INBOX under this private prefix.
   They're under the pvt/ prefix so they won't be listed as regular INBOX
   attributes, but unlike other pvt/ attributes it's actually possible to
   access these attributes as regular users.

   If INBOX is deleted, attributes under this prefix are preserved. */
#define MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT"server/"

/* User can get/set all non-pvt/ attributes and also pvt/server/
   (but not pvt/server/pvt/) attributes. */
#define MAILBOX_ATTRIBUTE_KEY_IS_USER_ACCESSIBLE(key) \
	(!str_begins(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT) || \
	 (str_begins(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER) && \
	  strncmp(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT, \
		 strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT)) != 0))

enum mail_attribute_type {
	MAIL_ATTRIBUTE_TYPE_PRIVATE,
	MAIL_ATTRIBUTE_TYPE_SHARED
};
enum mail_attribute_value_flags {
	MAIL_ATTRIBUTE_VALUE_FLAG_READONLY	= 0x01,
	MAIL_ATTRIBUTE_VALUE_FLAG_INT_STREAMS	= 0x02
};

struct mail_attribute_value {
	/* mailbox_attribute_set() can set either value or value_stream.
	   mailbox_attribute_get() returns only values, but
	   mailbox_attribute_get_stream() may return either value or
	   value_stream. The caller must unreference the returned streams. */
	const char *value;
	struct istream *value_stream;

	/* Last time the attribute was changed (0 = unknown). This may be
	   returned even for values that don't exist anymore. */
	time_t last_change;

	enum mail_attribute_value_flags flags;
};

/*
 * Internal attribute
 */

enum mail_attribute_internal_rank {
	/* The internal attribute serves only as a source for a default value
	   when the normal mailbox attribute storage has no entry for this
	   attribute. Otherwise it is ignored. The `set' function is called
	   only as a notification, not with the intention to store the value.
	   The value is always assigned to the normal mailbox attribute storage. 
	 */
	MAIL_ATTRIBUTE_INTERNAL_RANK_DEFAULT = 0,
	/* The internal attribute serves as the main source of the attribute
	   value. If the `get' function returns 0, the normal mailbox attribute
	   storage is attempted to obtain the value. The `set' function is
	   called only as a notification, not with the intention to store the
	   value. The value is assigned to the normal mailbox attribute storage.
	 */
	MAIL_ATTRIBUTE_INTERNAL_RANK_OVERRIDE,
	/* The value for the internal attribute is never read from the normal
	   mailbox attribute storage. If the `set' function is NULL, the
	   attribute is read-only. If it is not NULL it is used to assign the
	   attribute value; it is not assigned to the normal mailbox attribute
	   storage.
	 */
	MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY
};

enum mail_attribute_internal_flags {
	/* Apply this attribute to the given key and its children. */
	MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN	= 0x01
};

struct mailbox_attribute_internal {
	enum mail_attribute_type type;
	const char *key; /* relative to the GUID, e.g., "comment" */
	enum mail_attribute_internal_rank rank;
	enum mail_attribute_internal_flags flags;

	/* Get the value of this internal attribute */
	int (*get)(struct mailbox *box, const char *key,
		   struct mail_attribute_value *value_r);
	/* Set the value of this internal attribute */
	int (*set)(struct mailbox_transaction_context *t, const char *key,
		   const struct mail_attribute_value *value);
};

void mailbox_attribute_register_internal(
	const struct mailbox_attribute_internal *iattr);
void mailbox_attribute_register_internals(
	const struct mailbox_attribute_internal *iattrs, unsigned int count);

void mailbox_attribute_unregister_internal(
	const struct mailbox_attribute_internal *iattr);
void mailbox_attribute_unregister_internals(
	const struct mailbox_attribute_internal *iattrs, unsigned int count);

/*
 * Attribute API
 */

/* Set mailbox attribute key to value. The key should be compatible with
   IMAP METADATA, so for Dovecot-specific keys use
   MAILBOX_ATTRIBUTE_PREFIX_DOVECOT. */
int mailbox_attribute_set(struct mailbox_transaction_context *t,
			  enum mail_attribute_type type, const char *key,
			  const struct mail_attribute_value *value);
/* Delete mailbox attribute key. This is just a wrapper to
   mailbox_attribute_set() with value->value=NULL. */
int mailbox_attribute_unset(struct mailbox_transaction_context *t,
			    enum mail_attribute_type type, const char *key);
/* Returns value for mailbox attribute key. Returns 1 if value was returned,
   0 if value wasn't found (set to NULL), -1 if error */
int mailbox_attribute_get(struct mailbox *box,
			  enum mail_attribute_type type, const char *key,
			  struct mail_attribute_value *value_r);
/* Same as mailbox_attribute_get(), but the returned value may be either an
   input stream or a string. */
int mailbox_attribute_get_stream(struct mailbox *box,
				 enum mail_attribute_type type, const char *key,
				 struct mail_attribute_value *value_r);

/* Iterate through mailbox attributes of the given type. The prefix can be used
   to restrict what attributes are returned. */
struct mailbox_attribute_iter *
mailbox_attribute_iter_init(struct mailbox *box, enum mail_attribute_type type,
			    const char *prefix);
/* Returns the attribute key or NULL if there are no more attributes. */
const char *mailbox_attribute_iter_next(struct mailbox_attribute_iter *iter);
int mailbox_attribute_iter_deinit(struct mailbox_attribute_iter **iter);

#endif
