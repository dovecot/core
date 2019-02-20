#ifndef IMAP_FEATURE_H
#define IMAP_FEATURE_H

typedef void imap_client_enable_callback_t(struct client *);

struct imap_feature {
	const char *feature;
	enum mailbox_feature mailbox_features;
	imap_client_enable_callback_t *callback;
	bool enabled;
};
ARRAY_DEFINE_TYPE(imap_feature, struct imap_feature);

bool imap_feature_lookup(const char *name, unsigned int *feature_idx_r);
const struct imap_feature *imap_feature_idx(unsigned int feature_idx);

unsigned int
imap_feature_register(const char *feature, enum mailbox_feature mailbox_features,
		      imap_client_enable_callback_t *callback);

void imap_features_init(void);
void imap_features_deinit(void);

#endif
