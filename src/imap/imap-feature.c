/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-feature.h"

static ARRAY_TYPE(imap_feature) feature_register = ARRAY_INIT;

bool imap_feature_lookup(const char *name, unsigned int *feature_idx_r)
{
	for (unsigned int idx = 0; idx < array_count(&feature_register); idx++) {
		const struct imap_feature *feat =
			array_idx(&feature_register, idx);
		if (strcasecmp(name, feat->feature) == 0) {
			*feature_idx_r = idx;
			return TRUE;
		}
	}
	return FALSE;
}

const struct imap_feature *imap_feature_idx(unsigned int feature_idx)
{
	return array_idx(&feature_register, feature_idx);
}

unsigned int
imap_feature_register(const char *feature, enum mailbox_feature mailbox_features,
		      imap_client_enable_callback_t *callback)
{
	struct imap_feature *feat = array_append_space(&feature_register);
	feat->feature = feature;
	feat->mailbox_features = mailbox_features;
	feat->callback = callback;
	return array_count(&feature_register)-1;
}

void imap_features_init(void)
{
	i_assert(!array_is_created(&feature_register));
	i_array_init(&feature_register, 8);
}

void imap_features_deinit(void)
{
	array_free(&feature_register);
}
