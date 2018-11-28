/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-feature.h"

bool imap_feature_lookup(const char *name, unsigned int *feature_idx_r)
{
	if (strcasecmp(name, "CONDSTORE") == 0)
		*feature_idx_r = imap_feature_condstore;
	else if (strcasecmp(name, "QRESYNC") == 0)
		*feature_idx_r = imap_feature_qresync;
	else
		return FALSE;
	return TRUE;
}
