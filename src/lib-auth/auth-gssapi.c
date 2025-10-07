/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-gssapi.h"

bool auth_gssapi_oid_equal(const gss_OID_desc *oid1, const gss_OID_desc *oid2)
{
	return (oid1->length == oid2->length &&
		mem_equals_timing_safe(oid1->elements, oid2->elements,
				       oid1->length));
}
