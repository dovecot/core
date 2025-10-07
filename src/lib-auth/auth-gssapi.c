/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-gssapi.h"

static const gss_OID_desc auth_gssapi_mech_krb5_oid_desc =
	{ 9, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" };

const gss_OID_desc *auth_gssapi_mech_krb5_oid =
	&auth_gssapi_mech_krb5_oid_desc;

bool auth_gssapi_oid_equal(const gss_OID_desc *oid1, const gss_OID_desc *oid2)
{
	return (oid1->length == oid2->length &&
		mem_equals_timing_safe(oid1->elements, oid2->elements,
				       oid1->length));
}
