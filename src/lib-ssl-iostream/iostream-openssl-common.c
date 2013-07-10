/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "iostream-openssl.h"

#include <openssl/x509v3.h>

enum {
	DOVECOT_SSL_PROTO_SSLv2		= 0x01,
	DOVECOT_SSL_PROTO_SSLv3		= 0x02,
	DOVECOT_SSL_PROTO_TLSv1		= 0x04,
	DOVECOT_SSL_PROTO_TLSv1_1	= 0x08,
	DOVECOT_SSL_PROTO_TLSv1_2	= 0x10,
	DOVECOT_SSL_PROTO_ALL		= 0x1f
};

int openssl_get_protocol_options(const char *protocols)
{
	const char *const *tmp;
	int proto, op = 0, include = 0, exclude = 0;
	bool neg;

	tmp = t_strsplit_spaces(protocols, " ");
	for (; *tmp != NULL; tmp++) {
		const char *name = *tmp;

		if (*name != '!')
			neg = FALSE;
		else {
			name++;
			neg = TRUE;
		}
		if (strcasecmp(name, SSL_TXT_SSLV2) == 0)
			proto = DOVECOT_SSL_PROTO_SSLv2;
		else if (strcasecmp(name, SSL_TXT_SSLV3) == 0)
			proto = DOVECOT_SSL_PROTO_SSLv3;
		else if (strcasecmp(name, SSL_TXT_TLSV1) == 0)
			proto = DOVECOT_SSL_PROTO_TLSv1;
#ifdef SSL_TXT_TLSV1_1
		else if (strcasecmp(name, SSL_TXT_TLSV1_1) == 0)
			proto = DOVECOT_SSL_PROTO_TLSv1_1;
#endif
#ifdef SSL_TXT_TLSV1_2
		else if (strcasecmp(name, SSL_TXT_TLSV1_2) == 0)
			proto = DOVECOT_SSL_PROTO_TLSv1_2;
#endif
		else {
			i_fatal("Invalid ssl_protocols setting: "
				"Unknown protocol '%s'", name);
		}
		if (neg)
			exclude |= proto;
		else
			include |= proto;
	}
	if (include != 0) {
		/* exclude everything, except those that are included
		   (and let excludes still override those) */
		exclude |= DOVECOT_SSL_PROTO_ALL & ~include;
	}
	if ((exclude & DOVECOT_SSL_PROTO_SSLv2) != 0) op |= SSL_OP_NO_SSLv2;
	if ((exclude & DOVECOT_SSL_PROTO_SSLv3) != 0) op |= SSL_OP_NO_SSLv3;
	if ((exclude & DOVECOT_SSL_PROTO_TLSv1) != 0) op |= SSL_OP_NO_TLSv1;
#ifdef SSL_OP_NO_TLSv1_1
	if ((exclude & DOVECOT_SSL_PROTO_TLSv1_1) != 0) op |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
	if ((exclude & DOVECOT_SSL_PROTO_TLSv1_2) != 0) op |= SSL_OP_NO_TLSv1_2;
#endif
	return op;
}

static const char *asn1_string_to_c(ASN1_STRING *asn_str)
{
	const char *cstr;
	unsigned int len;

	len = ASN1_STRING_length(asn_str);
	cstr = t_strndup(ASN1_STRING_data(asn_str), len);
	if (strlen(cstr) != len) {
		/* NULs in the name - could be some MITM attack.
		   never allow. */
		return "";
	}
	return cstr;
}

static const char *get_general_dns_name(const GENERAL_NAME *name)
{
	if (ASN1_STRING_type(name->d.ia5) != V_ASN1_IA5STRING)
		return "";

	return asn1_string_to_c(name->d.ia5);
}

static const char *get_cname(X509 *cert)
{
	X509_NAME *name;
	X509_NAME_ENTRY *entry;
	ASN1_STRING *str;
	int cn_idx;

	name = X509_get_subject_name(cert);
	if (name == NULL)
		return "";
	cn_idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
	if (cn_idx == -1)
		return "";
	entry = X509_NAME_get_entry(name, cn_idx);
	i_assert(entry != NULL);
	str = X509_NAME_ENTRY_get_data(entry);
	i_assert(str != NULL);
	return asn1_string_to_c(str);
}

static bool openssl_hostname_equals(const char *ssl_name, const char *host)
{
	const char *p;

	if (strcmp(ssl_name, host) == 0)
		return TRUE;

	/* check for *.example.com wildcard */
	if (ssl_name[0] != '*' || ssl_name[1] != '.')
		return FALSE;
	p = strchr(host, '.');
	return p != NULL && strcmp(ssl_name+2, p+1) == 0;
}

int openssl_cert_match_name(SSL *ssl, const char *verify_name)
{
	X509 *cert;
	STACK_OF(GENERAL_NAME) *gnames;
	const GENERAL_NAME *gn;
	const char *dnsname;
	bool dns_names = FALSE;
	unsigned int i, count;
	int ret;

	cert = SSL_get_peer_certificate(ssl);
	i_assert(cert != NULL);

	/* verify against SubjectAltNames */
	gnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	count = gnames == NULL ? 0 : sk_GENERAL_NAME_num(gnames);
	for (i = 0; i < count; i++) {
		gn = sk_GENERAL_NAME_value(gnames, i);
		if (gn->type == GEN_DNS) {
			dns_names = TRUE;
			dnsname = get_general_dns_name(gn);
			if (openssl_hostname_equals(dnsname, verify_name))
				break;
		}
	}
	sk_GENERAL_NAME_pop_free(gnames, GENERAL_NAME_free);

	/* verify against CommonName only when there wasn't any DNS
	   SubjectAltNames */
	if (dns_names)
		ret = i < count ? 0 : -1;
	else if (openssl_hostname_equals(get_cname(cert), verify_name))
		ret = 0;
	else
		ret = -1;
	X509_free(cert);
	return ret;
}
