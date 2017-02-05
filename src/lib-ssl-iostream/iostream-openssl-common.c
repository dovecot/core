/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "iostream-openssl.h"

#include <openssl/x509v3.h>
#include <openssl/err.h>

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

	tmp = t_strsplit_spaces(protocols, ", ");
	for (; *tmp != NULL; tmp++) {
		const char *name = *tmp;

		if (*name != '!')
			neg = FALSE;
		else {
			name++;
			neg = TRUE;
		}
#ifdef SSL_TXT_SSLV2
		if (strcasecmp(name, SSL_TXT_SSLV2) == 0)
			proto = DOVECOT_SSL_PROTO_SSLv2;
		else
#endif
#ifdef SSL_TXT_SSLV3
		if (strcasecmp(name, SSL_TXT_SSLV3) == 0)
			proto = DOVECOT_SSL_PROTO_SSLv3;
		else
#endif
		if (strcasecmp(name, SSL_TXT_TLSV1) == 0)
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
	cstr = t_strndup(ASN1_STRING_get0_data(asn_str), len);
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

static const char *ssl_err2str(unsigned long err, const char *data, int flags)
{
	const char *ret;
	char *buf;
	size_t err_size = 256;

	buf = t_malloc0(err_size);
	ERR_error_string_n(err, buf, err_size-1);
	ret = buf;

	if ((flags & ERR_TXT_STRING) != 0)
		ret = t_strdup_printf("%s: %s", buf, data);
	return ret;
}

const char *openssl_iostream_error(void)
{
	string_t *errstr = NULL;
	unsigned long err;
	const char *data, *final_error;
	int flags;

	while ((err = ERR_get_error_line_data(NULL, NULL, &data, &flags)) != 0) {
		if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE)
			i_fatal_status(FATAL_OUTOFMEM, "OpenSSL malloc() failed");
		if (ERR_peek_error() == 0)
			break;
		if (errstr == NULL)
			errstr = t_str_new(128);
		else
			str_append(errstr, ", ");
		str_append(errstr, ssl_err2str(err, data, flags));
	}
	if (err == 0) {
		if (errno != 0)
			final_error = strerror(errno);
		else
			final_error = "Unknown error";
	} else {
		final_error = ssl_err2str(err, data, flags);
	}
	if (errstr == NULL)
		return final_error;
	else {
		str_printfa(errstr, ", %s", final_error);
		return str_c(errstr);
	}
}

const char *openssl_iostream_key_load_error(void)
{
       unsigned long err = ERR_peek_error();

       if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
           ERR_GET_REASON(err) == X509_R_KEY_VALUES_MISMATCH)
               return "Key is for a different cert than ssl_cert";
       else
               return openssl_iostream_error();
}

static bool is_pem_key(const char *cert)
{
	return strstr(cert, "PRIVATE KEY---") != NULL;
}

const char *
openssl_iostream_use_certificate_error(const char *cert, const char *set_name)
{
	unsigned long err;

	err = ERR_peek_error();
	if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
	    ERR_GET_REASON(err) != PEM_R_NO_START_LINE)
		return openssl_iostream_error();
	else if (is_pem_key(cert)) {
		return "The file contains a private key "
			"(you've mixed ssl_cert and ssl_key settings)";
	} else if (set_name != NULL && strchr(cert, '\n') == NULL) {
		return t_strdup_printf("There is no valid PEM certificate. "
			"(You probably forgot '<' from %s=<%s)", set_name, cert);
	} else {
		return "There is no valid PEM certificate.";
	}
}

void openssl_iostream_clear_errors(void)
{
	while (ERR_get_error() != 0)
		;
}
