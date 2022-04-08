/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "iostream-openssl.h"

#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define SSL_TXT_ANY "ANY"

#ifndef TLS_ANY_VERSION
#  define TLS_ANY_VERSION TLS1_VERSION
#endif

#ifndef TLS_MAX_VERSION
#  define TLS_MAX_VERSION 0
#endif

/* openssl_min_protocol_to_options() scans this array for name and returns
   version and opt. opt is used with SSL_set_options() and version is used with
   SSL_set_min_proto_version(). Using either method should enable the same
   SSL protocol versions. */
static const struct {
	const char *name;
	int version;
	long opt;
} protocol_versions[] = {
	{ SSL_TXT_ANY,	   TLS_ANY_VERSION, SSL_OP_NO_SSLv3 },
	{ SSL_TXT_TLSV1,   TLS1_VERSION,    SSL_OP_NO_SSLv3 },
	{ SSL_TXT_TLSV1_1, TLS1_1_VERSION,  SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 },
	{ SSL_TXT_TLSV1_2, TLS1_2_VERSION,  SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
					    SSL_OP_NO_TLSv1_1 },
#if defined(TLS1_3_VERSION)
	{ "TLSv1.3",	   TLS1_3_VERSION,  SSL_OP_NO_SSLv3   | SSL_OP_NO_TLSv1 |
					    SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 },
#endif
	/* Use latest protocol version. If this is used on some
	   ancient system which does not support ssl_min_protocol,
	   ensure only TLSv1.2 is supported. */
	{ "LATEST",	   TLS_MAX_VERSION, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
					    SSL_OP_NO_TLSv1_1 },
};
int openssl_min_protocol_to_options(const char *min_protocol, long *opt_r,
				    int *version_r)
{
	unsigned i = 0;
	for (; i < N_ELEMENTS(protocol_versions); i++) {
		if (strcasecmp(protocol_versions[i].name, min_protocol) == 0)
			break;
	}
	if (i >= N_ELEMENTS(protocol_versions))
		return -1;

	if (opt_r != NULL)
		*opt_r = protocol_versions[i].opt;
	if (version_r != NULL)
		*version_r = protocol_versions[i].version;
	return 0;
}

#if !defined(HAVE_X509_CHECK_HOST) || !defined(HAVE_X509_CHECK_IP_ASC)
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

static int get_general_ip_addr(const GENERAL_NAME *name, struct ip_addr *ip_r)
{
	if (ASN1_STRING_type(name->d.ip) != V_ASN1_OCTET_STRING)
		return 0;
	const unsigned char *data = ASN1_STRING_get0_data(name->d.ip);

	if (name->d.ip->length == sizeof(ip_r->u.ip4.s_addr)) {
		ip_r->family = AF_INET;
		memcpy(&ip_r->u.ip4.s_addr, data, sizeof(ip_r->u.ip4.s_addr));
	} else if (name->d.ip->length == sizeof(ip_r->u.ip6.s6_addr)) {
		ip_r->family = AF_INET6;
		memcpy(ip_r->u.ip6.s6_addr, data, sizeof(ip_r->u.ip6.s6_addr));
	} else
		return -1;
	return 0;
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

	if (strcasecmp(ssl_name, host) == 0)
		return TRUE;

	/* check for *.example.com wildcard */
	if (ssl_name[0] != '*' || ssl_name[1] != '.')
		return FALSE;
	p = strchr(host, '.');
	return p != NULL && strcasecmp(ssl_name+2, p+1) == 0;
}
#endif

bool openssl_cert_match_name(SSL *ssl, const char *verify_name,
			     const char **reason_r)
{
	X509 *cert;
	bool ret;

	*reason_r = NULL;

	cert = SSL_get_peer_certificate(ssl);
	i_assert(cert != NULL);

#if defined(HAVE_X509_CHECK_HOST) && defined(HAVE_X509_CHECK_IP_ASC)
	char *peername;
	int check_res;

	/* First check DNS name agains CommonName or SubjectAltNames.
	   If failed, check IP addresses. */
	if ((check_res = X509_check_host(cert, verify_name, strlen(verify_name),
					 X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
					 &peername)) == 1) {
		*reason_r = t_strdup_printf("Matched to %s", peername);
		free(peername);
		ret = TRUE;
	} else if (check_res == 0 &&
		   (check_res = X509_check_ip_asc(cert, verify_name, 0)) == 1) {
		*reason_r = t_strdup_printf("Matched to IP address %s", verify_name);
		ret = TRUE;
	} else if (check_res == 0) {
		*reason_r = "did not match to any IP or DNS fields";
		ret = FALSE;
	} else {
		*reason_r = "Malformed input";
		ret = FALSE;
	}
#else
	STACK_OF(GENERAL_NAME) *gnames;
	const GENERAL_NAME *gn;
	struct ip_addr ip;
	const char *dnsname;
	bool dns_names = FALSE;
	unsigned int i, count;

	/* verify against SubjectAltNames */
	gnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	count = gnames == NULL ? 0 : sk_GENERAL_NAME_num(gnames);

	if (net_addr2ip(verify_name, &ip) < 0)
		i_zero(&ip);

	for (i = 0; i < count; i++) {
		gn = sk_GENERAL_NAME_value(gnames, i);

		if (gn->type == GEN_DNS) {
			dns_names = TRUE;
			dnsname = get_general_dns_name(gn);
			if (openssl_hostname_equals(dnsname, verify_name)) {
				*reason_r = t_strdup_printf(
					"Matches DNS name in SubjectAltNames: %s", dnsname);
				break;
			}
		} else if (gn->type == GEN_IPADD) {
			struct ip_addr ip_2;
			i_zero(&ip_2);
			dns_names = TRUE;
			if (get_general_ip_addr(gn, &ip_2) == 0 &&
			    net_ip_compare(&ip, &ip_2)) {
				*reason_r = t_strdup_printf(
					"Matches IP in SubjectAltNames: %s", net_ip2addr(&ip_2));
				break;
			}
		}
	}
	sk_GENERAL_NAME_pop_free(gnames, GENERAL_NAME_free);

	/* verify against CommonName only when there wasn't any DNS
	   SubjectAltNames */
	if (dns_names) {
		i_assert(*reason_r != NULL || i == count);
		if (i == count) {
			*reason_r = t_strdup_printf(
				"No match to %u SubjectAltNames",
				count);
			ret = FALSE;
		} else {
			ret = TRUE;
		}
	} else {
		const char *cname = get_cname(cert);

		if (openssl_hostname_equals(cname, verify_name)) {
			ret = TRUE;
			*reason_r = t_strdup_printf(
				"Matches to CommonName: %s", cname);
		} else {
			*reason_r = t_strdup_printf(
				"No match to CommonName=%s or %u SubjectAltNames",
				cname, count);
			ret = FALSE;
		}
	}
#endif
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

	if (cert[0] == '\0')
		return "The certificate is empty";

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
