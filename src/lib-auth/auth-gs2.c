/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"

#include "auth-gs2.h"

static const unsigned char auth_gs2_cb_name_char_mask = (1<<0);

static const unsigned char auth_gs2_char_lookup[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 00
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, // 20
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 30
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 40
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 50
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 60
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 70

	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 80
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 90
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // A0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // B0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // C0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // D0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // E0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // F0
};

static inline bool auth_gs2_char_is_cb_name(unsigned char ch) {
	return ((auth_gs2_char_lookup[ch] & auth_gs2_cb_name_char_mask) != 0);
}

static inline const char *_char_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("<0x%02x>", c);
}

/* RFC 5801, Section 4:

   The "gs2-authzid" holds the SASL authorization identity. It is encoded using
   UTF-8 [RFC3629] with three exceptions:

   o  The NUL character is forbidden as required by section 3.4.1 of [RFC4422].

   o  The server MUST replace any "," (comma) in the string with "=2C".

   o  The server MUST replace any "=" (equals) in the string with "=3D".
 */

void auth_gs2_encode_username(const char *in, buffer_t *out)
{
	for (; *in != '\0'; in++) {
		if (in[0] == ',')
			str_append(out, "=2C");
		else if (in[0] == '=')
			str_append(out, "=3D");
		else
			str_append_c(out, *in);
	}
}

int auth_gs2_decode_username(const unsigned char *in, size_t in_size,
			     const char **out_r)
{
	const unsigned char *p = in, *pend = in + in_size;
	string_t *out;

	out = t_str_new(64);
	while (p < pend) {
		if (*p == '\0' || *p == ',')
			return -1;
		if (*p == '=') {
			p++;
			if (p >= pend)
				return -1;
			if (*p == '2') {
				p++;
				if (p >= pend)
					return -1;
				if (*p != 'C')
					return -1;
				str_append_c(out, ',');
			} else if (*p == '3') {
				p++;
				if (p >= pend)
					return -1;
				if (*p != 'D')
					return -1;
				str_append_c(out, '=');
			} else {
				return -1;
			}
		} else {
			str_append_c(out, *p);
		}
		p++;
	}
	*out_r = str_c(out);
	return 0;
}

/* RFC 5801, Section 4:

    UTF8-1-safe    = %x01-2B / %x2D-3C / %x3E-7F
                     ;; As UTF8-1 in RFC 3629 except
                     ;; NUL, "=", and ",".
    UTF8-2         = <as defined in RFC 3629 (STD 63)>
    UTF8-3         = <as defined in RFC 3629 (STD 63)>
    UTF8-4         = <as defined in RFC 3629 (STD 63)>
    UTF8-char-safe = UTF8-1-safe / UTF8-2 / UTF8-3 / UTF8-4

    saslname       = 1*(UTF8-char-safe / "=2C" / "=3D")
    gs2-authzid    = "a=" saslname
                      ;; GS2 has to transport an authzid since
                      ;; the GSS-API has no equivalent
    gs2-nonstd-flag = "F"
                      ;; "F" means the mechanism is not a
                      ;; standard GSS-API mechanism in that the
                      ;; RFC 2743, Section 3.1 header was missing
    cb-name         = 1*(ALPHA / DIGIT / "." / "-")
                      ;; See RFC 5056, Section 7.
    gs2-cb-flag     = ("p=" cb-name) / "n" / "y"
                      ;; GS2 channel binding (CB) flag
                      ;; "p" -> client supports and used CB
                      ;; "n" -> client does not support CB
                      ;; "y" -> client supports CB, thinks the server
                      ;;           does not
    gs2-header = [gs2-nonstd-flag ","] gs2-cb-flag "," [gs2-authzid] ","
                      ;; The GS2 header is gs2-header.
 */

void auth_gs2_header_encode(const struct auth_gs2_header *hdr, buffer_t *out)
{
	/* [gs2-nonstd-flag ","] */
	if (hdr->nonstd)
		str_append(out, "F,");

	/* gs2-cb-flag "," */
	switch (hdr->cbind.status) {
	case AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT:
		str_append_c(out, 'n');
		break;
	case AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT:
		str_append_c(out, 'y');
		break;
	case AUTH_GS2_CBIND_STATUS_PROVIDED:
		i_assert(hdr->cbind.name != NULL && *hdr->cbind.name != '\0');
		str_append(out, "p=");
		str_append(out, hdr->cbind.name);
		break;
	};
	str_append_c(out, ',');

	/* [gs2-authzid] "," */
	if (hdr->authzid != NULL && *hdr->authzid != '\0') {
		str_append(out, "a=");
		auth_gs2_encode_username(hdr->authzid, out);
	}
	str_append_c(out, ',');
}

int auth_gs2_header_decode(const unsigned char *data, size_t size,
			   bool expect_nonstd, struct auth_gs2_header *hdr_r,
			   const unsigned char **hdr_end_r,
			   const char **error_r)
{
	if (size < 3) {
		*error_r = "Message too small for GS2 header";
		return -1;
	}

	const unsigned char *p = data, *pend = data + size, *offset;
	struct auth_gs2_header hdr;

	i_zero(&hdr);

	/* [gs2-nonstd-flag ","] */
	if (*p == 'F') {
		if (!expect_nonstd) {
			*error_r = "Unexpected nonstd 'F' flag";
			return -1;
		}
		p++;
		if (*p != ',') {
			*error_r = "Missing ',' after nonstd 'F' flag";
			return -1;
		}
		hdr.nonstd = TRUE;
		p++;
	}

	/* gs2-cb-flag "," */
	switch (*p) {
	case 'n':
		hdr.cbind.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT;
		break;
	case 'y':
		hdr.cbind.status = AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT;
		break;
	case 'p':
		hdr.cbind.status = AUTH_GS2_CBIND_STATUS_PROVIDED;
		break;
	default:
		*error_r = t_strdup_printf(
			"Invalid channel bind flag %s",
			_char_sanitize(*p));
		return -1;
	}
	p++;
	if (hdr.cbind.status == AUTH_GS2_CBIND_STATUS_PROVIDED) {
		/* "=" cb-name */
		if (p >= pend || *p != '=') {
			*error_r = "Missing '=' after 'p' flag";
			return -1;
		}
		p++;

		offset = p;
		if (p >= pend || *p == ',') {
			*error_r = "Empty channel bind name";
			return -1;
		}
		while (p < pend && *p != ',') {
			if (!auth_gs2_char_is_cb_name(*p)) {
				*error_r = "Invalid channel bind name";
				return -1;
			}
			p++;
		}
		hdr.cbind.name = t_strdup_until(offset, p);
	}
	if (p >= pend || *p != ',') {
		*error_r = "Missing ',' after channel bind flag";
		return -1;
	}
	p++;

	/* [gs2-authzid] "," */
	if (p < pend && *p == 'a') {
		p++;
		if (p >= pend || *p != '=') {
			*error_r = "Missing '=' after 'a'";
			return -1;
		}
		p++;

		offset = p;
		if (p >= pend || *p == ',') {
			*error_r = "Empty authzid field";
			return -1;
		}
		while (p < pend && *p != ',')
			p++;
		if (auth_gs2_decode_username(offset, p - offset,
					     &hdr.authzid) < 0) {
			*error_r = "Invalid authzid field";
			return -1;
		}
	}
	if (p >= pend || *p != ',') {
		*error_r = "Missing ',' after authzid field";
		return -1;
	}
	p++;

	*error_r = NULL;
	*hdr_r = hdr;
	*hdr_end_r = p;
	return 0;
}
