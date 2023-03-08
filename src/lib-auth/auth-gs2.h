#ifndef AUTH_GS2_H
#define AUTH_GS2_H

enum auth_gs2_cbind_status {
	AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT = 0,
	AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT,
	AUTH_GS2_CBIND_STATUS_PROVIDED,
};

struct auth_gs2_header {
	struct {
		enum auth_gs2_cbind_status status;
		const char *name;
	} cbind;

	const char *authzid;

	bool nonstd:1;
};

void auth_gs2_encode_username(const char *in, buffer_t *out);
int auth_gs2_decode_username(const unsigned char *in, size_t in_size,
			     const char **out_r);

void auth_gs2_header_encode(const struct auth_gs2_header *hdr, buffer_t *out);
int auth_gs2_header_decode(const unsigned char *data, size_t size,
			   bool expect_nonstd, struct auth_gs2_header *hdr_r,
			   const unsigned char **hdr_end_r,
			   const char **error_r);

#endif
