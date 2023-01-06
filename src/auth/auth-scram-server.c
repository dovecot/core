static const char *auth_scram_unescape_username(const char *in)
{
	string_t *out;

	/* RFC 5802, Section 5.1:

	   The characters ',' or '=' in usernames are sent as '=2C' and '=3D'
	   respectively.  If the server receives a username that contains '='
	   not followed by either '2C' or '3D', then the server MUST fail the
	   authentication.
	 */

	out = t_str_new(64);
	for (; *in != '\0'; in++) {
		i_assert(in[0] != ','); /* strsplit should have caught this */

		if (in[0] == '=') {
			if (in[1] == '2' && in[2] == 'C')
				str_append_c(out, ',');
			else if (in[1] == '3' && in[2] == 'D')
				str_append_c(out, '=');
			else
				return NULL;
			in += 2;
		} else {
			str_append_c(out, *in);
		}
	}
	return str_c(out);
}

static int
auth_scram_parse_client_first(struct scram_auth_request *server,
			      const unsigned char *data, size_t size,
			      const char **error_r)
{
	const char *login_username = NULL;
	const char *data_cstr, *p;
	const char *gs2_header, *gs2_cbind_flag, *authzid;
	const char *cfm_bare, *username, *nonce;
	const char *const *fields;

	data_cstr = gs2_header = t_strndup(data, size);

	/* RFC 5802, Section 7:

	   client-first-message = gs2-header client-first-message-bare
	   gs2-header      = gs2-cbind-flag "," [ authzid ] ","
	   gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"

	   client-first-message-bare = [reserved-mext ","]
	                     username "," nonce ["," extensions]
	   reserved-mext   = "m=" 1*(value-char)

	   username        = "n=" saslname
	   nonce           = "r=" c-nonce [s-nonce]

	   extensions      = attr-val *("," attr-val)
	                     ;; All extensions are optional,
	                     ;; i.e., unrecognized attributes
	                     ;; not defined in this document
	                     ;; MUST be ignored.
	   attr-val        = ALPHA "=" value
	 */
	p = strchr(data_cstr, ',');
	if (p == NULL) {
		*error_r = "Invalid initial client message: "
			"Missing first ',' in GS2 header";
		return -1;
	}
	gs2_cbind_flag = t_strdup_until(data_cstr, p);
	data_cstr = p + 1;

	p = strchr(data_cstr, ',');
	if (p == NULL) {
		*error_r = "Invalid initial client message: "
			"Missing second ',' in GS2 header";
		return -1;
	}
	authzid = t_strdup_until(data_cstr, p);
	gs2_header = t_strdup_until(gs2_header, p + 1);
	cfm_bare = p + 1;

	fields = t_strsplit(cfm_bare, ",");
	if (str_array_length(fields) < 2) {
		*error_r = "Invalid initial client message: "
			"Missing nonce field";
		return -1;
	}
	username = fields[0];
	nonce = fields[1];

	/* gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"
	 */
	switch (gs2_cbind_flag[0]) {
	case 'p':
		*error_r = "Channel binding not supported";
		return -1;
	case 'y':
	case 'n':
		break;
	default:
		*error_r = "Invalid GS2 header";
		return -1;
	}

	/* authzid         = "a=" saslname
	                     ;; Protocol specific.
	 */
	if (authzid[0] == '\0')
		;
	else if (authzid[0] == 'a' && authzid[1] == '=') {
		/* Unescape authzid */
		login_username = auth_scram_unescape_username(authzid + 2);

		if (login_username == NULL) {
			*error_r = "authzid escaping is invalid";
			return -1;
		}
	} else {
		*error_r = "Invalid authzid field";
		return -1;
	}

	/* reserved-mext   = "m=" 1*(value-char)
	 */
	if (username[0] == 'm') {
		*error_r = "Mandatory extension(s) not supported";
		return -1;
	}
	/* username        = "n=" saslname
	 */
	if (username[0] == 'n' && username[1] == '=') {
		/* Unescape username */
		username = auth_scram_unescape_username(username + 2);
		if (username == NULL) {
			*error_r = "Username escaping is invalid";
			return -1;
		}
		if (!auth_request_set_username(&server->auth_request,
					       username, error_r))
			return -1;
	} else {
		*error_r = "Invalid username field";
		return -1;
	}
	if (login_username != NULL) {
		if (!auth_request_set_login_username(&server->auth_request,
						     login_username, error_r))
			return -1;
	}

	/* nonce           = "r=" c-nonce [s-nonce] */
	if (nonce[0] == 'r' && nonce[1] == '=')
		server->cnonce = p_strdup(server->pool, nonce+2);
	else {
		*error_r = "Invalid client nonce";
		return -1;
	}

	server->gs2_header = p_strdup(server->pool, gs2_header);
	server->client_first_message_bare =
		p_strdup(server->pool, cfm_bare);
	return 0;
}

static string_t *
auth_scram_get_server_first(struct scram_auth_request *server)
{
	const struct hash_method *hmethod = server->hash_method;
	struct auth_scram_key_data *kdata = &server->key_data;
	unsigned char snonce[SCRAM_SERVER_NONCE_LEN+1];
	string_t *str;
	size_t i;

	/* RFC 5802, Section 7:

	   server-first-message =
	                     [reserved-mext ","] nonce "," salt ","
	                     iteration-count ["," extensions]

	   nonce           = "r=" c-nonce [s-nonce]

	   salt            = "s=" base64

	   iteration-count = "i=" posit-number
	                     ;; A positive number.
	 */

	i_assert(kdata->hmethod == hmethod);
	i_assert(kdata->salt != NULL);
	i_assert(kdata->iter_count != 0);

	random_fill(snonce, sizeof(snonce)-1);

	/* Make sure snonce is printable and does not contain ',' */
	for (i = 0; i < sizeof(snonce)-1; i++) {
		snonce[i] = (snonce[i] % ('~' - '!')) + '!';
		if (snonce[i] == ',')
			snonce[i] = '~';
	}
	snonce[sizeof(snonce)-1] = '\0';
	server->snonce = p_strndup(server->pool, snonce, sizeof(snonce));

	str = t_str_new(32 + strlen(server->cnonce) + sizeof(snonce) +
			strlen(kdata->salt));
	str_printfa(str, "r=%s%s,s=%s,i=%d", server->cnonce, server->snonce,
		    kdata->salt, kdata->iter_count);
	return str;
}

static bool
auth_scram_server_verify_credentials(struct scram_auth_request *server)
{
	const struct hash_method *hmethod = server->hash_method;
	struct auth_scram_key_data *kdata = &server->key_data;
	struct hmac_context ctx;
	const char *auth_message;
	unsigned char client_key[hmethod->digest_size];
	unsigned char client_signature[hmethod->digest_size];
	unsigned char stored_key[hmethod->digest_size];
	size_t i;

	i_assert(kdata->hmethod == hmethod);

	/* RFC 5802, Section 3:

	   AuthMessage     := client-first-message-bare + "," +
	                      server-first-message + "," +
	                      client-final-message-without-proof
	   ClientSignature := HMAC(StoredKey, AuthMessage)
	 */
	auth_message = t_strconcat(server->client_first_message_bare, ",",
			server->server_first_message, ",",
			server->client_final_message_without_proof, NULL);

	hmac_init(&ctx, kdata->stored_key, hmethod->digest_size, hmethod);
	hmac_update(&ctx, auth_message, strlen(auth_message));
	hmac_final(&ctx, client_signature);

	/* ClientProof     := ClientKey XOR ClientSignature */
	const unsigned char *proof_data = server->proof->data;
	for (i = 0; i < sizeof(client_signature); i++)
		client_key[i] = proof_data[i] ^ client_signature[i];

	/* StoredKey       := H(ClientKey) */
	hash_method_get_digest(hmethod, client_key, sizeof(client_key),
			       stored_key);

	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(client_signature, 0, sizeof(client_signature));

	return mem_equals_timing_safe(stored_key, kdata->stored_key,
				      sizeof(stored_key));
}

static int
auth_scram_parse_client_final(struct scram_auth_request *server,
			      const unsigned char *data, size_t size,
			      const char **error_r)
{
	const struct hash_method *hmethod = server->hash_method;
	const char **fields, *cbind_input, *nonce_str;
	unsigned int field_count;
	string_t *str;

	/* RFC 5802, Section 7:

	   client-final-message-without-proof =
	                     channel-binding "," nonce [","
	                     extensions]
	   client-final-message =
	                     client-final-message-without-proof "," proof
	 */
	fields = t_strsplit(t_strndup(data, size), ",");
	field_count = str_array_length(fields);
	if (field_count < 3) {
		*error_r = "Invalid final client message";
		return -1;
	}

	/* channel-binding = "c=" base64
	                     ;; base64 encoding of cbind-input.

	   cbind-data      = 1*OCTET
	   cbind-input     = gs2-header [ cbind-data ]
	                     ;; cbind-data MUST be present for
	                     ;; gs2-cbind-flag of "p" and MUST be absent
	                     ;; for "y" or "n".
	 */
	cbind_input = server->gs2_header;
	str = t_str_new(2 + MAX_BASE64_ENCODED_SIZE(strlen(cbind_input)));
	str_append(str, "c=");
	base64_encode(cbind_input, strlen(cbind_input), str);

	if (strcmp(fields[0], str_c(str)) != 0) {
		*error_r = "Invalid channel binding data";
		return -1;
	}

	/* nonce           = "r=" c-nonce [s-nonce]
	                     ;; Second part provided by server.
	   c-nonce         = printable
	   s-nonce         = printable
	 */
	nonce_str = t_strconcat("r=", server->cnonce, server->snonce, NULL);
	if (strcmp(fields[1], nonce_str) != 0) {
		*error_r = "Wrong nonce";
		return -1;
	}

	/* proof           = "p=" base64
	 */
	if (fields[field_count-1][0] == 'p') {
		size_t len = strlen(&fields[field_count-1][2]);

		server->proof = buffer_create_dynamic(server->pool,
					MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(&fields[field_count-1][2], len,
				  server->proof) < 0) {
			*error_r = "Invalid base64 encoding";
			return -1;
		}
		if (server->proof->used != hmethod->digest_size) {
			*error_r = "Invalid ClientProof length";
			return -1;
		}
	} else {
		*error_r = "Invalid ClientProof";
		return -1;
	}

	(void)str_array_remove(fields, fields[field_count-1]);
	server->client_final_message_without_proof =
		p_strdup(server->pool, t_strarray_join(fields, ","));

	return 0;
}

static string_t *
auth_scram_get_server_final(struct scram_auth_request *server)
{
	const struct hash_method *hmethod = server->hash_method;
	struct auth_scram_key_data *kdata = &server->key_data;
	struct hmac_context ctx;
	const char *auth_message;
	unsigned char server_signature[hmethod->digest_size];
	string_t *str;

	/* RFC 5802, Section 3:

	   AuthMessage     := client-first-message-bare + "," +
	                      server-first-message + "," +
	                      client-final-message-without-proof
	   ServerSignature := HMAC(ServerKey, AuthMessage)
	 */
	auth_message = t_strconcat(server->client_first_message_bare, ",",
			server->server_first_message, ",",
			server->client_final_message_without_proof, NULL);

	hmac_init(&ctx, kdata->server_key, hmethod->digest_size, hmethod);
	hmac_update(&ctx, auth_message, strlen(auth_message));
	hmac_final(&ctx, server_signature);

	/* RFC 5802, Section 7:

	   server-final-message = (server-error / verifier)
	                     ["," extensions]

	   verifier        = "v=" base64
	                     ;; base-64 encoded ServerSignature.

	 */
	str = t_str_new(2 + MAX_BASE64_ENCODED_SIZE(sizeof(server_signature)));
	str_append(str, "v=");
	base64_encode(server_signature, sizeof(server_signature), str);

	return str;
}
