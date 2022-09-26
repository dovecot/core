static const char *scram_unescape_username(const char *in)
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

static bool
parse_scram_client_first(struct scram_auth_request *request,
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

	   client-first-message-bare = [reserved-mext ","]
	                     username "," nonce ["," extensions]

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
		return FALSE;
	}
	gs2_cbind_flag = t_strdup_until(data_cstr, p);
	data_cstr = p + 1;

	p = strchr(data_cstr, ',');
	if (p == NULL) {
		*error_r = "Invalid initial client message: "
			"Missing second ',' in GS2 header";
		return FALSE;
	}
	authzid = t_strdup_until(data_cstr, p);
	gs2_header = t_strdup_until(gs2_header, p + 1);
	cfm_bare = p + 1;

	fields = t_strsplit(cfm_bare, ",");
	if (str_array_length(fields) < 2) {
		*error_r = "Invalid initial client message: "
			"Missing nonce field";
		return FALSE;
	}
	username = fields[0];
	nonce = fields[1];

	/* gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"
	 */
	switch (gs2_cbind_flag[0]) {
	case 'p':
		*error_r = "Channel binding not supported";
		return FALSE;
	case 'y':
	case 'n':
		break;
	default:
		*error_r = "Invalid GS2 header";
		return FALSE;
	}

	/* authzid         = "a=" saslname
	                     ;; Protocol specific.
	 */
	if (authzid[0] == '\0')
		;
	else if (authzid[0] == 'a' && authzid[1] == '=') {
		/* Unescape authzid */
		login_username = scram_unescape_username(authzid + 2);

		if (login_username == NULL) {
			*error_r = "authzid escaping is invalid";
			return FALSE;
		}
	} else {
		*error_r = "Invalid authzid field";
		return FALSE;
	}

	/* reserved-mext   = "m=" 1*(value-char)
	 */
	if (username[0] == 'm') {
		*error_r = "Mandatory extension(s) not supported";
		return FALSE;
	}
	/* username        = "n=" saslname
	 */
	if (username[0] == 'n' && username[1] == '=') {
		/* Unescape username */
		username = scram_unescape_username(username + 2);
		if (username == NULL) {
			*error_r = "Username escaping is invalid";
			return FALSE;
		}
		if (!auth_request_set_username(&request->auth_request,
					       username, error_r))
			return FALSE;
	} else {
		*error_r = "Invalid username field";
		return FALSE;
	}
	if (login_username != NULL) {
		if (!auth_request_set_login_username(&request->auth_request,
						     login_username, error_r))
			return FALSE;
	}

	/* nonce           = "r=" c-nonce [s-nonce] */
	if (nonce[0] == 'r' && nonce[1] == '=')
		request->cnonce = p_strdup(request->pool, nonce+2);
	else {
		*error_r = "Invalid client nonce";
		return FALSE;
	}

	request->gs2_header = p_strdup(request->pool, gs2_header);
	request->client_first_message_bare = p_strdup(request->pool, cfm_bare);
	return TRUE;
}

static const char *
get_scram_server_first(struct scram_auth_request *request,
		       int iter, const char *salt)
{
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

	random_fill(snonce, sizeof(snonce)-1);

	/* Make sure snonce is printable and does not contain ',' */
	for (i = 0; i < sizeof(snonce)-1; i++) {
		snonce[i] = (snonce[i] % ('~' - '!')) + '!';
		if (snonce[i] == ',')
			snonce[i] = '~';
	}
	snonce[sizeof(snonce)-1] = '\0';
	request->snonce = p_strndup(request->pool, snonce, sizeof(snonce));

	str = t_str_new(32 + strlen(request->cnonce) + sizeof(snonce) +
			strlen(salt));
	str_printfa(str, "r=%s%s,s=%s,i=%d", request->cnonce, request->snonce,
		    salt, iter);
	return str_c(str);
}
