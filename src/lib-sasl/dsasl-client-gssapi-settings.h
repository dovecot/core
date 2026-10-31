#ifndef DSASL_CLIENT_GSSAPI_SETTINGS_H
#define DSASL_CLIENT_GSSAPI_SETTINGS_H

/* Settings of the GSSAPI and GSS-SPNEGO client mechanisms. They are set inside
   the client_auth/<mechanism> filter, e.g.:

   client_auth GSSAPI {
     gssapi_channel_binding = no
   }
*/
struct dsasl_client_gssapi_settings {
	pool_t pool;

	/* Send the tls-server-end-point channel binding with TLS. If it can't
	   be got, the authentication fails. */
	bool channel_binding;
};

extern const struct setting_parser_info dsasl_client_gssapi_setting_parser_info;

/* Compares the settings of the two events. Returns 1 if they are equal, 0 if
   not and -1 with an error if getting the settings failed. */
int dsasl_client_gssapi_settings_equal(struct event *event1,
				       struct event *event2,
				       const char **error_r);

#endif
