#ifndef DSASL_CLIENT_H
#define DSASL_CLIENT_H

struct dsasl_client_settings {
	/* authentication ID - must be set with most mechanisms */
	const char *authid;
	/* authorization ID (who to log in as, if authentication ID is a
	   master user) */
	const char *authzid;
	/* password - must be set with most mechanisms */
	const char *password;
};

/* PLAIN mechanism always exists and can be accessed directly via this. */
extern const struct dsasl_client_mech dsasl_client_mech_plain;

const struct dsasl_client_mech *dsasl_client_mech_find(const char *name);
const char *dsasl_client_mech_get_name(const struct dsasl_client_mech *mech);

struct dsasl_client *dsasl_client_new(const struct dsasl_client_mech *mech,
				      const struct dsasl_client_settings *set);
void dsasl_client_free(struct dsasl_client **client);

/* Call for server input. */
int dsasl_client_input(struct dsasl_client *client,
		       const unsigned char *input,
		       unsigned int input_len,
		       const char **error_r);
/* Call for getting server output. Also used to get the initial SASL response
   if supported by the protocol. */
int dsasl_client_output(struct dsasl_client *client,
			const unsigned char **output_r,
			unsigned int *output_len_r,
			const char **error_r);

void dsasl_clients_init(void);
void dsasl_clients_deinit(void);

#endif
