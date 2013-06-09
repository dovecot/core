#ifndef SASL_CLIENT_H
#define SASL_CLIENT_H

struct sasl_client_settings {
	/* authentication ID - must be set with most mechanisms */
	const char *authid;
	/* authorization ID ("master user") */
	const char *authzid;
	/* password - must be set with most mechanisms */
	const char *password;
};

/* PLAIN mechanism always exists and can be accessed directly via this. */
extern const struct sasl_client_mech sasl_client_mech_plain;

const struct sasl_client_mech *sasl_client_mech_find(const char *name);
const char *sasl_client_mech_get_name(const struct sasl_client_mech *mech);

struct sasl_client *sasl_client_new(const struct sasl_client_mech *mech,
				    const struct sasl_client_settings *set);
void sasl_client_free(struct sasl_client **client);

/* Call for server input. */
int sasl_client_input(struct sasl_client *client,
		      const unsigned char *input,
		      unsigned int input_len,
		      const char **error_r);
/* Call for getting server output. Also used to get the initial SASL response
   if supported by the protocol. */
int sasl_client_output(struct sasl_client *client,
		       const unsigned char **output_r,
		       unsigned int *output_len_r,
		       const char **error_r);

void sasl_clients_init(void);
void sasl_clients_deinit(void);

#endif
