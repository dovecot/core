#ifndef AUTH_SASL_MECH_APOP_H
#define AUTH_SASL_MECH_APOP_H

/* Parse the "<pid.connect_uid.timestamp." prefix of an APOP challenge. */
bool auth_sasl_mech_apop_parse_challenge(const char *challenge,
					 unsigned long *pid_r,
					 unsigned long *connect_uid_r,
					 unsigned long *timestamp_r);

#endif
