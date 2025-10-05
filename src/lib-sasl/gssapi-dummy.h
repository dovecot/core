#ifndef GSSAPI_DUMMY_H
#define GSSAPI_DUMMY_H

void gss_dummy_kinit(const char *principal);
void gss_dummy_add_principal(const char *principal);

void gss_dummy_deinit(void);

#endif
