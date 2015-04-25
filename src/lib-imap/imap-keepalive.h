#ifndef IMAP_KEEPALIVE_H
#define IMAP_KEEPALIVE_H

/* This function can be used to set IMAP IDLE keepalive notification timeout
   interval so that the client gets the keepalive notifications at exactly the
   same time for all the IMAP connections. This helps to reduce battery usage
   in mobile devices.

   One problem with this is that we don't really want to send the notifications
   to everyone at the same time, because it would cause huge peaks of activity.
   Basing the notifications on the username works well for one account, but
   basing it on the IP address allows the client to get all of the
   notifications at the same time for multiple accounts as well (of course
   assuming Dovecot is running on all the servers :)

   One potential downside to using IP is that if a proxy hides the client's IP
   address, the notifications are sent to everyone at the same time. This can
   be avoided by using a properly configured Dovecot proxy, but we'll also try
   to avoid this by not doing it for the commonly used intranet IP ranges. */
unsigned int
imap_keepalive_interval_msecs(const char *username, const struct ip_addr *ip,
			      unsigned int interval_secs);

#endif
