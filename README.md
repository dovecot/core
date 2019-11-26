dovecot-extensions
==================

Extensions for dovecot

Added Ceritificate and Certificate Checks to Dovecot 2.3.x

- ssl_verify_depth:      will check the maximal certificate chain depth
- ssl_cert_md_algorithm: will check the corresponding certificate fingerprint algorithm (md5/sha1/...)
- cert_loginname:        will handle the loginname included in special client certificates (x509 fields)
- cert_fingerprint:      allows to access the fingerprint of a certificate inbound of the dovecot (used for select and  compare with LDAP backend where the fingerprint of a user is stored)

This patches are ported to dovecot-2.2.x from a patch serie done on Dovecot 2.0.16 done in 2011/2012


ORIGINAL README


Installation
============

See [INSTALL.md](INSTALL.md) file.


Configuration
=============

See [doc/documentation.txt](doc/documentation.txt) or [http://wiki2.dovecot.org/](http://wiki2.dovecot.org/)


RFCs conformed
==============


email
-----

- [RFC822 - Standard for ARPA Internet Text Messages](https://tools.ietf.org/html/rfc822)
- [RFC2822 - Internet Message Format (updated RFC822)](https://tools.ietf.org/html/rfc2822)
- [RFC2045 - Multipurpose Internet Mail Extensions (MIME) (part 1)](https://tools.ietf.org/html/rfc2045)
- [RFC2046 - Multipurpose Internet Mail Extensions (MIME) (part 2)](https://tools.ietf.org/html/rfc2046)
- [RFC2047 - Multipurpose Internet Mail Extensions (MIME) (part 3)](https://tools.ietf.org/html/rfc2047)
- [RFC2048 - Multipurpose Internet Mail Extensions (MIME) (part 4)](https://tools.ietf.org/html/rfc2048)
- [RFC2049 - Multipurpose Internet Mail Extensions (MIME) (part 5)](https://tools.ietf.org/html/rfc2049)

Auth
----         

- [RFC2245 - Anonymous SASL Mechanism.](https://tools.ietf.org/html/rfc2245)
- [RFC2595 - Using TLS with IMAP, POP3 and ACAP](https://tools.ietf.org/html/rfc2595)
- [RFC2831 - Using Digest Authentication as a SASL Mechanism (DIGEST-MD5)](https://tools.ietf.org/html/rfc2831)
- [RFC5802 - Salted Challenge Response Authentication Mechanism (SCRAM)](https://tools.ietf.org/html/rfc5802)
- SASL and GSS-API Mechanisms 
- [RFC7628 - A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth](https://tools.ietf.org/html/rfc7628)
- [Google XOAUTH2 protocol](https://developers.google.com/gmail/xoauth2_protocol)

POP3
----           

- [RFC1939 - Post Office Protocol - Version 3](https://tools.ietf.org/html/rfc1939)
- [RFC2449 - POP3 Extension Mechanism](https://tools.ietf.org/html/rfc2449)
- [RFC2595 - Using TLS with IMAP, POP3 and ACAP](https://tools.ietf.org/html/rfc2595)
- [RFC3206 - The SYS and AUTH POP Response Codes](https://tools.ietf.org/html/rfc3206)
- [RFC5034 - The Post Office Protocol (POP3) - Simple Authentication and Security Layer (SASL) Authentication Mechanism](https://tools.ietf.org/html/rfc5034)

IMAP base
---------

- [RFC3501 - IMAP4rev1](https://tools.ietf.org/html/rfc3501)
- [RFC2180 - IMAP4 Multi-Accessed Mailbox Practice](https://tools.ietf.org/html/rfc2180)
- [RFC2595 - Using TLS with IMAP, POP3 and ACAP](https://tools.ietf.org/html/rfc2595)
- [RFC2683 - IMAP4 Implementation Recommendations](https://tools.ietf.org/html/rfc2683)

IMAP extensions
---------------

- [RFC2087 - IMAP4 QUOTA extension](https://tools.ietf.org/html/rfc2087)
- [RFC2088 - IMAP4 non-synchronizing literals (LITERAL+)](https://tools.ietf.org/html/rfc2088)
- [RFC2177 - IMAP4 IDLE command](https://tools.ietf.org/html/rfc2177)
- [RFC2221 - IMAP4 Login Referrals](https://tools.ietf.org/html/rfc2221)
- [RFC2342 - IMAP4 Namespace](https://tools.ietf.org/html/rfc2342)
- [RFC2971 - IMAP4 ID extension](https://tools.ietf.org/html/rfc2971)
- [RFC3348 - IMAP4 Child Mailbox Extension](https://tools.ietf.org/html/rfc3348)
- [RFC3502 - IMAP4 MULTIAPPEND Extension](https://tools.ietf.org/html/rfc3502)
- [RFC3516 - IMAP4 Binary Content Extension](https://tools.ietf.org/html/rfc3516)
- [RFC3691 - IMAP4 UNSELECT command](https://tools.ietf.org/html/rfc3691)
- [RFC4314 - IMAP4 Access Control List (ACL) Extension](https://tools.ietf.org/html/rfc4314)
- [RFC4315 - IMAP UIDPLUS extension](https://tools.ietf.org/html/rfc4315)
- [RFC4467 - IMAP URLAUTH Extension](https://tools.ietf.org/html/rfc4467)
- [RFC4469 - IMAP CATENATE Extension](https://tools.ietf.org/html/rfc4469)
- [RFC4551 - IMAP Extension for Conditional STORE Operation or Quick Flag Changes Resynchronization](https://tools.ietf.org/html/rfc4551)
- [RFC4731 - IMAP4 Extension to SEARCH Command for Controlling What Kind of Information Is Returned](https://tools.ietf.org/html/rfc4731)
- [RFC4959 - IMAP Extension for Simple Authentication and Security Layer (SASL) Initial Client Response](https://tools.ietf.org/html/rfc4959)
- [RFC4978 - The IMAP COMPRESS Extension](https://tools.ietf.org/html/rfc4978)
- [RFC5032 - WITHIN Search Extension to the IMAP Protocol](https://tools.ietf.org/html/rfc5032)
- [RFC5161 - The IMAP ENABLE Extension](https://tools.ietf.org/html/rfc5161)
- [RFC5162 - IMAP4 Extensions for Quick Mailbox Resynchronization](https://tools.ietf.org/html/rfc5162)
- [RFC5182 - IMAP Extension for Referencing the Last SEARCH Result](https://tools.ietf.org/html/rfc5182)
- [RFC5255 - IMAP Internationalization (I18NLEVEL=1 only)](https://tools.ietf.org/html/rfc5255)
- [RFC5256 - IMAP SORT and THREAD Extensions](https://tools.ietf.org/html/rfc5256)
- [RFC5258 - IMAP4 - LIST Command Extensions](https://tools.ietf.org/html/rfc5258)
- [RFC5267 - Contexts for IMAP4 (ESORT and CONTEXT=SEARCH only)](https://tools.ietf.org/html/rfc5267)
- [RFC5464 - The IMAP METADATA Extension](https://tools.ietf.org/html/rfc5464)
- [RFC5465 - The IMAP NOTIFY Extension](https://tools.ietf.org/html/rfc5465)
- [RFC5524 - Extended URLFETCH for Binary and Converted Parts](https://tools.ietf.org/html/rfc5524)
- [RFC5530 - IMAP Response Codes](https://tools.ietf.org/html/rfc5530)
- [RFC5819 - IMAP4 Extension for Returning STATUS Information in Extended LIST](https://tools.ietf.org/html/rfc5819)
- [RFC5957 - Display-Based Address Sorting for the IMAP4 SORT Extension](https://tools.ietf.org/html/rfc5957)
- [RFC6154 - IMAP LIST Extension for Special-Use Mailboxes (SPECIAL-USE only)](https://tools.ietf.org/html/rfc6154)
- [RFC6203 - IMAP4 Extension for Fuzzy Search](https://tools.ietf.org/html/rfc6203)
- [RFC6785 - Support for IMAP Events in Sieve (via Pigeonhole plugin)](https://tools.ietf.org/html/rfc6785)
- [RFC6851 - Internet Message Access Protocol (IMAP) - MOVE Extension](https://tools.ietf.org/html/rfc6851)
- [RFC7162 - IMAP Extensions: Quick Flag Changes Resynchronization (CONDSTORE) and Quick Mailbox Resynchronization (QRESYNC) (updated RFC4551 and RFC5162)](https://tools.ietf.org/html/rfc7162)
- [RFC7888 - IMAP4 Non-synchronizing Literals (updated RFC2088)](https://tools.ietf.org/html/rfc7888)

SMTP/LMTP base
--------------

- [RFC821 - Simple Mail Transfer Protocol](https://tools.ietf.org/html/rfc821)
- [RFC2821 - Simple Mail Transfer Protocol (updated RFC821)](https://tools.ietf.org/html/rfc2821)
- [RFC5321 - Simple Mail Transfer Protocol (updated RFC2821)](https://tools.ietf.org/html/rfc5321)
- [RFC2033 - Local Mail Transfer Protocol](https://tools.ietf.org/html/rfc2033)
- [RFC6409 - Message Submission for Mail](https://tools.ietf.org/html/rfc6409)

SMTP/LMTP extensions
--------------------

- [RFC1870 - SMTP Service Extension for Message Size Declaration](https://tools.ietf.org/html/rfc1870)
- [RFC2034 - SMTP Service Extension for Returning Enhanced Error Codes](https://tools.ietf.org/html/rfc2034)
- [RFC2920 - SMTP Service Extension for Command Pipelining](https://tools.ietf.org/html/rfc2920)
- [RFC3030 - SMTP Service Extensions for Transmission of Large and Binary MIME Messages](https://tools.ietf.org/html/rfc3030)
- [RFC3207 - SMTP Service Extension for Secure SMTP over Transport Layer Security](https://tools.ietf.org/html/rfc3207)
- [RFC4468 - Message Submission BURL Extension](https://tools.ietf.org/html/rfc4468)
- [RFC4954 - SMTP Service Extension for Authentication](https://tools.ietf.org/html/rfc4954)
- [RFC6152 - SMTP Service Extension for 8-bit MIME Transport](https://tools.ietf.org/html/rfc6152)

Contact info
============

Timo Sirainen tss@iki.fi, [http://www.dovecot.org/](http://www.dovecot.org/)

Please use the Dovecot mailing list dovecot@dovecot.org for questions about Dovecot. You can post to the list without subscribing, the mail then waits in a moderator queue for a while. See [http://dovecot.org/mailinglists.html](http://dovecot.org/mailinglists.html)
