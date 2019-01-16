@@
expression E;
@@

- if (E != NULL) {
- 	mailbox_header_lookup_unref(&E);
- }
+ mailbox_header_lookup_unref(&E);
