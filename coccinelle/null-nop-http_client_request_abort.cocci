@@
expression E;
@@

- if (E != NULL) {
- 	http_client_request_abort(&E);
- }
+ http_client_request_abort(&E);
