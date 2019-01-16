@@
expression E;
@@

- if (E != NULL) {
- 	o_stream_destroy(&E);
- }
+ o_stream_destroy(&E);
