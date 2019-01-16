@@
expression E;
@@

- if (E != NULL) {
- 	o_stream_close(E);
- }
+ o_stream_close(E);
