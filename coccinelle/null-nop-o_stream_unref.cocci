@@
expression E;
@@

- if (E != NULL) {
- 	o_stream_unref(&E);
- }
+ o_stream_unref(&E);
