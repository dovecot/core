@@
expression E;
@@

- if (E != NULL) {
- 	dict_iterate_deinit(&E);
- }
+ dict_iterate_deinit(&E);

@@
expression E, error;
@@
- if (E != NULL) {
-	if (dict_iterate_deinit(&E, error) < 0) {
+ if (dict_iterate_deinit(&E, error) < 0) {
		...
-	}
- }
+ }

@@
expression E, error;
expression block;
@@
- if (E != NULL) {
-	if (dict_iterate_deinit(&E, error) < 0)
-		block;
- }
+ if (dict_iterate_deinit(&E, error) < 0)
+	block;
