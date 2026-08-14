/* Code generation flags can conflict with each other, e.g. -mindirect-branch and
   -fcf-protection. Gcc only reports that conflict while compiling a function. The
   indirect call makes the thunk flags reference the thunks they need, so that a value
   like thunk-extern, which expects something else to provide them, is rejected here
   rather than at link time.
*/

int f(void);
int (*volatile fp)(void) = f;

int f(void) {
	return 0;
}

int main(void) {
	return fp();
}
