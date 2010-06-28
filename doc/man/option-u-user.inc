.TP
.BI \-u\  user/mask
Run the
.I command
only for the given
.IR user .
It\(aqs also possible to use
.RB \(aq * \(aq
and
.RB \(aq ? \(aq
wildcards (e.g. \-u *@example.org).
.br
When neither the
.B \-A
option nor
.BI \-u\  user
was specified, the
.I command
will be executed with the environment of the
currently logged in user.
