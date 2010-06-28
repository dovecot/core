.SH OPTIONS
Global
.BR doveadm (1)
.IR options :
.TP
.B \-D
Enables verbosity and debug messages.
.TP
.BI \-f\  formatter
Specifies the
.I formatter
for formatting the output.
Supported formatters are:
.RS
.TP
.B flow
prints each line with
.IB key = value
pairs.
.TP
.B pager
prints each
.IR key :\  value
pair on its own line and separates records with form feed character
.RB ( ^L ).
.TP
.B tab
prints a table header followed by tab separated value lines.
.TP
.B table
prints a table header followed by adjusted value lines.
.RE
.TP
.B \-v
Enables verbosity, including progress counter.
