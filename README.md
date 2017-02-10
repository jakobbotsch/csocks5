# Compiling
`clang main.c -pthreads`

# Running:
`./a.out <port> [<username> <password>]`

If username and password are not specified then no auth is required. Otherwise only username/password auth can be used.

The proxy will use the IP that was connected to as the source IP for outgoing requests.
