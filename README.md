# Compiling
`clang main.c -pthreads`

# Running:
`./a.out`

Default port is 1080 and auth is username/password. No other auth is supported.
The default parameters can be changed in `main.c`.
The proxy will use the IP that was connected to as the source IP
for outgoing requests.
