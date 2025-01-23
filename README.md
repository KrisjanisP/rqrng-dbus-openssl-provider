(W.I.P.)
# qrng-provider
OpenSSL 3 remote quantum random number generation provider

```bash
make
openssl rand -provider-path  ./lib/ -provider librqrng 10
```

running this give the same output for the same provider input
```bash
openssl genpkey -provider-path ./lib/ -provider librqrng -provider default -algorithm RSA -out private.key
```

through experiment by running the cmd above and restarting mock dbus service in between, we got the same private key.
the mock dbus service read from a pre-recorded output of /dev/random.
if the mock dbus service returned a banal output, such as all zeros, the openssl private key generation threw an error.