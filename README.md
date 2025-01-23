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