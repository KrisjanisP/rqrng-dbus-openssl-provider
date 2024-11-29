(W.I.P.)
# qrng-provider
OpenSSL 3 remote quantum random number generation provider

```bash
make
openssl rand -provider-path  ./lib/ -provider librqrng 10
```