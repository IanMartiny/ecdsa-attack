# ECDSA Attack 
### Rust PFRing integration


## Installing
```sh
# Install dependencies
sudo apt install libelf-dev build-essential bison flex linux-headers-$(uname -r) libnuma-dev

# pull the repo and submodule (PF_RING) repos
git clone --recursive-submodules git@github.com:IanMartiny/ecdsa-attack.git

# Build PF_RING
cd PF_RING
make

# Build Parser
cd ../
make
```

## Running 

Run simple version off local network interface.

```sh
./rust-src/target/release/tls_fingerprint <interface name (i.e. eth0)>
```


Run with advanced `PF_Ring` integration. 
```sh
TODO
```



Useful RFC's
* [X.509 RFC 5280](https://tools.ietf.org/html/rfc5280)
* [TLS 1.2 RFC 5246](https://tools.ietf.org/html/rfc5246)
* [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
* [TCP RFC 793](https://tools.ietf.org/html/rfc793)
* [ECDSA RFC 6979](https://tools.ietf.org/html/rfc6979)
* [ECC for TLS RFC 4492](https://tools.ietf.org/html/rfc4492)




>>>>>>> rust_sfrolov
