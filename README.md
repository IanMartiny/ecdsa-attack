# ECDSA Attack 

### Rust PFRing integration

## Installing

```sh
# Install dependencies
sudo apt install libelf-dev build-essential bison pkg-config libpcap-dev flex linux-headers-$(uname -r) libnuma-dev

# pull the repo and submodule (PF_RING) repos
git clone --recursive git@github.com:IanMartiny/ecdsa-attack.git

# Build PF_RING
cd PF_RING
make

# Build Parser
cd ../
make
```

## Running

### Simple

Run simple version off local network interface.

```sh
./rust-src/target/release/tls_fingerprint <interface name (i.e. eth0)>
```

### Advanced

Run with advanced `PF_RING` integration.

See [PF_RING Documentation](https://www.ntop.org/guides/pf_ring) for the latest
information on how to run PF_RING ZC correctly.

#### 1. Install the PF_RING kernel Module

```sh
cd PF_RING/kernel
make
sudo make install
```

#### 2. Run PF_RING

See the [docs](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#running-pf-ring)
for more options.

```sh
# sudo insmod ./pf_ring.ko [min_num_slots=N] [enable_tx_capture=1|0] [ enable_ip_defrag=1|0]
sudo insmod pf_ring.ko min_num_slots=65536
```

**min_num_slots**
    Minimum number of packets the kernel module should be able to enqueue (default – 4096).

#### 3. Compile and run Zero Copy (ZC) drivers

```sh
# Determine the driver family
ethtool -i eth1 | grep driver
> e1000e

# Compile and load the corresponding driver
cd PF_RING/drivers/intel
make
cd e1000e/e1000e-*-zc/src
sudo ./load_driver.sh
```

#### 4. Run Zero Copy Load Balancer

Start the ZC load balancer establishing cluster and queues to interface with.

see the [docs](https://www.ntop.org/guides/pf_ring/rss.html?highlight=zbalance_ipc#zc-load-balancing-zbalance-ipc)
for more options

```sh
cd PF_R/userland/examples_zc
# sudo zbalance_ipc -i zc:eth1 -n $CORES -c $CLUSTER_NUM -g 1
sudo zbalance_ipc -i zc:eth1 -n 2 -c 10 -g 1
```

-g is the core affinity for the capture/distribution thread

-c declares the ZC cluster ID

-n specifies the number of egress queues

#### 5. Run Application

Connect the `ecdsa-attack` parser to PF_RING and we're off!

```sh
# sudo ./tls-fingerprint -c $CLUSTER_NUM -n $CORES -d $DATA_SOURCE_NAME [-m $QUEUE_OFFSET]
sudo ./tls-fingerprint -c 10 -n 2 -d "postgresql://user:secret@localhost/dbname" -m 0
```

-c specifies the ZC cluster ID

-n specifies the number of egress queues

-m cluster queue numeric offset

-d data source name for connecting to database

## Useful RFC's

* [X.509 RFC 5280](https://tools.ietf.org/html/rfc5280)
* [TLS 1.2 RFC 5246](https://tools.ietf.org/html/rfc5246)
* [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
* [TCP RFC 793](https://tools.ietf.org/html/rfc793)
* [ECDSA RFC 6979](https://tools.ietf.org/html/rfc6979)
* [ECC for TLS RFC 4492](https://tools.ietf.org/html/rfc4492)