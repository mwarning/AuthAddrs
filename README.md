AuthAddrs
===========

## DESCRIPTION

AuthAddrs filters a list of addresses for nodes that can solve
a specific cryptographic challenge.

Authentication is done via a public/secret key system
implemented by the [libnacl](http://nacl.cr.yp.to/)/[libsodium](https://github.com/jedisct1/libsodium) library.


## OPTIONS

Usage: `auth_addr` gen

  * Generates a new public/secret key pair.

Usage: `auth_addr` client [arguments] -s *secret* [addresses]

  * `--port` *port*  
    Set the port to listen for replies.  
    Default: 5292

  * `--help, -h`  
    Show this help text.

  * `--ipv6,-6`  
    IPv6 mode. Default is IPv4.

  * `--public-key` *key*  
    The public key.

  * `--verbosity` *level*  
    Verbosity level: quiet, verbose or debug.  
    Default: verbose

  * `--timeout` *seconds*  
    Quit after n seconds.  
    Default: 1

  * `--wait`  
    Wait for the timeout to expire.

Usage: `auth_addr` server [arguments] -s *secret*

  * `--port` *port*  
    Set the port to listen for replies.  
    Default: 5292

  * `--help, -h`  
    Show this help text.

  * `--ipv6,-6`  
    IPv6 mode. Default is IPv4.

  * `--secret-key` *key*  
    The secret key.

  * `--verbosity` *level*  
    Verbosity level: quiet, verbose or debug  
    Default: verbose

  *  `--daemon`  
    Run server as daemon.

  *  `--user` *name*  
    Change user when starting as daemon.


##Example

As an example we generate a new key pair.
The keys are displayed shortened.

```
./auth_addrs gen
public key: 1d749d4d...
secret key: 7aec1be6514b6...
```

Now we start two server instances with the correct secret key
and one with a wrong key.

```
auth_addrs server --port 3333 --secret-key 7aec1be6514b6...
auth_addrs server --port 4444 --secret-key 999c1be6514b6...
auth_addrs server --port 5555 --secret-key 7aec1be6514b6...
```

The client node now checks all given servers for the secret message:

```
auth_addrs client --port 1234 --wait --public-key 1d749d4d... localhost:3333 localhost:4444 localhost:5555
127.0.0.1:3333
127.0.0.1:5555
```

As you can see, only two instances have the correct secret key.
