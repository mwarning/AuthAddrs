AuthAddrs
===========

## Description

AuthAddrs filters a list of IP addresses for nodes that can solve
a specific cryptographic challenge. By default, AuthAddrs
exits after one verified IP address will be printed out or after
the timeout is reached.

This tool is used for the testing of authentification schemes.

Authentication is done via a public/secret key system
implemented by the [libnacl](http://nacl.cr.yp.to/)/[libsodium](https://github.com/jedisct1/libsodium) library.

## Usage Example

1. Generate a key pair:
    ```
$ ./auth_addrs gen
public key: bea123645d036aa9eddd745d5c87d0e328b28f9a1eb8d86e86ce360e2fabfaaa
secret key: ce75e6ec974f29462bd4bd255f7eac2f4a51d214eb4503d939ade2fd757fab60bea123645d036aa9eddd745d5c87d0e328b28f9a1eb8d86e86ce360e2fabfaaa
```

2. Start server instances on one or more computers:

    Node at 192.168.1.2
    ```$./auth_addrs server --secret-key ce75e6ec974f29462bd4bd255f7eac2f4a51d214eb4503d939ade2fd757fab60bea123645d036aa9eddd745d5c87d0e328b28f9a1eb8d86e86ce360e2fabfaaa```

    Node at 192.168.1.5
    ```$./auth_addrs server --secret-key ce75e6ec974f29462bd4bd255f7eac2f4a51d214eb4503d939ade2fd757fab60bea123645d036aa9eddd745d5c87d0e328b28f9a1eb8d86e86ce360e2fabfaaa```

    Node at 192.168.1.8 (but using the wrong secret)
    ```$./auth_addrs server --secret-key aaaae6ec974f29462bd4bd255f7eac2f4a51d214eb4503d939ade2fd757fab60bea123645d036aa9eddd745d5c87d0e328b28f9a1eb8d86e86ce360e2fabfaaa```

3. Start client with public key and all potential address
    ```
$./auth_addrs client 192.168.1.2 192.168.1.5 192.168.8 --wait --public-key bea123645d036aa9eddd745d5c87d0e328b28f9a1eb8d86e86ce360e2fabfaaa
192.168.1.2
192.168.1.5
```

    The client will now send random strings to each node (a challenge).
    Every server will sign the challenge using its secret key and send it
    back to the client. The client will try to verify the response using the
    public key. The address of every successfully verified server will be
    then printed out to the console.

## Options

Usage: `auth_addr` gen

  * Generates a new public/secret key pair.

Usage: `auth_addr` client [arguments] --public-key *key* [addresses]

  * `--port` *port*  
    Set the port to listen for replies.  
    Default: 5292

  * `--help, -h`  
    Show this help text.

  * `--ipv6,-6`  
    IPv6 mode. Default is IPv4.

  * `--public-key` *key/file*  
    The public key or a file.

  * `--verbosity` *level*  
    Verbosity level: quiet, verbose or debug.  
    Default: verbose

  * `--timeout` *seconds*  
    Quit after n seconds.  
    Default: 1

  * `--wait`  
    Wait for the timeout to expire.

Usage: `auth_addr` server [arguments] --secret-key *key*

  * `--port` *port*  
    Set the port to listen for replies.  
    Default: 5292

  * `--help, -h`  
    Show this help text.

  * `--ipv6,-6`  
    IPv6 mode. Default is IPv4.

  * `--secret-key` *key/file*  
    The secret key or a file.

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

## LICENSE

  GPLv3
