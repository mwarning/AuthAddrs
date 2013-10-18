
#include <assert.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include "log.h"
#include "main.h"
#include "utils.h"


void randombytes(UCHAR buffer[], unsigned long long size)
{
	int fd;

	fd = open( "/dev/urandom", O_RDONLY );
	if( fd < 0 ) {
		log_err( "Failed to open /dev/urandom" );
		exit(1);
	}

	int rc;
	if( (rc = read( fd, buffer, size )) >= 0 ) {
		close( fd );
	}
}

int is_hex( const char string[], size_t size )
{
	int i = 0;

	for( i = 0; i < size; i++ ) {
		const char c = string[i];
		if( (c >= '0' && c <= '9')
				|| (c >= 'A' && c <= 'F')
				|| (c >= 'a' && c <= 'f') ) {
			continue;
		} else {
			return 0;
		}
	}

	return 1;
}

void from_hex( UCHAR bin[], const char hex[], size_t length )
{
	int i;
	int xv = 0;

	for( i = 0; i < length; ++i ) {
		const char c = hex[i];
		if( c >= 'a' ) {
			xv += (c - 'a') + 10;
		} else if ( c >= 'A') {
			xv += (c - 'A') + 10;
		} else {
			xv += c - '0';
		}

		if( i % 2 ) {
			bin[i/2] = xv;
			xv = 0;
		} else {
			xv *= 16;
		}
	}
}

char* to_hex( char hex[], const UCHAR bin[], size_t length )
{
	int i;
	UCHAR *p0 = (UCHAR *)bin;
	char *p1 = hex;

	for( i = 0; i < length; i++ ) {
		snprintf( p1, 3, "%02x", *p0 );
		p0 += 1;
		p1 += 2;
	}

	return hex;
}

void conf_load( int argc, char **argv, void (*cb)(char *var, char *val) )
{
	unsigned int i;

	if( argv == NULL ) {
		return;
	}

	for( i = 1; i < argc; i++ ) {
		if( argv[i][0] == '-' ) {
			if( i+1 < argc && argv[i+1][0] != '-' ) {
				/* -x abc */
				cb( argv[i], argv[i+1] );
				i++;
			} else {
				/* -x -y => -x */
				cb( argv[i], NULL );
			}
		} else {
			/* x */
			cb( NULL, argv[i] );
		}
	}
}

void unix_signal( void )
{

	/* STRG+C aka SIGINT => Stop the program */
	gstate->sig_stop.sa_handler = unix_sig_stop;
	gstate->sig_stop.sa_flags = 0;
	if( ( sigemptyset( &gstate->sig_stop.sa_mask ) == -1) || (sigaction( SIGINT, &gstate->sig_stop, NULL ) != 0) ) {
		log_err( "Failed to set SIGINT to handle Ctrl-C" );
	}

	/* SIGTERM => Stop the program gracefully */
	gstate->sig_term.sa_handler = unix_sig_term;
	gstate->sig_term.sa_flags = 0;
	if( ( sigemptyset( &gstate->sig_term.sa_mask ) == -1) || (sigaction( SIGTERM, &gstate->sig_term, NULL ) != 0) ) {
		log_err( "Failed to set SIGTERM to handle Ctrl-C" );
	}
}

void unix_sig_stop( int signo )
{
	gstate->is_running = 0;
	log_info( "Shutting down..." );
}

void unix_sig_term( int signo )
{
	gstate->is_running = 0;
}

void unix_fork( void )
{
	pid_t pid;

	pid = fork();

	if( pid < 0 ) {
		log_err( "Failed to fork." );
	} else if( pid != 0 ) {
		exit( 0 );
	}

	/* Become session leader */
	setsid();

	/* Clear out the file mode creation mask */
	umask( 0 );
}

void unix_dropuid0( void )
{
	struct passwd *pw = NULL;

	/* Return if no user is set */
	if( gstate->user == NULL ) {
		return;
	}

	/* Return if we are not root */
	if( getuid() != 0 ) {
		return;
	}

	/* Process is running as root, drop privileges */
	if( (pw = getpwnam( gstate->user )) == NULL ) {
		log_err( "Dropping uid 0 failed. Set a valid user." );
	}

	if( setenv( "HOME", pw->pw_dir, 1 ) != 0 ) {
		log_err( "Setting new $HOME failed." );
	}

	if( setgid( pw->pw_gid ) != 0 ) {
		log_err( "Unable to drop group privileges" );
	}

	if( setuid( pw->pw_uid ) != 0 ) {
		log_err( "Unable to drop user privileges" );
	}

	/* Test permissions */
	if( setuid( 0 ) != -1 || setgid( 0 ) != -1 ) {
		log_err( "We still have root privileges" );
	}
}

/* Compare two ip addresses */
int addr_equal( const IP *addr1, const IP *addr2 )
{
	if( addr1->ss_family != addr2->ss_family ) {
		return 0;
	} else if( addr1->ss_family == AF_INET ) {
		const IP4 *a1 = (IP4 *)addr1;
		const IP4 *a2 = (IP4 *)addr2;
		return (memcmp( &a1->sin_addr, &a2->sin_addr, 4 ) == 0) && (a1->sin_port == a2->sin_port);
	} else if( addr1->ss_family == AF_INET6 ) {
		const IP6 *a1 = (IP6 *)addr1;
		const IP6 *a2 = (IP6 *)addr2;
		return (memcmp( &a1->sin6_addr, &a2->sin6_addr, 16 ) == 0) && (a1->sin6_port == a2->sin6_port);
	} else {
		return 0;
	}
}

/*
* Resolve/Parse an IP address.
* The port must be specified separately.
*/
int addr_parse( IP *addr, const char *addr_str, const char *port_str, int af )
{
	struct addrinfo hints;
	struct addrinfo *info = NULL;
	struct addrinfo *p = NULL;

	memset( &hints, '\0', sizeof(struct addrinfo) );
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = af;

	if( getaddrinfo( addr_str, port_str, &hints, &info ) != 0 ) {
		return ADDR_PARSE_CANNOT_RESOLVE;
	}

	p = info;
	while( p != NULL ) {
		if( p->ai_family == AF_INET6 ) {
			memcpy( addr, p->ai_addr, sizeof(IP6) );
			freeaddrinfo( info );
			return ADDR_PARSE_SUCCESS;
		}
		if( p->ai_family == AF_INET ) {
			memcpy( addr, p->ai_addr, sizeof(IP4) );
			freeaddrinfo( info );
			return ADDR_PARSE_SUCCESS;
		}
	}

	freeaddrinfo( info );
	return ADDR_PARSE_NO_ADDR_FOUND;
}

/*
* Parse/Resolve various string representations of
* IPv4/IPv6 addresses and optional port.
* An address can also be a domain name.
* A port can also be a service  (e.g. 'www').
*
* "<address>"
* "<ipv4_address>:<port>"
* "[<address>]"
* "[<address>]:<port>"
*/
int addr_parse_full( IP *addr, const char *full_addr_str, const char* default_port, int af )
{
	char addr_buf[256];

	char *addr_beg, *addr_tmp;
	char *last_colon;
	const char *addr_str = NULL;
	const char *port_str = NULL;
	int len;

	len = strlen( full_addr_str );
	if( len >= (sizeof(addr_buf) - 1) ) {
		/* address too long */
		return ADDR_PARSE_INVALID_FORMAT;
	} else {
		addr_beg = addr_buf;
	}

	memset( addr_buf, '\0', sizeof(addr_buf) );
	memcpy( addr_buf, full_addr_str, len );

	last_colon = strrchr( addr_buf, ':' );

	if( addr_beg[0] == '[' ) {
		/* [<addr>] or [<addr>]:<port> */
		addr_tmp = strrchr( addr_beg, ']' );

		if( addr_tmp == NULL ) {
			/* broken format */
			return ADDR_PARSE_INVALID_FORMAT;
		}

		*addr_tmp = '\0';
		addr_str = addr_beg + 1;

		if( *(addr_tmp+1) == '\0' ) {
			port_str = default_port;
		} else if( *(addr_tmp+1) == ':' ) {
			port_str = addr_tmp + 2;
		} else {
			/* port expected */
			return ADDR_PARSE_INVALID_FORMAT;
		}
	} else if( last_colon && last_colon == strchr( addr_buf, ':' ) ) {
		/* <non-ipv6-addr>:<port> */
		addr_tmp = last_colon;
		if( addr_tmp ) {
			*addr_tmp = '\0';
			addr_str = addr_buf;
			port_str = addr_tmp+1;
		} else {
			addr_str = addr_buf;
			port_str = default_port;
		}
	} else {
		/* <addr> */
		addr_str = addr_buf;
		port_str = default_port;
	}

	return addr_parse( addr, addr_str, port_str, af );
}

char* str_addr( const IP *addr, char *addrbuf )
{
	char buf[INET6_ADDRSTRLEN+1];
	unsigned short port;

	switch( addr->ss_family ) {
	case AF_INET6:
		port = ntohs( ((IP6 *)addr)->sin6_port );
		inet_ntop( AF_INET6, &((IP6 *)addr)->sin6_addr, buf, sizeof(buf) );
		sprintf( addrbuf, "[%s]:%hu", buf, port );
		break;
	case AF_INET:
		port = ntohs( ((IP4 *)addr)->sin_port );
		inet_ntop( AF_INET, &((IP4 *)addr)->sin_addr, buf, sizeof(buf) );
		sprintf( addrbuf, "%s:%hu", buf, port );
		break;
	default:
		sprintf( addrbuf, "<invalid address>" );
	}

	return addrbuf;
}

int net_set_nonblocking(int fd)
{
	int rc;
	int nonblocking = 1;

	rc = fcntl(fd, F_GETFL, 0);
	if(rc < 0)
		return -1;

	rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
	if(rc < 0)
		return -1;

	return 0;
}
int net_bind(
	const char* addr,
	const char* port,
	const char* ifce,
	int protocol, int af
)
{
	char addrbuf[FULL_ADDSTRLEN+1];
	int sock;
	int val;
	IP sockaddr;

	if( af != AF_INET && af != AF_INET6 ) {
		log_err( "Unknown address family value." );
		return -1;
	}

	if( addr_parse( &sockaddr, addr, port, af ) != 0 ) {
		log_err( "Failed to parse IP address '%s' and port '%s'.", addr, port );
		return -1;
	}

	if( protocol == IPPROTO_TCP ) {
		sock = socket( sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP );
	} else if( protocol == IPPROTO_UDP ) {
		sock = socket( sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP );
	} else {
		sock = -1;
	}

	if( sock < 0 ) {
		log_err( "Failed to create socket: %s", strerror( errno ) );
		return -1;
	}

	val = 1;
	if ( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val) ) < 0 ) {
		close( sock );
		log_err( "Failed to set socket option SO_REUSEADDR: %s", strerror( errno ));
		return -1;
	}

	if( ifce && setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifce, strlen( ifce ) ) ) {
		close( sock );
		log_err( "Unable to bind to device '%s': %s", ifce, strerror( errno ) );
		return -1;
	}

	if( af == AF_INET6 ) {
		val = 1;
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val) ) < 0 ) {
			close( sock );
			log_err( "Failed to set socket option IPV6_V6ONLY: %s", strerror( errno ));
			return -1;
		}
	}

	if( bind( sock, (struct sockaddr*) &sockaddr, sizeof(IP) ) < 0 ) {
		close( sock );
		log_err( "Failed to bind socket to address: '%s'", strerror( errno ) );
		return -1;
	}

	if( net_set_nonblocking( sock ) < 0 ) {
		close( sock );
		log_err( "Failed to make socket nonblocking: '%s'", strerror( errno ) );
		return -1;
	}

	if( protocol == IPPROTO_TCP && listen( sock, 5 ) < 0 ) {
		close( sock );
		log_err( "Failed to listen on socket: '%s'", strerror( errno ) );
		return -1;
	}

	log_debug( ifce ? "Bind to %s, interface %s" : "Bind to %s" ,
			   str_addr( &sockaddr, addrbuf ), ifce
			 );

	return sock;
}
