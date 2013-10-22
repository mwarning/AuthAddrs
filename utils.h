
#ifndef _UTILS_H_
#define _UTILS_H_

#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)

#define ADDR_PARSE_SUCCESS 0
#define ADDR_PARSE_INVALID_FORMAT 1
#define ADDR_PARSE_CANNOT_RESOLVE 2
#define ADDR_PARSE_NO_ADDR_FOUND 3

/* Simple string match */
#define match(opt, arg) ((opt != NULL) && (strcmp( opt, arg ) == 0))

typedef struct sockaddr_storage IP;
typedef struct sockaddr_in6 IP6;
typedef struct sockaddr_in IP4;
typedef unsigned int UINT;
typedef unsigned char UCHAR;

int read_file( char buf[], int buflen, const char *path );
void randombytes(UCHAR buffer[], unsigned long long size);

int is_hex( const char string[], size_t size );
void from_hex( UCHAR bin[], const char hex[], size_t length );
char* to_hex( char hex[], const UCHAR bin[], size_t length );

void conf_load( int argc, char **argv, void (*cb)(char *var, char *val) );

void unix_signal( void );
void unix_sig_stop( int signo );
void unix_sig_term( int signo );
void unix_fork( void );
void unix_dropuid0( void );

int addr_equal( const IP *addr1, const IP *addr2 );
int addr_parse_full( IP *addr, const char *full_addr_str, const char* default_port, int af );
char* str_addr( const IP *addr, char *addrbuf );

int net_bind(
	const char* addr,
	const char* port,
	const char* ifce,
	int protocol, int af
);

#endif /* _UTILS_H_ */
