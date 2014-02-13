
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#ifdef SODIUM
#include <sodium.h>
#else
#include <nacl/crypto_sign.h>
#endif

#include "utils.h"
#include "log.h"
#include "main.h"
#include "server.h"


void conf_server_init()
{
	conf_init(1);
}

void conf_server_parse( char *var, char *val )
{
	char filebuf[1024];
	int len;

	if(conf_main_parse(var, val) == 0) {
		/* Nothing to do */
	} else if( match(var, "--daemon")) {
		gstate->is_daemon = 1;
	} else if( match(var, "--user")) {
		if(val == NULL) {
			conf_val_missing(var);
		}
		gstate->user = strdup(val);
	} else if( match(var, "--max-requests")) {
		if(val == NULL) {
			conf_val_missing(var);
		}
		gstate->max_requests = atoi(val);
	} else if( match(var, "--secret-key")) {
		if(val == NULL) {
			conf_val_missing(var);
		}

		/* Assume var to be a file path */
		if(!is_hex(val, strlen(val))) {
			len = read_file(filebuf, sizeof(filebuf), val);
			if( len < 0 ) {
				log_err("Cannot read secret key '%s': %s", val, strerror( errno ) );
				exit(1);
			}
			val = filebuf;
		}

		if(strlen(val) != (2*crypto_sign_SECRETKEYBYTES)) {
			log_err("Invalid secret key size of %d characters.", strlen(val));
			exit(1);
		}

		if(!is_hex(val, strlen(val))) {
			log_err("Invalid secret key.");
			exit(1);
		}

		gstate->secret_key = strdup(val);
	} else {
		log_err( "Unknown parameter: %s", var);
		exit(1);
	}
}

void conf_server_check()
{
	conf_check();

	if(gstate->secret_key == NULL) {
		log_err("Secret key is missing.");
		exit(1);
	}
}

int server( int argc, char **argv )
{
	char addrbuf[FULL_ADDSTRLEN+1];
	UCHAR secret_key[crypto_sign_SECRETKEYBYTES];
	UCHAR sm[CHALLENGE_LEN+crypto_sign_BYTES];
	UCHAR m[CHALLENGE_LEN+crypto_sign_BYTES];
	unsigned long long smlen;
	unsigned long long mlen;
	socklen_t addrlen_ret;
	IP addr;
	struct timeval tv;
	int fd, rc, counter;
	time_t counter_started;
	fd_set fds;

	conf_server_init();
	conf_load(argc, argv, conf_server_parse);
	conf_server_check();

	fd = net_bind((gstate->af == AF_INET) ? "0.0.0.0" : "::0", gstate->port, NULL, IPPROTO_UDP, gstate->af);
	if(fd < 0) {
		/* Failed to bind - net_bind will tell */
		return 1;
	}

	if( gstate->is_daemon == 1 ) {
		if( chdir( "/" ) != 0 ) {
			log_err( "Changing working directory to / failed: %s", strerror( errno ) );
			exit(1);
		}

		gstate->use_syslog = 1;

		/* Close pipes */
		fclose( stderr );
		fclose( stdout );
		fclose( stdin );

		/* Fork before any threads are started */
		unix_fork();

		/* Drop privileges */
		unix_dropuid0();
	}

	/* Register SIGINT */
	unix_signal();

	/* Set the servers public key */
	from_hex(secret_key, gstate->secret_key, 2*crypto_sign_SECRETKEYBYTES );

	counter = 0;
	counter_started = 0;

	while( gstate->is_running ) {
		counter++;

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO( &fds );
		FD_SET( fd, &fds );

		log_debug("Listen for incoming messages.");
		rc = select( fd + 1, &fds, NULL, NULL, &tv );
		if( rc <= 0 ) {
			continue;
		}

		addrlen_ret = sizeof(IP);
		mlen = recvfrom( fd, m, sizeof(m), 0, (struct sockaddr *) &addr, &addrlen_ret );

		/* Check if the challenge is too long */
		if(mlen > CHALLENGE_LEN) {
			continue;
		}

		/* Reset counter every second */
		if(time(NULL) > counter_started) {
			counter_started = time(NULL);
			counter = 0;
		}

		/* Too many challenges */
		if(counter > gstate->max_requests) {
			continue;
		}

		/* Solve the challenge */
		if( crypto_sign(sm, &smlen, m, mlen, secret_key) == 0) {
			log_debug( "Send reply of %llu bytes to %s", smlen, str_addr(&addr, addrbuf) );
			sendto( fd, sm, smlen, 0, (struct sockaddr*) &addr, sizeof(IP) );
		}
	}

	return 0;
}
