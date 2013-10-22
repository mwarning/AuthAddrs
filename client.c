
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <time.h>

#ifdef SODIUM
#include <sodium.h>
#else
#include <nacl/crypto_sign.h>
#endif

#include "utils.h"
#include "log.h"
#include "main.h"
#include "client.h"


struct Task {
	IP addr;
	UCHAR m[CHALLENGE_LEN]; /* A random challenge */
	int done;
	struct Task *next;
};

/* List of IP addresses /random challenge pairs */
struct Task *tasks = NULL;

struct Task* add_task(IP *addr) {
	struct Task *a;
	struct Task *n;

	a = tasks;
	while(a)  {
		if(a->next == NULL)  {
			break;
		}
		a = a->next;
	}

	n = (struct Task*) malloc(sizeof(struct Task));
	memcpy(&n->addr, addr, sizeof(IP));
	randombytes(n->m, CHALLENGE_LEN);
	n->next = NULL;
	n->done = 0;

	if(a) {
		a->next = n;
	} else {
		tasks = n;
	}

	return n;
}

struct Task *find_task(IP *addr) {
	struct Task *a;

	a = tasks;
	while(a)  {
		if(addr_equal(&a->addr, addr)) {
			return a;
		}
		a = a->next;
	}
	return NULL;
}

void conf_client_init()
{
	conf_init(0);
}

void conf_client_check()
{
	conf_check();

	if(tasks == NULL) {
		log_err("No tasks was given to ping.");
		exit(1);
	}

	if(gstate->public_key == NULL) {
		log_err("Public key is missing.");
		exit(1);
	}

	if(gstate->timeout < 1) {
		log_err("Invalid timeout.");
		exit(1);
	}
}

void conf_client_handle( char *var, char *val )
{
	char filebuf[1024];
	int len;
	IP addr;
	int rc;

	if(conf_handle(var, val) == 0) {
		/* Nothing to do */
	} else if( var == NULL) {
		rc = addr_parse_full( &addr, val, DEFAULT_PORT, gstate->af );
		if( rc == ADDR_PARSE_INVALID_FORMAT) {
			log_err( "Cannot parse %s address: %s", (gstate->af == AF_INET) ? "IPv4" : "IPv6", var);
			exit(1);
		}

		if( rc != ADDR_PARSE_SUCCESS) {
			/* Ignore addresses we cannot resolve */
			return;
		}

		/* Check if IP address is already in array */
		if(find_task(&addr) == NULL)  {
			add_task(&addr);
		}
	} else if( match(var, "--public-key")) {
		if(val == NULL) {
			conf_val_missing(var);
		}

		/* Assume var to be a file path */
		if(!is_hex(val, strlen(val))) {
			len = read_file(filebuf, sizeof(filebuf), val);
			if( len < 0 ) {
				log_err("Cannot read public key %s: %s", val, strerror( errno ) );
				exit(1);
			}
			val = filebuf;
		}

		if(strlen(val) != (2*crypto_sign_PUBLICKEYBYTES)) {
			log_err("Invalid secret key size of %d characters.", strlen(val));
			exit(1);
		}

		if(!is_hex(val, strlen(val))) {
			log_err("Invalid public key.");
			exit(1);
		}

		gstate->public_key = strdup(val);
	} else if( match(var, "--timeout")) {
		if(val == NULL) {
			conf_val_missing(var);
		}
		gstate->timeout = atoi(val);
	} else if( match(var, "--wait")) {
		if(val != NULL) {
			conf_val_not_missing(var);
		}
		gstate->wait = 1;
	} else {
		log_err( "Unknown parameter: %s", var);
		exit(1);
	}
}

int receive_response(int fd, UCHAR public_key[])
{
	char addrbuf[FULL_ADDSTRLEN+1];
	UCHAR sm[CHALLENGE_LEN+crypto_sign_BYTES];
	UCHAR m[CHALLENGE_LEN+crypto_sign_BYTES];
	unsigned long long smlen;
	unsigned long long mlen;
	IP addr_ret;
	socklen_t addrlen_ret;
	struct Task *task;

	addrlen_ret = sizeof(IP);
	smlen = recvfrom( fd, sm, sizeof(sm), 0, (struct sockaddr *) &addr_ret, &addrlen_ret );
	log_debug("Received reply from %s: %d bytes.", str_addr(&addr_ret, addrbuf), smlen);

	task = find_task(&addr_ret);
	if( task == NULL ) {
		log_debug("Received reply from unknown address: %s", str_addr(&addr_ret, addrbuf));
		return 1;
	}

	if(task->done) {
		log_debug("Reply address was already verified: %s", str_addr(&addr_ret, addrbuf));
		return 1;
	}

	if( crypto_sign_open(m, &mlen, sm, smlen, public_key) != 0) {
		log_debug("Signature does not verify.");
		return 1;
	}

	if(mlen != CHALLENGE_LEN || memcmp(m, task->m, CHALLENGE_LEN) != 0) {
		log_debug("Challenge does not match.");
		return 1;
	}

	task->done = 1;

	/* Print out verified address */
	printf("%s\n", str_addr(&task->addr, addrbuf));

	return 0;
}

int client( int argc, char **argv )
{
	UCHAR public_key[crypto_sign_PUBLICKEYBYTES];
	struct Task *task;
	int round;
	int verified_addresses;
	int fd, rc, all_done;
	fd_set fds;
	struct timeval tv;
	time_t until;

	conf_client_init();
	conf_load(argc, argv, conf_client_handle);
	conf_client_check();

	fd = net_bind((gstate->af == AF_INET) ? "0.0.0.0" : "::0", gstate->port, NULL, IPPROTO_UDP, gstate->af);
	if(fd < 0) {
		/* Failed to bind - net_bind will tell */
		return 1;
	}

	/* Register SIGINT */
	unix_signal();

	/* Set the servers public key */
	from_hex(public_key, gstate->public_key, 2*crypto_sign_PUBLICKEYBYTES);

	round = 0;
	verified_addresses = 0;

	/* Every round takes one second */
	while( round < gstate->timeout && gstate->is_running ) {
		round++;

		/* Send challenges to servers */
		all_done = 1;
		task = tasks;
		while(task) {
			if(task->done == 0) {
				all_done = 0;
				sendto( fd, task->m, CHALLENGE_LEN, 0, (struct sockaddr*) &task->addr, sizeof(IP) );
			}
			task = task->next;
		}

		if(all_done == 1) {
			goto end;
		}

		/* Handle replies for 1 second */
		until = time(NULL) + 1;
		do {
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			FD_ZERO( &fds );
			FD_SET( fd, &fds );

			rc = select( fd + 1, &fds, NULL, NULL, &tv );

			if( rc <= 0 ) {
				continue;
			}

			if( receive_response(fd, public_key) == 0) {
				verified_addresses++;
				if( gstate->wait == 0 ) {
					goto end;
				}
			}
		} while(until > time(NULL) && gstate->is_running);
	}

	end:;

	if(verified_addresses > 0) {
		return 0;
	} else {
		log_debug("No valid replies received.");
		return 1;
	}
}
