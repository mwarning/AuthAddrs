
#ifndef _MAIN_H_
#define _MAIN_H_

#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "utils.h"

#define MAIN_NAME "AuthAddrs"
#define MAIN_BIN_NAME "auth_addrs"
#define DEFAULT_PORT "5292"

#define CHALLENGE_LEN 32


typedef struct {
	int af;
	const char* port;
	const char* user;
	int is_running;
	int verbosity;
	int is_daemon;
	int is_server;
	int use_syslog;

	struct sigaction sig_stop;
	struct sigaction sig_term;

	/* Server only */
	const char *secret_key;

	/* Client only */
	const char *public_key;
	int timeout;
	int wait; /* Wait for the timeout to expire */
} gstate_t;

extern gstate_t *gstate;

void conf_val_missing(const char* var);
void conf_val_not_missing(const char* var);

void conf_init(int is_server);
int conf_handle( char *var, char *val );
void conf_check();

#endif /* _MAIN_H_ */
