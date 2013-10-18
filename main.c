
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>

#ifdef SODIUM
#include <sodium.h>
#else
#include <nacl/crypto_sign.h>
#endif

#include "utils.h"
#include "log.h"
#include "server.h"
#include "client.h"
#include "main.h"


gstate_t *gstate;

const char *usage =
	MAIN_NAME" filters a list of addresses for nodes that can solve a specific cryptographic challenge.\n"
	"\n"
	"Usage: "MAIN_BIN_NAME " gen\n\n"
	"  This command generates a new public/secret key pair.\n"
	"\n"
	"Usage: "MAIN_BIN_NAME" client [arguments] --public-key <key> [addresses]\n\n"
	"--port <port>		Set the port to listen for replies (Default: "DEFAULT_PORT").\n"
	"--help, -h		Show this help text.\n"
	"--ipv6,-6		IPv6 mode. Default is IPv4.\n"
	"--public-key <key>	The public text.\n"
	"--timeout <n>		Quit after n seconds (Default: 1).\n"
	"--wait			Wait for the timeout to expire.\n"
	"\n"
	"Usage: "MAIN_BIN_NAME" server [arguments] --secret-key <key>\n\n"
	"--port <port>		Set the port to listen for requests (Default: "DEFAULT_PORT").\n"
	"--help, -h		Show this help text.\n"
	"--ipv6,-6		IPv6 mode. Default is IPv4.\n"
	"--secret-key <key>	The secret key.\n"
	"--daemon		Run as daemon.\n"
	"--user <name>		Change user when starting as daemon.\n"
	"\n";

void conf_init(int is_server)
{
	gstate = (gstate_t*) calloc(sizeof(gstate_t), 1);
	gstate->af = AF_INET;
	gstate->port = DEFAULT_PORT;
	gstate->user = NULL;
	gstate->is_running = 1;
	gstate->verbosity = VERBOSITY_VERBOSE;
	gstate->is_server = is_server;

	/* Server only */
	gstate->secret_key = NULL;

	/* Client only */
	gstate->public_key = NULL;
	gstate->timeout = 1;
	gstate->wait = 0;
}

void conf_val_missing(const char* var)
{
	fprintf(stderr, "Missing value for %s\n", var);
	exit(1);
}

void conf_val_not_missing(const char* var)
{
	fprintf(stderr, "No value for %s expected\n", var);
	exit(1);
}

int conf_handle( char *var, char *val )
{
	if( match(var, "--port")) {
		if(val == NULL) {
			conf_val_missing(var);
		}
		gstate->port = strdup(val);
	} else if( match(var, "-h") || match(var, "--help") ) {
		fprintf( stdout, "%s", usage);
		exit(0);
	} else if( match(var, "-6") || match(var, "--ipv6")) {
		gstate->af = AF_INET6;
	} else if( match(var, "--verbosity")) {
		if( match( val, "quiet" ) ) {
			gstate->verbosity = VERBOSITY_QUIET;
		} else if( match( val, "verbose" ) ) {
			gstate->verbosity = VERBOSITY_VERBOSE;
		} else if( match( val, "debug" ) ) {
			gstate->verbosity = VERBOSITY_DEBUG;
		} else {
			log_err( "Invalid argument for %s.", var );
		}
	} else {
		return 1;
	}
	return 0;
}

void conf_check()
{
	/* Nothing to do */
}

int generate_keys()
{
	UCHAR pk[crypto_sign_PUBLICKEYBYTES];
	UCHAR sk[crypto_sign_SECRETKEYBYTES];
	char pkhexbuf[2*crypto_sign_PUBLICKEYBYTES+1];
	char skhexbuf[2*crypto_sign_SECRETKEYBYTES+1];

	if( crypto_sign_keypair(pk, sk) == 0) {
		fprintf(stdout, "public key: %s\n", to_hex(pkhexbuf, pk, sizeof(pk)));
		fprintf(stdout, "secret key: %s\n", to_hex(skhexbuf, sk, sizeof(sk)));
		return 0;
	} else {
		fprintf(stderr, "Failed to generate keys.");
		return 1;
	}
}

int main( int argc, char **argv )
{
	if(argc < 2) {
		fprintf(stdout, "%s", usage);
		return 1;
	} else if(match(argv[1], "gen")) {
		return generate_keys();
	} else if(match(argv[1], "client")) {
		return client(argc - 1, argv + 1);
	} else if(match(argv[1], "server")) {
		return server(argc - 1, argv + 1);
	} else {
		fprintf(stdout, "%s", usage);
		return 1;
	}
}
