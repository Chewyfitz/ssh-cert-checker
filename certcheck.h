#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <pthread.h>
#include <semaphore.h>

// Need something bigger than the minimum requirement of 2048 bits.
#define CERT_INIT_SIZE 4096
#define MAXLINELENGTH 1000

#ifndef DEBUG
#define DEBUGPRINT(...) do{ } while ( 0 )
#else
#define DEBUGPRINT(...) (printf)(__VA_ARGS__)
#endif

typedef struct certificate_t{
	char certfile[MAXLINELENGTH];
	char domain[MAXLINELENGTH];
	char *line;
	int pass;
	struct certificate_t* next;
}certificate_t;

int extract_domcert(char *string, char *path, char **certfile, char **domain);
certificate_t *make_cert(char* certfile, char* domain, char* line);
certificate_t *add_to_list(certificate_t* cert);
void free_certs();
int validate_name(const char* certdomain, const char* givendomain);
char *get_ext_string(X509_EXTENSION *ext);
void check_cert(certificate_t *cert);