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

typedef struct certificate_t{
	char certfile[100];
	char domain[100];
	int pass;
	struct certificate_t* next;
}certificate_t;

certificate_t *make_cert(char* certfile, char* domain);
certificate_t *add_to_list(certificate_t* cert);
void free_certs();
void check_cert(certificate_t *cert);