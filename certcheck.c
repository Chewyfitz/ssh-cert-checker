/*
**	Aidan Fitzpatrick (835833)
**	Computer Systems Assignment 2.
**
*/

#include "certcheck.h"

int main(int argc, char *argv[]){
	// make sure the command line stuff is right
	if(argc < 2){
		fprintf(stderr, "not enough arguments\nusage: ./certcheck pathToTestFile\n");
		return 1;
	}

	char* filename = argv[1];

	struct certificate_t *head;

	FILE *in_file = NULL;
	fprintf(stdout, "Successfully opened file at %s\n", filename);
	if((in_file = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERR: File not found.\n");
		return 1;
	}

	char *temp = malloc(sizeof(filename));
	strcpy(temp, filename);
	char *prepath = strtok(temp, "/");
	int pre_len = strlen(prepath);
	if(pre_len > 1){
		pre_len++;

		char *temp = calloc(pre_len, sizeof(char));
		assert(temp != NULL);
		strcpy(temp, prepath);
		temp[pre_len-1] = '/';
		temp[pre_len] = '\0';

		free(prepath);
		prepath = temp;
	}	
	printf("%s\n", prepath);
	fprintf(stdout, "Successfully opened file at %s\n", filename);
	char *line = calloc(1000, sizeof(char));


	// Make a list of Certificates to check
	while(fscanf(in_file, "%s\n ", line) != EOF){
		char *certfile = strtok(line, ",");
		char *domain = strtok(NULL, ",");

		if(pre_len > 1){
			char *temp = calloc(strlen(domain) + pre_len + 2, sizeof(char));
			temp = strcat(prepath, domain);
			free(domain);
			domain = temp;
		}

		certificate_t *cert = make_cert(certfile, domain);

		// Add the certificate to a linked list and check it.
		head = add_to_list(cert);
		fprintf(stdout, "Checking \"%s\" for domain \"%s\"\n", certfile, domain);
		check_cert(cert);
	}

	// Write the results to file
	// write_results(results);

	free_certs();
	return 0;
}

// Helper functions for linked lists
certificate_t *make_cert(char* certfile, char* domain){
	certificate_t *cert = malloc(sizeof(certificate_t));
	assert(cert != NULL);

	strcpy(cert->certfile, certfile);
	strcpy(cert->domain, domain);
	return cert;
}

certificate_t *add_to_list(certificate_t* cert){
	// returns a pointer to the head of the list
	static struct certificate_t *head = NULL;
	if(cert == NULL){
		return head;
	}

	if(head == NULL){
		head = cert;
	} else {
		head->next = cert;
		head = cert;
	}
	return head;
}

void free_certs(){
	struct certificate_t *head = NULL;
	head = add_to_list(NULL);

	struct certificate_t *temp = NULL;
	while(head != NULL){
		temp = head;
		head = head->next;
		free(temp);
	}
	return;
}

// Actual checking takes place here
void check_cert(certificate_t *cert){
	BIO *certificate_bio = NULL;
	X509 *current_cert = NULL;
	X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
	STACK_OF(X509_EXTENSION) * ext_list;

	//initialise openSSL
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	//open file given by cert->certfile.


	return;
}