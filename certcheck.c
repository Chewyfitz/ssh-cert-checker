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

	char *temp = calloc(strlen(filename) + 2, sizeof(char));
	assert(temp != NULL);
	strcpy(temp, filename);

	char *prepath = calloc(strlen(temp), sizeof(char));
	strcpy(prepath, strtok(temp, "/"));
	int pre_len = strlen(prepath);
	if(pre_len > 1){
		pre_len++;
		free(temp);
		temp = calloc(pre_len + 1, sizeof(char));
		assert(temp != NULL);
		strcpy(temp, prepath);
		temp[pre_len-1] = '/';
		temp[pre_len] = '\0';

		free(prepath);
		prepath = temp;
		temp = NULL;
	}	


	char *line = calloc(MAXLINELENGTH, sizeof(char));
	int len = 0, certfile_len = 0;
	char *certfile = NULL, *domain = NULL;
	// Make a list of Certificates to check
	while(fscanf(in_file, "%s\n ", line) != EOF){
		printf("%s\n", line);
		len = strlen(line);
		certfile = calloc(MAXLINELENGTH, sizeof(char));
		domain = calloc(MAXLINELENGTH, sizeof(char));

		if(!extract_domcert(line, prepath, &certfile, &domain)){
			break;
		}

		printf("Certfile: %s, Domain: %s\nprepath: %s\n", certfile, domain, prepath);

		len = 0;

		// len = strlen(line);
		// char *certfile_tok = strtok(line, ",");
		// char *domain_tok = strtok(NULL, ",");
		//
		// certfile_len = strlen(certfile_tok);
		//
		// char *certfile = calloc(certfile_len, sizeof(char));
		// char *domain = calloc(len - certfile_len + 1, sizeof(char));
		//
		// strcpy(certfile, certfile_tok);
		// strcpy(domain, domain_tok);
		//
		// if(pre_len > 1){
		// 	temp = calloc(strlen(certfile) + pre_len + 2, sizeof(char));
		// 	temp = strcat(prepath, certfile);
		// 	free(certfile);
		// 	certfile = temp;
		// 	temp = NULL;
		// }

		certificate_t *cert = make_cert(certfile, domain);

		// Add the certificate to a linked list and check it.
		head = add_to_list(cert);
		fprintf(stdout, "Checking \"%s\" for domain \"%s\"\n", certfile, domain);
		//check_cert(cert);
	}

<<<<<<< HEAD
	// Write the results to file
	// write_results(results);

	free(line);
=======
	// Traverse the linked list and write the results to file
	// write_results(head);
	// Free the certificate memory.
>>>>>>> 33d783ac030b941122c5d70bbd75482543ada691
	free_certs();
	return 0;
}

// Helper function for string parsing ("Extract Domain, Certificate")
int extract_domcert(char *string, char *path, char **certfile, char **domain){
	if(string == NULL){
		return 0;
	}

	char* temp_certfile = calloc(MAXLINELENGTH, sizeof(char));
	char* temp_domain = calloc(MAXLINELENGTH, sizeof(char));

	char* copy_string = calloc(strlen(string) + 1, sizeof(char));
	char* copy_path = calloc(strlen(path) + 1, sizeof(char));

	strcpy(copy_string, string);
	strcpy(copy_path, path);

	char *full_string = calloc(strlen(copy_path) + strlen(copy_string) + 1, sizeof(char));
	full_string = strcat(full_string, copy_path);
	full_string = strcat(full_string, copy_string);

	int i, commapoint = 0;
	int str_len = strlen(full_string);

	for(i=0; i < str_len; i++){
		if(commapoint == 0){
			if(full_string[i] == ','){
				commapoint = i;
				temp_certfile[i] = '\0';
				continue;
			}
			temp_certfile[i] = full_string[i];
		} else {
			temp_domain[i - commapoint - 1] = full_string[i];
		}
	}
	temp_domain[i - commapoint - 1] = '\0';

	strcpy(*certfile, temp_certfile);
	strcpy(*domain, temp_domain);

	free(temp_certfile);
	free(temp_domain);
	free(copy_string);
	free(copy_path);
	free(full_string);
	return 1;
}

// Helper functions for linked lists
certificate_t *make_cert(char* certfile, char* domain){
	// makes a list node
	certificate_t *cert = malloc(sizeof(certificate_t));
	assert(cert != NULL);

	strcpy(cert->certfile, certfile);
	strcpy(cert->domain, domain);
	return cert;
}

certificate_t *add_to_list(certificate_t* cert){
	// returns a pointer to the head of the list
	// adds a passed certificate_t to the list at the head.
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
	// Got a decent amount of this from the supplied certexample.c
	// (what did you expect?)
	BIO *certificate_bio = NULL;
	X509 *current_cert = NULL;
	X509_NAME *cert_issuer = NULL;
	X509_CINF *cert_inf = NULL;
	STACK_OF(X509_EXTENSION) * ext_list;

	//initialise openSSL
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	//create BIO object to read certificate
	certificate_bio = BIO_new(BIO_s_file());
	
	//Read certificate into BIO
	if (!(BIO_read_filename(certificate_bio, cert->certfile)))
	{
	    fprintf(stderr, "Error in reading cert BIO filename");
	    exit(EXIT_FAILURE);
	}
	if (!(current_cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
	{
	    fprintf(stderr, "Error in loading certificate");
	    exit(EXIT_FAILURE);
	}


	return;
}