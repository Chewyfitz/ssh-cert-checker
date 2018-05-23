/*
**	Aidan Fitzpatrick (835833)
**	Computer Systems Assignment 2.
**
*/

#include "certcheck.h"

int main(int argc, char *argv[]){
	// make sure the command line stuff is right
	// char *version = SSLeay_version(SSLEAY_VERSION);
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
	if(strtok(NULL, "/") == NULL){
		free(temp);
		prepath[0] = '\0';
		pre_len = 0;
	}else if(pre_len > 1){
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
	char *certfile = NULL, *domain = NULL;
	// Make a list of Certificates to check
	while(fscanf(in_file, "%s\n ", line) != EOF){
		// allocate some memory to be copied to by extract_domcert
		certfile = calloc(MAXLINELENGTH, sizeof(char));
		domain = calloc(MAXLINELENGTH, sizeof(char));

		// TODO: add pre_len to extract_domcert to check if a prepath is required.
		if(!extract_domcert(line, prepath, &certfile, &domain)){
			break;
		}

		certificate_t *cert = make_cert(certfile, domain, line);

		// Add the certificate to a linked list and check it.
		head = add_to_list(cert);
		fprintf(stdout, "Checking \"%s\" for domain \"%s\"\n", certfile, domain);
		check_cert(cert);
		fprintf(stdout, "\n");
	}

	// Write the results to file
	// write_results(results);

	free(line);
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
certificate_t *make_cert(char* certfile, char* domain, char* line){
	certificate_t *cert = malloc(sizeof(certificate_t));
	assert(cert != NULL);

	cert->line = calloc(MAXLINELENGTH, sizeof(char));
	strcpy(cert->line, line);
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

// returns 1 on success, 0 on fail
int validate_name(const char* certdomain, const char* givendomain){
	// validate from the end to the start (this allows for wildcards)
	int i;
	int len_cert, len_given;
	len_cert = strlen(certdomain);
	len_given = strlen(givendomain);

	for(i = 0; i < len_cert && i < len_given; i++){
		if(certdomain[len_cert - i] != givendomain[len_given - i]){
			if(certdomain[len_cert - i] == '*' && certdomain[len_given - i+1] == '.'){
				return 1;
			}
			return 0;
		}
	}
	if(len_cert < len_given){
		return 0;
	} else {
		return 1;
	}
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

	fprintf(stdout, "Loaded \"%s\" to check for domain \"%s\"\n", cert->certfile, cert->domain);

	// Loaded! Checking time... ===============================================

	ASN1_TIME *notBefore = X509_get_notBefore(current_cert);
	ASN1_TIME *notAfter = X509_get_notAfter(current_cert);

	int beforeDay = 0;
	int beforeSec = 0;
	// if *from or *to is NULL, uses current time
	ASN1_TIME_diff(&beforeDay, &beforeSec, notBefore, NULL);

	int afterDay = 0;
	int afterSec = 0;
	ASN1_TIME_diff(&afterDay, &afterSec, NULL, notAfter);

	int after_start_pass = 0;
	int before_end_pass = 0;
	if(beforeDay > 0 || beforeSec > 0){
		after_start_pass = 1;
	}
	if(afterDay > 0 || afterSec > 0){
		before_end_pass = 1;
	}

	fprintf(stdout, "Checking time: difference to notBefore: %d Days, %d Seconds (%d) | difference to notAfter %d Days, %d Seconds (%d)\n", beforeSec, beforeDay, after_start_pass, afterSec, afterDay, before_end_pass);

	// Checking size of key... ================================================
	// (numbytes * numbits/byte)
	int len = current_cert->cert_info->key->public_key->length *8;
	int longer_2048_pass = 0;
	if(len > 2048){
		longer_2048_pass = 1;
	}

	fprintf(stdout, "Checking size: size = %d (%d)\n", len, longer_2048_pass);

	// Checking domain name correct ===========================================
	fprintf(stdout, "Checking Domain name correct: ");
	int common_name_pass = 0;
	char *name_value_copy = calloc(strlen(current_cert->name) + 1, sizeof(char));
	strcpy(name_value_copy, current_cert->name);
	// Could extract country, state, location, organisation, and organisation unit here
	int i;
	int name_value_len = strlen(name_value_copy);
	for(i = 0; i < name_value_len && (name_value_copy[i] != 'C' || name_value_copy[i+1] != 'N'  || name_value_copy[i+2] != '='); i++){
	} // skip past what we don't need
	//CN should be at the end
	i += 3;
	name_value_len = strlen(&(name_value_copy[i]));
	char givendomain[name_value_len + 1];
	int j;
	for(j = 0; j<name_value_len && (name_value_copy[i+j] != '\n' || name_value_copy[i+j] != '\0'); j++){
		givendomain[j] = name_value_copy[ i+j ];
	}
	givendomain[name_value_len] = '\0';

	common_name_pass = validate_name(cert->domain, givendomain);

	fprintf(stdout, "(%d)\n", common_name_pass);

	// Checking constraints... ================================================
	fprintf(stdout, "Checking CA flag: ");
	int not_CA_pass = 0;
	X509_EXTENSION *ext = X509_get_ext(current_cert, X509_get_ext_by_NID(current_cert, NID_basic_constraints, -1));
	
	const struct asn1_object_st *ext_obj = X509_EXTENSION_get_object(ext);
	BUF_MEM *bio_ptr = NULL;

	char buff[1024];
	OBJ_obj2txt(buff, 1024, ext_obj, 0);

	BIO *ext_bio = BIO_new(BIO_s_mem());
	//if(!X509V3_EXT_print(ext_bio, (X509_EXTENSION *)ext_obj, 0, 0)){
	if(!X509V3_EXT_print(ext_bio, ext, 0, 0)){
		fprintf(stderr, "Error reading extensions\n");
	}
	BIO_flush(ext_bio);
	BIO_get_mem_ptr(ext_bio, &bio_ptr);

	//make it a proper string
	char *buf = calloc(bio_ptr->length + 1, sizeof(char));
	memcpy(buf, bio_ptr->data, bio_ptr->length);
	buf[bio_ptr->length] = '\0';

	// Should match exactly because of how the cert is structured.
	for(i=0; (i + 4) < bio_ptr->length; i++){
		if(buf[i] == 'F' && buf[i + 1] == 'A' && buf[i + 2] == 'L' && buf[i + 3] == 'S' && buf[i + 4] == 'E'){
			not_CA_pass = 1;
		}
	}

	fprintf(stdout, "(%d)\n", not_CA_pass);


	// *current_cert->cert_info->extensions
	// *current_cert->cert_info->extensions->stack->data
	return;
}