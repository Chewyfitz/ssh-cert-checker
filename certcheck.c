/*
**	Aidan Fitzpatrick (835833)
**	Computer Systems Assignment 2.
**  Compile with -DDEBUG if you want to see the DEBUGPRINTs :)
*/

#include "certcheck.h"

int main(int argc, char *argv[]){
	// make sure the command line stuff is right
	if(argc < 2){
		fprintf(stderr, "not enough arguments\nusage: ./certcheck pathToTestFile\n");
		return 1;
	}

	char* filename = argv[1];
	
	// Create a linked list head pointer
	struct certificate_t *head;

	// Open up the given file
	FILE *in_file = NULL;
	DEBUGPRINT("Successfully opened file at %s\n", filename);
	if((in_file = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERR: File not found.\n");
		return 1;
	}

	// copy the filename to a temp variable for messing around
	char *temp = calloc(strlen(filename) + 2, sizeof(char));
	assert(temp != NULL);
	strcpy(temp, filename);

	// create "prepath" variable. This is for handling subdirectories
	// (may only work for directories inside current)
	char *prepath = calloc(strlen(temp), sizeof(char));
	strcpy(prepath, strtok(temp, "/"));
	int pre_len = strlen(prepath);
	if(strtok(NULL, "/") == NULL){
		// if you run strtok again and it's NULL, there probably wasn't
		// a subdirectory to begin with.
		free(temp);
		prepath[0] = '\0';
		pre_len = 0;
	}else if(pre_len > 1){
		// if there is a file (ie. not a directory), we'll deal with the string
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
	} else {
		// Something went wrong
		fprintf(stderr, "Directories are not valid arguments\nusage: ./certcheck pathToTestFile\n");
		return 1;
	}


	// Time to read some lines
	char *line = calloc(MAXLINELENGTH, sizeof(char));
	char *certfile = NULL, *domain = NULL;
	while(fscanf(in_file, "%s\n ", line) != EOF){
		// allocate some memory to be copied to by extract_domcert
		certfile = calloc(MAXLINELENGTH, sizeof(char));
		domain = calloc(MAXLINELENGTH, sizeof(char));

		if(!extract_domcert(line, prepath, &certfile, &domain)){
			break;
		}

		// Make a certificate struct
		certificate_t *cert = make_cert(certfile, domain, line);

		// Add the certificate to a linked list.
		head = add_to_list(cert);
		DEBUGPRINT("Checking \"%s\" for domain \"%s\"\n", certfile, domain);

		// Check the certificate (Here comes the monster).
		check_cert(cert);
		
		DEBUGPRINT("\n");
		// this stuff isn't needed anymore, since make_cert creates its own
		// versions.
		free(certfile);
		free(domain);
	}

	// Write the results to file

	certificate_t *prev = head;
	certificate_t *current = NULL;
	if(head != NULL){
		current = head->next;
	}
	certificate_t *next = NULL;
	// first we've got to reverse the linked list
	// (I neglected the fact that it would be in reverse order)
	while(current != NULL){
		next = current->next;

		current->next = prev;
		prev = current;
		current = next;
	}
	// set the head (now the end of the LL) to NULL
	head->next = NULL;
	head = prev;

	write_results(head);

	free(line);
	free_certs(head);
	return 0;
}

// Helper function for string parsing ("Extract Domain, Certificate")
int extract_domcert(char *string, char *path, char **certfile, char **domain){
	if(string == NULL){
		return 0;
	}
	// allocate some variables to perform operations with
	char* temp_certfile = calloc(MAXLINELENGTH, sizeof(char));
	char* temp_domain = calloc(MAXLINELENGTH, sizeof(char));

	char* copy_string = calloc(strlen(string) + 1, sizeof(char));
	char* copy_path = calloc(strlen(path) + 1, sizeof(char));

	// literally copying the input arguments so we don't change them by mistake.
	strcpy(copy_string, string);
	strcpy(copy_path, path);

	/*
	*  creating "full string" as path + string. This is because if the
	*  certificates are located in a different directory we need to append the
	*  new directory to the start of the path (which, luckily, is the first
	*  input value
	*/
	char *full_string = calloc(strlen(copy_path) + strlen(copy_string) + 1, sizeof(char));
	full_string = strcat(full_string, copy_path);
	full_string = strcat(full_string, copy_string);

	// preparing some variables for a loop
	int i, commapoint = 0;
	int str_len = strlen(full_string);
	for(i=0; i < str_len; i++){
		if(commapoint == 0){
			if(full_string[i] == ','){
				// setting the point of the first comma 
				// (so we can find the domain value)
				commapoint = i;
				temp_certfile[i] = '\0';
				continue;
			}
			temp_certfile[i] = full_string[i];
		} else {
			// once commapoint has been found, start copying to temp_domain;
			temp_domain[i - commapoint - 1] = full_string[i];
		}
	}
	// put a null byte at the end of the string.
	temp_domain[i - commapoint - 1] = '\0';

	// copy the certfile location and domain to the cert struct values
	// which were passed in to the function
	strcpy(*certfile, temp_certfile);
	strcpy(*domain, temp_domain);

	// get rid of all this junk we don't need anymore.
	free(temp_certfile);
	free(temp_domain);
	free(copy_string);
	free(copy_path);
	free(full_string);
	return 1;
}

// Helper functions for linked lists ------------------------------------------
certificate_t *make_cert(char* certfile, char* domain, char* line){
	certificate_t *cert = malloc(sizeof(certificate_t));
	assert(cert != NULL);

	cert->line = calloc(MAXLINELENGTH, sizeof(char));
	strcpy(cert->line, line);
	strcpy(cert->certfile, certfile);
	strcpy(cert->domain, domain);
	cert->next = NULL;
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
		cert->next = head;
		head = cert;
	}
	return head;
}

// classic linked list traversal function
void write_results(certificate_t* head){
	certificate_t *current = head;
	FILE *fp = fopen("output.csv", "w+");

	while(current != NULL){
		fprintf(fp, "%s,%s,%d\n", current->certfile, current->domain, current->pass);
		current = current->next;
	}
}

// gotta free everything up at the end
void free_certs(certificate_t *head){

	struct certificate_t *temp = NULL;
	while(head != NULL){
		temp = head;
		head = head->next;
		free(temp->line);
		free(temp);
	}
	return;
}

// Actual checking takes place here
void check_cert(certificate_t *cert){
	// This function is a monster.
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

	DEBUGPRINT("Loaded \"%s\" to check for domain \"%s\"\n", cert->certfile, cert->domain);

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
	if(beforeDay > 0 && beforeSec > 0){
		after_start_pass = 1;
	}
	if(afterDay > 0 && afterSec > 0){
		before_end_pass = 1;
	}

	DEBUGPRINT("Checking time: difference to notBefore: %d Days, %d Seconds (%d)\n", beforeSec, beforeDay, after_start_pass);
	DEBUGPRINT("Checking time: difference to notAfter:  %d Days, %d Seconds (%d)\n", afterSec, afterDay, before_end_pass);

	// Checking size of key... ================================================
	// (numbytes * numbits/byte)
	int len = current_cert->cert_info->key->public_key->length *8;
	int longer_2048_pass = 0;
	if(len > 2048){
		longer_2048_pass = 1;
	}

	DEBUGPRINT("Checking size: size = %d (%d)\n", len, longer_2048_pass);

	// Checking domain name correct ===========================================
	DEBUGPRINT("Checking Domain name correct: ");

	int common_name_pass = 0;
	char *name_value_copy = calloc(strlen(current_cert->name) + 1, sizeof(char));
	strcpy(name_value_copy, current_cert->name);
	// Could extract country, state, location, organisation, and organisation unit here
	int i;
	int name_value_len = strlen(name_value_copy);
	for(i = 0; i < name_value_len && (name_value_copy[i] != 'C' || name_value_copy[i+1] != 'N'  || name_value_copy[i+2] != '='); i++){
	} // skip past what we don't need
	//CN is at the end
	i += 3;
	name_value_len = strlen(&(name_value_copy[i]));
	char givendomain[name_value_len + 1];
	int j;
	for(j = 0; j<name_value_len && (name_value_copy[i+j] != '\n' || name_value_copy[i+j] != '\0'); j++){
		givendomain[j] = name_value_copy[ i+j ];
	}
	givendomain[name_value_len] = '\0';

	common_name_pass = validate_name(cert->domain, givendomain);

	DEBUGPRINT("(%d)\n", common_name_pass);

	// Checking constraints... ================================================
	int not_CA_pass = 0;
	int ext_key_client_auth_pass = 0;

	X509_EXTENSION *ext = X509_get_ext(current_cert, X509_get_ext_by_NID(current_cert, NID_basic_constraints, -1));

	char* buf = NULL;
	buf = get_ext_string(ext);

	DEBUGPRINT("Checking CA flag: ");

	if(strstr(buf, "CA:FALSE") != NULL){
		not_CA_pass = 1;
	}
	free(buf);
	buf = NULL;

	DEBUGPRINT("(%d)\n", not_CA_pass);
	ext = X509_get_ext(current_cert, X509_get_ext_by_NID(current_cert, NID_ext_key_usage, -1));

	buf = get_ext_string(ext);
	
	DEBUGPRINT("Checking Extended Key Usage: ");

	if(strstr(buf, "TLS Web Server Authentication") != NULL){
		ext_key_client_auth_pass = 1;
	}
	free(buf);
	buf = NULL;

	DEBUGPRINT("(%d)\n", ext_key_client_auth_pass);

	// What's that, your certificate didn't sign that name? ===================
	// Well did they sign... ==================================================
	if(common_name_pass != 1){
		ext = X509_get_ext(current_cert, X509_get_ext_by_NID(current_cert, NID_subject_alt_name, -1));

		buf = get_ext_string(ext);
		if(buf != NULL){
			DEBUGPRINT("Checking Subject Alternative Name: ");

			DEBUGPRINT("\nbuf: %s ", buf);
			char* alt_name_pointer;
			int i = 0;

			// Check all the alternate names

			char *string = strtok(buf, ",");
			for(i = 0; string[i] != ':'; i++);
			DEBUGPRINT("%d |", i+1);
			string = string + i + 1;
			DEBUGPRINT("%s\n", string);
			common_name_pass = validate_name(cert->domain, string);
			while((string = strtok(NULL, ",")) != NULL && common_name_pass != 1){
				for(i = 0; string[i] != ':'; i++);
				DEBUGPRINT("%d |", i+1);
				string = string + i + 1;
				DEBUGPRINT("%s\n", string);
				common_name_pass = validate_name(cert->domain, string);
			}
			free(buf);
			buf = NULL;
			DEBUGPRINT("(%d)\n", common_name_pass);
		}
	}

	DEBUGPRINT("Results: (%d, %d, %d, %d, %d, %d)", after_start_pass, before_end_pass, longer_2048_pass, common_name_pass, not_CA_pass, ext_key_client_auth_pass);
	
	// if ANY of the tests failed, the certificate failed =====================
	if(after_start_pass == 1 
		&& before_end_pass == 1 
		&& longer_2048_pass == 1 
		&& common_name_pass == 1 
		&& not_CA_pass == 1 
		&& ext_key_client_auth_pass == 1){

		// store the pass status in the certificate_t struct
		cert->pass = 1;
	} else {
		cert->pass = 0;
	}

	DEBUGPRINT("Pass? (%d)\n\n", cert->pass);

	// free the stuff that needs to be freed
	X509_free(current_cert);
	BIO_free_all(certificate_bio);
	free(name_value_copy);
	return;
}

// Helper functions for check_cert --------------------------------------------

// Validate a givendomain against a certdomain (the one on the cert)
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
				DEBUGPRINT("Wildcard Success\n");
				return 1;
			}
			DEBUGPRINT("Wildcard Failure\n");
			return 0;
		}
	}
	if(len_cert < len_given){
		DEBUGPRINT("Match Failure\n");
		return 0;
	} else {
		DEBUGPRINT("Match SUCCESS\n");
		return 1;
	}
}

// returns a pointer to a string which NEEDS TO BE FREED
char *get_ext_string(X509_EXTENSION *ext){
	if(ext == NULL){
		return NULL;
	}
	const struct asn1_object_st *ext_obj = X509_EXTENSION_get_object(ext);
	BUF_MEM *bio_ptr = NULL;

	// abusing MAXLINELENGTH a bit here, but it's the same number...
	char* buff = calloc(MAXLINELENGTH, sizeof(char));
	assert(buff != NULL);
	OBJ_obj2txt(buff, MAXLINELENGTH, ext_obj, 0);

	BIO *ext_bio = BIO_new(BIO_s_mem());

	// Read the extension and get the string
	if(!X509V3_EXT_print(ext_bio, ext, 0, 0)){
		fprintf(stderr, "Error reading extensions\n");
	}
	BIO_flush(ext_bio);
	BIO_get_mem_ptr(ext_bio, &bio_ptr);

	//make it a proper string
	char *buf = calloc(bio_ptr->length + 1, sizeof(char));
	memcpy(buf, bio_ptr->data, bio_ptr->length);
	buf[bio_ptr->length] = '\0';

    BIO_free_all(ext_bio);

	free(buff);
	return buf;
}