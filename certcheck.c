/*
**	Aidan Fitzpatrick (835833)
**	Computer Systems Assignment 2.
**
*/

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]){
	// make sure the command line stuff is right
	if(argc < 2){
		fprintf(stderr, "not enough arguments\nusage: ./certcheck pathToTestFile\n");
		return 1;
	}

	char* filename = argv[1];

	FILE *in_file = NULL;

	if((in_file = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERR: File not found.\n");
		return 1;
	}
	fprintf(stdout, "Successfully opened file at %s\n", filename);


	return 0;
}