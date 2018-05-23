Doube check that the -g -DDEBUG aren't in place in Makefile or you'll end up with a lot of excess output :)
Important note: if you try to run the program with a subdirectory/input.csv, it will prepend subdirectory/ to all of the cert.crt filenames in the output.
If there is no subdirectory everything will be normal :)