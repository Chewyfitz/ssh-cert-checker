* my program was originally written with multi-threading in mind, so there are some remnants of that still in place (It's why I use a linkedlist to store the lines).
* -g and -DDEBUG shouldn't be in Makefile, but if they are that's why you're getting excess output.
* _**Important note**: if you try to run the program with a subdirectory/input.csv, it will prepend subdirectory/ to all of the cert.crt filenames in the output._
* If there is no subdirectory everything will be normal :)