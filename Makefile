CC=gcc
CFLAGS= -g -pthread -lssl -lcrypto
DEPS= 
OBJ= 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cert: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f cert *.o