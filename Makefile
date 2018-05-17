CC=gcc
CFLAGS= -g -pthread -lssl -lcrypto
DEPS= 
OBJ= 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

certcheck: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f certcheck *.o