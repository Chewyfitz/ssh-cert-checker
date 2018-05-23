CC=gcc
CFLAGS= -g -lssl -lcrypto
DEBUG = -DDEBUG=1
DEPS= 
OBJ= certcheck.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

certcheck: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

debug: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(DEBUG)

clean:
	rm -f certcheck debug *.o