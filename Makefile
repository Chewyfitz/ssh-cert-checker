CC=gcc
CFLAGS= -lssl -lcrypto -g
DEPS= 
OBJ= certcheck.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

certcheck: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

debug: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGSS)

clean:
	rm -f certcheck debug *.o