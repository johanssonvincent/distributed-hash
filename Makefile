CFLAGS = -g -std=gnu11 -Wall -Wextra
DEPS = node.h hashtable.h

%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS)

node: node.o hashtable.o
	gcc -o $@ $^ $(CFLAGS)
