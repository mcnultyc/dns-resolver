TARGETS=hw3

hw3: resolve.c
	gcc -g -o hw3 resolve.c

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

