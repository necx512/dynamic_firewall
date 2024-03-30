all:
	gcc -g3 -ggdb -Wall -lmnl -lnetfilter_queue -o nf-queue main.c cache.c  dns_handle.c
test:
	gcc -DTEST -g3 -ggdb -Wall -lmnl -lnetfilter_queue -o test cache.c
clean:
	rm -f nf-queue *.o test
