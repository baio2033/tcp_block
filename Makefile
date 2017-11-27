all: tcp_block

tcp_block: tcp_block.c
	gcc -o tcp_block tcp_block.c -lpcap

clean:
	rm tcp_block

