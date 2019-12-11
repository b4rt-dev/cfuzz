default: all

all: Cfuzz

Cfuzz:
	gcc -o cfuzz -IIE -IPRBGEN *.c IE/*.c PRBGEN/*.c -lpcap -lm

clean:
	rm -f cfuzz
