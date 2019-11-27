default: all

all: Cfuzz

Cfuzz:
	gcc -o cfuzz -IIE *.c IE/*.c -lpcap -lm

clean:
	rm -f cfuzz
