default: all

all: Cfuzz

Cfuzz:
	gcc -o cfuzz -IIE *.c IE/*.c -lpcap

clean:
	rm -f cfuzz
