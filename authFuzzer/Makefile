default: all

all: Cfuzz

Cfuzz:
	gcc -o cfuzz -IIE -IAUTHGEN *.c IE/*.c AUTHGEN/*.c -lpcap -lm

clean:
	rm -f cfuzz
