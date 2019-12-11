default: all

all: Cfuzz

Cfuzz:
	gcc -o cfuzz -IIE -IASSGEN *.c IE/*.c ASSGEN/*.c -lpcap -lm

clean:
	rm -f cfuzz
