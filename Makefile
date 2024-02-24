all:
	gcc -o my_program zenity.c `pkg-config --cflags --libs gtk+-3.0` -Wall
clean:
	rm -f my_program
