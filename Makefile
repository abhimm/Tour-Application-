CC = gcc
CFLAGS = -g -O2 -I/users/cse533/Stevens/unpv13e/lib
LIBS = /users/cse533/Stevens/unpv13e/libunp.a 



PROGS = abhmishra_arp abhmishra_tour

all:    ${PROGS}


abhmishra_tour: tour.o abhmishra_api.o get_hw_addrs.o
	${CC} ${FLAGS} -o abhmishra_tour tour.o abhmishra_api.o get_hw_addrs.o ${LIBS}

abhmishra_arp: abhmishra_arp.o abhmishra_api.o get_hw_addrs.o
	${CC} ${FLAGS} -o abhmishra_arp abhmishra_arp.o abhmishra_api.o get_hw_addrs.o ${LIBS} 

tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c

get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c

abhmishra_arp.o: abhmishra_arp.c
		${CC} ${CFLAGS} -c abhmishra_arp.c

abhmishra_api.o: abhmishra_api.c
		${CC} ${CFLAGS} -c abhmishra_api.c

clean:
	rm -f ${PROGS} ${CLEANFILES}



