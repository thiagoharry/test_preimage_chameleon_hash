CC=g++
FLAGS=-O2
#INCLUDE=-Isrc/palisade/signature/include -Isrc/palisade/core/include -Isrc/cereal/include
INCLUDE=-I/usr/local/include/palisade/signature/ -I/usr/local/include/palisade/core -I/usr/local/include/palisade/
LIB=-L/usr/local/lib/ -L/usr/lib/x86_64-linux-gnu/
#OBJ=signaturecontext.o main.o
OBJ=main.o chameleon_hash.o context.o

all: ${OBJ}
	${CC} ${FLAGS} ${OBJ} -o preimage -lPALISADEcore -lPALISADEsignature -lssl -lcrypto
main.o: src/main.cpp
	${CC} ${FLAGS} ${INCLUDE} -c src/main.cpp
chameleon_hash.o: src/chameleon_hash.cpp src/chameleon_hash.h
	${CC} ${FLAGS} ${INCLUDE}  -c src/chameleon_hash.cpp
context.o: src/context.cpp src/context.h
	${CC} ${FLAGS} ${INCLUDE} -c src/context.cpp

clean:
	rm -rf preimage *.o *~
#signaturecontext.o:
#	${CC} ${FLAGS} ${INCLUDE} -c src/palisade/signature/lib/signaturecontext.cpp
