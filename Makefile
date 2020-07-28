CC=g++
PLAIN_CC=gcc
FLAGS=-O2
#INCLUDE=-Isrc/palisade/signature/include -Isrc/palisade/core/include -Isrc/cereal/include
INCLUDE=-I/usr/local/include/palisade/signature/ -I/usr/local/include/palisade/core -I/usr/local/include/palisade/ 
LIB=-L/usr/local/lib/  -L/usr/lib/ipsec/
#OBJ=signaturecontext.o main.o
OBJ=main.o chameleon_hash.o context.o test_bliss.o

all: ${OBJ}
	${CC} ${FLAGS} ${OBJ} ${LIB} -o preimage -lPALISADEcore -lPALISADEsignature -lssl -lcrypto -lstrongswan
main.o: src/main.cpp
	${CC} ${FLAGS} ${INCLUDE} -c src/main.cpp
chameleon_hash.o: src/chameleon_hash.cpp src/chameleon_hash.h
	${CC} ${FLAGS} ${INCLUDE}  -c src/chameleon_hash.cpp
context.o: src/context.cpp src/context.h
	${CC} ${FLAGS} ${INCLUDE} -c src/context.cpp
test_bliss.o: src/test_bliss.h src/test_bliss.c
	${PLAIN_CC} ${FLAGS} -Isrc/libstrongswan -include src/config.h -c src/test_bliss.c
clean:
	rm -rf preimage *.o *~
#signaturecontext.o:
#	${CC} ${FLAGS} ${INCLUDE} -c src/palisade/signature/lib/signaturecontext.cpp
