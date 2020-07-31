CC=g++
PLAIN_CC=gcc
FLAGS=-O2
INCLUDE=-I/usr/local/include/palisade/signature/ -I/usr/local/include/palisade/core -I/usr/local/include/palisade/ 
LIB=-L/usr/local/lib/  -L/usr/lib/ipsec/
OBJ=main.o chameleon_hash.o context.o test_bliss.o test_dilithium.o test_falcon.o
DILITHIUM_SRC=$(shell find src/dilithium/ -name "*.c")
DILITHIUM_OBJ=$(DILITHIUM_SRC:src/dilithium/%.c=%.o)
FALCON_SRC=$(shell find src/falcon/ -name "*.c")
FALCON_OBJ=$(FALCON_SRC:src/falcon/%.c=%.o)

all: ${OBJ} $(DILITHIUM_OBJ) $(FALCON_OBJ)
	${CC} ${FLAGS} ${OBJ} $(DILITHIUM_OBJ) $(FALCON_OBJ) ${LIB} -o preimage -lPALISADEcore -lPALISADEsignature -lssl -lcrypto -lstrongswan
main.o: src/main.cpp
	${CC} ${FLAGS} ${INCLUDE} -c src/main.cpp
chameleon_hash.o: src/chameleon_hash.cpp src/chameleon_hash.h
	${CC} ${FLAGS} ${INCLUDE}  -c src/chameleon_hash.cpp
context.o: src/context.cpp src/context.h
	${CC} ${FLAGS} ${INCLUDE} -c src/context.cpp
test_bliss.o: src/test_bliss.h src/test_bliss.c
	${PLAIN_CC} ${FLAGS} -Isrc/libstrongswan -include src/config.h -c src/test_bliss.c
test_dilithium.o: src/test_dilithium.c src/test_dilithium.h
	${PLAIN_CC} ${FLAGS} -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES -c src/test_dilithium.c
test_falcon.o: src/test_falcon.c src/test_falcon.h
	${PLAIN_CC} ${FLAGS} -c src/test_falcon.c
.SECONDEXPANSION:
$(DILITHIUM_OBJ): $$(patsubst %.o,src/dilithium/%.c,$$@)
	${PLAIN_CC} ${FLAGS} -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES  -c $<
$(FALCON_OBJ): $$(patsubst %.o,src/falcon/%.c,$$@)
	${PLAIN_CC} ${FLAGS} -c $<
clean:
	rm -rf preimage *.o *~
#signaturecontext.o:
#	${CC} ${FLAGS} ${INCLUDE} -c src/palisade/signature/lib/signaturecontext.cpp
