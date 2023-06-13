CC= gcc
ARGS= -Wall -O2
LIB_ARG= -fPIC
LIB_PATH= 
SRC= ./src
BUILD= ./build

default: pe_interface.o
	${CC} ${ARGS} -o peparser ${BUILD}/pe_interface.o  ${BUILD}/misc.o  ${SRC}/main.c


pe_interface.o: misc.o
	${CC} ${ARGS} -c ${SRC}/pe_interface.c -o ${BUILD}/pe_interface.o

misc.o:
	${CC} ${ARGS} -c ${SRC}/misc.c -o ${BUILD}/misc.o


# Section for making a library 
lib: pe_interface_lib misc_lib
	${CC} ${ARGS} ${LIB_ARG} -shared -o libpeparser.so -Wl,-soname,libpeparser.so ${BUILD}/pe_interface.o ${BUILD}/misc.o

pe_interface_lib: misc_lib
	${CC} ${ARGS} ${LIB_ARG} -c ${SRC}/pe_interface.c -o ${BUILD}/pe_interface.o

misc_lib:
	${CC} ${ARGS} ${LIB_ARG} -c ${SRC}/misc.c -o ${BUILD}/misc.o
####

format:
	astyle --style=allman --indent=spaces=2 ./src/*.c
	rm ./src/*.orig

clean:
	rm -rf peparser libpeparser* ${BUILD}/*.o
