ARCHIVE_NAME=xkozub06.tar
CPPFLAGS= -std=c++17 
LIBS=-lssl -lcrypto
PRJ=feedreader
LIBXML!=pkg-config --libs libxml-2.0
LIBXML?=$(shell pkg-config --libs libxml-2.0)
CFXML!=pkg-config --cflags libxml-2.0
CFXML?=$(shell pkg-config --cflags libxml-2.0)
STATIC_FLAGS=-static-libstdc++


all:
	g++ $(CPPFLAGS) $(STATIC_FLAGS) -o $(PRJ) $(PRJ).cpp $(LIBS) $(CFXML) $(LIBXML)

nostatic:
	g++ $(CPPFLAGS) -o $(PRJ) $(PRJ).cpp $(LIBS) $(CFXML) $(LIBXML)

test:
	./tests/test_basic.sh

clean:
	rm -f *.o $(PRJ) *.tar

tar:
	tar -cvf $(ARCHIVE_NAME) docs/* tests/* feedreader.cpp Makefile README
