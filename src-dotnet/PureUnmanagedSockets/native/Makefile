# Makefile for OpenSSL native wrapper

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -pthread
LDFLAGS = -shared
LIBS = -lssl -lcrypto -lpthread

TARGET = libopenssl_native.so
SOURCES = openssl_native.c nginx_server.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

openssl_native.o: openssl_native.c openssl_native.h
	$(CC) $(CFLAGS) -c $< -o $@

nginx_server.o: nginx_server.c nginx_server.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) ../bin/Debug/net10.0/

.PHONY: install

