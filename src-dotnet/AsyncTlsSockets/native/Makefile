# Makefile for nginx_tls native library

CC = gcc
CFLAGS = -Wall -Wextra -O3 -fPIC -std=c11
LDFLAGS = -shared
LIBS = -lssl -lcrypto

# Output
TARGET = libnginx_tls.so
SRCS = nginx_tls.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c nginx_tls.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	ldconfig

# For testing, copy to project directory
install-local: $(TARGET)
	cp $(TARGET) ../bin/Debug/net9.0/

.PHONY: all clean install install-local
