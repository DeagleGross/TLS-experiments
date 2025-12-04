CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared
LIBS = -lssl -lcrypto

TARGET = libdemo_native.so
SOURCES = demo_native.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
