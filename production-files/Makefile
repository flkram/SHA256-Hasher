# Compiler and compiler flags
CC = gcc
CFLAGS = -Wall -std=c99 -g

# File List
SOURCES = hash.c sha256.c sha256constants.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = hash

# Default target
all: $(EXECUTABLE) sha256test

# Linking for hash
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

# Compilation rules
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compilation and linking for sha256test
sha256test: sha256test.c sha256.c sha256constants.c
	$(CC) $(CFLAGS) $^ -o $@

# Clean rule
clean:
	rm -f $(OBJECTS) $(EXECUTABLE) sha256test
