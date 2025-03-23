CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic -D_POSIX_C_SOURCE=200809L
LDFLAGS = 

SRC_DIR = src
INC_DIR = src/include
SRC = $(SRC_DIR)/main.c \
      $(SRC_DIR)/init.c \
      $(SRC_DIR)/collector.c \
      $(SRC_DIR)/parser.c \
      $(SRC_DIR)/detector.c \
      $(SRC_DIR)/generator.c \
      $(SRC_DIR)/report.c

OBJ = $(SRC:.c=.o)

TARGET = log_analyzer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall

