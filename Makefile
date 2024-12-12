TARGET = httpProxy
SRCS = main.c worker.c data_parser.c proccess_http.c
CFLAGS =  -Wall -fsanitize=address  -fsanitize=undefined  -g  -fno-omit-frame-pointer
LDFLAGS = -luring
CC = gcc
all: $(TARGET)
$(TARGET) : $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)


clean:
	rm -f $(TARGET)

rebuild: clean all


