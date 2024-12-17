TARGET = httpProxy
SRCS = main.c worker.c data_parser.c proccess_http.c cache.c cache_allocator.c
CFLAGS =  -Wall -fsanitize=address  -fsanitize=undefined  -g  -fno-omit-frame-pointer
LDFLAGS = -luring
CC = gcc
all: $(TARGET)
$(TARGET) : $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)


clean:
	rm -f $(TARGET)
	rm -rf t/results
	rm -rf t/os-proxy-tests/results

rebuild: clean all


