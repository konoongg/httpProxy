TARGET_SAN = httpProxy_with_san
TARGET = httpProxy
SRCS = main.c worker.c data_parser.c proccess_http.c cache.c cache_allocator.c
CFLAGS = -Wall -g -fno-omit-frame-pointer
SANFLAGS = -fsanitize=address -fsanitize=undefined
LDFLAGS = -luring
CC = gcc

# Цель по умолчанию
all: $(TARGET_SAN) $(TARGET)

# Правило для сборки с флагами санитайзеров
$(TARGET_SAN): $(SRCS)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(TARGET_SAN) $(SRCS) $(LDFLAGS)

# Правило для обычной сборки
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

# Очистка
clean:
	rm -f $(TARGET) $(TARGET_SAN)
	rm -rf t/results
	rm -rf t/os-proxy-tests/results

# Пересборка
rebuild: clean all