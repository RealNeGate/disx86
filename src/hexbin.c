#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

typedef struct {
	uint8_t *data;
	uint64_t length;
} Slice;

Slice parse_file(char *filepath) {
	Slice fi = {};

	int fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		printf("Unable to find %s\n", filepath);
		return fi;
	}

	int64_t length = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	uint8_t *binary = (uint8_t *)malloc(length + 1);
	int64_t ret = read(fd, binary, length);
	if (length != ret) {
		free(binary);
		printf("Failed to read!\n");
		return fi;
	}
	binary[length] = 0;
	close(fd);

	fi.data = binary;
	fi.length = length;
	return fi;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		printf("Expected %s <filename in> <filename out>\n", argv[0]);
		return 1;
	}

	Slice in_file = parse_file(argv[1]);
	int out_file = open(argv[2], O_RDWR | O_CREAT, 0644);
	if (errno) {
		printf("%s: %s\n", strerror(errno), argv[2]);
		return 1;
	}

	int i = 0;
	int old_i = 0;
	while (i < in_file.length) {
		char *head = (char *)(in_file.data + i);
		char *tail;
		long ret = strtol(head, &tail, 16);
		if (!ret && errno) {
			printf("Failed to parse near %.*s | %s\n", 4, head, strerror(errno));
			return 2;
		}

		// This kills the loop when there's nothing left to read
		i += tail - head;
		if (old_i == i) {
			break;
		}
		old_i = i;

		uint8_t buffer[1];
		buffer[0] = (uint8_t)ret;
		int len = write(out_file, buffer, 1);
		if (!len) {
			printf("wat!\n");
			return 3;
		}
	}

	close(out_file);
}
