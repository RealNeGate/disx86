#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

typedef struct {
	uint8_t *data;
	uint64_t length;
} Slice;

Slice parse_file(char *filepath) {
	Slice fi = {};

	FILE *file = fopen(filepath, "r");
	if (!file) {
		printf("Unable to find %s\n", filepath);
		return fi;
	}

	fseek(file, 0, SEEK_END);
	int64_t length = ftell(file);
	fseek(file, 0, SEEK_SET);

	uint8_t *binary = (uint8_t *)malloc(length + 1);
	int64_t ret = fread(binary, 1, length, file);
	if (length != ret) {
		free(binary);
		printf("Failed to open %s!\n", filepath);
		return fi;
	}
	binary[length] = 0;
	fclose(file);

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
	if (!in_file.data) {
		printf("Failed to load %s\n", argv[1]);
		return 1;
	}
	FILE *out_file = fopen(argv[2], "w+");
	if (!out_file) {
		printf("failed to open %s\n", argv[2]);
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
			return 1;
		}

		// This kills the loop when there's nothing left to read
		i += tail - head;
		if (old_i == i) {
			break;
		}
		old_i = i;

		uint8_t buffer[1];
		buffer[0] = (uint8_t)ret;
		int len = fwrite(buffer, 1, 1, out_file);
		if (!len) {
			printf("wat!\n");
			return 1;
		}
	}

	fclose(out_file);
}
