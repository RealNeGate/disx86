#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef struct {
	u8 *data;
	u64 length;
} Slice;

int eat_space(Slice s) {
	i64 i = 0;
	while (i < (i64)s.length) {
		char c = s.data[i];
		int rem_length = ((i64)s.length - i);
		if (c == ' ' || c == '\n' || c == '\t') {
			i += 1;
		} else if (rem_length > 2 && s.data[i] == '/' && s.data[i+1] == '/') {
			i += 2;
			while (i < (i64)s.length) {
				if (s.data[i] == '\n') {
					break;
				}
				i += 1;
			}
		} else {
			break;
		}
	}

	return i;
}

Slice parse_file(char *filepath) {
	Slice fi = {};

	FILE *file = fopen(filepath, "r");
	if (!file) {
		printf("Unable to find %s\n", filepath);
		return fi;
	}

	fseek(file, 0, SEEK_END);
	i64 length = ftell(file);
	fseek(file, 0, SEEK_SET);

	u8 *binary = (u8 *)malloc(length + 1);
	i64 ret = fread(binary, 1, length, file);
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
	while (i < (i64)in_file.length) {
		Slice rem_slice = (Slice){ in_file.data + i, in_file.length - i };
		i += eat_space(rem_slice);

		if ((in_file.data + i)[0] == '\0') {
			break;
		}

		char *head = (char *)(in_file.data + i);

		int skip;
		long ret;
		if (strncmp(head, "00", 2) == 0) {
			ret = 0;
			skip = 2;
		} else {
			char *tail;
			ret = strtol(head, &tail, 16);
			if (!ret && errno) {
				printf("Failed to parse near %.*s | %s\n", 4, head, strerror(errno));
				return 1;
			}

			skip = tail - head;
		}
		i += skip;

		if (!skip) {
			break;
		}

		u8 buffer[1];
		buffer[0] = (u8)ret;
		int len = fwrite(buffer, 1, 1, out_file);
		if (!len) {
			printf("wat!\n");
			return 1;
		}
	}

	fclose(out_file);
}