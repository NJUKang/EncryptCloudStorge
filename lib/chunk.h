#ifndef CHUNK_H_
#define CHUNK_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TEMPORARY_ID (-1L)

#define CHUNK_UNIQUE (0x0000)

#define CHUNK_FILE_START (0x0001)

#define CHUNK_FILE_END (0x0002)

#define DEFAULT_BLOCK_SIZE 1048576 // 1MB

#define CHUNK_MAX_SIZE 65536

#define CHUNK_AVG_SIZE (8192)

#define CHUNK_MIN_SIZE 2048

#define FINGERPRINT_LENGTH 20

#define SET_CHUNK(c, f) (c->flag |= f)

#define UNSET_CHUNK(c, f) (c->flag &= ~f)

#define CHECK_CHUNK(c, f) (c->flag & f)

typedef unsigned char fingerprint[20];

struct chunk
{
	int32_t size;
	int flag;
	int64_t id;
	fingerprint fp;
	unsigned char *data;
};

struct chunk *new_chunk(int32_t);

void free_chunk(struct chunk *);

static int (*chunking)(unsigned char *buf, int size);



#endif /* CHUNK_H */
