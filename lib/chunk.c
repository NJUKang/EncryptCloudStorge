#include "chunk.h"
#include "chunking/chunking.h"


struct chunk* new_chunk(int32_t size) {
	struct chunk* ck = (struct chunk*) malloc(sizeof(struct chunk));

	ck->flag = CHUNK_UNIQUE;
	ck->id = TEMPORARY_ID;
	memset(&ck->fp, 0x0, 20);
	ck->size = size;

	if (size > 0)
		ck->data = malloc(size);
	else
		ck->data = NULL;

	return ck;
}

void free_chunk(struct chunk* ck) {
	if (ck->data) {
		free(ck->data);
		ck->data = NULL;
	}
	free(ck);
}