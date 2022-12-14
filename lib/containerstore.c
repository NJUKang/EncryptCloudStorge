#include "containerstore.h"

#include <unistd.h>

static int64_t container_count = 0;
static FILE *fp;
/* Control the concurrent accesses to fp. */
static pthread_mutex_t mutex;

static pthread_t append_t;

static SyncQueue *container_buffer;

struct metaEntry
{
	int32_t off;
	int32_t len;
	fingerprint fp;
};

/*
 * We must ensure a container is either in the buffer or written to disks.
 */
static void *append_thread(void *arg)
{

	while (1)
	{
		struct container *c = sync_queue_get_top(container_buffer);
		if (c == NULL)
			break;

		write_container(c);

		sync_queue_pop(container_buffer);

		free_container(c);
	}

	return NULL;
}

void init_container_store()
{
	char *containerfile = "/home/kid/CODE/EncryptCloudStorge/kvstore/container.pool";

	if ((fp = fopen(containerfile, "r+")))
	{
		fread(&container_count, 8, 1, fp);
	}
	else if (!(fp = fopen(containerfile, "w+")))
	{
		perror(
			"Can not create container.pool for read and write because");
		exit(1);
	}

	container_buffer = sync_queue_new(25);

	pthread_mutex_init(&mutex, NULL);

	pthread_create(&append_t, NULL, append_thread, NULL);
}

void container_store_sync()
{
	fdatasync(fileno(fp));
}

void close_container_store()
{
	sync_queue_term(container_buffer);

	pthread_join(append_t, NULL);

	fseek(fp, 0, SEEK_SET);
	fwrite(&container_count, sizeof(container_count), 1, fp);

	fclose(fp);
	fp = NULL;

	pthread_mutex_destroy(&mutex);
}

gboolean g_fingerprint_equal(fingerprint *fp1, fingerprint *fp2)
{
	return !memcmp(fp1, fp2, sizeof(fingerprint));
}

static void init_container_meta(struct containerMeta *meta)
{
	meta->chunk_num = 0;
	meta->data_size = 0;
	meta->id = TEMPORARY_ID;
	meta->map = g_hash_table_new_full(g_int_hash, (void *)g_fingerprint_equal, NULL,
									  free);
}

/*
 * For backup.
 */
struct container *create_container()
{
	struct container *c = (struct container *)malloc(sizeof(struct container));

	c->data = calloc(1, CONTAINER_SIZE);

	init_container_meta(&c->meta);
	c->meta.id = container_count++;
	return c;
}

inline containerid get_container_id(struct container *c)
{
	return c->meta.id;
}

void write_container_async(struct container *c)
{
	assert(c->meta.chunk_num == g_hash_table_size(c->meta.map));

	if (container_empty(c))
	{
		/* An empty container
		 * It possibly occurs in the end of backup */
		container_count--;
		return;
	}

	sync_queue_push(container_buffer, c);
}

/*
 * Called by Append phase
 */
void write_container(struct container *c)
{

	assert(c->meta.chunk_num == g_hash_table_size(c->meta.map));

	if (container_empty(c))
	{
		/* An empty container
		 * It possibly occurs in the end of backup */
		container_count--;
		return;
	}

	unsigned char *cur = &c->data[CONTAINER_SIZE - CONTAINER_META_SIZE];
	ser_declare;
	ser_begin(cur, CONTAINER_META_SIZE);
	ser_int64(c->meta.id);
	ser_int32(c->meta.chunk_num);
	ser_int32(c->meta.data_size);

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, c->meta.map);
	while (g_hash_table_iter_next(&iter, &key, &value))
	{
		struct metaEntry *me = (struct metaEntry *)value;
		ser_bytes(&me->fp, sizeof(fingerprint));
		ser_bytes(&me->len, sizeof(int32_t));
		ser_bytes(&me->off, sizeof(int32_t));
	}

	ser_end(cur, CONTAINER_META_SIZE);

	pthread_mutex_lock(&mutex);

	if (fseek(fp, c->meta.id * CONTAINER_SIZE + 8, SEEK_SET) != 0)
	{
		perror("Fail seek in container store.");
		exit(1);
	}
	if (fwrite(c->data, CONTAINER_SIZE, 1, fp) != 1)
	{
		perror("Fail to write a container in container store.");
		exit(1);
	}

	pthread_mutex_unlock(&mutex);
}

struct container *retrieve_container_by_id(containerid id)
{
	struct container *c = (struct container *)malloc(sizeof(struct container));

	init_container_meta(&c->meta);

	unsigned char *cur = 0;

	c->data = malloc(CONTAINER_SIZE);

	pthread_mutex_lock(&mutex);

	fseek(fp, id * CONTAINER_SIZE + 8, SEEK_SET);
	fread(c->data, CONTAINER_SIZE, 1, fp);

	pthread_mutex_unlock(&mutex);

	cur = &c->data[CONTAINER_SIZE - CONTAINER_META_SIZE];

	unser_declare;
	unser_begin(cur, CONTAINER_META_SIZE);

	unser_int64(c->meta.id);
	unser_int32(c->meta.chunk_num);
	unser_int32(c->meta.data_size);

	if (c->meta.id != id)
	{
		assert(c->meta.id == id);
	}

	int i;
	for (i = 0; i < c->meta.chunk_num; i++)
	{
		struct metaEntry *me = (struct metaEntry *)malloc(
			sizeof(struct metaEntry));
		unser_bytes(&me->fp, sizeof(fingerprint));
		unser_bytes(&me->len, sizeof(int32_t));
		unser_bytes(&me->off, sizeof(int32_t));
		g_hash_table_insert(c->meta.map, &me->fp, me);
	}

	unser_end(cur, CONTAINER_META_SIZE);

	return c;
}

static struct containerMeta *container_meta_duplicate(struct container *c)
{
	struct containerMeta *base = &c->meta;
	struct containerMeta *dup = (struct containerMeta *)malloc(
		sizeof(struct containerMeta));
	init_container_meta(dup);
	dup->id = base->id;
	dup->chunk_num = base->chunk_num;
	dup->data_size = base->data_size;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, base->map);
	while (g_hash_table_iter_next(&iter, &key, &value))
	{
		struct metaEntry *me = (struct metaEntry *)malloc(
			sizeof(struct metaEntry));
		memcpy(me, value, sizeof(struct metaEntry));
		g_hash_table_insert(dup->map, &me->fp, me);
	}

	return dup;
}

struct containerMeta *retrieve_container_meta_by_id(containerid id)
{
	struct containerMeta *cm = NULL;

	/* First, we find it in the buffer */
	cm = sync_queue_find(container_buffer, (void *)container_check_id, &id,
						 (void *)container_meta_duplicate);

	if (cm)
		return cm;

	cm = (struct containerMeta *)malloc(sizeof(struct containerMeta));
	init_container_meta(cm);

	unsigned char buf[CONTAINER_META_SIZE];

	pthread_mutex_lock(&mutex);

	fseek(fp, (id + 1) * CONTAINER_SIZE - CONTAINER_META_SIZE + 8, SEEK_SET);

	fread(buf, CONTAINER_META_SIZE, 1, fp);

	pthread_mutex_unlock(&mutex);

	unser_declare;
	unser_begin(buf, CONTAINER_META_SIZE);

	unser_int64(cm->id);
	unser_int32(cm->chunk_num);
	unser_int32(cm->data_size);

	if (cm->id != id)
	{
		assert(cm->id == id);
	}

	int i;
	for (i = 0; i < cm->chunk_num; i++)
	{
		struct metaEntry *me = (struct metaEntry *)malloc(
			sizeof(struct metaEntry));
		unser_bytes(&me->fp, sizeof(fingerprint));
		unser_bytes(&me->len, sizeof(int32_t));
		unser_bytes(&me->off, sizeof(int32_t));
		g_hash_table_insert(cm->map, &me->fp, me);
	}

	return cm;
}

static struct metaEntry *get_metaentry_in_container_meta(
	struct containerMeta *cm, fingerprint *fp)
{
	return g_hash_table_lookup(cm->map, fp);
}

struct chunk *get_chunk_in_container(struct container *c, fingerprint *fp)
{
	struct metaEntry *me = get_metaentry_in_container_meta(&c->meta, fp);

	assert(me);

	struct chunk *ck = new_chunk(me->len);

	memcpy(ck->data, c->data + me->off, me->len);

	ck->size = me->len;
	ck->id = c->meta.id;
	memcpy(&ck->fp, &fp, sizeof(fingerprint));

	return ck;
}

int container_overflow(struct container *c, int32_t size)
{
	if (c->meta.data_size + size > CONTAINER_SIZE - CONTAINER_META_SIZE)
		return 1;
	/*
	 * 28 is the size of metaEntry.
	 */
	if ((c->meta.chunk_num + 1) * 28 + 16 > CONTAINER_META_SIZE)
		return 1;
	return 0;
}

/*
 * For backup.
 * return 1 indicates success.
 * return 0 indicates fail.
 */
int add_chunk_to_container(struct container *c, struct chunk *ck)
{
	assert(!container_overflow(c, ck->size));
	if (g_hash_table_contains(c->meta.map, &ck->fp))
	{
		ck->id = c->meta.id;
		return 0;
	}

	struct metaEntry *me = (struct metaEntry *)malloc(sizeof(struct metaEntry));
	memcpy(&me->fp, &ck->fp, sizeof(fingerprint));
	me->len = ck->size;
	me->off = c->meta.data_size;

	g_hash_table_insert(c->meta.map, &me->fp, me);
	c->meta.chunk_num++;

	memcpy(c->data + c->meta.data_size, ck->data, ck->size);

	c->meta.data_size += ck->size;

	ck->id = c->meta.id;

	return 1;
}

void free_container_meta(struct containerMeta *cm)
{
	g_hash_table_destroy(cm->map);
	free(cm);
}

void free_container(struct container *c)
{
	g_hash_table_destroy(c->meta.map);
	if (c->data)
		free(c->data);
	free(c);
}

int container_empty(struct container *c)
{
	return c->meta.chunk_num == 0 ? 1 : 0;
}

/*
 * Return 0 if doesn't exist.
 */
int lookup_fingerprint_in_container_meta(struct containerMeta *cm,
										 fingerprint *fp)
{
	return g_hash_table_lookup(cm->map, fp) == NULL ? 0 : 1;
}

int lookup_fingerprint_in_container(struct container *c, fingerprint *fp)
{
	return lookup_fingerprint_in_container_meta(&c->meta, fp);
}

gint g_container_cmp_desc(struct container *c1, struct container *c2,
						  gpointer user_data)
{
	return g_container_meta_cmp_desc(&c1->meta, &c2->meta, user_data);
}

gint g_container_meta_cmp_desc(struct containerMeta *cm1,
							   struct containerMeta *cm2, gpointer user_data)
{
	return cm2->id - cm1->id;
}

int container_check_id(struct container *c, containerid *id)
{
	return container_meta_check_id(&c->meta, id);
}

int container_meta_check_id(struct containerMeta *cm, containerid *id)
{
	return cm->id == *id ? 1 : 0;
}

/*
 * foreach the fingerprints in the container.
 * Apply the 'func' for each fingerprint.
 */
void container_meta_foreach(struct containerMeta *cm, void (*func)(fingerprint *, void *), void *data)
{
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, cm->map);
	while (g_hash_table_iter_next(&iter, &key, &value))
	{
		func(key, data);
	}
}
