#ifndef UTILS_H_
#define UTILS_H_
#include <assert.h>
#include <pthread.h>
#include <mh_sha1.h>
#include <glib.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "chunk.h"
#include "chunking/chunking.h"
#include "sync_queue.h"
#include "containerstore.h"
#include "kvstore.h"

#define CHANNEL_CHUNK_NUMBER 16

SyncQueue *read_queue;

SyncQueue *chunk_queue;

SyncQueue *hash_queue;

SyncQueue *dedup_queue;

SyncQueue *upload_queue;

SyncQueue *receive_queue;

void *read_thread(char *path);

void *chunk_thread(void *arg);

void *hash_thread(void *arg);

void *dedup_thread(void *arg);

void *upload_thread(SSL *ssl);

void *receive_thread(SSL *ssl);
#endif