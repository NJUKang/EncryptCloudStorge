#include "utils.h"

void *read_thread(char *path)
{
    static unsigned char buf[DEFAULT_BLOCK_SIZE];

    char *filename = strdup(path);
    if (path[strlen(path) - 1] == '/')
    {
        strncpy(path, filename, strlen(path));
    }
    else
    {
        int cur = strlen(filename) - 1;
        while (filename[cur] != '/')
            cur--;
        strncpy(filename, filename + cur + 1, strlen(filename) - cur);
    }

    FILE *fp;
    if ((fp = fopen(path, "r")) == NULL)
    {
        perror("The reason is");
        exit(1);
    }

    struct chunk *c = new_chunk(strlen(filename) + 1);
    strcpy(c->data, filename);

    SET_CHUNK(c, CHUNK_FILE_START);

    sync_queue_push(read_queue, c);

    int size = 0;

    while ((size = fread(buf, 1, DEFAULT_BLOCK_SIZE, fp)) != 0)
    {
        c = new_chunk(size);
        memcpy(c->data, buf, size);
        sync_queue_push(read_queue, c);
    }

    c = new_chunk(0);
    SET_CHUNK(c, CHUNK_FILE_END);
    sync_queue_push(read_queue, c);

    // printf("%d\n", sync_queue_size(read_queue));
    fclose(fp);
}

void *chunk_thread(void *arg)
{

    // fast-cdc
    chunking = fastcdc_chunk_data;
    fastcdc_init(CHUNK_AVG_SIZE);

    int leftlen = 0;
    int leftoff = 0;
    unsigned char *leftbuf = malloc(DEFAULT_BLOCK_SIZE + CHUNK_MAX_SIZE);

    unsigned char *zeros = malloc(CHUNK_MAX_SIZE);
    bzero(zeros, CHUNK_MAX_SIZE);
    unsigned char *data = malloc(CHUNK_MAX_SIZE);

    struct chunk *c = sync_queue_pop(read_queue);

    if (c == NULL)
    {
        sync_queue_term(chunk_queue);
    }

    assert(CHECK_CHUNK(c, CHUNK_FILE_START));
    sync_queue_push(chunk_queue, c);

    c = sync_queue_pop(read_queue);

    if (!CHECK_CHUNK(c, CHUNK_FILE_END))
    {
        memcpy(leftbuf, c->data, c->size);
        leftlen += c->size;
        free_chunk(c);
        c = NULL;
    }

    while (1)
    {
        while ((leftlen < CHUNK_MAX_SIZE) && c == NULL)
        {
            c = sync_queue_pop(read_queue);
            if (!CHECK_CHUNK(c, CHUNK_FILE_END))
            {
                memmove(leftbuf, leftbuf + leftoff, leftlen);
                leftoff = 0;
                memcpy(leftbuf + leftlen, c->data, c->size);
                leftlen += c->size;
                free_chunk(c);
                c = NULL;
            }
        }
        if (leftlen == 0)
        {
            assert(c);
            break;
        }

        int chunk_size = chunking(leftbuf + leftoff, leftlen);

        struct chunk *nc = new_chunk(chunk_size);
        memcpy(nc->data, leftbuf + leftoff, chunk_size);
        leftlen -= chunk_size;
        leftoff += chunk_size;

        sync_queue_push(chunk_queue, nc);
    }

    assert(CHECK_CHUNK(c, CHUNK_FILE_END));
    sync_queue_push(chunk_queue, c);

    free(leftbuf);
    free(zeros);
    free(data);
    return NULL;
}

void *hash_thread(void *arg)
{
    struct mh_sha1_ctx *ctx;

    ctx = malloc(sizeof(struct mh_sha1_ctx));
    while (1)
    {
        struct chunk *c = sync_queue_pop(chunk_queue);

        if (c == NULL)
        {
            sync_queue_term(hash_queue);
            break;
        }

        if (CHECK_CHUNK(c, CHUNK_FILE_START))
        {
            sync_queue_push(hash_queue, c);
            continue;
        }

        if (CHECK_CHUNK(c, CHUNK_FILE_END))
        {
            sync_queue_push(hash_queue, c);
            break;
        }

        mh_sha1_init(ctx);
        mh_sha1_update_avx2(ctx, c->data, c->size);
        mh_sha1_finalize_avx2(ctx, c->fp);
        
        sync_queue_push(hash_queue, c);
    }
    return NULL;
}

void *dedup_thread(void *arg)
{
    struct container *con;
    int total = 0;
    int aim = 0;
    while (1)
    {
        total++;
        struct chunk *c = sync_queue_pop(hash_queue);

        if (c == NULL)
        {
            sync_queue_term(dedup_queue);
            break;
        }

        if (CHECK_CHUNK(c, CHUNK_FILE_START))
        {
            con = create_container();
            sync_queue_push(dedup_queue, c);
            continue;
        }

        if (CHECK_CHUNK(c, CHUNK_FILE_END))
        {
            sync_queue_push(dedup_queue, c);
            write_container_async(con);
            break;
        }

        int64_t *con_id;
        if ((con_id = kvstore_lookup(c->fp)) == NULL)
        {
            if (container_overflow(con, c->size))
            {
                write_container_async(con);
                con = create_container();
            }
            add_chunk_to_container(con, c);
            c->id = con->meta.id;
            kvstore_update(c->fp, c->id);
        }
        else
        {
            struct container *retrieve_con = retrieve_container_by_id(*con_id);
            struct chunk *retrieve_c = get_chunk_in_container(retrieve_con, &c->fp);
            aim++;
        }
    }
    container_store_sync();
    return NULL;
}

char int_to_hex(int i)
{
    char *trans_string = "0123456789ABCDEF";
    return trans_string[i];
}

char *string_to_hex(char *str)
{
    int length = strlen(str);
    char *res = malloc(sizeof(char) * length * 2 + 1);
    char byte;
    unsigned char low_four, high_four;
    for (int i = 0; i < length; i++)
    {
        byte = str[i];
        high_four = (byte & 0xf0) >> 4;
        low_four = byte & 0x0f;
        res[2 * i] = int_to_hex(high_four);
        res[2 * i + 1] = int_to_hex(low_four);
    }
    res[sizeof(char) * length * 2] = '\0';
    // printf("%s\n", res);
    return res;
}

void *upload_thread(SSL *ssl)
{
    SyncQueue *wait_queue;
    wait_queue = sync_queue_new(16);
    while (1)
    {
        struct chunk *c = sync_queue_pop(hash_queue);

        if (c == NULL)
        {
            sync_queue_term(dedup_queue);
            break;
        }
        sync_queue_push(upload_queue, c);
        if (sync_queue_size(upload_queue) == 16 || CHECK_CHUNK(c, CHUNK_FILE_END))
        {
            int upload_num = sync_queue_size(upload_queue);

            if (SSL_write(ssl, &upload_num, sizeof(int)) <= 0)
            {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }
            for (int i = 0; i < upload_num; i++)
            {
                struct chunk *ss = sync_queue_pop(upload_queue);
                if (SSL_write(ssl, ss->fp, sizeof(fingerprint)) <= 0)
                {
                    ERR_print_errors_fp(stderr);
                    break;
                }
                if (SSL_write(ssl, &ss->flag, sizeof(int)) <= 0)
                {
                    ERR_print_errors_fp(stderr);
                    break;
                }
                sync_queue_push(wait_queue, ss);
            }

            int unique;
            if (SSL_read(ssl, &unique, sizeof(int)) <= 0)
            {
                ERR_print_errors_fp(stderr);
                break;
            }

            if (unique > 0)
            {
                
            }
        }
    }
    return NULL;
}

void *receive_thread(SSL *ssl)
{
    struct container *con;
    int chunk_num = 0, unique = 0;
    if ((SSL_read(ssl, &chunk_num, sizeof(int))) <= 0)
    {
        printf("Client closed connection\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    for (int i = 0; i < chunk_num; i++)
    {
        struct chunk *c = new_chunk(0);
        if ((SSL_read(ssl, c->fp, sizeof(fingerprint))) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        if ((SSL_read(ssl, &c->flag, sizeof(int))) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        if (CHECK_CHUNK(c, CHUNK_FILE_START) || CHECK_CHUNK(c, CHUNK_FILE_END))
        {
            sync_queue_push(receive_queue, c);
            continue;
        }
        int64_t *con_id;
        if ((con_id = kvstore_lookup(c->fp)) == NULL)
        {
            unique++;
            sync_queue_push(receive_queue, c);
        }
        else
        {
            struct container *retrieve_con = retrieve_container_by_id(*con_id);
            struct chunk *retrieve_c = get_chunk_in_container(retrieve_con, &c->fp);
            sync_queue_push(receive_queue, retrieve_c);
        }
    }

    if (SSL_write(ssl, &unique, sizeof(int)) <= 0)
    {
        printf("Client closed connection\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (unique > 0)
    {
    }

    return NULL;
}
