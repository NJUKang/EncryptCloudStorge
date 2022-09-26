#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "matrix.h"
using namespace osuCrypto;

extern "C"
{
#include "utils.h"
}

static container *con;

void hash2code(unsigned char hash[20], char code[40])
{
    int i, j, b;
    unsigned char a, c;
    i = 0;
    for (i = 0; i < 20; i++)
    {
        a = hash[i];
        for (j = 0; j < 2; j++)
        {
            b = a / 16;
            switch (b)
            {
            case 10:
                c = 'A';
                break;
            case 11:
                c = 'B';
                break;
            case 12:
                c = 'C';
                break;
            case 13:
                c = 'D';
                break;
            case 14:
                c = 'E';
                break;
            case 15:
                c = 'F';
                break;
            default:
                c = b + 48;
                break;
            }
            code[2 * i + j] = c;
            a = a << 4;
        }
    }
}

std::string chunkToHash(struct chunk *c)
{
    char code[41];
    struct mh_sha1_ctx *ctx;
    ctx = malloc(sizeof(struct mh_sha1_ctx));
    mh_sha1_init(ctx);
    mh_sha1_update_avx2(ctx, c->data, c->size);
    mh_sha1_finalize_avx2(ctx, c->fp);
    hash2code(c->fp, code);
    code[40] = 0;
    std::string resultStr = code;
    return resultStr;
}

mpz_class chunkToBN(struct chunk *c)
{
    BitVector chunkBV((u8 *)c->data, c->size);
    std::string chunkString;
    for (u64 i = 0; i < chunkBV.size(); ++i)
    {
        chunkString += char('0' + (u8)chunkBV[i]);
    }
    mpz_class chunkBN;
    chunkBN.set_str(chunkString, 2);
    return chunkBN;
}

struct chunk *BNToChunk(mpz_class bn)
{
    BitVector bv(bn.get_str(2));
    struct chunk *newChunk = new_chunk(0);
    newChunk->size = bv.size();
    newChunk->data = malloc(sizeof(unsigned char *) * newChunk->size);
    memcpy(newChunk->data, bv.data(), newChunk->size);
    return newChunk;
}

std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> chunksDecode(std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> encodedChunks, int receivedCount, int missingCount)
{
    std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> resultChunks;

    mpq_class **decodeMatrix = inverseMatrix(vandermondeMatrix(receivedCount - missingCount, receivedCount), receivedCount);

    mpq_class receivedBN;
    for (int i = 0; i < receivedCount; i++)
    {
        receivedBN = 0;
        for (int j = 0; j < receivedCount; j++)
        {
            receivedBN += decodeMatrix[i][j] * chunkToBN(encodedChunks[j]);
        }
        mpz_class intBN = receivedBN.get_num();
        resultChunks[i] = BNToChunk(intBN);
    }

    return resultChunks;
}

void receiveChunks(Channel chl)
{
    std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> chunks;

    int missingCount = 0;
    int receivedCount = 0;
    for (int i = 0; i < CHANNEL_CHUNK_NUMBER; i++)
    {
        chunks[i] = new_chunk(0);
        chl.recv(chunks[i]->flag);
        if (!CHECK_CHUNK(chunks[i], CHUNK_FILE_END))
        {
            chl.recv(chunks[i]->fp);
            receivedCount++;

            containerid *con_id = NULL;
            if ((con_id = kvstore_lookup(chunks[i]->fp)) == NULL)
            {
                missingCount++;
                chunks[i]->size = 0;
                chunks[i]->data = NULL;
            }
            else
            {
                struct container *retrieve_con = retrieve_container_by_id(*con_id);
                chunks[i] = get_chunk_in_container(retrieve_con, &chunks[i]->fp);
                free_container(retrieve_con);
            }
        }
        else
            break;
    }

    chl.send(missingCount);

    if (missingCount == receivedCount)
    {
        for (int i = 0; i < receivedCount; i++)
        {
            chl.recv(chunks[i]->size);
            chunks[i]->data = malloc(sizeof(unsigned char) * chunks[i]->size);

            chl.recv(chunks[i]->data, chunks[i]->size);

            if (container_overflow(con, chunks[i]->size))
            {
                write_container_async(con);
                con = create_container();
            }
            add_chunk_to_container(con, chunks[i]);
            chunks[i]->id = con->meta.id;
            kvstore_update(chunks[i]->fp, chunks[i]->id);
        }
    }

    if (missingCount > 0 && missingCount < receivedCount)
    {
        std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> encodedChunks;

        int index = 0;
        for (int i = 0; i < receivedCount; i++)
        {
            if (chunks[i]->data != NULL)
            {
                encodedChunks[index] = chunks[i];
                index++;
            }
        }
        for (int i = 0; i < missingCount; i++)
        {
            struct chunk *newChunk = new_chunk(0);
            chl.recv(newChunk->size);
            newChunk->data = malloc(sizeof(unsigned char) * newChunk->size);
            chl.recv(newChunk->data, newChunk->size);
            encodedChunks[index] = newChunk;
            index++;
        }

        std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> receivedChunks = chunksDecode(encodedChunks, receivedCount, missingCount);

        int count = 0;
        for (int i = 0; i < receivedCount; i++)
        {
            if (chunks[i]->data == NULL)
            {
                chunks[i]->size = receivedChunks[receivedCount - missingCount + count]->size;
                chunks[i]->data = malloc(sizeof(unsigned char) * chunks[i]->size);
                memcpy(chunks[i]->data, receivedChunks[receivedCount - missingCount + count]->data, chunks[i]->size);

                if (container_overflow(con, chunks[i]->size))
                {
                    write_container_async(con);
                    con = create_container();
                }
                add_chunk_to_container(con, chunks[i]);
                chunks[i]->id = con->meta.id;
                kvstore_update(chunks[i]->fp, chunks[i]->id);

                count++;
            }
        }
    }

    bool FIN = 1;
    chl.send(FIN);
}

int main()
{
    IOService ios(4);

    ios.showErrorMessages(true);

    auto ip = std::string("127.0.0.1");
    auto port = 1212;

    std::string serversIpAddress = ip + ':' + std::to_string(port);

    std::string sessionHint = "cloud_storge_system";

    Session server(ios, serversIpAddress, SessionMode::Server, sessionHint);

    // Actually get the channel that can be used to communicate on.
    Channel chl = server.addChannel();
    init_container_store();
    con = create_container();
    bool SYN;
    while (1)
    {
        init_kvstore();
        chl.recv(SYN);
        if (!SYN)
            break;

        receiveChunks(chl);
        close_kvstore();
    }
    write_container_async(con);
    close_container_store();
    // close everything down in this order.
    chl.close();
    server.stop();
    ios.stop();

    return 0;
}
