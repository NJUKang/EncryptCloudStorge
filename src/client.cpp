#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/BitVector.h>

#include <stack>
#include <string>
#include <gmpxx.h>

using namespace osuCrypto;

extern "C"
{
#include "utils.h"
}

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
    ctx = (struct mh_sha1_ctx *)malloc(sizeof(struct mh_sha1_ctx));
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
    newChunk->data = (unsigned char*)malloc(sizeof(unsigned char *) * newChunk->size);
    memcpy(newChunk->data, bv.data(), newChunk->size);
    return newChunk;
}

std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> chunksEncode(std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> chunks, int originalSize, int targetSize)
{
    std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> resultChunks;
    for (int i = 0; i < targetSize; i++)
    {
        mpz_class chunkBN = chunkToBN(chunks[0]);
        mpz_class encodedBN = chunkBN;
        for (int j = 1; j < originalSize; j++)
        {
            mpz_class matrixBN;
            mpz_ui_pow_ui(matrixBN.get_mpz_t(), i + 1, j);
            encodedBN += chunkToBN(chunks[j]) * matrixBN;
        }
        resultChunks[i] = BNToChunk(encodedBN);
    }
    return resultChunks;
}

void sendChunks(Channel chl, std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> chunks)
{
    int transferCount = 0;
    int missingCount = 0;
    for (int i = 0; i < CHANNEL_CHUNK_NUMBER; i++)
    {
        chl.send(chunks[i]->flag);
        if (!CHECK_CHUNK(chunks[i], CHUNK_FILE_END))
        {
            chl.send(chunks[i]->fp);
            transferCount++;
        }
        else
            break;
    }

    chl.recv(missingCount);

    if (missingCount == transferCount)
    {
        for (int i = 0; i < transferCount; i++)
        {
            chl.send(chunks[i]->size);
            chl.send(chunks[i]->data, chunks[i]->size);
        }
    }
    if (missingCount > 0 && missingCount < transferCount)
    {
        std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> encodedChunks = chunksEncode(chunks, transferCount, missingCount);
        for (int i = 0; i < missingCount; i++)
        {
            chl.send(encodedChunks[i]->size);
            chl.send(encodedChunks[i]->data, encodedChunks[i]->size);
        }
    }

    bool FIN;
    chl.recv(FIN);

    if (FIN)
        return;
}

int main()
{

    static pthread_t read_t, chunk_t, hash_t;

    read_queue = sync_queue_new(10);
    chunk_queue = sync_queue_new(100);
    hash_queue = sync_queue_new(100);
    IOService ios(4);

    ios.showErrorMessages(true);

    auto ip = std::string("127.0.0.1");
    auto port = 1212;

    std::string serversIpAddress = ip + ':' + std::to_string(port);

    std::string sessionHint = "cloud_storge_system";

    Session client(ios, serversIpAddress, SessionMode::Client, sessionHint);

    // Actually get the channel that can be used to communicate on.
    Channel chl = client.addChannel();

    struct dirent *ptr;
    std::string path = "/home/kid/CODE/EncryptCloudStorge/dataset/";
    std::vector<std::string> files;
    std::stack<std::string> folders;
    folders.push(path);

    while (!folders.empty())
    {
        path = folders.top();
        folders.pop();
        DIR *dir = opendir(path.c_str());

        while ((ptr = readdir(dir)) != NULL)
        {
            if (ptr->d_name[0] == '.')
                continue;
            if ((opendir((path + ptr->d_name).c_str()) == NULL))
                files.push_back(path + ptr->d_name);
            else
                folders.push(path + ptr->d_name + '/');
        }
        closedir(dir);
    }

    for (int i = 0; i < files.size(); ++i)
    {
        pthread_create(&read_t, NULL, read_thread, files[i].c_str());
        pthread_create(&chunk_t, NULL, chunk_thread, NULL);
        pthread_create(&hash_t, NULL, hash_thread, NULL);
        bool SYN = true;
        while (1)
        {
            std::array<struct chunk *, CHANNEL_CHUNK_NUMBER> chunks;

            for (int i = 0; i < CHANNEL_CHUNK_NUMBER; i++)
            {
                struct chunk *c = (struct chunk *)sync_queue_pop(hash_queue);

                if (CHECK_CHUNK(c, CHUNK_FILE_START))
                {
                    i--;
                    continue;
                }
                chunks[i] = c;
                if (CHECK_CHUNK(c, CHUNK_FILE_END))
                {
                    SYN=false;
                    break;
                }
            }
            chl.send(true);
            sendChunks(chl, chunks);
            if(SYN==false)
                break;
        }
    }
    chl.send(false);
    // close everything down in this order.
    chl.close();

    client.stop();

    ios.stop();

    return 0;
}
