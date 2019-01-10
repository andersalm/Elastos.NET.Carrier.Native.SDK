#include <cjson/cJSON.h>
#include <sys/types.h>
#include <base58.h>
#include <crypto.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <vlog.h>

#include "dstore_stub.h"

static void print_raw_value(const uint8_t *value, size_t len)
{
    char buf[1024];

    for (size_t i = 0; i < len; ++i) {
        sprintf(buf + (i << 1), "%02hhX", value[i]);
    }
    vlogE("value: %s", buf);
}

int dstore_add_value(const uint8_t *key, const uint8_t *value, size_t len)
{
    char key_str[1024 + SHA256_BYTES];
    char val_str[1024 + len];
    int fd = -1;
    struct stat fbuf;
    char *json_str = NULL;
    cJSON *jvals = NULL;
    cJSON *json_root = NULL;
    int ret = 0;
    size_t key_str_len = sizeof(key_str);
    size_t val_str_len = sizeof(val_str);

    base58_encode(key, SHA256_BYTES, key_str, &key_str_len);
    base58_encode(value, len, val_str, &val_str_len);

    fd = open(".offmsg.json", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0)
        goto fail;

    if (fstat(fd, &fbuf))
        goto fail;

    if (fbuf.st_size) {
        json_str = mmap(0, fbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (json_str == MAP_FAILED) {
            json_str = NULL;
            goto fail;
        }

        json_root = cJSON_Parse(json_str);
        munmap(json_str, fbuf.st_size);
        json_str = NULL;
        if (!json_root)
            goto fail;
    } else {
        json_root = cJSON_CreateObject();
        if (!json_root)
            goto fail;
    }

    jvals = cJSON_GetObjectItemCaseSensitive(json_root, key_str);
    if (!jvals) {
        jvals = cJSON_CreateArray();
        if (!jvals)
            goto fail;

        cJSON_AddItemToObjectCS(json_root, key_str, jvals);
    }

    cJSON *jval = cJSON_CreateString(val_str);
    if (!jval)
        goto fail;
    cJSON_AddItemToArray(jvals, jval);

    json_str = cJSON_Print(json_root);
    if (!json_str)
        goto fail;

    ssize_t nwr = write(fd, json_str, strlen(json_str) + 1);
    if (nwr >= 0)
        goto succeed;

fail:
    ret = -1;
succeed:
    if (json_str)
        free(json_str);
    if (json_root)
        cJSON_Delete(json_root);
    if (fd >= 0)
        close(fd);
    return ret;
}

void dstore_get_values(const uint8_t *key, bool (*cb)(const uint8_t *key,
                                                      const void *value,
                                                      size_t length,
                                                      void *ctx), void *ctx)
{
    char key_str[1024 + SHA256_BYTES];
    size_t key_str_len = sizeof(key_str);
    int fd = -1;
    struct stat fbuf;
    char *json_str = NULL;
    cJSON *json_root = NULL;
    cJSON *jvals = NULL;
    cJSON *jval = NULL;

    base58_encode(key, SHA256_BYTES, key_str, &key_str_len);

    fd = open(".offmsg.json", O_RDWR);
    if (fd < 0)
        goto end;

    if (fstat(fd, &fbuf))
        goto end;

    if (!fbuf.st_size)
        goto end;

    json_str = mmap(0, fbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (json_str == MAP_FAILED)
        goto end;

    json_root = cJSON_Parse(json_str);
    munmap(json_str, fbuf.st_size);
    json_str = NULL;
    if (!json_root)
        goto end;

    jvals = cJSON_DetachItemFromObject(json_root, key_str);
    if (!jvals || !cJSON_IsArray(jvals))
        goto end;

    cJSON_ArrayForEach(jval, jvals) {
        ssize_t val_len;

        if (!cJSON_IsString(jval))
            goto end;

        uint8_t val[strlen(jval->valuestring)];
        val_len = sizeof(val);
        val_len = base58_decode(jval->valuestring, strlen(jval->valuestring),
                                val, val_len);
        if (val_len < 0)
            goto end;

        bool cont = cb(key, val + sizeof(val) - val_len, val_len, ctx);
        if (!cont)
            goto end;
    }

    json_str = cJSON_Print(json_root);
    if (!json_str)
        goto end;

    if (ftruncate(fd, 0) == -1)
        goto end;

    ssize_t nwr = write(fd, json_str, strlen(json_str) + 1);
end:
    if (json_str)
        free(json_str);
    if (fd >= 0)
        close(fd);
    if (json_root)
        cJSON_Delete(json_root);
    if (jvals)
        cJSON_Delete(jvals);
}

void dstore_remove_values(const uint8_t *key)
{
}
