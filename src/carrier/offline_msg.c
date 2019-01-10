/*
 * Copyright (c) 2018 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <string.h>
#include <vlog.h>
#include <crypto.h>
#include <base58.h>
#include <pthread.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#include <rc_mem.h>

#include "offline_msg.h"
#include "dht.h"
#include "ela_carrier.h"
#include "ela_carrier_impl.h"
#include "dstore_stub.h"

typedef struct OfflineMsgCtx {
    ElaCarrier *w;
    OfflineMsgOnRecvCb cb;
    const uint8_t *friend_public_key;
    uint8_t shared_key[SYMMETRIC_KEY_BYTES];
} OfflineMsgCtx;

static inline uint8_t *get_friend_public_key(const char *friendid,
                                             uint8_t *public_key)
{
    ssize_t len;

    len = base58_decode(friendid, strlen(friendid), public_key, PUBLIC_KEY_BYTES);
    assert(len == PUBLIC_KEY_BYTES);
    return public_key;
}

static inline uint8_t *self_get_public_key(ElaCarrier *w, uint8_t *buf)
{
    dht_self_get_public_key(&w->dht, buf);
    return buf;
}

static void compute_keys(ElaCarrier *w, const uint8_t *friend_id_or_pk,
                         bool is_send, uint8_t *shared_key, uint8_t *dstore_key)
{
    ssize_t len;
    uint8_t self_secret_key[SECRET_KEY_BYTES];
    const uint8_t *friend_public_key;
    const uint8_t *sha256_key;

    dht_self_get_secret_key(&w->dht, self_secret_key);
    friend_public_key = is_send ?
                        get_friend_public_key((char *)friend_id_or_pk,
                                              alloca(PUBLIC_KEY_BYTES)) :
                        friend_id_or_pk;
    sha256_key = is_send ? friend_public_key :
                 self_get_public_key(w, alloca(PUBLIC_KEY_BYTES));
    crypto_compute_symmetric_key(friend_public_key, self_secret_key, shared_key);

    len = hmac_sha256(sha256_key, PUBLIC_KEY_BYTES,
                      shared_key, SYMMETRIC_KEY_BYTES,
                      dstore_key, SHA256_BYTES);
    assert(len == SHA256_BYTES);
}

static inline uint8_t *compute_nonce(const uint8_t *dstore_key)
{
    uint8_t offset;

    offset = dstore_key[0] & (SHA256_BYTES - NONCE_BYTES - 1);
    return (uint8_t *)dstore_key + offset;
}

static inline int compute_dstore_value(const uint8_t *shared_key,
                                       const uint8_t *dstore_key,
                                       const uint8_t *plain, size_t len,
                                       uint8_t *dstore_value)
{
    const uint8_t *nonce;

    nonce = compute_nonce(dstore_key);
    return crypto_encrypt(shared_key, nonce, plain, len, dstore_value);
}

int offline_msg_send(ElaCarrier *w, const char *to, const void *msg, size_t len)
{
    uint8_t shared_key[SYMMETRIC_KEY_BYTES];
    uint8_t dstore_key[SHA256_BYTES];
    uint8_t dstore_value[MAC_BYTES + len];
    ssize_t dstore_value_len;

    compute_keys(w, (uint8_t *)to, true, shared_key, dstore_key);
    dstore_value_len = compute_dstore_value(shared_key, dstore_key, msg, len,
                                            dstore_value);
    if (dstore_value_len <= 0) {
        vlogE("Offline Msg: compute dstore value error.");
        return ELA_GENERAL_ERROR(ELAERR_ENCRYPT);
    }

    dstore_add_value(dstore_key, dstore_value, dstore_value_len); //TODO
    return 0;
}

static bool get_offline_msg(const uint8_t *dstore_key, const void *buf,
                            size_t length, void *context)
{
    OfflineMsgCtx *ctx = (OfflineMsgCtx *)context;
    uint8_t *msg = alloca(length - MAC_BYTES);
    ssize_t len;
    const uint8_t *nonce;
    char friend_id[ELA_MAX_ID_LEN + 1];
    size_t id_len = sizeof(friend_id);

    nonce = compute_nonce(dstore_key);
    len = crypto_decrypt(ctx->shared_key, nonce, buf, length, msg);
    if (len <= 0) {
        vlogE("Offline Msg: crypto handler decrypt data error.");
        return true;
    }

    base58_encode(ctx->friend_public_key, DHT_PUBLIC_KEY_SIZE, friend_id, &id_len);
    ctx->cb(ctx->w, friend_id, msg, len);
    return true;
}

static bool check_friend_offline_msg(uint32_t friend_number,
                                     const uint8_t *public_key,
                                     int user_status,
                                     const uint8_t *desc, size_t desc_length,
                                     void *context)
{
    OfflineMsgCtx *ctx = (OfflineMsgCtx *)context;
    uint8_t dstore_key[SHA256_BYTES];

    ctx->friend_public_key = public_key;

    compute_keys(ctx->w, public_key, false, ctx->shared_key, dstore_key);
    dstore_get_values(dstore_key, &get_offline_msg, ctx);
    dstore_remove_values(dstore_key);
    return true;
}

static void *__offline_msg_recv(void *arg)
{
    OfflineMsgCtx *ctx = (OfflineMsgCtx *)arg;

    dht_get_friends(&ctx->w->dht, check_friend_offline_msg, ctx);
    deref(ctx);
    return NULL;
}

OffToken *offline_msg_recv(ElaCarrier *w, OfflineMsgOnRecvCb cb)
{
    pthread_t *pid = rc_alloc(sizeof(pthread_t), NULL);
    if (!pid)
        return NULL;

    OfflineMsgCtx *ctx = rc_zalloc(sizeof(OfflineMsgCtx), NULL);
    if (!ctx)
        return NULL;

    ctx->w = w;
    ctx->cb = cb;

    pthread_create(pid, NULL, __offline_msg_recv, ctx);
    return pid;
}

void offline_msg_recv_finish(OffToken *off_tok)
{
    pthread_t *pid = (pthread_t *)off_tok;

    pthread_join(*pid, NULL);
}
