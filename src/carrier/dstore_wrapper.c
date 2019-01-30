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
#include <DStoreC.h>

#include "dht.h"
#include "dsotre_wrapper.h"
#include "ela_carrier.h"

#define DSTORE_SERVICE_PORT (9094)

typedef struct DStoreWrapper {
    ElaCarrier *carrier;
    DStoreOnMsgCallback cb;
    pthread_t worker;
    DStoreC *dstore;
} DStoreWrapper;

static inline uint8_t *compute_nonce(const char *dstore_key)
{
    uint8_t offset;

    offset = dstore_key[0] % ((SHA256_BYTES << 1) - NONCE_BYTES + 1);
    return (uint8_t *)dstore_key + offset;
}

size_t dstore_send_msg(DStoreWrapper *ctx, const char *friendid,
                      const void *msg, size_t length)
{
    uint8_t self_sk[SECRET_KEY_BYTES];
    uint8_t self_pk[PUBLIC_KEY_BYTES];
    uint8_t peer_pk[PUBLIC_KEY_BYTES];
    uint8_t sharedkey[SYMMETRIC_KEY_BYTES];
    uint8_t msgbody[MAC_BYTES + len];
    ssize_t size;
    uint8_t *nonce;
    char msgkey[(SHA256_BYTES << 1) + 1];
    char *key;
    int rc;

    len = base58_decode(friendid, strlen(friendid), peer_pk, sizeof(peer_pk));
    if (len != sizeof(peer_pk))  {
        vlogE("Carrier: Decode friendid %s error.", friendid);
        return ELA_GENERAL_ERROR(ELAERR_ENCRYPT);
    }

    dht_self_get_secret_key(&w->dht, self_sk);
    dht_self_get_public_key(&w->dht, self_pk);
    crypto_compute_symmetric_key(self_sk, peer_pk, shared_key);

    // Compute sending msgkey.
    // msgkey=SHA256<SYMMTRIC(self_sk, peer_pk), peer_pk>
    key = hmac_sha256a(sharedkey, SYMMETRIC_KEY_BYTES,
                       peer_pk, PUBLIC_KEY_BYTES,
                       msgkey, sizeof(msgkey));
    if (!key) {
        vlogE("Carrier: Computing sending msgkey error.");
        return ELA_GENERAL_ERROR(ELAERR_INVALID_ARGS);
    }

    nonce = compute_nonce(dstore_key);
    size  = crypto_encrypt(shared_key, nonce, msg, lenth, msgbody);
    if (size < 0) {
        vlogE("Carrier: Encrypt offline message body error.");
        return ELA_GENERAL_ERROR(ELAERR_ENCRYPT);
    }

    rc = dstore_add_value(ctx->dstore, msgkey, dstore_value, dstore_value_len);
    if (rc < 0) {
        vlogE("Carrier: Sending offline message <K,V> error.");
        return ELA_GENERAL_ERROR(ELAERR_BUSY);
    }

    return length;
}

static bool get_msg_body(const char *msg_key,
                         const uint8_t *buf, size_t length,
                         void *context
{
    DStoreWrapper *ctx = (DStoreWrapper *)((void **)context)[0];
    uint8_t *friendkey = (uint8_t *)((void **)context)[1];
    uint8_t *sharekey  = (uint8_t *)((void **)context)[2];

    uint8_t *msg = alloca(length - MAC_BYTES);
    ssize_t size;
    const uint8_t *nonce;
    char friendid[ELA_MAX_ID_LEN + 1] = {0};
    size_t idlen = sizeof(friendid);

    nonce = compute_nonce(msg_key);
    size  = crypto_decrypt(sharedkey, nonce, buf, length, msg);
    if (len <= 0) {
        vlogE("Carrier: decrypt offline message body error.");
        return false;
    }

    base58_encode(peer_key, DHT_PUBLIC_KEY_SIZE, friendid, &idlen);
    ctx->cb(ctx, friendid, msg, len);
    return true;
}

static bool check_offline_msg_cb(uint32_t friend_number,
                                 const uint8_t *friend_pk,
                                 int user_status,
                                 const uint8_t *desc, size_t desc_length,
                                 void *context)
{
    DStoreWrapper *ctx = (DStoreWrapper *)context;
    ElaCarrier *w = ctx->carrier;

    uint8_t self_sk[SECRET_KEY_BYTES];
    uint8_t self_pk[PUBLIC_KEY_BYTES];
    uint8_t sharedkey[SYMMETRIC_KEY_BYTES];
    char msgkey[(SHA256_BYTES << 1) + 1];
    char *key;
    void *argv[] = {
        ctxt,
        friend_pk,
        sharedkey,
    };

    (void)user_status;
    (void)desc;
    (void)desc_length;

    dht_self_get_secret_key(&w->dht, self_sk);
    dht_self_get_public_key(&w->dht, self_pk);
    crypto_compute_symmetric_key(self_sk, friend_pk, shared_key);

    // Compute receiving msgkey.
    // msgkey=SHA256<SYMMTRIC(self_sk, peer_pk), self_pk>
    key = hmac_sha256a(sharedkey, SYMMETRIC_KEY_BYTES,
                       self_pk, PUBLIC_KEY_BYTES,
                       msgkey, sizeof(msgkey));
    if (!key) {
        vlogE("Carrier: Computing receiving msgkey error.");
        return false;
    }

    // iterate messages from friend with friend_pk.
    dstore_get_values(ctx->dstore, key, &get_msg_body, argv);
    dstore_remove_values(ctx->dstore, key);

    return true;
}

static void * scrawl_offline_msg(void *arg)
{
    DStoreWrapper *ctx = (DStoreWrapper *)arg;
    dht_get_friends(&ctx->w->dht, check_friend_offline_msg_cb, ctx);
    return NULL;
}

static void DStoreWrapperDestroy(void *arg)
{
    DStoreWrapper *ctx = (DStoreWrapper *)arg;

    if (ctx->dstore) {
        dstore_destroy(ctx->dstore);
        ctx->dstore = NULL;
    }
}

DStoreWrapper *dstore_wrapper_create(ElaCarrier *w, DStoreOnMsgCallback *cb)
{
    DStoreWrapper *ctx;


    ctx = rc_zalloc(sizeof(DStoreWrapper), DStoreWrapperDestroy);
    if (!ctx)
        return NULL;

    /* ctx->dstore = dstore_create(ctx->w->pref.bootstraps[0].ipv4,
                                DSTORE_SERVICE_PORT);
      ctx->dstore = dstore_create("45.32.197.17",
                                DSTORE_SERVICE_PORT); */
    ctx->dstore = dstore_create("149.28.244.92", DSTORE_SERVICE_PORT);
    if (!ctx->dstore) {
        deref(ctx);
        return NULL;
    }

    ctx->carrier = w;
    ctx->cb = *cb;

    rc = pthread_create(&ctx->worker, NULL, scrawl_offline_msg, ctx);
    if (rc != 0) {
        deref(ctx);
        return NULL;
    }

    return ctx;
}

void dstore_wrapper_destroy(DStoreWrapper *ctx)
{
    // worker should be started, so join for exiting.
    pthread_join(ctx->worker, NULL);
    deref(ctx);
}
