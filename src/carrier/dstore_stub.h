#ifndef ELASTOS_CARRIER_DSTORE_H
#define ELASTOS_CARRIER_DSTORE_H

#include <stdlib.h>
#include <stdbool.h>

int dstore_add_value(const uint8_t *key, const uint8_t *value, size_t len);
void dstore_get_values(const uint8_t *key, bool (*cb)(const uint8_t *key,
                                                      const void *value,
                                                      size_t length,
                                                      void *ctx), void *ctx);
void dstore_remove_values(const uint8_t *key);
#endif //ELASTOS_CARRIER_DSTORE_H
