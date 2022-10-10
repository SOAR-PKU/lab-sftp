/**
 * @file kdf.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Key derivation functions.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef KDF_H
#define KDF_H

#include <stdbool.h>
#include "crypto.h"

int sshkdf_derive_key(struct ssh_crypto_struct *crypto,
                      unsigned char *key, size_t key_len,
                      int key_type, unsigned char *output,
                      size_t requested_len);

#endif /* KDF_H */