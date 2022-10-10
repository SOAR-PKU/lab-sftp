/**
 * @file dh.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Diffie-Hellman key exchange functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef DH_H_
#define DH_H_

#include "crypto.h"

struct dh_ctx;

#define DH_CLIENT_KEYPAIR 0
#define DH_SERVER_KEYPAIR 1

int ssh_dh_handshake(ssh_session session);
void dh_cleanup(struct ssh_crypto_struct *crypto);

#endif /* DH_H_ */
