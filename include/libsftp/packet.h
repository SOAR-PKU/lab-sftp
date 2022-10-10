/**
 * @file packet.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH packet IO functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef PACKET_H
#define PACKET_H

#include "libssh.h"
#include "crypto.h"

int ssh_packet_send(ssh_session session);
int ssh_packet_receive(ssh_session session);


#endif /* PACKET_H */
