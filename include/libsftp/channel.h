/**
 * @file channel.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH connection layer channel abstraction.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef CHANNEL_H
#define CHANNEL_H

#include "libssh.h"

struct ssh_channel_struct {
    ssh_session session; /* SSH_SESSION pointer */
    uint32_t local_channel;
    uint32_t local_window;
    int local_eof;
    uint32_t local_maxpacket;

    uint32_t remote_channel;
    uint32_t remote_window;
    int remote_eof; /* end of file received */
    uint32_t remote_maxpacket;
    ssh_buffer out_buffer;
};

typedef struct ssh_channel_struct *ssh_channel;

ssh_channel ssh_channel_new(ssh_session session);
int ssh_channel_open_session(ssh_channel channel);
int ssh_channel_request_sftp(ssh_channel channel);
int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len);
int ssh_channel_read(ssh_channel channel, void *dest, uint32_t count);
int ssh_channel_eof(ssh_channel channel);
int ssh_channel_close(ssh_channel channel);
void ssh_channel_free(ssh_channel channel);

#endif /* CHANNEL_H */