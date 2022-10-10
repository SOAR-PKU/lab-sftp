/**
 * @file socket.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Socket wrapper for handy and robust socket IO.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>
#include "libssh.h"

struct ssh_socket_struct {
    int fd;
    ssh_buffer in_buffer;
};

typedef struct ssh_socket_struct *ssh_socket;

ssh_socket ssh_socket_new();

void ssh_socket_free(ssh_socket s);

int ssh_socket_connect(ssh_socket s, const char *host, uint16_t port,
                       const char *bind_addr);

void ssh_socket_close(ssh_socket s);

void ssh_socket_set_fd(ssh_socket s, int fd);

int ssh_socket_write(ssh_socket s, const void *buffer, size_t len);

int ssh_socket_read(ssh_socket s, void *buffer, size_t len);

#endif /* SOCKET_H */