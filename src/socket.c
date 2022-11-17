/**
 * @file socket.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Socket wrapper for handy and robust socket IO.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "libsftp/socket.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/util.h"

static int getai(const char *host, int port, struct addrinfo **ai) {
    const char *service = NULL;
    struct addrinfo hints;
    char s_port[10];

    ZERO_STRUCT(hints);

    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (port == 0) {
        hints.ai_flags = AI_PASSIVE;
    } else {
        snprintf(s_port, sizeof(s_port), "%hu", (unsigned short)port);
        service = s_port;
    }

    return getaddrinfo(host, service, &hints, ai);
}

ssh_socket ssh_socket_new() {
    ssh_socket s = calloc(1, sizeof(struct ssh_socket_struct));
    s->in_buffer = ssh_buffer_new();
    return s;
}

void ssh_socket_close(ssh_socket s) {
    if(s->fd > 0) {
        close(s->fd);
    }
}

void ssh_socket_free(ssh_socket s) {
    if (s == NULL) return;
    ssh_buffer_free(s->in_buffer);
}

int ssh_socket_connect(ssh_socket s, const char *host, uint16_t port,
                       const char *bind_addr) {
    int fd;
    int rc;

    struct addrinfo *ai = NULL;
    struct addrinfo *itr = NULL;

    rc = getai(host, port, &ai);
    if (rc != 0) {
        ssh_set_error(SSH_FATAL, "failed to resolve hostname %s", host);
        return SSH_ERROR;
    }

    for (itr = ai; itr != NULL; itr = itr->ai_next) {
        fd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
        if (fd < 0) continue;

        rc = connect(fd, itr->ai_addr, itr->ai_addrlen);
        if (rc < 0) {
            ssh_set_error(SSH_REQUEST_DENIED, "failed to connect: %s",
                          strerror(errno));
            close(fd);
            continue;
        }
        break;
    }
    freeaddrinfo(ai);

    ssh_socket_set_fd(s, fd);
    return SSH_OK;
}

void ssh_socket_set_fd(ssh_socket s, int fd) { s->fd = fd; }

int ssh_socket_write(ssh_socket s, const void *buffer, size_t len) {
    size_t total=0;
    
    while (total < len) {
        int writen = write(s->fd, buffer+total, len-total);
        if (writen < 0) {
            if (errno == EINTR)
                continue;
            LOG_ERROR("write error on fd %d", s->fd);
            ssh_set_error(SSH_FATAL, "socket %d write error", s->fd);
            return SSH_ERROR;
        } else if (writen == 0) {
            LOG_ERROR("write EOF on fd %d", s->fd);
            ssh_set_error(SSH_FATAL, "socket %d write EOF", s->fd);
            return SSH_ERROR;
        }
        total += writen;
    }
    return SSH_OK;
}

int ssh_socket_read(ssh_socket s, void *buffer, size_t len) {
    int readn;

    while (ssh_buffer_get_len(s->in_buffer) < len) {
        char tmp[256];
        readn = read(s->fd, tmp, sizeof(tmp));
        if (readn < 0) {
            if(errno == EINTR)
                continue;
            LOG_ERROR("read error on fd %d", s->fd);
            ssh_set_error(SSH_FATAL, "socket %d read error", s->fd);
            return SSH_ERROR;
        } else if (readn == 0) {
            LOG_ERROR("read EOF on fd %d", s->fd);
            ssh_set_error(SSH_FATAL, "socket %d read EOF", s->fd);
            return SSH_ERROR;
        }
        ssh_buffer_add_data(s->in_buffer, tmp, readn);
    }

    ssh_buffer_get_data(s->in_buffer, buffer, len);
    return SSH_OK;
}