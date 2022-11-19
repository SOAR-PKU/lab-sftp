/**
 * @file stfp.c
 * @author Zhou Yuhan (zhouyuhan@pku.edu.cn)
 * @brief Implementaiton of SFTP functions, including APIs and helpers.
 * Only open, close, read, write of regular files are supported
 * @version 0.1
 * @date 2022-07-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <fcntl.h>
#include <stddef.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/libsftp.h"
#include "libsftp/logger.h"
#include "libsftp/session.h"
#include "libsftp/util.h"

/* Buffer size maximum is 256M */
#define SFTP_PACKET_SIZE_MAX 0x10000000
#define SFTP_BUFFER_SIZE_MAX 16384

struct sftp_session_struct {
    ssh_session session;
    uint32_t id_counter;
    uint32_t version;
    ssh_channel channel;
};

struct sftp_packet_struct {
    sftp_session sftp;
    uint8_t type;
    ssh_buffer payload;
};

/* file handle */
struct sftp_file_struct {
    sftp_session sftp;
    uint64_t offset;
    ssh_string handle;
    uint8_t eof;
};

/* SSH_FXP_MESSAGE described into .7 page 26 */
struct sftp_status_struct {
    uint32_t id;
    uint32_t status;
    char *errormsg;
    char *langtag;
};

struct sftp_attributes_struct {
    char *name;
    char *longname; /* ls -l output on openssh, not reliable else */
    uint32_t flags;
    uint8_t type;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    char *owner; /* set if openssh and version 4 */
    char *group; /* set if openssh and version 4 */
    uint32_t permissions;
    uint64_t atime64;
    uint32_t atime;
    uint32_t atime_nseconds;
    uint64_t createtime;
    uint32_t createtime_nseconds;
    uint64_t mtime64;
    uint32_t mtime;
    uint32_t mtime_nseconds;
    ssh_string acl;
    uint32_t extended_count;
    ssh_string extended_type;
    ssh_string extended_data;
};

static void sftp_status_free(sftp_status status);
static sftp_packet sftp_packet_new(sftp_session sftp);
static void sftp_packet_free(sftp_packet packet);
static void sftp_file_free(sftp_file file);
static sftp_status sftp_parse_status(sftp_packet packet);
static sftp_file sftp_parse_handle(sftp_packet packet, uint32_t orig_id);
static sftp_packet sftp_packet_read(sftp_session sftp);
static int32_t sftp_packet_write(sftp_session sftp, uint8_t type,
                                 ssh_buffer payload);

static uint32_t sftp_get_new_id(sftp_session sftp) {
    return ++sftp->id_counter;
}

sftp_session sftp_new(ssh_session session) {
    sftp_session sftp;

    if (session == NULL) {
        return NULL;
    }

    sftp = calloc(1, sizeof(struct sftp_session_struct));
    if (sftp == NULL) {
        LOG_ERROR("can not create sftp session");
        return NULL;
    }

    /* Skip: SFTP extended data */

    sftp->session = session;
    sftp->channel = ssh_channel_new(session);
    if (sftp->channel == NULL) {
        LOG_ERROR("can not create ssh channel");
        goto error;
    }

    if (ssh_channel_open_session(sftp->channel) != SSH_OK) {
        goto error;
    }

    if (ssh_channel_request_sftp(sftp->channel) != SSH_OK) {
        goto error;
    }

    return sftp;

error:
    if (sftp->channel != NULL) {
        ssh_channel_free(sftp->channel);
    }
    SAFE_FREE(sftp);
    return NULL;
}

int sftp_init(sftp_session sftp) {
    sftp_packet response = NULL;
    ssh_buffer buffer = NULL;
    uint32_t version;
    int rc;

    sftp->version = LIBSFTP_VERSION;
    sftp->id_counter = 0;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_pack(buffer, "d", sftp->version)) != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    if (sftp_packet_write(sftp, SSH_FXP_INIT, buffer) < 0) {
        LOG_CRITICAL("can not send init request");
        ssh_set_error(SSH_FATAL, "init request error");
        ssh_buffer_free(buffer);
    }
    ssh_buffer_free(buffer);

    response = sftp_packet_read(sftp);
    if (response == NULL) {
        ssh_set_error(SSH_FATAL, "can not read sftp packet");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    if (response->type != SSH_FXP_VERSION) {
        LOG_ERROR("unexpected server response");
        ssh_set_error(SSH_FATAL, "received code %d during init",
                      response->type);
        sftp_packet_free(response);
        return SSH_ERROR;
    }

    rc = ssh_buffer_unpack(response->payload, "d", &version);
    if (rc != SSH_OK) {
        LOG_ERROR("can not parse server response");
        ssh_set_error(SSH_FATAL, "buffer error");
        sftp_packet_free(response);
        return SSH_ERROR;
    }

    if (version != sftp->version) {
        LOG_ERROR("sftp server version %d does not match client version %d",
                  version, sftp->version);
        ssh_set_error(SSH_REQUEST_DENIED,
                      "version mismatch (server: %d client: %d)", version,
                      sftp->version);
        sftp_packet_free(response);
        return SSH_ERROR;
    }

    return SSH_OK;
}

sftp_file sftp_open(sftp_session sftp, const char *filename, int flags,
                    mode_t mode) {
    sftp_packet response = NULL;
    sftp_status status = NULL;
    sftp_file handle = NULL;
    ssh_buffer buffer = NULL;
    uint32_t perm_flags = 0;
    uint32_t attr_flags =
        SSH_FILEXFER_ATTR_PERMISSIONS; /* only specify permission flags when
                                          opening a file */

    uint32_t id;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return NULL;
    }

    if ((flags & O_RDWR) == O_RDWR) {
        perm_flags |= (SSH_FXF_WRITE | SSH_FXF_READ);
    } else if ((flags & O_WRONLY) == O_WRONLY) {
        perm_flags |= SSH_FXF_WRITE;
    } else {
        perm_flags |= SSH_FXF_READ;
    }
    if ((flags & O_CREAT) == O_CREAT) perm_flags |= SSH_FXF_CREAT;
    if ((flags & O_TRUNC) == O_TRUNC) perm_flags |= SSH_FXF_TRUNC;
    if ((flags & O_EXCL) == O_EXCL) perm_flags |= SSH_FXF_EXCL;
    if ((flags & O_APPEND) == O_APPEND) {
        perm_flags |= SSH_FXF_APPEND;
    }

    id = sftp_get_new_id(sftp);

    /* pack a new SFTP packet and send it using `sftp_packet_write` */
    // LAB: insert your code here. (finished)
    if ((rc = ssh_buffer_pack(buffer, "dSddd", id, handle, perm_flags,
        attr_flags, mode)) != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return NULL;
    }

    if (sftp_packet_write(sftp, SSH_FXP_OPEN, buffer) < 0) {
        LOG_CRITICAL("can not send open request");
        ssh_set_error(SSH_FATAL, "open request error");
        ssh_buffer_free(buffer);
        return NULL;
    }

    response = sftp_packet_read(sftp);
    if (response == NULL) {
        ssh_set_error(SSH_FATAL, "can not read sftp packet");
        ssh_buffer_free(buffer);
        return NULL;
    }

    switch (response->type) {
        case SSH_FXP_STATUS:
            // LAB: insert your code here. (finished)
            status = sftp_parse_status(response);
            ssh_set_error(SSH_FATAL, "open request rejected by server");
            ssh_buffer_free(buffer);
            sftp_status_free(status);
            return NULL;

        case SSH_FXP_HANDLE:
            // LAB: insert your code here. (finished)
            handle = sftp_parse_handle(response, id);
            ssh_buffer_free(buffer);
            return handle;

        default:
            // LAB: insert your code here. (finished)
            ssh_set_error(SSH_FATAL, "unexpected response type received");
            ssh_buffer_free(buffer);
            return NULL;

    }
    return NULL;
}

int sftp_close(sftp_file file) {
    sftp_session sftp = file->sftp;
    ssh_string handle = file->handle;
    sftp_packet response = NULL;
    sftp_status status = NULL;
    ssh_buffer buffer = NULL;
    uint32_t id;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);

    if ((rc = ssh_buffer_pack(buffer, "dS", id, handle)) != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    if (sftp_packet_write(sftp, SSH_FXP_CLOSE, buffer) < 0) {
        LOG_CRITICAL("can not send close request");
        ssh_set_error(SSH_FATAL, "close request error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }
    ssh_buffer_free(buffer);

    response = sftp_packet_read(sftp);
    if (response == NULL) {
        ssh_set_error(SSH_FATAL, "can not read sftp packet");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    switch (response->type) {
        // LAB: insert your code here. (finished)
        case SSH_FXP_STATUS:
            status = sftp_parse_status(response);
            sftp_status_free(status);
            return SSH_NO_ERROR;

        default:
            ssh_set_error(SSH_FATAL, "unexpected response type received");
            return SSH_ERROR;

    }
}

int32_t sftp_read(sftp_file file, void *buf, uint32_t count) {
    sftp_session sftp = file->sftp;
    sftp_packet response = NULL;
    sftp_status status = NULL;
    ssh_string data = NULL;
    uint32_t recvlen;
    ssh_buffer buffer = NULL;
    uint32_t id;
    uint32_t recv_id;
    int rc;

    if (file->eof) return 0;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);

    rc = ssh_buffer_pack(buffer, "dSqd", id, file->handle, file->offset, count);
    if (rc != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    if (sftp_packet_write(sftp, SSH_FXP_READ, buffer) < 0) {
        LOG_CRITICAL("can not send read request");
        ssh_set_error(SSH_FATAL, "read request error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }
    ssh_buffer_free(buffer);

    response = sftp_packet_read(sftp);
    if (response == NULL) {
        ssh_set_error(SSH_FATAL, "can not read sftp packet");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    switch (response->type) {
        // LAB: insert your code here. (finished)
        case SSH_FXP_DATA:
            data = calloc(1, sizeof(struct ssh_string_struct));
            if (data == NULL) return SSH_ERROR;
            rc = ssh_buffer_unpack(response->payload, "dS", &recv_id, &data);
            if (rc != SSH_OK || data == NULL) return SSH_ERROR;
            if (id != recv_id) {
                LOG_ERROR("sftp response id %d does not match with origin id %d", recv_id,
                        id);
                ssh_set_error(SSH_FATAL, "id does not match");
                SAFE_FREE(data);
                return SSH_ERROR;
            }
            memcpy(buf, data->data, min(data->size, count));
            return min(data->size, count);

        case SSH_FXP_STATUS:
            status = sftp_parse_status(response);
            ssh_set_error(SSH_FATAL, "read request rejected by server");
            sftp_status_free(status);
            return SSH_ERROR;

        default:
            ssh_set_error(SSH_FATAL, "unexpected response type received");
            return SSH_ERROR;

    }
    return SSH_ERROR;
}

int32_t sftp_write(sftp_file file, const void *buf, uint32_t count) {
    sftp_session sftp = file->sftp;
    sftp_packet response = NULL;
    sftp_status status = NULL;
    ssh_string data = NULL;
    uint32_t nleft = count;
    uint32_t nwrite;
    uint32_t nsend;
    ssh_buffer buffer = NULL;
    uint32_t id;
    int rc;

    while (nleft > 0) {
        buffer = ssh_buffer_new();
        if (buffer == NULL) {
            LOG_CRITICAL("can not create ssh buffer");
            ssh_set_error(SSH_FATAL, "buffer error");
            return SSH_ERROR;
        }

        id = sftp_get_new_id(sftp);

        nwrite = MIN(nleft, SSH_FXP_MAXLEN);

        rc = ssh_buffer_pack(buffer, "dSqdP", id, file->handle, file->offset,
                             nwrite, nwrite, (char *)buf + (count - nleft));
        if (rc != SSH_OK) {
            LOG_CRITICAL("can not pack buffer");
            ssh_set_error(SSH_FATAL, "buffer error");
            ssh_buffer_free(buffer);
            return SSH_ERROR;
        }

        nsend = sftp_packet_write(sftp, SSH_FXP_WRITE, buffer);
        ssh_buffer_free(buffer);

        response = sftp_packet_read(sftp);
        if (response == NULL) {
            ssh_set_error(SSH_FATAL, "can not read sftp packet");
            ssh_buffer_free(buffer);
            return SSH_ERROR;
        }

        switch (response->type) {
            // LAB: insert your code here. (finished)
            case SSH_FXP_STATUS:
                status = sftp_parse_status(response);
                sftp_status_free(status);
                break;
            
            default:
                ssh_set_error(SSH_FATAL, "unexpected response type received");
                return SSH_ERROR;

        }
    }
    return count - nleft;
}

void sftp_free(sftp_session sftp) {
    if (sftp == NULL) return;
    if (sftp->channel != NULL) {
        ssh_channel_eof(sftp->channel);
        ssh_channel_close(sftp->channel);
        ssh_channel_free(sftp->channel);
        sftp->channel = NULL;
    }

    SAFE_FREE(sftp);
}

/**
 * @brief Grap an SFTP packet from channel, extracting type and payload.
 *
 * @param sftp
 * @return sftp_packet
 */
sftp_packet sftp_packet_read(sftp_session sftp) {
    uint8_t buffer[SFTP_BUFFER_SIZE_MAX];
    uint32_t size;
    sftp_packet packet = sftp_packet_new(sftp);
    int nread;
    bool is_eof;
    int rc;

    if (packet == NULL) return NULL;

    /* read packet length and type */
    nread = ssh_channel_read(sftp->channel, buffer,
                             sizeof(uint32_t) + sizeof(uint8_t));
    if (nread != sizeof(uint32_t) + sizeof(uint8_t) && nread != SSH_EOF) {
        LOG_ERROR("can not read packet length and type");
        goto error;
    }

    size = ntohl(*(uint32_t *)buffer) - sizeof(uint8_t);
    LOG_DEBUG("sftp packet size: %d", size);

    packet->type = buffer[4];

    rc = ssh_buffer_allocate_size(packet->payload, size);
    if (rc != SSH_OK) goto error;

    /* read packet payload */
    while (size > 0 && size < SFTP_PACKET_SIZE_MAX) {
        nread =
            ssh_channel_read(sftp->channel, buffer, MIN(size, sizeof(buffer)));
        if (nread == SSH_EOF) break;
        if (nread < 0) goto error;

        rc = ssh_buffer_add_data(packet->payload, buffer, nread);
        if (rc != SSH_OK) goto error;

        size -= nread;
    }

    return packet;

error:
    sftp_packet_free(packet);
    return NULL;
}

/**
 * @brief Encapsulate an SFTP packet and write it into the channel.
 *
 * @param sftp
 * @param type
 * @param payload
 * @return int32_t
 */
int32_t sftp_packet_write(sftp_session sftp, uint8_t type, ssh_buffer payload) {
    uint8_t header[5] = {0};
    uint32_t size;
    int nwrite;
    int rc;

    size = ssh_buffer_get_len(payload) + sizeof(uint8_t);
    *(uint32_t *)header = htonl(size);
    header[4] = type;

    rc = ssh_buffer_prepend_data(payload, header, sizeof(header));
    if (rc != SSH_OK) {
        ssh_set_error(SSH_FATAL, "can not create sftp packet");
        return SSH_ERROR;
    }

    nwrite = ssh_channel_write(sftp->channel, ssh_buffer_get(payload),
                               ssh_buffer_get_len(payload));
    if (nwrite != ssh_buffer_get_len(payload)) {
        ssh_set_error(SSH_FATAL, "can not write sftp packet");
        return SSH_ERROR;
    }

    return nwrite;
}

static void sftp_status_free(sftp_status status) {
    if (status == NULL) return;
    SAFE_FREE(status->errormsg);
    SAFE_FREE(status->langtag);
    SAFE_FREE(status);
}

static sftp_packet sftp_packet_new(sftp_session sftp) {
    sftp_packet packet = NULL;

    packet = calloc(1, sizeof(struct sftp_packet_struct));
    if (packet == NULL) return NULL;

    packet->sftp = sftp;
    packet->payload = ssh_buffer_new();
    if (packet->payload == NULL) {
        SAFE_FREE(packet);
        return NULL;
    }

    return packet;
}

static void sftp_packet_free(sftp_packet packet) {
    if (packet == NULL) return;
    ssh_buffer_free(packet->payload);
    SAFE_FREE(packet);
}

static void sftp_file_free(sftp_file file) {
    if (file == NULL) return;
    ssh_string_free(file->handle);
    SAFE_FREE(file);
}

/**
 * @brief Parse an SFTP packet with type SSH_FXP_HANDLE. Allocate and initiate a
 * file structure.
 *
 * @param packet
 * @param orig_id
 * @return sftp_file
 */
static sftp_file sftp_parse_handle(sftp_packet packet, uint32_t orig_id) {
    sftp_file file;
    uint32_t id;
    int rc;

    if (packet->type != SSH_FXP_HANDLE) return NULL;

    file = calloc(1, sizeof(struct sftp_file_struct));
    if (file == NULL) return NULL;

    rc = ssh_buffer_unpack(packet->payload, "dS", &id, &file->handle);
    if (rc != SSH_OK || file->handle == NULL) {
        SAFE_FREE(file);
        return NULL;
    }

    if (id != orig_id) {
        LOG_ERROR("sftp response id %d does not match with origin id %d", id,
                  orig_id);
        SAFE_FREE(file);
        return NULL;
    }

    file->sftp = packet->sftp;
    file->offset = 0;
    file->eof = 0;

    return file;
}

/**
 * @brief Parse an SFTP packet with type SSH_FXP_STATUS. Allocate and initiate a
 * status structure.
 *
 * @param packet
 * @return sftp_status
 */
static sftp_status sftp_parse_status(sftp_packet packet) {
    sftp_status status;
    int rc;

    if (packet->type != SSH_FXP_STATUS) return NULL;

    status = calloc(1, sizeof(struct sftp_status_struct));
    if (status == NULL) return NULL;

    rc = ssh_buffer_unpack(packet->payload, "dd", &status->id, &status->status);
    if (rc != SSH_OK) {
        SAFE_FREE(status);
        return NULL;
    }
    rc = ssh_buffer_unpack(packet->payload, "ss", &status->errormsg,
                           &status->langtag);

    if (rc != SSH_OK) {
        SAFE_FREE(status);
        return NULL;
    }

    return status;
}

/**
 * @brief Get file attributes from the server.
 * @todo Not implemented since we only want to read and write (excluding append)
 *
 * @param session
 * @param path
 * @return sftp_attributes
 */
sftp_attributes sftp_stat(sftp_session session, const char *path) {
    return NULL;
}
