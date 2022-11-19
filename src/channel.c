/**
 * @file channel.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH connection layer channel abstraction.
 * This file handles open, close, and data transfer on a virtual channel.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/channel.h"

#include "libsftp/error.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/**
 * RFC4253 section 6.1
 * All implementations MUST be able to process packets with an
 * uncompressed payload length of 32768 bytes or less and a total packet
 * size of 35000 bytes or less
 *
 */

#define CHANNEL_MAX_PACKET 32768
#define CHANNEL_INITIAL_WINDOW 64000

/**
 * @brief Get a new channel id.
 * @todo Since we only support one channel per session, returning 1 meets the
 * need. This function needs to be updated if we want to support arbitrary
 * number of channels in the future.
 *
 * @param session
 * @return uint32_t
 */
static uint32_t channel_new_id(ssh_session session) { return 1; }

/**
 * @brief Open a channel by sending a SSH_CHANNEL_OPEN message and
 *        wait for the reply.
 *
 * @param[in]  channel  The current channel.
 *
 * @param[in]  type   A C string describing the kind of channel (e.g. "exec").
 *
 * @param[in]  window   The receiving window of the channel. The window is the
 *                      maximum size of data that can stay in buffers and
 *                      network.
 *
 * @param[in]  maxpacket The maximum packet size allowed (like MTU).
 *
 * @param[in]  payload   The buffer containing additional payload for the query.
 *
 * @return             SSH_OK if successful; SSH_ERROR otherwise.
 */
static int channel_open(ssh_channel channel, const char *type, uint32_t window,
                        uint32_t maxpacket, ssh_buffer payload) {
    ssh_session session = channel->session;
    uint8_t reply_type;
    uint32_t recipient_channel;
    uint32_t reason_code;
    char *description = NULL;
    ssh_string req;
    bool want;
    int rc;

    channel->local_channel = channel_new_id(session);
    channel->local_maxpacket = maxpacket;
    channel->local_window = window;

    rc = ssh_buffer_pack(session->out_buffer, "bsddd", SSH_MSG_CHANNEL_OPEN,
                         type, channel->local_channel, channel->local_window,
                         channel->local_maxpacket);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        return SSH_ERROR;
    }

    if (payload != NULL) {
        if (ssh_buffer_add_buffer(session->out_buffer, payload) < 0) {
            return SSH_ERROR;
        }
    }

    if (ssh_packet_send(session) != SSH_OK) {
        return SSH_ERROR;
    }

    while (1) {
        /* wait until the channel is opened or an error occurs */
        rc = ssh_packet_receive(session);
        if (rc != SSH_OK) return SSH_ERROR;

        rc = ssh_buffer_get_u8(session->in_buffer, &reply_type);
        switch (reply_type) {
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                // LAB: insert your code here. (finished)
                rc = ssh_buffer_unpack(session->in_buffer, "dddd",
                    &recipient_channel, &channel->remote_channel,
                    &channel->remote_window, &channel->remote_maxpacket);
                if (rc != SSH_OK) return SSH_ERROR;
                if(recipient_channel != channel->local_channel)
                {
                    LOG_ERROR(
                        "channel number in the reply %d does not match with "
                        "the original %d",
                        recipient_channel, channel->local_channel);
                    return SSH_ERROR;
                }
                return SSH_OK;

            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                // LAB: insert your code here. (finished)
                rc = ssh_buffer_get_u32(session->in_buffer, &recipient_channel);
                if(recipient_channel != channel->local_channel)
                {
                    LOG_ERROR(
                        "channel number in the reply %d does not match with "
                        "the original %d",
                        recipient_channel, channel->local_channel);
                    return SSH_ERROR;
                }
                rc = ssh_buffer_get_u32(session->in_buffer, &reason_code);
                description = ssh_buffer_get_ssh_string(session->in_buffer);
                switch(reason_code)
                {
                    case SSH_OPEN_ADMINISTRATIVELY_PROHIBITED:
                        LOG_ERROR(
                            "administratively prohibited while opening "
                            "local channel %d", channel->local_channel);
                        break;
                    case SSH_OPEN_CONNECT_FAILED:
                        LOG_ERROR(
                            "connect failed while opening "
                            "local channel %d", channel->local_channel);
                        break;
                    case SSH_OPEN_UNKNOWN_CHANNEL_TYPE:
                        LOG_ERROR(
                            "unknown channel type while opening "
                            "local channel %d", channel->local_channel);
                        break;
                    case SSH_OPEN_RESOURCE_SHORTAGE:
                        LOG_ERROR(
                            "resource shortage while opening "
                            "local channel %d", channel->local_channel);
                        break;
                    default:
                        LOG_ERROR(
                            "unknown error while opening local channel %d",
                            channel->local_channel);
                }
                LOG_ERROR(description);
                return SSH_ERROR;

            case SSH_MSG_GLOBAL_REQUEST:
                /**
                 * RFC 4254 Section 4
                 * There are several kinds of requests that affect the state of
                 * the remote end globally, independent of any channels.  An
                 * example is a request to start TCP/IP forwarding for a
                 * specific port.  Note that both the client and server MAY send
                 * global requests at any time, and the receiver MUST respond
                 * appropriately.  All such requests use the following format.
                 *      byte      SSH_MSG_GLOBAL_REQUEST
                 *      string    request name in US-ASCII only
                 *      boolean   want reply
                 *      ....      request-specific data follows
                 *
                 * The value of 'request name' follows the DNS extensibility
                 * naming convention outlined in [SSH-ARCH].
                 *
                 */
                // LAB: insert your code here. (finished)
                rc = ssh_buffer_unpack(session->in_buffer, "Sb", &req, &want);
                if (want)
                {
                    rc = ssh_buffer_add_u8(session->out_buffer,
                        SSH_MSG_REQUEST_FAILURE);
                    if (rc != SSH_OK) {
                        LOG_ERROR("can not create buffer");
                        return SSH_ERROR;
                    }
                    if (ssh_packet_send(session) != SSH_OK) return SSH_ERROR;
                }
                break;

            default:
                // LAB: insert your code here. (finished)
                LOG_ERROR(
                    "unknown reply type while opening local channel %d",
                    channel->local_channel);
                return SSH_ERROR;

        }
    }

    return SSH_OK;
}

/**
 * @brief Send SSH channel request and wait for reply if `reply` is set to 1.
 *
 * @param channel
 * @param request
 * @param reply
 * @param req_spec
 * @return int
 */
static int channel_request(ssh_channel channel, const char *request, int reply,
                           ssh_buffer req_spec) {
    ssh_session session = channel->session;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    int rc;

    rc = ssh_buffer_pack(session->out_buffer, "bdsb", SSH_MSG_CHANNEL_REQUEST,
                         channel->remote_channel, request, reply == 0 ? 0 : 1);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        goto error;
    }

    if (req_spec != NULL) {
        if (ssh_buffer_add_data(session->out_buffer, ssh_buffer_get(req_spec),
                                ssh_buffer_get_len(req_spec)) < 0) {
            LOG_ERROR("can not concat buffer");
            goto error;
        }
    }
    if (ssh_packet_send(session) != SSH_OK) {
        goto error;
    }

    if (reply == 0) return SSH_OK;

    while (1) {
        /* wait for reply or an error occurs */
        if (ssh_packet_receive(session) != SSH_OK) {
            return SSH_ERROR;
        }

        rc = ssh_buffer_unpack(session->in_buffer, "bd", &type,
                               &recipient_channel);
        if (recipient_channel != channel->local_channel) {
            LOG_ERROR(
                "channel number in the reply does not match with the "
                "original");
            return SSH_ERROR;
        }

        switch (type) {
            case SSH_MSG_CHANNEL_SUCCESS:
                return SSH_OK;
            case SSH_MSG_CHANNEL_FAILURE:
                return SSH_ERROR;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                /* window adjust message could happen here */
                ssh_buffer_unpack(session->in_buffer, "d", &bytes_to_add);
                channel->remote_window += bytes_to_add;
                LOG_NOTICE("remote window adjust to %d",
                           channel->remote_window);
                break;
            default:
                LOG_ERROR("received type %d during channel open", type);
                return SSH_ERROR;
        }
    }

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Grow local channel window to at least `minimum_size`.
 * This function sends SSH_MSG_CHANNEL_WINDOW_ADJUST.
 *
 * @param channel
 * @param minimum_size
 * @return int
 */
static int grow_window(ssh_channel channel, uint32_t minimum_size) {
    ssh_session session;
    int rc;

    if (channel == NULL) return SSH_ERROR;
    session = channel->session;

    if (channel->local_window >= minimum_size) return SSH_OK;

    rc = ssh_buffer_pack(session->out_buffer, "bdd",
                         SSH_MSG_CHANNEL_WINDOW_ADJUST, channel->remote_channel,
                         minimum_size - channel->local_window);
    if (rc != SSH_OK) {
        LOG_ERROR("can not pack buffer");
        goto error;
    }

    if (ssh_packet_send(session) != SSH_OK) goto error;

    channel->local_window = minimum_size;
    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Wait for WINDOW_ADJUST message to grow remote window.
 *
 * @param channel
 * @return int
 */
static int wait_window(ssh_channel channel) {
    ssh_session session;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    int rc;

    if (channel == NULL) return SSH_ERROR;
    session = channel->session;

    type = 0;
    while (type != SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        rc = ssh_packet_receive(session);
        if (rc != SSH_OK || ssh_buffer_unpack(session->in_buffer, "bd", &type,
                                              &recipient_channel) != SSH_OK)
            return SSH_ERROR;
        if (recipient_channel != channel->local_channel) {
            LOG_ERROR(
                "channel number in the reply %d does not match with the "
                "original %d",
                recipient_channel, channel->local_channel);
            return SSH_ERROR;
        }

        switch (type) {
            case SSH_MSG_CHANNEL_DATA:
                LOG_ERROR("channel %d received data on window waiting",
                          channel->local_channel);
                return SSH_ERROR;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                ssh_buffer_unpack(session->in_buffer, "d", &bytes_to_add);
                LOG_NOTICE("remote window grows: +%d", bytes_to_add);
                channel->remote_window += bytes_to_add;
                return SSH_OK;
            case SSH_MSG_CHANNEL_EOF:
                LOG_ERROR("channel %d received EOF on window waiting",
                          channel->local_channel);
                return SSH_ERROR;
            case SSH_MSG_CHANNEL_CLOSE:
                LOG_ERROR("remote channel %d closed on window waiting",
                          channel->remote_channel);
                return SSH_ERROR;
            default:
                LOG_ERROR("unexpected message type %d on window waiting", type);
                return SSH_ERROR;
        }
    }

    return SSH_OK;
}

/**
 * @brief Create a new channel and attach it to the SSH session.
 *
 * @param session
 * @return ssh_channel
 */
ssh_channel ssh_channel_new(ssh_session session) {
    ssh_channel channel = NULL;

    if (session == NULL) {
        return NULL;
    }

    channel = calloc(1, sizeof(struct ssh_channel_struct));
    if (channel == NULL) {
        LOG_ERROR("can not create ssh channel");
        return NULL;
    }

    channel->out_buffer = ssh_buffer_new();
    if (channel->out_buffer == NULL) {
        LOG_ERROR("can not create buffer");
        SAFE_FREE(channel);
        return NULL;
    }

    channel->session = session;
    session->channel = channel;

    return channel;
}

/**
 * @brief Open a channel for `session` service
 * @see RFC4254 section 6.1
 *
 * @param channel
 * @return int
 */
int ssh_channel_open_session(ssh_channel channel) {
    if (channel == NULL) {
        return SSH_ERROR;
    }

    return channel_open(channel, "session", CHANNEL_INITIAL_WINDOW,
                        CHANNEL_MAX_PACKET, NULL);
}

/**
 * @brief Request SFTP subsystem service on an opened channel.
 *
 * @param channel
 * @return int
 */
int ssh_channel_request_sftp(ssh_channel channel) {
    ssh_buffer subsys = NULL;
    int rc;

    if (channel == NULL) {
        return SSH_ERROR;
    }

    subsys = ssh_buffer_new();
    if (subsys == NULL) {
        LOG_ERROR("can not create buffer");
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(subsys, "s", "sftp");

    rc = channel_request(channel, "subsystem", 1, subsys);
    if (rc != SSH_OK) {
        ssh_buffer_free(subsys);
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Write data to the channel. This function would block until `len` bytes
 * of data are written.
 *
 * @param channel
 * @param data
 * @param len
 * @return bytes written, SSH_ERR on error.
 */
int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len) {
    ssh_session session;
    uint32_t origlen = len;
    size_t effectivelen;
    size_t maxpacketlen;
    int rc;

    if (channel == NULL || data == NULL || len > INT_MAX) {
        LOG_ERROR("param error");
        ssh_set_error(SSH_FATAL, "invalid params");
        return SSH_ERROR;
    }

    if (channel->local_eof) {
        ssh_set_error(SSH_REQUEST_DENIED,
                      "Can't write to channel %d:%d  after EOF was sent",
                      channel->local_channel, channel->remote_channel);
        return SSH_ERROR;
    }

    session = channel->session;
    /*
     * Handle the max packet len from remote side
     * be nice, 10 bytes for the headers
     */
    maxpacketlen = channel->remote_maxpacket - 10;

    while (len > 0) {
        if (channel->remote_window < len) {
            if (channel->remote_window == 0) {
                /* can not send, wait for window adjust message */
                rc = wait_window(channel);
                if (rc != SSH_OK) goto error;
            }
            effectivelen = MIN(len, channel->remote_window);
        } else {
            effectivelen = len;
        }
        effectivelen = MIN(effectivelen, maxpacketlen);

        rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_DATA,
                             channel->remote_channel);
        if (rc != SSH_OK) goto error;

        rc = ssh_buffer_pack(session->out_buffer, "dP", effectivelen,
                             effectivelen, data);
        if (rc != SSH_OK) goto error;

        rc = ssh_packet_send(session);
        if (rc != SSH_OK) goto error;

        channel->remote_window -= effectivelen;
        len -= effectivelen;
        data = ((uint8_t *)data + effectivelen);
    }

    return origlen;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Read data from channel. This function would block until `count` bytes
 * of data is read.
 *
 * @todo take care of static `buf`
 * @param channel
 * @param dest
 * @param count
 * @return bytes read, SSH_ERR on error.
 */
int ssh_channel_read(ssh_channel channel, void *dest, uint32_t count) {
    ssh_session session;
    static ssh_buffer buf = NULL;
    ssh_string channel_data = NULL;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    uint32_t effectivelen;
    uint32_t nread = 0;
    ssh_string req;
    bool want;
    int rc;

    if (channel == NULL) return SSH_ERROR;
    session = channel->session;

    if (channel->remote_eof) return SSH_EOF;

    if (buf == NULL) buf = ssh_buffer_new();

    /* local window should be at least `count` size */
    if (count >= channel->local_window) {
        grow_window(channel, count);
    }

    while (count > 0) {
        if (ssh_buffer_get_len(buf) > 0) {
            /* try to read channel data from static buffer first */
            // LAB: insert your code here. (finished)
            uint32_t len;
            ssh_buffer_unpack(buf, "d", &len);
            if (len <= count)
            {
                ssh_buffer_get_data(buf, dest, len);
                count -= len, dest += len, nread += len;
            }
            else
            {
                ssh_buffer_get_data(buf, dest, count);
                dest += count, nread += count;
                len -= count;
                ssh_buffer_prepend_data(buf, &len, sizeof(uint32_t));
                count = 0;
            }

        } else {
            /* static buffer has insufficient data, read another
             * SSH_MSG_CHANNEL_DATA packet */
            rc = ssh_packet_receive(session);
            if (rc != SSH_OK) goto error;

            rc = ssh_buffer_unpack(session->in_buffer, "bd", &type,
                                   &recipient_channel);
            if (recipient_channel != channel->local_channel) {
                LOG_ERROR(
                    "channel number in the reply %d does not match with the "
                    "original %d",
                    recipient_channel, channel->local_channel);
                goto error;
            }
            switch (type) {
                case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    /* window adjust message could happen here */
                    // LAB: insert your code here. (finished)
                    rc = ssh_buffer_get_u32(session->in_buffer, &bytes_to_add);
                    channel->remote_window += bytes_to_add;
                    break;

                case SSH_MSG_CHANNEL_DATA:
                    // LAB: insert your code here. (finished)
                    channel_data = ssh_buffer_get_ssh_string(session->in_buffer);
                    ssh_buffer_add_ssh_string(buf, channel_data);
                    ssh_string_free(channel_data);
                    break;

                case SSH_MSG_CHANNEL_EOF:
                    // LAB: insert your code here. (finished)
                    channel->remote_eof = 1;
                    goto cleanup;

                case SSH_MSG_CHANNEL_CLOSE:
                    // LAB: insert your code here. (finished)
                    goto cleanup;

                case SSH_MSG_CHANNEL_REQUEST:
                    // LAB: insert your code here. (finished)
                    rc = ssh_buffer_unpack(session->in_buffer, "Sb", &req, &want);
                    if (want)
                    {
                        rc = ssh_buffer_add_u8(session->out_buffer,
                            SSH_MSG_REQUEST_FAILURE);
                        if (rc != SSH_OK) {
                            LOG_ERROR("can not create buffer");
                            return SSH_ERROR;
                        }
                        if (ssh_packet_send(session) != SSH_OK) return SSH_ERROR;
                    }
                    break;

                default:
                    // LAB: insert your code here. (finished)
                    LOG_ERROR("unexpected message type %d on channel reading", type);
                    goto error;

            }
        }
    }

    return nread;

error:
    if (buf != NULL) ssh_buffer_free(buf);
    if (channel_data != NULL) ssh_string_free(channel_data);
    return SSH_ERROR;

cleanup:
    if (buf != NULL) ssh_buffer_free(buf);
    if (channel_data != NULL) ssh_string_free(channel_data);
    return SSH_EOF;
}

/**
 * @brief Send EOF to the channel.
 *
 * @param channel
 * @return int
 */
int ssh_channel_eof(ssh_channel channel) {
    ssh_session session;
    int rc;

    if (channel == NULL || channel->session == NULL) {
        return SSH_ERROR;
    }

    /* If the EOF has already been sent we're done here. */
    if (channel->local_eof != 0) {
        return SSH_OK;
    }

    session = channel->session;

    rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_EOF,
                         channel->remote_channel);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        goto error;
    }

    if (ssh_packet_send(session) != SSH_OK) goto error;

    channel->local_eof = 1;
    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Close a SSH channel. Send SSH_CHANNEL_CLOSE and wait for reply.
 *
 * RFC 4254 section 5.3
 * The channel is considered closed for a
 * party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and
 * the party may then reuse the channel number.  A party MAY send
 * SSH_MSG_CHANNEL_CLOSE without having sent or receive
 * SSH_MSG_CHANNEL_EOF.
 *
 */
int ssh_channel_close(ssh_channel channel) {
    ssh_session session;
    uint8_t type;
    uint32_t recipient_channel;
    int rc;

    if (channel == NULL) {
        return SSH_ERROR;
    }

    session = channel->session;

    rc = ssh_channel_eof(channel);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_CLOSE,
                         channel->remote_channel);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        goto error;
    }

    rc = ssh_packet_send(session);

    /* wait for SSH_MSG_CHANNEL_CLOSE reply */
    type = 0;
    while (type != SSH_MSG_CHANNEL_CLOSE) {
        rc = ssh_packet_receive(session);
        rc = ssh_buffer_unpack(session->in_buffer, "bd", &type,
                               &recipient_channel);
        if (recipient_channel != channel->local_channel) {
            LOG_ERROR(
                "channel number in the reply %d does not match with the "
                "original %d",
                recipient_channel, channel->local_channel);
            return SSH_ERROR;
        }
        LOG_NOTICE("received code %d during channel close", type);
    }

    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Free the channel and deallocate its resource.
 *
 * @param channel
 */
void ssh_channel_free(ssh_channel channel) {
    ssh_buffer_free(channel->out_buffer);
    channel->session->channel = NULL;
    channel->session = NULL;
    SAFE_FREE(channel);
}