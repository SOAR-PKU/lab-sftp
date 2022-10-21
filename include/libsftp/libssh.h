/**
 * @file libssh.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH APIs
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef LIBSSH_H
#define LIBSSH_H

#include <sys/types.h>
#include <stdint.h>

#define API

/* SSHv2 message types */

/* Additional messages */
#define SSH_MSG_DISCONNECT 1
#define SSH_MSG_IGNORE 2
#define SSH_MSG_UNIMPLEMENTED 3
#define SSH_MSG_DEBUG 4
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT 6
#define SSH_MSG_EXT_INFO 7

/* Key exchange */
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_NEWKEYS 21

#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_KEXDH_REPLY 31
#define SSH_MSG_KEX_ECDH_INIT 30
#define SSH_MSG_KEX_ECDH_REPLY 31
#define SSH_MSG_ECMQV_INIT 30
#define SSH_MSG_ECMQV_REPLY 31

#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD 30
#define SSH_MSG_KEX_DH_GEX_GROUP 31
#define SSH_MSG_KEX_DH_GEX_INIT 32
#define SSH_MSG_KEX_DH_GEX_REPLY 33
#define SSH_MSG_KEX_DH_GEX_REQUEST 34

/* Authentication */
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_BANNER 53
#define SSH_MSG_USERAUTH_PK_OK 60
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ 60
#define SSH_MSG_USERAUTH_INFO_REQUEST 60
#define SSH_MSG_USERAUTH_GSSAPI_RESPONSE 60
#define SSH_MSG_USERAUTH_INFO_RESPONSE 61
#define SSH_MSG_USERAUTH_GSSAPI_TOKEN 61
#define SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE 63
#define SSH_MSG_USERAUTH_GSSAPI_ERROR 64
#define SSH_MSG_USERAUTH_GSSAPI_ERRTOK 65
#define SSH_MSG_USERAUTH_GSSAPI_MIC 66

/* User request and server response */
#define SSH_MSG_GLOBAL_REQUEST 80
#define SSH_MSG_REQUEST_SUCCESS 81
#define SSH_MSG_REQUEST_FAILURE 82

/* Connection channel */
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA 94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF 96
#define SSH_MSG_CHANNEL_CLOSE 97
#define SSH_MSG_CHANNEL_REQUEST 98
#define SSH_MSG_CHANNEL_SUCCESS 99
#define SSH_MSG_CHANNEL_FAILURE 100

/* Disconnection reason code */
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT 1
#define SSH_DISCONNECT_PROTOCOL_ERROR 2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED 3
#define SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED 4
#define SSH_DISCONNECT_RESERVED 4
#define SSH_DISCONNECT_MAC_ERROR 5
#define SSH_DISCONNECT_COMPRESSION_ERROR 6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE 7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED 8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE 9
#define SSH_DISCONNECT_CONNECTION_LOST 10
#define SSH_DISCONNECT_BY_APPLICATION 11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS 12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER 13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE 14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME 15

/* Channel failure reason code */
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define SSH_OPEN_CONNECT_FAILED 2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE 3
#define SSH_OPEN_RESOURCE_SHORTAGE 4

#define SSH_EXTENDED_DATA_STDERR 1

/* Error return codes */
#define SSH_OK 0     /* No error */
#define SSH_ERROR -1 /* Error of some kind */
#define SSH_AGAIN -2 /* The nonblocking call must be repeated */
#define SSH_EOF -127 /* We have already a eof */

enum ssh_options_e {
    SSH_OPTIONS_HOST,
    SSH_OPTIONS_PORT,
    SSH_OPTIONS_USER,
};


/* ssh API */
typedef struct ssh_session_struct *ssh_session;
API ssh_session ssh_new(void);
API int ssh_options_set(ssh_session session, enum ssh_options_e type, const void *value);
API int ssh_connect(ssh_session session);
API void ssh_disconnect(ssh_session session);
API void ssh_free(ssh_session session);

/* Authentication API */
API int ssh_userauth_password(ssh_session session, const char *password);
API void ssh_get_password(char *password);

/* buffer API */
typedef struct ssh_buffer_struct *ssh_buffer;
API ssh_buffer ssh_buffer_new(void);
API void ssh_buffer_free(ssh_buffer buffer);
API int ssh_buffer_reinit(ssh_buffer buffer);
API int ssh_buffer_add_data(ssh_buffer buffer, const void *data, uint32_t len);
API uint32_t ssh_buffer_get_data(ssh_buffer buffer, void *data,
                                 uint32_t requestedlen);
API void *ssh_buffer_get(ssh_buffer buffer);
API uint32_t ssh_buffer_get_len(ssh_buffer buffer);

/* error API */
API char *ssh_get_error(void);
API char *sftp_get_error(void);

/* string API */
typedef struct ssh_string_struct *ssh_string;
API void ssh_string_burn(ssh_string str);
API ssh_string ssh_string_copy(ssh_string str);
API void *ssh_string_data(ssh_string str);
API int ssh_string_fill(ssh_string str, const void *data, size_t len);
#define SSH_STRING_FREE(x)      \
    do {                        \
        if ((x) != NULL) {      \
            ssh_string_free(x); \
            x = NULL;           \
        }                       \
    } while (0)
API void ssh_string_free(ssh_string str);
API ssh_string ssh_string_from_char(const char *what);
API size_t ssh_string_len(ssh_string str);
API ssh_string ssh_string_new(size_t size);
API const char *ssh_string_get_char(ssh_string str);
API char *ssh_string_to_char(ssh_string str);
#define SSH_STRING_FREE_CHAR(x)      \
    do {                             \
        if ((x) != NULL) {           \
            ssh_string_free_char(x); \
            x = NULL;                \
        }                            \
    } while (0)
API void ssh_string_free_char(char *s);

/* universal defs */
typedef struct ssh_key_struct* ssh_key;

#endif /* LIBSSH_H */
