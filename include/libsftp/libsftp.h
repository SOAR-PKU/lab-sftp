/**
 * @file sftp.h
 * @author Yuhan Zhou
 * @brief SFTP APIs
 * @version 0.1
 * @date 2022-07-14
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SFTP_H
#define SFTP_H

#include "libssh.h"

#define LIBSFTP_VERSION 3

/**
 * Constants defined in RFC2026, we only use a subset of them
 */

/* Request or response types */
#define SSH_FXP_INIT 1
#define SSH_FXP_VERSION 2
#define SSH_FXP_OPEN 3
#define SSH_FXP_CLOSE 4
#define SSH_FXP_READ 5
#define SSH_FXP_WRITE 6
#define SSH_FXP_LSTAT 7
#define SSH_FXP_FSTAT 8
#define SSH_FXP_SETSTAT 9
#define SSH_FXP_FSETSTAT 10
#define SSH_FXP_OPENDIR 11
#define SSH_FXP_READDIR 12
#define SSH_FXP_REMOVE 13
#define SSH_FXP_MKDIR 14
#define SSH_FXP_RMDIR 15
#define SSH_FXP_REALPATH 16
#define SSH_FXP_STAT 17
#define SSH_FXP_RENAME 18
#define SSH_FXP_READLINK 19
#define SSH_FXP_SYMLINK 20

#define SSH_FXP_STATUS 101
#define SSH_FXP_HANDLE 102
#define SSH_FXP_DATA 103
#define SSH_FXP_NAME 104
#define SSH_FXP_ATTRS 105

#define SSH_FXP_EXTENDED 200
#define SSH_FXP_EXTENDED_REPLY 201

/* File attributes indicators */
#define SSH_FILEXFER_ATTR_SIZE 0x00000001
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004
#define SSH_FILEXFER_ATTR_ACCESSTIME 0x00000008
#define SSH_FILEXFER_ATTR_ACMODTIME 0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME 0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME 0x00000020
#define SSH_FILEXFER_ATTR_ACL 0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP 0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES 0x00000100
#define SSH_FILEXFER_ATTR_EXTENDED 0x80000000
#define SSH_FILEXFER_ATTR_UIDGID 0x00000002

/* Types */
#define SSH_FILEXFER_TYPE_REGULAR 1
#define SSH_FILEXFER_TYPE_DIRECTORY 2
#define SSH_FILEXFER_TYPE_SYMLINK 3
#define SSH_FILEXFER_TYPE_SPECIAL 4
#define SSH_FILEXFER_TYPE_UNKNOWN 5

/* Permission flags */
#define SSH_FXF_READ 0x01
#define SSH_FXF_WRITE 0x02
#define SSH_FXF_APPEND 0x04
#define SSH_FXF_CREAT 0x08
#define SSH_FXF_TRUNC 0x10
#define SSH_FXF_EXCL 0x20
#define SSH_FXF_TEXT 0x40

/* Status codes */
/** No error */
#define SSH_FX_OK 0
/** End-of-file encountered */
#define SSH_FX_EOF 1
/** File doesn't exist */
#define SSH_FX_NO_SUCH_FILE 2
/** Permission denied */
#define SSH_FX_PERMISSION_DENIED 3
/** Generic failure */
#define SSH_FX_FAILURE 4
/** Garbage received from server */
#define SSH_FX_BAD_MESSAGE 5
/** No connection has been set up */
#define SSH_FX_NO_CONNECTION 6
/** There was a connection, but we lost it */
#define SSH_FX_CONNECTION_LOST 7
/** Operation not supported by the server */
#define SSH_FX_OP_UNSUPPORTED 8
/** Invalid file handle */
#define SSH_FX_INVALID_HANDLE 9
/** No such file or directory path exists */
#define SSH_FX_NO_SUCH_PATH 10
/** An attempt to create an already existing file or directory has been made */
#define SSH_FX_FILE_ALREADY_EXISTS 11
/** We are trying to write on a write-protected filesystem */
#define SSH_FX_WRITE_PROTECT 12
/** No media in remote drive */
#define SSH_FX_NO_MEDIA 13

#define SSH_FXP_MAXLEN 32768

typedef struct sftp_session_struct* sftp_session;
typedef struct sftp_file_struct* sftp_file;
typedef struct sftp_packet_struct* sftp_packet;
typedef struct sftp_attributes_struct* sftp_attributes;
typedef struct sftp_status_struct* sftp_status;


/**
 * @brief Creates a new sftp session.
 *
 * This function creates a new sftp session and allocates a new sftp channel
 * with the server inside of the provided ssh session. This function call is
 * usually followed by the sftp_init(), which initializes SFTP protocol itself.
 *
 * @param session       The ssh session to use.
 *
 * @return              A new sftp session or NULL on error.
 *
 * @see sftp_free()
 * @see sftp_init()
 */
API sftp_session sftp_new(ssh_session session);

/**
 * @brief Close and deallocate a sftp session.
 * Internally, it close the underlying SSH channel.
 *
 * @param sftp          The sftp session handle to free.
 */
API void sftp_free(sftp_session sftp);

/**
 * @brief Initialize the sftp protocol with the server.
 *
 * This function involves the SFTP protocol initialization (as described
 * in the SFTP specification), including the version and extensions negotiation.
 *
 * @param sftp          The sftp session to initialize.
 *
 * @return              0 on success, < 0 on error with ssh error set.
 *
 * @see sftp_new()
 */
API int sftp_init(sftp_session sftp);

/**
 * @brief Close an open file handle.
 *
 * @param file          The open sftp file handle to close.
 *
 * @return              Returns SSH_NO_ERROR or SSH_ERROR if an error occured.
 *
 * @see                 sftp_open()
 */
API int sftp_close(sftp_file file);

/**
 * @brief Open a file on the server.
 *
 * @param session       The sftp session handle.
 *
 * @param file          The file to be opened.
 *
 * @param accesstype    Is one of O_RDONLY, O_WRONLY or O_RDWR which request
 *                      opening  the  file  read-only,write-only or read/write.
 *                      Acesss may also be bitwise-or'd with one or  more of
 *                      the following:
 *                      O_CREAT - If the file does not exist it will be
 *                      created.
 *                      O_EXCL - When  used with O_CREAT, if the file already
 *                      exists it is an error and the open will fail.
 *                      O_TRUNC - If the file already exists it will be
 *                      truncated.
 *
 * @param mode          Mode specifies the permissions to use if a new file is
 *                      created.  It  is  modified  by  the process's umask in
 *                      the usual way: The permissions of the created file are
 *                      (mode & ~umask)
 *
 * @return              A sftp file handle, NULL on error with ssh and sftp
 *                      error set.
 *
 * @see sftp_get_error()
 */
API sftp_file sftp_open(sftp_session sftp, const char* file, int accesstype,
                        mode_t mode);

/**
 * @brief Get information about a file or directory.
 * @todo Not implemented
 * @param session       The sftp session handle.
 * @param path          The path to the file or directory to obtain the
 *                      information.
 *
 * @return              The sftp attributes structure of the file or directory,
 *                      NULL on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
API sftp_attributes sftp_stat(sftp_session session, const char *path);

/**
 * @brief Read from a file using an opened sftp file handle.
 *
 * @param file          The opened sftp file handle to be read from.
 *
 * @param buf           Pointer to buffer to recieve read data.
 *
 * @param count         Size of the buffer in bytes.
 *
 * @return              Number of bytes read, < 0 on error with ssh and sftp
 *                      error set.
 *
 * @see sftp_get_error()
 */
API int32_t sftp_read(sftp_file file, void* buf, uint32_t count);

/**
 * @brief Write to a file using an opened sftp file handle.
 *
 * @param file          Open sftp file handle to write to.
 *
 * @param buf           Pointer to buffer to write data.
 *
 * @param count         Size of buffer in bytes.
 *
 * @return              Number of bytes written, < 0 on error with ssh and sftp
 *                      error set.
 *
 * @see                 sftp_open()
 * @see                 sftp_read()
 * @see                 sftp_close()
 */
API int32_t sftp_write(sftp_file file, const void* buf, uint32_t count);

#endif /* SFTP_H */