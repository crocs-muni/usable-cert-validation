#ifndef CLIENT_H
#define CLIENT_H

/* Buffer lengths for command line arguments */
#define HOST_BUFFER_LENGTH 256
#define PORT_BUFFER_LENGTH 16
#define PATH_BUFFER_LENGTH 4096

#define PARSING_SUCCESS 0
#define PARSING_ERROR 1

/* Macros for dealing with mbedTLS errors */
#define MBEDTLS_FAIL(x)                                                        \
  do {                                                                         \
    char error_buffer[500] = "";                                               \
    mbedtls_strerror(x, error_buffer, 500);                                    \
    fprintf(stderr, "%s\n", error_buffer);                                     \
    ret = EXIT_FAILURE;                                                        \
    goto cleanup;                                                              \
  } while (0)

#define MBEDTLS_CHECK(x)                                                       \
  if ((ret = (x)) != 0) {                                                      \
    MBEDTLS_FAIL(ret);                                                         \
  }

/* Macro for dealing with custom application errors */
#define CUSTOM_FAIL(error)                                                     \
  do {                                                                         \
    ret = EXIT_FAILURE;                                                        \
    fprintf(stderr, "Application error: %s\n", error);                         \
    goto cleanup;                                                              \
  } while (0)

/* Possible command line arguments */
struct tls_options {
  /* Path to a local certificate revocation list */
  char crl_file[PATH_BUFFER_LENGTH];
  /* Hostname to connect to */
  char host[HOST_BUFFER_LENGTH];
  /* Port number to use for the connection */
  char port[PORT_BUFFER_LENGTH];
  /* Path to a trusted root certificate */
  char trust_anchor[PATH_BUFFER_LENGTH];
};

/* Function to parse the command line arguments */
int parse_opts(int argc, char **argv, struct tls_options *opts);

#endif