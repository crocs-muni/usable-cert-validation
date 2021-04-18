#ifndef CLIENT_H
#define CLIENT_H

int get_purpose_id(const char *purpose);
int get_trust_id(const char *trust);
int tcp_connect(const char *host, const char *port);

#endif