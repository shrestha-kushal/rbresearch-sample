#ifndef REMOTE_BLACK_BOX_AWS_H
#define REMOTE_BLACK_BOX_AWS_H

#include <stdlib.h>

char *sha256_signature(const char *method, size_t method_size,
                       const char *uri, size_t uri_size,
                       const char *query, size_t query_size,
                       const char *headers, size_t headers_size,
                       const char *sheaders, size_t sheaders_size,
                       const char *payload, size_t payload_size,
                       const char *requestdtm, size_t requestdtm_size,
                       const char *date, size_t date_size,
                       const char *region, size_t region_size,
                       const char *service, size_t service_size,
                       const char *secret, size_t secret_size);

#endif //REMOTE_BLACK_BOX_AWS_H
