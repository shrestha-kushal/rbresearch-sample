#ifndef REMOTE_BLACK_BOX_CRYPT_UTILS_H
#define REMOTE_BLACK_BOX_CRYPT_UTILS_H

struct hmac_output {
    char *hmac;
    int *hmac_size;
};

char *hexstr_u(char *input, int input_len);
char *sha256_mdstr(const char *input, const int size);
void free_hmac_output(struct hmac_output *ctx);
struct hmac_output *sha256_hmac(const char *key, int key_len, const unsigned char *data, size_t data_len);

#endif // REMOTE_BLACK_BOX_CRYPT_UTILS_H
