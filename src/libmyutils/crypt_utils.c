#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/openssl/conf.h"
#include "../../include/openssl/evp.h"
#include "../../include/openssl/err.h"
#include "../../include/openssl/crypto.h"
#include "../../include/openssl/hmac.h"


char *hexstr_u(char *input, int input_len) {
    char *output;
    int loc_len;
    /* allocate space for output string */
    loc_len = (input_len * 2) + 1;
    output = (char *) malloc(loc_len * sizeof(char));
    if (output == NULL) {
        fprintf(
                stderr,
                "[ERROR] [crypt_utils.c, hexstr_u]: "
                "output string allocation failed.\n"
        );
        return NULL;
    }
    /* fill output string with hex characters */
    int j = 0;
    for (int i = 0; i < input_len; i++) {
        sprintf((char *) (output + j), "%02x", (unsigned char) input[i]);
        j += 2;
    }
    output[j + 1] = '\0';
    return output;
}


int digest_message(const unsigned char *message, size_t message_len,
                   unsigned char **digest, unsigned int *digest_len,
                   const EVP_MD *md) {
    EVP_MD_CTX *mdctx = NULL;
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
        return 1;
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if ((*digest = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md))) == NULL) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)) {
        OPENSSL_free(*digest);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}


char *mdstr(const char *input, const int size, const EVP_MD *md) {
    char *output, *digest;
    unsigned char *ssl_digest;
    unsigned int digest_len;
    int ecode;
    ecode = digest_message((unsigned char *) input, (size_t) size,
                           &ssl_digest, &digest_len, md);
    if (ecode != 0) {
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, mdstr]: "
                "message digest failed.\n");
        return NULL;
    }
    digest = (char *) malloc(digest_len * sizeof(char));
    if (digest == NULL) {
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, mdstr]: "
                "temporary digest allocation failed.\n");
        return NULL;
    }
    memcpy(digest, ssl_digest, digest_len);
    OPENSSL_free(ssl_digest);
    output = hexstr_u(digest, digest_len);
    if (output == NULL) {
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, mdstr]: "
                "conversion to hex string failed.\n");
        free(digest);
        return NULL;
    }
    free(digest);
    return output;
}


char *sha256_mdstr(const char *input, const int size)
{
    const EVP_MD *md = EVP_sha256();
    char *output;
    output = mdstr(input, size, md);
    return output;
}


struct hmac_output {
    unsigned char *hmac;
    size_t *hmac_size;
};


void free_hmac_output(struct hmac_output *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx->hmac);
    free(ctx->hmac_size);
    free(ctx);
}

struct hmac_output *get_hmac(const char *key, int key_len, const unsigned char *data,
                           size_t data_len, const EVP_MD *evp_md)
{
    unsigned char *digest, *hmac_out, *output;
    /* get space for digest */
    digest = (unsigned char *) OPENSSL_malloc(EVP_MD_size(evp_md));
    if (digest == NULL) {
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, get_hmac]: "
                "digest allocation failed.\n");
        return NULL;
    }
    /* compute message authentication code */
    unsigned int digest_len = 0;
    hmac_out = HMAC(evp_md,
                  key, key_len,
                  data, data_len,
                  digest, &digest_len);
    if (hmac_out == NULL) {
        OPENSSL_free(digest);
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, get_hmac]: "
                "hmac generation failed.\n");
        return NULL;
    }
    /* copy over to output char array */
    output = (unsigned char *) malloc((size_t)digest_len * sizeof(unsigned char));
    if (output == NULL) {
        OPENSSL_free(digest);
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, get_hmac]: "
                "hmac output allocation failed.\n");
        return NULL;
    }
    memcpy(output, digest, digest_len);
    OPENSSL_free(digest);
    struct hmac_output *out_struct;
    out_struct = malloc(sizeof(struct hmac_output));
    if (out_struct == NULL) {
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, get_hmac]: "
                "hmac object allocation failed.\n");
        free(output);
        return NULL;
    }
    out_struct->hmac_size = (size_t *) malloc(sizeof(size_t));
    if (out_struct->hmac_size == NULL) {
        fprintf(stderr,
                "[ERROR] [crypt_utils.c, get_hmac]: "
                "hmac object int attribute allocation failed.\n");
        free(output);
        free(out_struct);
        return NULL;
    }
    *(out_struct->hmac_size) = ((size_t) digest_len) * sizeof(unsigned char);
    out_struct->hmac = NULL;
    out_struct->hmac = (char *) output;
    return out_struct;
}


struct hmac_output *sha256_hmac(const char *key, int key_len, const unsigned char *data, size_t data_len)
{
    const EVP_MD *evp_md = EVP_sha256();
    struct hmac_output *output;
    output = get_hmac(key, key_len, data, data_len, evp_md);
    return output;
}

