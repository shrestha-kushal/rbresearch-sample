#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./crypt_utils.h"


struct sign_context {
    char *method;
    size_t *method_size;
    char *uri;
    size_t *uri_size;
    char *query;
    size_t *query_size;
    char *headers;
    size_t *headers_size;
    char *sheaders;
    size_t *sheaders_size;
    char *payload;
    size_t *payload_size;
    char *payload_hash;
    size_t *payload_hash_size;
    char *canon_request;
    size_t *canon_request_size;
    char *canon_hash;
    size_t *canon_hash_size;
    char *algorithm;
    size_t *algorithm_size;
    char *requestdtm;
    size_t *requestdtm_size;
    char *date;
    size_t *date_size;
    char *region;
    size_t *region_size;
    char *service;
    size_t *service_size;
    char *secret;
    size_t *secret_size;
    char *scope;
    size_t *scope_size;
    char *str_sign;
    size_t *str_sign_size;
    char *signature;
    size_t *signature_size;
};


struct sign_context *init_ctx()
{
    struct sign_context *ctx;
    ctx = malloc(sizeof(struct sign_context));
    if (ctx == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, init_ctx]: "
                "unable to allocate space for context object.\n");
        return NULL;
    }
    ctx->method = NULL;
    ctx->method_size = NULL;
    ctx->uri = NULL;
    ctx->uri_size = NULL;
    ctx->query = NULL;
    ctx->query_size = NULL;
    ctx->headers = NULL;
    ctx->headers_size = NULL;
    ctx->sheaders = NULL;
    ctx->sheaders_size = NULL;
    ctx->payload = NULL;
    ctx->payload_size = NULL;
    ctx->payload_hash = NULL;
    ctx->payload_hash_size = NULL;
    ctx->canon_request = NULL;
    ctx->canon_request_size = NULL;
    ctx->canon_hash = NULL;
    ctx->canon_hash_size = NULL;
    ctx->algorithm = NULL;
    ctx->algorithm_size = NULL;
    ctx->requestdtm = NULL;
    ctx->requestdtm_size = NULL;
    ctx->date = NULL;
    ctx->date_size = NULL;
    ctx->region = NULL;
    ctx->region_size = NULL;
    ctx->service = NULL;
    ctx->service_size = NULL;
    ctx->secret = NULL;
    ctx->secret_size = NULL;
    ctx->scope = NULL;
    ctx->scope_size = NULL;
    ctx->str_sign = NULL;
    ctx->str_sign_size = NULL;
    ctx->signature = NULL;
    ctx->signature_size = NULL;
    return ctx;
}


void free_ctx(struct sign_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx->method);
    free(ctx->method_size);
    free(ctx->uri);
    free(ctx->uri_size);
    free(ctx->query);
    free(ctx->query_size);
    free(ctx->headers);
    free(ctx->headers_size);
    free(ctx->sheaders);
    free(ctx->sheaders_size);
    free(ctx->payload);
    free(ctx->payload_size);
    free(ctx->payload_hash);
    free(ctx->payload_hash_size);
    free(ctx->canon_request);
    free(ctx->canon_request_size);
    free(ctx->canon_hash);
    free(ctx->canon_hash_size);
    free(ctx->algorithm);
    free(ctx->algorithm_size);
    free(ctx->requestdtm);
    free(ctx->requestdtm_size);
    free(ctx->date);
    free(ctx->date_size);
    free(ctx->region);
    free(ctx->region_size);
    free(ctx->service);
    free(ctx->service_size);
    free(ctx->secret);
    free(ctx->secret_size);
    free(ctx->scope);
    free(ctx->scope_size);
    free(ctx->str_sign);
    free(ctx->str_sign_size);
    free(ctx->signature);
    free(ctx->signature_size);
    free(ctx);
    ctx = NULL;
}


int set_ctx_component(struct sign_context *ctx, const char* component, const char* data, size_t dsize)
{
    char **ctx_data;
    size_t **ctx_dsize;
    if (strcmp(component, "method") == 0) {
        ctx_data = &(ctx->method);
        ctx_dsize = &(ctx->method_size);
    }
    else if (strcmp(component, "uri") == 0) {
        ctx_data = &(ctx->uri);
        ctx_dsize = &(ctx->uri_size);
    }
    else if (strcmp(component, "query") == 0) {
        ctx_data = &(ctx->query);
        ctx_dsize = &(ctx->query_size);
    }
    else if (strcmp(component, "headers") == 0) {
        ctx_data = &(ctx->headers);
        ctx_dsize = &(ctx->headers_size);
    }
    else if (strcmp(component, "sheaders") == 0) {
        ctx_data = &(ctx->sheaders);
        ctx_dsize = &(ctx->sheaders_size);
    }
    else if (strcmp(component, "payload") == 0) {
        ctx_data = &(ctx->payload);
        ctx_dsize = &(ctx->payload_size);
    }
    else if (strcmp(component, "payload_hash") == 0) {
        ctx_data = &(ctx->payload_hash);
        ctx_dsize = &(ctx->payload_hash_size);
    }
    else if (strcmp(component, "canon_request") == 0) {
        ctx_data = &(ctx->canon_request);
        ctx_dsize = &(ctx->canon_request_size);
    }
    else if (strcmp(component, "canon_hash") == 0) {
        ctx_data = &(ctx->canon_hash);
        ctx_dsize = &(ctx->canon_hash_size);
    }
    else if (strcmp(component, "algorithm") == 0) {
        ctx_data = &(ctx->algorithm);
        ctx_dsize = &(ctx->algorithm_size);
    }
    else if (strcmp(component, "requestdtm") == 0) {
        ctx_data = &(ctx->requestdtm);
        ctx_dsize = &(ctx->requestdtm_size);
    }
    else if (strcmp(component, "date") == 0) {
        ctx_data = &(ctx->date);
        ctx_dsize = &(ctx->date_size);
    }
    else if (strcmp(component, "region") == 0) {
        ctx_data = &(ctx->region);
        ctx_dsize = &(ctx->region_size);
    }
    else if (strcmp(component, "service") == 0) {
        ctx_data = &(ctx->service);
        ctx_dsize = &(ctx->service_size);
    }
    else if (strcmp(component, "secret") == 0) {
        ctx_data = &(ctx->secret);
        ctx_dsize = &(ctx->secret_size);
    }
    else if (strcmp(component, "scope") == 0) {
        ctx_data = &(ctx->scope);
        ctx_dsize = &(ctx->scope_size);
    }
    else if (strcmp(component, "str_sign") == 0) {
        ctx_data = &(ctx->str_sign);
        ctx_dsize = &(ctx->str_sign_size);
    }
    else if (strcmp(component, "signature") == 0) {
        ctx_data = &(ctx->signature);
        ctx_dsize = &(ctx->signature_size);
    }
    else {
        fprintf(stderr,
                "[ERROR] [aws.c, set_ctx_component]: "
                "unrecognized context element.\n");
        return 1;
    }
    if (*(data + dsize) != '\0') {
        fprintf(stderr,
                "[ERROR] [aws.c, set_ctx_component] :"
                "data string not null terminated.\n");
        return 1;
    }
    if ((*ctx_data != NULL ) || (*ctx_dsize != NULL)) {
        fprintf(stderr,
                "[ERROR] [aws.c, set_ctx_component] :"
                "context component may have already been assigned.\n");
        return 1;
    }
    *ctx_data = (char *) malloc((dsize + 1) * sizeof(char));
    if (*ctx_data == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, set_ctx_component]: "
                "unable to allocate space for context data component.\n");
        return 1;
    }
    *ctx_dsize = (size_t *) malloc(sizeof(size_t));
    if (*ctx_dsize == NULL) {
        free(*ctx_data);
        *ctx_data = NULL;
        fprintf(stderr,
                "[ERROR] [aws.c, set_ctx_component]: "
                "unable to allocate space for context data size component.\n");
        return 1;
    }
    strcpy(*ctx_data, data);
    **ctx_dsize = dsize;
    return 0;
}


char *canonicalize_request(struct sign_context *ctx)
{
    char *output = NULL;
    size_t datsize = 0;
    if (ctx->method == NULL || ctx->method_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "method or method size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->method_size) + 1; // one extra for '\n'
    if (ctx->uri == NULL || ctx->uri_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "uri or uri size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->uri_size) + 1; // one extra for '\n'
    if (ctx->query == NULL || ctx->query_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "query or query size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->query_size) + 1; // one extra for '\n'
    if (ctx->headers == NULL || ctx->headers_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "headers or headers size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->headers_size) + 1; // one extra for '\n'
    if (ctx->sheaders == NULL || ctx->sheaders_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "sheaders or sheaders size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->sheaders_size) + 1; // one extra for '\n'
    if (ctx->payload_hash == NULL || ctx->payload_hash_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "payload_hash or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->payload_hash_size);
    output = (char *) malloc((sizeof(char) * datsize) + 1);
    if (output == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, canonalize_request]: "
                "failed to allocate space for canonalized request.\n");
        goto error_1;
    }
    memset(output, ' ', datsize + 1);
    output[0] = '\0';
    strcat(output, ctx->method);
    strcat(output, "\n");
    strcat(output, ctx->uri);
    strcat(output, "\n");
    strcat(output, ctx->query);
    strcat(output, "\n");
    strcat(output, ctx->headers);
    strcat(output, "\n");
    strcat(output, ctx->sheaders);
    strcat(output, "\n");
    strcat(output, ctx->payload_hash);
error_1:
    return output;
}


char *siginput(const struct sign_context *ctx)
{
    char *output = NULL;
    size_t datsize = 0;
    if (ctx->algorithm == NULL || ctx->algorithm_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, siginput]: "
                "algorithm or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->algorithm_size) + 1; // one extra for '\n'
    if (ctx->requestdtm == NULL || ctx->requestdtm_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, siginput]: "
                "requestdtm or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->requestdtm_size) + 1; // one extra for '\n'
    if (ctx->scope == NULL || ctx->scope_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, siginput]: "
                "scope or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->scope_size) + 1; // one extra for '\n'
    if (ctx->canon_hash == NULL || ctx->canon_hash_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, siginput]: "
                "canon_hash or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->canon_hash_size);
    output = (char *) malloc((sizeof(char) * datsize) + 1);
    if (output == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, siginput]: "
                "failed to allocate space for signature input string.\n");
        goto error_1;
    }
    memset(output, ' ', datsize + 1);
    output[0] = '\0';
    strcat(output, ctx->algorithm);
    strcat(output, "\n");
    strcat(output, ctx->requestdtm);
    strcat(output, "\n");
    strcat(output, ctx->scope);
    strcat(output, "\n");
    strcat(output, ctx->canon_hash);
error_1:
    return output;
}


char *make_scope(const struct sign_context *ctx)
{
    char *output = NULL;
    size_t datsize = 0;
    if (ctx->date == NULL || ctx->date_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, make_scope]: "
                "date or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->date_size) + 1; // one extra for '/'
    if (ctx->region == NULL || ctx->region_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, make_scope]: "
                "region or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->region_size) + 1; // one extra for '/'
    if (ctx->service == NULL || ctx->service_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, make_scope]: "
                "service or its size is undefined.\n");
        goto error_1;
    }
    datsize += *(ctx->service_size) + 1; // one extra for '/'
    char *terminus = "aws4_request";
    datsize += strlen(terminus);
    output = (char *) malloc((sizeof(char) * datsize) + 1);
    if (output == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, siginput]: "
                "failed to allocate space for signature input string.\n");
        goto error_1;
    }
    memset(output, ' ', datsize + 1);
    output[0] = '\0';
    strcat(output, ctx->date);
    strcat(output, "/");
    strcat(output, ctx->region);
    strcat(output, "/");
    strcat(output, ctx->service);
    strcat(output, "/");
    strcat(output, terminus);
error_1:
    return output;
}


char *sign_string(const struct sign_context *ctx)
{
    char *output = NULL;
    if (ctx->secret == NULL || ctx->secret_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "secret or its size is undefined.\n");
        goto error_1;
    }
    if (ctx->date == NULL || ctx->date_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "date or its size is undefined.\n");
        goto error_1;
    }
    if (ctx->region == NULL || ctx->region_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "region or its size is undefined.\n");
        goto error_1;
    }
    if (ctx->service == NULL || ctx->service_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "service or its size is undefined.\n");
        goto error_1;
    }
    if (ctx->str_sign == NULL || ctx->str_sign_size == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "string-to-sign or its size is undefined.\n");
        goto error_1;
    }
    char *secret_prefix = "AWS4";
    size_t secret_size = 4 + *ctx->secret_size + 1;
    char *secret = (char *) malloc(secret_size * sizeof(char));
    if (secret == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "unable to allocate space for secret.\n");
        goto error_1;
    }
    memset(secret, ' ', secret_size);
    secret[0] = '\0';
    strcat(secret, secret_prefix);
    strcat(secret, ctx->secret);
    struct hmac_output *kdate, *kregion, *kservice, *ksigning, *ksignature;
    kdate = sha256_hmac(secret,
                        (int) secret_size,
                        (unsigned char *) ctx->date,
                        (size_t) *ctx->date_size);
    if (kdate == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "failed to sign secret with date.\n");
        goto error_2;
    }
    kregion = sha256_hmac((char *) kdate->hmac,
                           (int) *kdate->hmac_size,
                           (unsigned char *) ctx->region,
                           (size_t) *ctx->region_size);
    if (kregion == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "failed to sign kdate with region.\n");
        goto error_3;
    }
    kservice = sha256_hmac((char *) kregion->hmac,
                            (int) *kregion->hmac_size,
                            (unsigned char *) ctx->service,
                            (size_t) *ctx->service_size);
    if (kservice == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "failed to sign kregion with service.\n");
        goto error_4;
    }
    char *aws_str = "aws4_request";
    ksigning = sha256_hmac((char *) kservice->hmac,
                            (int) *kservice->hmac_size,
                            (unsigned char *) aws_str,
                            (size_t) strlen(aws_str));
    if (ksigning == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "failed to sign kregion with service.\n");
        goto error_5;
    }
    ksignature = sha256_hmac((char *) ksigning->hmac,
                            (int) *ksigning->hmac_size,
                            (unsigned char *) ctx->str_sign,
                            (size_t) *ctx->str_sign_size);
    if (ksignature == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "failed to sign string-to-sign with full key.\n");
        goto error_6;
    }
    char *output_raw;
    output_raw = (char *) malloc(sizeof(char) * (*ksignature->hmac_size) + 1);
    if (output_raw == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "unable to allocate space for signature.\n");
        goto error_7;
    }
    memcpy(output_raw, ksignature->hmac, (size_t) *ksignature->hmac_size);
    *(output_raw + *ksignature->hmac_size) = '\0';
    output = hexstr_u(output_raw, *ksignature->hmac_size);
    if (output == NULL) {
        fprintf(stderr,
                "[ERROR] [aws.c, sign_string]: "
                "unable to convert binary signature to hex character string.\n");
        goto error_8;
    }
error_8:
    free(output_raw);
error_7:
    free_hmac_output(ksignature);
error_6:
    free_hmac_output(ksigning);
error_5:
    free_hmac_output(kservice);
error_4:
    free_hmac_output(kregion);
error_3:
    free_hmac_output(kdate);
error_2:
    free(secret);
error_1:
    return output;
}


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
                       const char *secret, size_t secret_size)
{
    char *signature = NULL;
    struct sign_context *ctx = init_ctx();
    if (ctx == NULL) {
        goto error_1;
    }
    if (set_ctx_component(ctx, "method", method, method_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "uri", uri, uri_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "query", query, query_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "headers", headers, headers_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "sheaders", sheaders, sheaders_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "payload", payload, payload_size) != 0) {
        goto error_2;
    }
    char *algorithm = "AWS4-HMAC-SHA256";
    if (set_ctx_component(ctx, "algorithm", algorithm, strlen(algorithm)) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "requestdtm", requestdtm, requestdtm_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "date", date, date_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "region", region, region_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "service", service, service_size) != 0) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "secret", secret, secret_size) != 0) {
        goto error_2;
    }
    char *payload_hash = sha256_mdstr(payload, (int) payload_size);
    if (payload_hash == NULL) {
        goto error_2;
    }
    if (set_ctx_component(ctx, "payload_hash", payload_hash, strlen(payload_hash)) != 0) {
        goto error_3;
    }
    char *canon_request = canonicalize_request(ctx);
    if (canon_request == NULL) {
        goto error_3;
    }
    if (set_ctx_component(ctx, "canon_request", canon_request, strlen(canon_request)) != 0) {
        goto error_4;
    }
    char *canon_hash = sha256_mdstr(canon_request, (int) strlen(canon_request));
    if (canon_hash == NULL) {
        goto error_4;
    }
    if (set_ctx_component(ctx, "canon_hash", canon_hash, strlen(canon_hash)) != 0) {
        goto error_5;
    }
    char *scope = make_scope(ctx);
    if (scope == NULL) {
        goto error_5;
    }
    if (set_ctx_component(ctx, "scope", scope, strlen(scope)) != 0) {
        goto error_6;
    }
    char *str_sign = siginput(ctx);
    if (str_sign == NULL) {
        goto error_6;
    }
    if (set_ctx_component(ctx, "str_sign", str_sign, strlen(str_sign)) != 0) {
        goto error_7;
    }
    signature = sign_string(ctx);
    if (signature == NULL) {
        goto error_7;
    }
    if (set_ctx_component(ctx, "signature", signature, strlen(signature)) != 0) {
        goto error_7;
    }
error_7:
    free(str_sign);
error_6:
    free(scope);
error_5:
    free(canon_hash);
error_4:
    free(canon_request);
error_3:
    free(payload_hash);
error_2:
    free_ctx(ctx);
error_1:
    return signature;
}