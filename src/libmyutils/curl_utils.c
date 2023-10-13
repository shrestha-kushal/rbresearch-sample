#include "../../include/curl/curl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct ResponsePack {
    size_t *size;
    char *buffer;
};


size_t store_response(char *data, size_t block_size, size_t nblocks, void *userdata) {
    size_t nbytes = block_size * nblocks; // get size of data block retrieved
    /* Do nothing if 0 bytes received */
    if (!nbytes) {
        return nbytes;
    }
    struct ResponsePack *ptrOutput;
    ptrOutput = (struct ResponsePack *) userdata;
    size_t oldsize = *(ptrOutput->size);
    size_t newsize = oldsize + nbytes;
    /* allocate space in heap to store response from server */
    if (oldsize == 0) {
        ptrOutput->buffer = (char *) malloc(newsize);
    } else {
        ptrOutput->buffer = (char *) realloc(ptrOutput->buffer, newsize);
    }
    /* error out if space (re)allocation fails */
    if (!ptrOutput->buffer) {
        nbytes += 1;
        return nbytes;
    }
    /* save new size of buffer */
    *(ptrOutput->size) = newsize;
    /* save response bytes to buffer */
    char *loadstart = ptrOutput->buffer + (int) oldsize;
    memcpy(loadstart, data, nbytes);
    return nbytes;
}


char* response_easy(CURL *curl)
{
    /* return NULL if curl handle is NULL */
    if (!curl){
        fprintf(stderr,
                "[ERROR] [curl_utils.c, response_easy] : "
                "Recieved NULL curl handle.\n");
        return NULL;
    }
    /* initialize objects that will contain response */
    char* response;
    struct ResponsePack package;
    size_t rsize;
    rsize = 0;
    package.size = &rsize;
    package.buffer = NULL;
    /* set write callback function, resetting previous setting */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, store_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &package);
    /* Perform the request, res will get the return code */
    CURLcode res = curl_easy_perform(curl);
    /* return NULL if libcurl error */
    if(res != CURLE_OK){
        fprintf(stderr,
                "[ERROR] [curl_utils.c, response_easy]: "
                " %s\n", curl_easy_strerror(res));
        /* free up heap resources before function return */
        if (package.buffer){
            free(package.buffer);
        }
        return NULL;
    }
    /* if nothing received from server, return NULL */
    if (!package.buffer) {
        return NULL;
    }
    /* make sure character array in heap is null terminated */
    response = (char*)realloc(package.buffer, rsize + 1);
    if (!response) {
        fprintf(stderr,
                "[ERROR] [curl_utils.c, response_easy]: "
                "Failed to null terminate response.\n");
        return NULL;
    }
    *(response + (int)*(package.size)) = '\0';
    return response;
}
