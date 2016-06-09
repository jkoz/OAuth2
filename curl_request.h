#ifndef __CURL_REQUEST_H__
#define __CURL_REQUEST_H__

#define MAX_BUFFER 2048 //2KB Buffers

typedef struct _data {
    char d[MAX_BUFFER];
    struct _data* next;
    int idx;
} data;

char* curl_make_request(char* url, char* params);

#endif
