#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include <yajl/yajl_tree.h>

typedef enum
{
    OAUTH2_RESPONSE_CODE = 0,
    OAUTH2_RESPONSE_TOKEN,
    OAUTH2_RESPONSE_TOKEN_AND_CODE
} oauth2_response_type;

typedef enum
{
    OAUTH2_ERROR_NO_ERROR = 0,
    OAUTH2_ERROR_INVALID_REQUEST,
    OAUTH2_ERROR_INVALID_CLIENT,
    OAUTH2_ERROR_UNAUTHORIZED_CLIENT,
    OAUTH2_ERROR_REDIRECT_URI_MISMATCH,
    OAUTH2_ERROR_ACCESS_DENIED,
    OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE,
    OAUTH2_ERROR_INVALID_SCOPE,
    OAUTH2_ERROR_INVALID_GRANT,
    OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE,
} oauth2_error_type;

//Internal structs
typedef struct _oauth2_error {
    oauth2_error_type error;
    char*             error_description;
    char*             error_uri;
    char*             state;
} oauth2_error;

typedef struct _oauth2_config
{
    char* auth_server;
    char* token_server;
    char* client_id;
    char* client_secret;
    char* redirect_uri;
    char* scope;
    char* state;
} oauth2_config;

typedef struct _oauth2_context
{
    const oauth2_config *conf;
    char* code; /* confirmation code */
    char* auth_code; /* access_token */
    char* refresh_token; /* refresh_token if any */
    char* inf;
    oauth2_error last_error;
} oauth2_context;

#include "config.h"

//Methods

//Initialiser

//Set the redirect URI for auth code authentication. This must be set before using oauth2_request_auth_code too.
oauth2_context* create_context(oauth2_config* conf);
void oauth2_set_code(oauth2_context* contex, char* code);
void oauth2_set_inf(oauth2_context* contex, char* inf);
void oauth2_set_auth_code(oauth2_context* contex, char* auth_code);

//Returns URL to redirect user to.
void oauth2_request_auth_code(oauth2_context* conf);
char* oauth2_access_auth_code(oauth2_context* conf);
char* oauth2_access_refresh_token(oauth2_context* conf, char* refresh_token);
char* oauth2_request(oauth2_context* conf, char* uri, char* params);  
void oauth2_cleanup(oauth2_context* conf);
static void oauth2_parse_conf(oauth2_context*);

#define MAX_BUFFER 2048 //2KB Buffers

typedef struct _data {
    char d[MAX_BUFFER];
    struct _data* next;
    int idx;
} data;

char* curl_make_request(char* url, char* params);


size_t curl_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t idx;
    size_t max;
    data* d;
    data* nd;
    
    d = (data*)userdata;

    idx = 0;
    max = nmemb * size;

    //Scan to the correct buffer
    while(d->next != NULL)
        d = d->next;

    //Store the data
    while(idx < max)
    {
        d->d[d->idx++] = ((char*)ptr)[idx++];

        if(d->idx == MAX_BUFFER)
        {
            nd = malloc(sizeof(data));
            nd->next = NULL;
            nd->idx = 0;
            d->next = nd;
            d = nd;
        }
    }

    return max;
}

void data_clean(data* d)
{
    data* pd;
    while(d)
    {
        pd = d->next;
        free(d);
        d = pd;
    }
}

char* curl_make_request(char* url, char* params)
{
    data* storage;
    data* curr_storage;
    CURL* handle;
    int data_len;
    char* retVal;

    assert(url != 0);
    assert(*url != 0);

    storage = malloc(sizeof(data));
    storage->idx = 0;
    storage->next = 0;

    handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, storage);

    //Do we need to add the POST parameters?
    if(params != NULL)
    {
        curl_easy_setopt(handle, CURLOPT_POST, 1);
        curl_easy_setopt(handle, CURLOPT_COPYPOSTFIELDS, params); //Copy them just incase
                                                                  //the user does something stupid
    }

    if(curl_easy_perform(handle) != 0)
    {
        //Error!
        curl_easy_cleanup(handle);
        data_clean(storage);
        return NULL;
    }

    //Everything went OK.
    //How long is the data?
    data_len = 0;
    curr_storage = storage;
    while(curr_storage)
    {
        data_len += curr_storage->idx;
        curr_storage = curr_storage->next;
    }

    //Allocate storage
    retVal = malloc(sizeof(char)*data_len);
    
    //Now copy in the data
    curr_storage = storage;
    data_len = 0;
    while(curr_storage)
    {
        memcpy(retVal+data_len, curr_storage->d, curr_storage->idx);
        curr_storage = curr_storage->next;
    }

    //Cleanup
    curl_easy_cleanup(handle);
    data_clean(storage);
    
    return retVal;
}

oauth2_context* create_context(oauth2_config* conf) {
     oauth2_context* contex = malloc(sizeof(oauth2_context));

     if(contex == NULL)
         return NULL;

     contex->conf = conf;
     contex->auth_code = NULL;
     contex->last_error.error = OAUTH2_ERROR_NO_ERROR;
     contex->last_error.error_description = NULL;
     contex->last_error.error_uri = NULL;
     contex->last_error.state = NULL;
     return contex;
}

void oauth2_set_code(oauth2_context* ctx, char* code)
{
    assert(ctx != NULL);
    ctx->code = malloc(sizeof(char) * (strlen(code)+1));
    strcpy(ctx->code, code);
}

void oauth2_set_inf(oauth2_context* ctx, char* inf) {
    assert(ctx != NULL);
    ctx->inf = malloc(sizeof(char) * (strlen(inf)+1));
    strcpy(ctx->inf, inf);
}

void oauth2_set_auth_code(oauth2_context* ctx, char* auth_code)
{
    int input_strlen;

    assert(ctx != NULL);

    input_strlen = strlen(auth_code)+1;
    ctx->auth_code = malloc(sizeof(char) * input_strlen);
    strcpy(ctx->auth_code, auth_code);
}

void oauth2_request_auth_code(oauth2_context* ctx)
{
    int core_len;
    int scope_len;
    int state_len;
    char* core_fmt;
    char* scope_fmt;
    char* state_fmt;
    char* final_str;

    scope_len = 1;
    state_len = 1;

    assert(ctx != NULL);

    //We just need to build the request string, since we can't actually handle the callback ourselves
    //URL Format: <server>?response_type=code&client_id=<client_id>&redirect_uri=<redir_uri>&scope=<scope>&state=<state>
    //Get the final length
    core_fmt = "%s?response_type=code&client_id=%s&redirect_uri=%s";
    scope_fmt = "&scope=%s";
    state_fmt = "&state=%s";

    //Get the string lengths
    core_len = snprintf(NULL, 0, (const char*)core_fmt, ctx->conf->auth_server, ctx->conf->client_id, ctx->conf->redirect_uri) + 1;
    if(ctx->conf->scope != NULL)
        scope_len = snprintf(NULL, 0, (const char*)scope_fmt, ctx->conf->scope) + 1;
    if(ctx->conf->state != NULL)
        state_len = snprintf(NULL, 0, (const char*)state_fmt, ctx->conf->state) + 1;

    //Actually build the string
    final_str = malloc(((core_len-1)+(scope_len-1)+(state_len-1)+1)*sizeof(char));

    sprintf(final_str, (const char*)core_fmt, ctx->conf->auth_server, ctx->conf->client_id, ctx->conf->redirect_uri);
    if(ctx->conf->scope != NULL)
        sprintf((char*)(final_str+(core_len-1)), (const char*)scope_fmt, ctx->conf->scope);

    if(ctx->conf->state != NULL)
        sprintf((char*)(final_str+(core_len-1)+(scope_len-1)), (const char*)state_fmt, ctx->conf->state);

    printf("Visit this url and hit authorize: %s\n", final_str);
    printf("Now put the auth token here: ");

    char code[255];
    scanf("%s", code);

    oauth2_set_code(ctx, code);

    return final_str;
}

static void oauth2_parse_conf(oauth2_context* ctx) {
    char errbuf[1024];
    errbuf[0] = 0;

    /* we have the whole config file in memory.  let's parse it ... */
    yajl_val node = yajl_tree_parse((const char *) ctx->inf, errbuf, sizeof(errbuf));

    /* parse error handling */
    if (node == NULL) {
        fprintf(stderr, "parse_error: ");
        if (strlen(errbuf))
            fprintf(stderr, " %s", errbuf);
        else
            fprintf(stderr, "unknown error");
        fprintf(stderr, "\n");
        return NULL;
    }

    const char * path[] = { "access_token", (const char *) 0 };
    yajl_val v = yajl_tree_get(node, path, yajl_t_string);
    if (v) {
        ctx->auth_code = strdup(YAJL_GET_STRING(v));

        printf("%s", ctx->auth_code);

    }
    else
        printf("No such node: %s/%s\n", path[0], path[1]);

    yajl_tree_free(node);
}

char* oauth2_access_auth_code(oauth2_context* ctx)
{
    //Build up the request
    char* uri;
    char* query_fmt;
    char* output;
    int query_len;

    assert(ctx->conf != NULL);
    assert(ctx->conf->token_server != NULL);
    assert(ctx->code != NULL);

    query_fmt = "grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s";

    query_len = snprintf(NULL, 0, query_fmt, ctx->conf->client_id, ctx->conf->client_secret, ctx->code, ctx->conf->redirect_uri);
    uri = malloc(sizeof(char)*query_len);
    sprintf(uri, query_fmt, ctx->conf->client_id, ctx->conf->client_secret, ctx->code, ctx->conf->redirect_uri);

    output = curl_make_request(ctx->conf->token_server, uri);
    free(uri);

    /*printf("Response from server: %s\n", output);*/

    oauth2_set_inf(ctx, output);

    return NULL;
}


char* oauth2_access_refresh_token(oauth2_context* conf, char* refresh_token)
{
    assert(0);
    return NULL;
}

char* oauth2_request(oauth2_context* ctx, char* uri, char* params)
{
    //For now, we'll just include the access code with the request vars
    //This is discouraged, but I don't know if most providers actually
    //support the header-field method (Facebook is still at draft 0...)
    
    char* retVal;
    char* uri2;
    int uri_len;

    //Sanity checks
    assert(ctx != NULL);
    assert(ctx->conf->client_id != NULL);
    assert(ctx->auth_code != NULL);
    assert(uri != NULL);
    
    //Are we POSTing?
    if(params != NULL)
    {
        //Attach the token to the params
        uri_len = snprintf(NULL, 0, "%s&access_token=%s", params, ctx->auth_code);
        uri2 = malloc(sizeof(char)*uri_len);
        sprintf(uri2, "%s&access_token=%s", params, ctx->auth_code);

        retVal = curl_make_request(uri, uri2);
        free(uri2);
        return retVal;
    }
    else
    {
        return NULL; //I'm not doing this now.
    }
}

void oauth2_cleanup(oauth2_context* ctx)
{
    if(ctx == NULL)
        return;

    if (ctx->auth_code != NULL)
        free(ctx->auth_code);
    if (ctx->code != NULL)
        free(ctx->code);
    if (ctx->inf != NULL)
        free(ctx->inf);
    free(ctx);
}

int main(int argc, char** argv)
{
    oauth2_context* ctx = create_context(&conf[0]);

    FILE *f;

    int uri_len;
    uri_len = snprintf(NULL, 0, "/home/tait/.cache/oauth_%s", ctx->conf->client_id);
    char* pat = malloc(sizeof(char)*uri_len);
    sprintf(pat, "/home/tait/.cache/oauth_%s", ctx->conf->client_id);
    f = fopen(pat, "r+");

    if (f != NULL) { /* there is cache*/
        char buffer[1024];
        fread(buffer, 1024, 1, f);

        ctx->inf = malloc(sizeof(char) * (strlen(buffer) + 1));
        sprintf(ctx->inf, buffer);

        oauth2_parse_conf(ctx);
    } else {
        oauth2_request_auth_code(ctx); /* prompt for URI to get code */
        oauth2_access_auth_code(ctx); /* get the code to request access_token*/
        oauth2_parse_conf(ctx);

        f = fopen(pat, "w");
        if (f == NULL)
            printf("not able to open file to write conf");
        else
            fprintf(f, ctx->inf);
    }
    free(pat);

    if (f != NULL)
        fclose(f);

    oauth2_cleanup(ctx);

    return 0;
}
