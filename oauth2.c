#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <yajl/yajl_tree.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "curl_request.h"

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
    char* user;
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
    int expires_in;
    char* inf;
    oauth2_error last_error;
} oauth2_context;

#include "config.h"

//Methods

//Initialiser

oauth2_context* create_context(oauth2_config* conf);
void oauth2_set_code(oauth2_context* contex, char* code);
void oauth2_set_inf(oauth2_context* contex, char* inf);
void oauth2_set_auth_code(oauth2_context* contex, char* auth_code);

//Returns URL to redirect user to.
void oauth2_request_auth_code(oauth2_context* conf);
void oauth2_request_access_token(oauth2_context* conf);

char* oauth2_create_auth_uri(oauth2_context* conf);
char* oauth2_create_access_token_uri(oauth2_context* conf);
char* oauth2_create_refresh_token_uri(oauth2_context* conf);

void oauth2_access_refresh_token(oauth2_context* conf);
char* oauth2_request(oauth2_context* conf, char* uri, char* params);
void oauth2_cleanup(oauth2_context* conf);
static void oauth2_parse_conf(oauth2_context*);

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

char* oauth2_create_auth_uri(oauth2_context* ctx) {
    int scope_len = 1;
    int state_len = 1;
    char* final_str;

    char* core_fmt = "%s?response_type=code&client_id=%s&redirect_uri=%s";
    char* scope_fmt = "&scope=%s";
    char* state_fmt = "&state=%s";

    //Get the string lengths
    int core_len = snprintf(NULL, 0, (const char*)core_fmt, ctx->conf->auth_server, ctx->conf->client_id, ctx->conf->redirect_uri) + 1;
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
    return final_str;
}

void oauth2_request_auth_code(oauth2_context* ctx)
{

    char* final_str = oauth2_create_auth_uri(ctx);
    printf("Visit this url and hit authorize: %s\n", final_str);
    printf("Now put the auth token here: ");
    free(final_str);

    char code[255];
    scanf("%s", code);
    oauth2_set_code(ctx, code);
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
    }

    const char * path[] = { "access_token", (const char *) 0 };
    yajl_val v = yajl_tree_get(node, path, yajl_t_string);
    if (v) {
        ctx->auth_code = strdup(YAJL_GET_STRING(v));
        /*printf("%s", ctx->auth_code);*/
    }
    else
        printf("No such node: %s\n", path[0]);

    /*refresh_token*/
    const char * path_rt[] = { "refresh_token", (const char *) 0 };
    yajl_val v_rt = yajl_tree_get(node, path_rt, yajl_t_string);
    if (v_rt) {
        ctx->refresh_token = strdup(YAJL_GET_STRING(v_rt));
        /*printf("%s", ctx->refresh_token);*/
    }
    else
        printf("No such node: %s\n", path_rt[0]);

    /*expires_in*/
    const char * path_ei[] = { "expires_in", (const char *) 0 };
    yajl_val v_ei = yajl_tree_get(node, path_ei, yajl_t_number);
    if (v_ei) {
        ctx->expires_in = YAJL_GET_INTEGER(v_ei);
    }
    else
        printf("No such node: %s\n", path_rt[0]);

    yajl_tree_free(node);
}

char* oauth2_create_access_token_uri(oauth2_context* ctx) {
    char* query_fmt = "grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s";
    int query_len = snprintf(NULL, 0, query_fmt, ctx->conf->client_id, ctx->conf->client_secret, ctx->code, ctx->conf->redirect_uri);
    char* uri = malloc(sizeof(char)*query_len);
    sprintf(uri, query_fmt, ctx->conf->client_id, ctx->conf->client_secret, ctx->code, ctx->conf->redirect_uri);
    return uri;
}

void oauth2_request_access_token(oauth2_context* ctx)
{
    assert(ctx->conf != NULL);
    assert(ctx->conf->token_server != NULL);
    assert(ctx->code != NULL);

    char* uri = oauth2_create_access_token_uri(ctx);
    /*printf("\n\nUsing: %s/%s\n\n", ctx->conf->token_server, uri );*/
    oauth2_set_inf(ctx, curl_make_request(ctx->conf->token_server, uri));
    free(uri);
}

char* oauth2_create_refresh_token_uri(oauth2_context* ctx) {
    char* query_fmt = "grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s";
    int query_len = snprintf(NULL, 0, query_fmt, ctx->conf->client_id, ctx->conf->client_secret, ctx->refresh_token);
    char* uri = malloc(sizeof(char)*query_len);
    sprintf(uri, query_fmt, ctx->conf->client_id, ctx->conf->client_secret, ctx->refresh_token);
    return uri;
}

void oauth2_access_refresh_token(oauth2_context* ctx)
{
    assert(ctx->conf != NULL);
    assert(ctx->conf->token_server != NULL);
    assert(ctx->refresh_token != NULL);

    char* uri = oauth2_create_refresh_token_uri(ctx);
    char* out = curl_make_request(ctx->conf->token_server, uri);
    oauth2_set_inf(ctx, out);
    free(uri);

    /*printf("Response from server: %s\n", out);*/
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

void run(oauth2_config *conf) {
    oauth2_context* ctx = create_context(conf);

    FILE *f;

    int uri_len;
    uri_len = snprintf(NULL, 0, "/home/tait/.cache/oauth_%s", ctx->conf->user);
    char* pat = malloc(sizeof(char)*uri_len);
    sprintf(pat, "/home/tait/.cache/oauth_%s", ctx->conf->user);
    f = fopen(pat, "r+");

    if (f != NULL) { /* there is cache*/
        char buffer[1024];
        fread(buffer, 1024, 1, f);

        ctx->inf = malloc(sizeof(char) * (strlen(buffer) + 1));
        sprintf(ctx->inf, buffer);

        oauth2_parse_conf(ctx);
        struct stat attr;
        stat(pat, &attr);

        int s = time(0) - attr.st_mtime;

        if (s > ctx->expires_in ) {

            oauth2_access_refresh_token(ctx); /* request for access_token based on refresh_token*/

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
            }

            const char * path[] = { "access_token", (const char *) 0 };
            yajl_val v = yajl_tree_get(node, path, yajl_t_string);
            if (v) {
                ctx->auth_code = strdup(YAJL_GET_STRING(v));
            }
            else
                printf("No such node: %s\n", path[0]);
        }
    } else {
        oauth2_request_auth_code(ctx); /* prompt for URI to get code */
        oauth2_request_access_token(ctx); /* get the code to request access_token*/
        oauth2_parse_conf(ctx);

        f = fopen(pat, "w");
        if (f == NULL)
            printf("not able to open file to write conf");
        else
            fprintf(f, ctx->inf);
    }

    printf("%s", ctx->auth_code);

    free(pat);

    if (f != NULL)
        fclose(f);

    oauth2_cleanup(ctx);
}


static void usage(const char * progname)
{
    fprintf(stderr,
            "usage:  %s [options]\n"
            "Parse input from stdin as JSON and ouput parsing details "
                                                          "to stdout\n"
            "   -b  set the read buffer size\n"
            "   -c  allow comments\n"
            "   -g  allow *g*arbage after valid JSON text\n"
            "   -m  allows the parser to consume multiple JSON values\n"
            "       from a single string separated by whitespace\n"
            "   -p  partial JSON documents should not cause errors\n",
            progname);
    exit(1);
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr,"No arguments given, do nothing\n");
        return 0;
    }

    int i;
    int len = sizeof(conf)/sizeof(conf[0]);
    for (i = 0; i < len; i++) {
        /*printf("Compare %s and %s\n", argv[1], conf[i].user);*/
        if (strcmp(argv[1], conf[i].user) == 0) {
            /*printf("Getting token for %s...\n", conf[i].user);*/
            run(&conf[i]);
            return 0;
        }
    }

    return 1;
}
