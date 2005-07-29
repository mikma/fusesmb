#include <libsmbclient.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/param.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "stringlist.h"
#include "smbctx.h"
#include "hash.h"

#define MAX_SERVERLEN 255
#define MAX_WGLEN 255


stringlist_t *cache;
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Some servers refuse to return a server list using libsmbclient, so using
 *  broadcast lookup through nmblookup
 */
static int nmblookup(const char *wg, stringlist_t *sl, hash_t *ipcache)
{
    /* Find all ips for the workgroup by running :
    $ nmblookup 'workgroup_name'
    */
    char wg_cmd[512];
    snprintf(wg_cmd, 512, "nmblookup '%s'", wg);
    //fprintf(stderr, "%s\n", cmd);
    FILE *pipe;
    pipe = popen(wg_cmd, "r");
    if (pipe == NULL)
        return -1;

    int ip_cmd_size = 8192;
    char *ip_cmd = (char *)malloc(ip_cmd_size * sizeof(char));
    if (ip_cmd == NULL)
        return -1;
    strcpy(ip_cmd, "nmblookup -A ");
    int ip_cmd_len = strlen(ip_cmd);
    while (!feof(pipe))
    {
        /* Parse output that looks like this:
        querying boerderie on 172.20.91.255
        172.20.89.134 boerderie<00>
        172.20.89.191 boerderie<00>
        172.20.88.213 boerderie<00>
        */
        char buf[4096];
        if (NULL == fgets(buf, 4096, pipe))
            continue;

        char *pip = buf;
        /* Yes also include the space */
        while (isdigit(*pip) || *pip == '.' || *pip == ' ')
        {
            pip++;
        }
        *pip = '\0';
        int len = strlen(buf);
        if (len == 0) continue;
        ip_cmd_len += len;
        if (ip_cmd_len >= (ip_cmd_size -1))
        {
            ip_cmd_size *= 2;
            char *tmp = realloc(ip_cmd, ip_cmd_size *sizeof(char));
            if (tmp == NULL)
            {
                ip_cmd_size /= 2;
                ip_cmd_len -= len;
                continue;
            }
            ip_cmd = tmp;
        }
        /* Append the ip to the command:
        $ nmblookup -A ip1 ... ipn
        */
        strcat(ip_cmd, buf);
    }
    pclose(pipe);

    if (strlen(ip_cmd) == 13)
    {
        free(ip_cmd);
        return 0;
    }
    fprintf(stderr, "%s\n", ip_cmd);
    pipe = popen(ip_cmd, "r");
    if (pipe == NULL)
    {
        free(ip_cmd);
        return -1;
    }

    while (!feof(pipe))
    {
        char buf2[4096];
        char buf[4096];
        char ip[32];

        char *start = buf;
        if (NULL == fgets(buf2, 4096, pipe))
            continue;
        if (strncmp(buf2, "Looking up status of ", strlen("Looking up status of ")) == 0)
        {
            char *tmp = rindex(buf2, ' ');
            tmp++;
            char *end = index(tmp, '\n');
            *end = '\0';
            strcpy(ip, tmp);
            printf("%s\n", ip);
        }
        else
        {
            continue;
        }

        while (!feof(pipe))
        {

            if (NULL == fgets(buf, 4096, pipe))
                break;
            char *sep = buf;

            if (*buf != '\t')
                break;
            if (NULL != strstr(buf, "<GROUP>"))
                break;
            if (NULL == (sep = strstr(buf, "<00>")))
                break;
            *sep = '\0';

            start++;

            while (*sep == '\t' || *sep == ' ' || *sep == '\0')
            {
                *sep = '\0';
                sep--;
            }
            sl_add(sl, start, 1);
            if (NULL == hash_lookup(ipcache, start))
                hash_alloc_insert(ipcache, strdup(start), strdup(ip));
            printf("%s : %s\n", ip, start);
        }

    }
    pclose(pipe);
    free(ip_cmd);
    return 0;
}

static int server_listing(SMBCCTX *ctx, stringlist_t *cache, const char *wg, const char *sv, const char *ip)
{
    //return 0;
    char tmp_path[MAXPATHLEN] = "smb://";
    if (ip != NULL)
    {
        strcat(tmp_path, ip);
        printf("Using IP: %s\n", ip);
    }
    else
        strcat(tmp_path, sv);

    struct smbc_dirent *share_dirent;
    SMBCFILE *dir;
    //SMBCCTX *ctx = fusesmb_new_context();
    dir = ctx->opendir(ctx, tmp_path);
    if (dir == NULL)
    {
        //smbc_free_context(ctx, 1);
        ctx->closedir(ctx, dir);
        return -1;
    }

    while (NULL != (share_dirent = ctx->readdir(ctx, dir)))
    {
        if (share_dirent->name[strlen(share_dirent->name)-1] == '$' ||
            share_dirent->smbc_type != SMBC_FILE_SHARE ||
            share_dirent->namelen == 0)
            continue;
        int len = strlen(wg)+ strlen(sv) + strlen(share_dirent->name) + 4;
        char tmp[len];
        snprintf(tmp, len, "/%s/%s/%s", wg, sv, share_dirent->name);
        printf("%s\n", tmp);
        pthread_mutex_lock(&cache_mutex);
        if (-1 == sl_add(cache, tmp, 1))
        {
            pthread_mutex_unlock(&cache_mutex);
            fprintf(stderr, "sl_add failed\n");
            ctx->closedir(ctx, dir);
            //smbc_free_context(ctx, 1);
            return -1;
        }
        pthread_mutex_unlock(&cache_mutex);

    }
    ctx->closedir(ctx, dir);
    //smbc_free_context(ctx, 1);
    return 0;
}

static void *workgroup_listing_thread(void *args)
{
    char *wg = (char *)args;
    //SMBCCTX *ctx, stringlist_t *cache, hash_t *ip_cache, const char *wg

    hash_t *ip_cache = hash_create(HASHCOUNT_T_MAX, NULL, NULL);
    if (NULL == ip_cache)
        return NULL;

    stringlist_t *servers = sl_init();
    if (NULL == servers)
    {
        fprintf(stderr, "Malloc failed\n");
        return NULL;
    }
    SMBCCTX *ctx = fusesmb_new_context();
    SMBCFILE *dir;
    char temp_path[MAXPATHLEN] = "smb://";
    strcat(temp_path, wg);

    struct smbc_dirent *server_dirent;
    dir = ctx->opendir(ctx, temp_path);
    if (dir == NULL)
    {
        ctx->closedir(ctx, dir);

        goto use_popen;
    }
    while (NULL != (server_dirent = ctx->readdir(ctx, dir)))
    {
        if (server_dirent->namelen == 0 ||
            server_dirent->smbc_type != SMBC_SERVER)
        {
            continue;
        }

        if (-1 == sl_add(servers, server_dirent->name, 1))
            continue;


    }
    ctx->closedir(ctx, dir);

use_popen:


    nmblookup(wg, servers, ip_cache);
    sl_casesort(servers);

    size_t i;
    for (i=0; i < sl_count(servers); i++)
    {
        fprintf(stderr, "%s\n", sl_item(servers, i));
        if (i > 0 && strcmp(sl_item(servers, i), sl_item(servers, i-1)) == 0)
            continue;
        hnode_t *node = hash_lookup(ip_cache, sl_item(servers, i));
        if (node == NULL)
            server_listing(ctx, cache, wg, sl_item(servers, i), NULL);
        else
            server_listing(ctx, cache, wg, sl_item(servers, i), hnode_get(node));
    }

    hscan_t sc;
    hnode_t *n;
    hash_scan_begin(&sc, ip_cache);
    while (NULL != (n = hash_scan_next(&sc)))
    {
        void *data = hnode_get(n);
        const void *key = hnode_getkey(n);
        hash_scan_delfree(ip_cache, n);
        free((void *)key);
        free(data);

    }
    hash_destroy(ip_cache);
    sl_free(servers);
    smbc_free_context(ctx, 1);
    return 0;
}


int cache_servers(SMBCCTX *ctx)
{
    //SMBCCTX *ctx = fusesmb_new_context();
    SMBCFILE *dir;
    struct smbc_dirent *workgroup_dirent;

    /* Initialize cache */
    cache = sl_init();
    size_t i;


    dir = ctx->opendir(ctx, "smb://");

    if (dir == NULL)
    {
        ctx->closedir(ctx, dir);
        sl_free(cache);
        //smbc_free_context(ctx, 1);
        return -1;
    }

    pthread_t *threads;
    threads = (pthread_t *)malloc(sizeof(pthread_t));
    if (NULL == threads)
        return -1;
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

    unsigned int num_threads = 0;

    while (NULL != (workgroup_dirent = ctx->readdir(ctx, dir)) )
    {
        if (workgroup_dirent->namelen == 0 ||
            workgroup_dirent->smbc_type != SMBC_WORKGROUP)
        {
            continue;
        }
        //char wg[1024];
        //strncpy(wg, workgroup_dirent->name, 1024);
        char *thread_arg = strdup(workgroup_dirent->name);
        if (NULL == thread_arg)
            continue;
        int rc;
        rc = pthread_create(&threads[num_threads],
                             &thread_attr, workgroup_listing_thread,
                             (void*)thread_arg);
        //workgroup_listing(ctx, cache, ip_cache, wg);
        if (rc)
        {
            fprintf(stderr, "Failed to create thread for workgroup: %s\n", workgroup_dirent->name);
            free(thread_arg);
            continue;
        }
        num_threads++;
        threads = (pthread_t *)realloc(threads, (num_threads+1)*sizeof(pthread_t));
    }
    ctx->closedir(ctx, dir);

    //smbc_free_context(ctx, 1);

    pthread_attr_destroy(&thread_attr);

    for (i=0; i<num_threads; i++)
    {
        int rc = pthread_join(threads[i], NULL);
        if (rc)
        {
            fprintf(stderr, "Error while joining thread, errorcode: %d\n", rc);
            exit(-1);
        }
    }
    free(threads);

    sl_casesort(cache);
    char cachefile[1024];
    char tmp_cachefile[1024] = "/tmp/fusesmb.cache.XXXXX";
    mkstemp(tmp_cachefile);
    snprintf(cachefile, 1024, "%s/.smb/fusesmb.cache", getenv("HOME"));
    FILE *fp = fopen(cachefile, "w");
    if (fp == NULL)
    {
        sl_free(cache);
        return -1;
    }

    for (i=0 ; i < sl_count(cache); i++)
    {
        fprintf(fp, "%s\n", sl_item(cache, i));
    }
    fclose(fp);
    /* Make refreshing cache file atomic */
    rename(tmp_cachefile, cachefile);
    sl_free(cache);
    return 0;
}

int main(int argc, char *argv[])
{
    char pidfile[1024];
    snprintf(pidfile, 1024, "%s/.smb/fusesmb.cache.pid", getenv("HOME"));
    struct stat st;
    if (argc == 1)
    {
        pid_t pid, sid;

        if (-1 != stat(pidfile, &st))
        {
            fprintf(stderr, "Error: %s is already running\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        pid = fork();
        if (pid < 0)
            exit(EXIT_FAILURE);
        if (pid > 0)
            exit(EXIT_SUCCESS);

        sid = setsid();
        if (sid < 0) {
            exit(EXIT_FAILURE);
        }
        if (chdir("/") < 0)
            exit(EXIT_FAILURE);
        umask(0);

        FILE *fp = fopen(pidfile, "w");
        if (NULL == fp)
            exit(EXIT_FAILURE);
        fprintf(fp, "%i\n", sid);
        fclose(fp);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }
    SMBCCTX *ctx = fusesmb_new_context();
    cache_servers(ctx);
    smbc_free_context(ctx, 1);
    if (argc == 1)
    {
        unlink(pidfile);
    }
    exit(EXIT_SUCCESS);
}

