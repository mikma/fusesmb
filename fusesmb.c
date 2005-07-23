/*
   SMB for FUSE
   Copyright (C) 2003-2005  Vincent Wagelaar <vincent@ricardis.tudelft.nl>
   This program can be distributed under the terms of the GNU GPL.
   See the file COPYING.

   Mount complete "Network Neighbourhood"

 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/vfs.h>
#include <pthread.h>
#include <libsmbclient.h>
#include <time.h>
#include "hash.h"

#define MY_MAXPATHLEN (MAXPATHLEN + 256)

/* Mutex for locking the Samba context */
static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rwd_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t cleanup_thread;
static SMBCCTX *ctx, *rwd_ctx;

/*
 * Hash for storing files/directories that were not found, an optimisation
 * for programs like konqueror and freevo that do a lot of lookups:
 * .directory, share.fxd etc..
 */
static hash_t *notfound_hash;
static pthread_mutex_t notfound_hash_mutex = PTHREAD_MUTEX_INITIALIZER;


typedef struct {
    time_t ctime;  /* Time of creation */
    int err;       /* errno variable */
} notfound_node_t;


static void fusesmb_auth_fn(const char *server, const char *share,
                            char *workgroup, int wgmaxlen,
                            char *username, int unmaxlen,
                            char *password, int pwmaxlen)
{
    (void)server;
    (void)share;
    (void)workgroup;
    (void)wgmaxlen;

    char cred_file[1024];
    FILE *fp;

    snprintf(cred_file, 1024, "%s/.smb/credentials", getenv("HOME"));
    fp = fopen(cred_file, "r");
    if (fp != NULL)
    {
        char fbuf[1024];

        while (fgets(fbuf, 1024, fp) != NULL)
        {
            if (strncmp(fbuf, "username", 8) == 0)
            {
                char *begin = fbuf + 8;
                char *end;

                while (*begin == ' ' || *begin == '\t')
                    begin++;
                if (*begin == '=')
                {
                    begin++;
                    while (*begin == ' ' || *begin == '\t')
                        begin++;

                    end = begin + strlen(begin) - 1;
                    while (*end == ' ' || *end == '\t' || *end == '\n'
                           || *end == '\0')
                    {
                        end--;
                    }
                    end++;
                    *end = '\0';
                    strncpy(username, begin, unmaxlen);

                }
            }
            else if (strncmp(fbuf, "password", 8) == 0)
            {
                char *begin = fbuf + 8;
                char *end;

                while (*begin == ' ' || *begin == '\t')
                    begin++;
                if (*begin == '=')
                {
                    begin++;
                    while (*begin == ' ' || *begin == '\t')
                        begin++;

                    end = begin + strlen(begin) - 1;
                    while (*end == ' ' || *end == '\t' || *end == '\n'
                           || *end == '\0')
                    {
                        end--;
                    }
                    end++;
                    *end = '\0';
                    strncpy(password, begin, pwmaxlen);
                }
            }
        }
        if (!strlen(username))
        {
            char un[] = "guest";
            char pw[] = "";

            strncpy(username, un, unmaxlen);
            strncpy(password, pw, pwmaxlen);
        }
    }
    else
    {
        char un[] = "guest";
        char pw[] = "";

        strncpy(username, un, unmaxlen);
        strncpy(password, pw, pwmaxlen);
    }
}
/*
 * Thread for cleaning up connections to hosts, current interval of
 * 15 seconds looks reasonable
 */
static void *smb_purge_thread(void *data)
{
    (void)data;
    int count = 0;
    while (1)
    {
        sleep(15);
        pthread_mutex_lock(&ctx_mutex);
        ctx->callbacks.purge_cached_fn(ctx);
        pthread_mutex_unlock(&ctx_mutex);

        pthread_mutex_lock(&rwd_ctx_mutex);
        rwd_ctx->callbacks.purge_cached_fn(rwd_ctx);
        pthread_mutex_unlock(&rwd_ctx_mutex);
        /*
         * Look every minute in the notfound cache for items that are
         * no longer used
         */
        if (count > (60 / 15)) /* 1 minute */
        {
            pthread_mutex_lock(&notfound_hash_mutex);
            hscan_t sc;
            hash_scan_begin(&sc, notfound_hash);
            hnode_t *n;
            while (NULL != (n = hash_scan_next(&sc)))
            {
                notfound_node_t *data = hnode_get(n);
                if (time(NULL) - data->ctime > 300) /* 5 minutes */
                {
                    const void *key = hnode_getkey(n);
                    fprintf(stderr, "Deleting notfound node: %s\n", (char *)key);
                    hash_scan_delfree(notfound_hash, n);
                    free((void *)key);
                    free(data);
                }

            }
            pthread_mutex_unlock(&notfound_hash_mutex);
            count = 0;
        }
        else
        {
            count++;
        }

    }
    return NULL;
}
/*
 * Create a new libsmbclient context with all necessary options
 */
static SMBCCTX *fusesmb_new_context(SMBCCTX *ctx)
{
    /* Initializing libsbmclient */
    ctx = smbc_new_context();
    ctx->callbacks.auth_fn = fusesmb_auth_fn;
    /* Timeout a bit bigger, by Jim Ramsay */
    ctx->timeout = 10000;       //10 seconds
    /* Kerberos authentication by Esben Nielsen */
#if defined(SMB_CTX_FLAG_USE_KERBEROS) && defined(SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS)
    ctx->flags |=
        SMB_CTX_FLAG_USE_KERBEROS | SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS;
#endif
    //ctx->options.one_share_per_server = 1;
    ctx = smbc_init_context(ctx);
    return ctx;
}

static const char *stripworkgroup(const char *file)
{
    unsigned int i = 0, ret = 0, goodpos = 0;

    for (i = 0; i < strlen(file); i++)
    {
        if (ret == 2)
        {
            goodpos--;
            break;
        }
        if (file[i] == '/')
            ret++;
        goodpos++;
    }
    if (ret == 1)
        return file;
    else
        return &file[goodpos];
}

static unsigned int slashcount(const char *file)
{
    unsigned int i = 0, count = 0;

    for (i = 0; i < strlen(file); i++)
    {
        if (file[i] == '/')
            count++;
    }
    return count;
}

static int fusesmb_getattr(const char *path, struct stat *stbuf)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/", buf[MY_MAXPATHLEN], cache_file[1024];
    int path_exists = 0;
    FILE *fp;
    struct stat cache;
    memset(stbuf, 0, sizeof(struct stat));

    /* Check the cache for valid workgroup, hosts and shares */
    if (slashcount(path) <= 3)
    {
        snprintf(cache_file, 1024, "%s/.smb/smbcache", getenv("HOME"));
        
        if (strlen(path) == 1 && path[0] == '/')
            path_exists = 1;
        else
        {
            fp = fopen(cache_file, "r");
            if (!fp)
                return -ENOENT;

            while (!feof(fp))
            {
                fgets(buf, MY_MAXPATHLEN, fp);
                if (strncmp(buf, path, strlen(path)) == 0 &&
                    (buf[strlen(path)] == '/' || buf[strlen(path)] == '\n'))
                {
                    path_exists = 1;
                    break;
                }
            }
            fclose(fp);
        }
        if (path_exists != 1)
            return -ENOENT;

        memset(&cache, 0, sizeof(cache));
        stat(cache_file, &cache);
        memset(stbuf, 0, sizeof(stbuf));
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 3;
        stbuf->st_size  = 4096;
        stbuf->st_uid   = cache.st_uid;
        stbuf->st_gid   = cache.st_gid;
        stbuf->st_ctime = cache.st_ctime;
        stbuf->st_mtime = cache.st_mtime;
        stbuf->st_atime = cache.st_atime;
        return 0;
    
    }
    /* We're within a share here  */
    else
    {
        /* Prevent to often connecting to a share because this is slow */
        if (slashcount(path) == 4)
        {
            pthread_mutex_lock(&notfound_hash_mutex);
            hnode_t *node = hash_lookup(notfound_hash, path);
            if (node)
            {
                fprintf(stderr, "NotFoundCache hit for: %s\n", path);
                notfound_node_t *data = hnode_get(node);
                int err = data->err;
                data->ctime = time(NULL);
                pthread_mutex_unlock(&notfound_hash_mutex);
                return -err;
            }
            pthread_mutex_unlock(&notfound_hash_mutex);
        }
        
        strcat(smb_path, stripworkgroup(path));
        pthread_mutex_lock(&ctx_mutex);
        if (ctx->stat(ctx, smb_path, stbuf) < 0)
        {
            pthread_mutex_unlock(&ctx_mutex);
            if (slashcount(path) == 4)
            {
                int err = errno;
                pthread_mutex_lock(&notfound_hash_mutex);
                char *key = strdup(path);
                if (key == NULL)
                {
                    pthread_mutex_unlock(&notfound_hash_mutex);
                    return -errno;
                }
                notfound_node_t *data = (notfound_node_t *)malloc(sizeof(notfound_node_t));
                if (data == NULL)
                {
                    pthread_mutex_unlock(&notfound_hash_mutex);
                    return -errno;
                }
                data->ctime = time(NULL);
                data->err = err;
                
                hash_alloc_insert(notfound_hash, key, data);
                pthread_mutex_unlock(&notfound_hash_mutex);
            }
            return -errno;

        }
        pthread_mutex_unlock(&ctx_mutex);
        return 0;
    
    }
}

static int fusesmb_opendir(const char *path, struct fuse_file_info *fi)
{
    if (slashcount(path) <= 2)
        return 0;
    SMBCFILE *dir;
    char smb_path[MY_MAXPATHLEN] = "smb:/";
    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);    
    dir = ctx->opendir(ctx, smb_path);
    if (dir == NULL)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    fi->fh = (unsigned long)dir;
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_readdir(const char *path, void *h, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    (void)offset;
    struct smbc_dirent *pdirent;
    //SMBCFILE *dir;
    char buf[MY_MAXPATHLEN],
         last_string[MY_MAXPATHLEN],
         cache_file[1024];
    FILE *fp;
    char *first_token;
    struct stat st;
    memset(&st, 0, sizeof(st));
    int dircount = 0;

    /*
       Check the cache file for workgroups/hosts and shares that are currently online
       Cases handled here are:
       / ,
       /WORKGROUP and
       /WORKGROUP/COMPUTER
     */

    if (slashcount(path) <= 2)
    {
        /* Listing Workgroups */
        snprintf(cache_file, 1024, "%s/.smb/smbcache", getenv("HOME"));
        fp = fopen(cache_file, "r");
        if (!fp)
            return -ENOENT;
        while (!feof(fp))
        {
            fgets(buf, sizeof(buf), fp);
            if (strncmp(buf, path, strlen(path)) == 0 &&
                (strlen(buf) > strlen(path)))
            {
                if (buf[strlen(path)] == '/' || strlen(path) == 1)
                {
                    if (strlen(path) > 1)
                    {
                        first_token = strtok(&buf[strlen(path) + 1], "/");
                    }
                    else
                    {
                        first_token = strtok(buf, "/");
                    }
                    if (strcmp(last_string, first_token) != 0)
                    {
                        //printf("%s\n",  strtok(first_token, "\n"));
                        st.st_mode = DT_DIR << 12;
                        filler(h, strtok(first_token, "\n"), &st, 0);
                        dircount++;
                        strncpy(last_string, first_token, 4096);
                    }
                }
            }
        }
        fclose(fp);

        if (dircount == 0)
            return -ENOENT;

        /* The workgroup / host and share lists don't have . and .. , so putting them in */
        st.st_mode = DT_DIR << 12;
        filler(h, ".", &st, 0);
        filler(h, "..", &st, 0);
        return 0;
    }
    /* Listing contents of a share */
    else
    {

        pthread_mutex_lock(&ctx_mutex);

        /* Put in . and .. for shares */
        /*if (slashcount(path) == 2)
        {
            st.st_mode = DT_DIR << 12;
            filler(h, ".", &st, 0);
            filler(h, "..", &st, 0);
        }*/
        while (NULL != (pdirent = ctx->readdir(ctx, (SMBCFILE *)fi->fh)))
        {
#if 0
            if (pdirent->smbc_type == SMBC_FILE_SHARE)
            {
                //* Don't show hidden shares */
                if (pdirent->name[strlen(pdirent->name) - 1] != '$')
                {
                    st.st_mode = DT_DIR << 12;
                    filler(h, pdirent->name, &st, 0);
                }
            }
#endif
            if (pdirent->smbc_type == SMBC_DIR)
            {
                st.st_mode = DT_DIR << 12;
                filler(h, pdirent->name, &st, 0);
            }
            if (pdirent->smbc_type == SMBC_FILE)
            {
                st.st_mode = DT_REG << 12;
                filler(h, pdirent->name, &st, 0);
            }
            /*
             * When doing a directory listing, check if the item is still valid in
             * notfound_hash
             */
#if 0
            if (slashcount(path) == 3 
                 && (pdirent->smbc_type == SMBC_DIR || pdirent->smbc_type == SMBC_FILE))
            {
                char lookup_path[MAXPATHLEN];
                strcpy(lookup_path, path);
                strcat(lookup_path, "/");
                strcat(lookup_path, pdirent->name);
                fprintf(stderr, "Lookup path: %s\n", lookup_path);

                pthread_mutex_lock(&notfound_hash_mutex);

                hnode_t *node = hash_lookup(notfound_hash, lookup_path);
                if (node)
                {
                    const void *key = hnode_getkey(node);
                    free((void *)key);
                    hash_delete_free(notfound_hash, node);
                }

                pthread_mutex_unlock(&notfound_hash_mutex);
            }
#endif
        }
        pthread_mutex_unlock(&ctx_mutex);
    }
    return 0;
}

static int fusesmb_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    if (slashcount(path) <= 2)
        return 0;

    pthread_mutex_lock(&ctx_mutex);
    ctx->closedir(ctx, (SMBCFILE *)fi->fh);
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_open(const char *path, struct fuse_file_info *fi)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    /* You cannot open directories */
    if (slashcount(path) <= 3)
        return -EACCES;

    /* Not sure what this code is doing */
    //if((flags & 3) != O_RDONLY)
    //    return -ENOENT;
    strcat(smb_path, stripworkgroup(path));

    pthread_mutex_lock(&rwd_ctx_mutex);
    file = rwd_ctx->open(rwd_ctx, smb_path, fi->flags, 0);

    if (file == NULL)
    {
        pthread_mutex_unlock(&rwd_ctx_mutex);
        return -errno;
    }

    fi->fh = (unsigned long)file;
    pthread_mutex_unlock(&rwd_ctx_mutex);
    return 0;
}

static int fusesmb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    //printf("%i\n", offset);
    //fflush(stdout);

    strcat(smb_path, stripworkgroup(path));

    int tries = 0;              //For number of retries before failing
    ssize_t ssize;              //Returned by ctx->read

    pthread_mutex_lock(&rwd_ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
    goto seek;
  top:
    if ((file = rwd_ctx->open(rwd_ctx, smb_path, O_RDONLY, 0)) == NULL)
    {
        /* Trying to reopen when out of memory */
        if (errno == ENOMEM)
        {
            tries++;
            if (tries > 4)
            {
                pthread_mutex_unlock(&rwd_ctx_mutex);
                return -errno;
            }
            goto top;
        }
        /* Other errors from docs cannot be recovered from so returning the error */
        else
        {
            pthread_mutex_unlock(&rwd_ctx_mutex);
            return -errno;
        }
    }
    fi->fh = (unsigned long)file;
  seek:
    if (rwd_ctx->lseek(rwd_ctx, (SMBCFILE *)fi->fh, offset, SEEK_SET) < offset)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto top;
        }
        else
        {
            //SMB Init failed
            pthread_mutex_unlock(&rwd_ctx_mutex);
            return -errno;
        }
    }
    if ((ssize = rwd_ctx->read(rwd_ctx, (SMBCFILE *)fi->fh, buf, size)) < 0)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto top;
        }
        /* Tried opening a directory / or smb_init failed */
        else
        {
            pthread_mutex_unlock(&rwd_ctx_mutex);
            return -errno;
        }
    }
    pthread_mutex_unlock(&rwd_ctx_mutex);
    return (size_t) ssize;
}


#if 0
static int fusesmb_write(const char *path, const char *buf, size_t size,
                     off_t offset)
{
    /* TODO:
       Increase write buffer size... throughput is about half of what is
       possible with libsmbclient, I'm also guessing that the open, seek, read,
       close cycle is expensive

       maybe create a cache struct with:

       struct fd_cache {
       SMBFILE *file;
       char *path,
       off_t offset,
       char *buf

       }
     */
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    //printf("%i\n", offset);
    //fflush(stdout);

    strcat(smb_path, stripworkgroup(path));

    int tries = 0;              //For number of retries before failing
    ssize_t ssize;              //Returned by ctx->read

    pthread_mutex_lock(&rwd_ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
  top:
    if (NULL == (file = rwd_ctx->open(rwd_ctx, smb_path, O_RDWR, 0)))
    {
        /* Trying to reopen when out of memory */
        if (errno == ENOMEM)
        {
            tries++;
            if (tries > 4)
            {
                pthread_mutex_unlock(&rwd_ctx_mutex);
                return -errno;
            }
            goto top;
        }
        /* Other errors from docs cannot be recovered from so returning the error */
        pthread_mutex_unlock(&rwd_ctx_mutex);
        return -errno;

    }
    if (rwd_ctx->lseek(rwd_ctx, file, offset, SEEK_SET) < offset)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto top;
        }
        else
        {
            //SMB Init failed
            pthread_mutex_unlock(&rwd_ctx_mutex);
            return -errno;
        }
    }
    if ((ssize = rwd_ctx->write(rwd_ctx, file, (void *) buf, size)) < 0)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto top;
        }
        /* Tried opening a directory / or smb_init failed */
        else
        {
            pthread_mutex_unlock(&rwd_ctx_mutex);
            return -errno;
        }
    }
    rwd_ctx->close(rwd_ctx, file);
    pthread_mutex_unlock(&rwd_ctx_mutex);
    return (size_t) ssize;
}
#endif

static int fusesmb_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    pthread_mutex_lock(&rwd_ctx_mutex);
    rwd_ctx->close(rwd_ctx, (SMBCFILE *)fi->fh);
    pthread_mutex_unlock(&rwd_ctx_mutex);
    return 0;

}

static int fusesmb_mknod(const char *path, mode_t mode,
                     __attribute__ ((unused)) dev_t rdev)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";
    SMBCFILE *file;

    /* FIXME:
       Check which rdevs are supported, currently only a file
       is created
     */
    //if (rdev != S_IFREG)
    //  return -EACCES;
    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);
    if ((file = ctx->creat(ctx, smb_path, mode)) == NULL)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    ctx->close(ctx, file);
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_statfs(const char *path, struct statfs *fst)
{
    /* Returning stat of local filesystem, call is too expensive */
    (void)path;
    memset(fst, 0, sizeof(struct statfs));
    if (statfs("/", fst) != 0)
        return -errno;
    return 0;
}

static int fusesmb_unlink(const char *file)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(file) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(file));
    pthread_mutex_lock(&ctx_mutex);
    if (ctx->unlink(ctx, smb_path) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_rmdir(const char *path)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);

    if (ctx->rmdir(ctx, smb_path) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_mkdir(const char *path, mode_t mode)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);
    if (ctx->mkdir(ctx, smb_path, mode) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_utime(const char *path, struct utimbuf *buf)
{
    (void)path;
    (void)buf;
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}

static int fusesmb_chmod(const char *path, mode_t mode)
{
    (void)path;
    (void)mode;
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}
static int fusesmb_chown(const char *path, uid_t uid, gid_t gid)
{
    (void)path;
    (void)uid;
    (void)gid;
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}

static int fusesmb_truncate(const char *path, off_t size)
{

    (void)path;
    (void)size;
    /* FIXME libsmbclient has no equivalent function for this, so
       always returning succes, but it should only return success
       for a few cases
     */
    return 0;
}

static int fusesmb_rename(const char *path, const char *new_path)
{
    char smb_path[MY_MAXPATHLEN]     = "smb:/",
         new_smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3 || slashcount(new_path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    strcat(new_smb_path, stripworkgroup(new_path));

    pthread_mutex_lock(&ctx_mutex);
    if (ctx->rename(ctx, smb_path, ctx, new_smb_path) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}
#if 0
static void *fusesmb_init()
{
    return NULL;
}

static void fusesmb_destroy(void *private_data)
{
    (void)private_data;
}
#endif
static struct fuse_operations fusesmb_oper = {
    .getattr    = fusesmb_getattr,
    .readlink   = NULL, //fusesmb_readlink,
    .opendir    = fusesmb_opendir,
    .readdir    = fusesmb_readdir,
    .releasedir = fusesmb_releasedir,
    .mknod      = fusesmb_mknod,
    .mkdir      = fusesmb_mkdir,
    .symlink    = NULL, //fusesmb_symlink,
    .unlink     = fusesmb_unlink,
    .rmdir      = fusesmb_rmdir,
    .rename     = fusesmb_rename,
    .link       = NULL, //fusesmb_link,
    .chmod      = fusesmb_chmod,
    .chown      = fusesmb_chown,
    .truncate   = fusesmb_truncate,
    .utime      = fusesmb_utime,
    .open       = fusesmb_open,
    .read       = fusesmb_read,
    .write      = NULL, //fusesmb_write,
    .statfs     = fusesmb_statfs,
    .release    = fusesmb_release,
    .fsync      = NULL, //fusesmb_fsync,
    .init       = NULL, //fusesmb_init,
    .destroy    = NULL, //fusesmb_destroy,
#ifdef HAVE_SETXATTR
    .setxattr   = fusesmb_setxattr,
    .getxattr   = fusesmb_getxattr,
    .listxattr  = fusesmb_listxattr,
    .removexattr= fusesmb_removexattr,
#endif
};


int main(int argc, char *argv[])
{
    /* Workaround for bug in libsmbclient:
       Limit reads to 32 kB
     */
    int my_argc = 0, i = 0;

    char **my_argv = (char **) malloc(argc + 10 * sizeof(char *));
    char *max_read = "-omax_read=33000";

    for (i = 0; i < argc; i++)
    {
        my_argv[i] = argv[i];
        my_argc++;
    }
    my_argv[my_argc++] = max_read;

    ctx = fusesmb_new_context(ctx);
    rwd_ctx = fusesmb_new_context(rwd_ctx);

    notfound_hash = hash_create(HASHCOUNT_T_MAX, NULL, NULL);

    if (0 != pthread_create(&cleanup_thread, NULL, smb_purge_thread, NULL))
        exit(EXIT_FAILURE);

    fuse_main(my_argc, my_argv, &fusesmb_oper);


    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);

    smbc_free_context(ctx, 1);
    smbc_free_context(rwd_ctx, 1);

    hscan_t sc;
    hash_scan_begin(&sc, notfound_hash);
    hnode_t *n;
    while (NULL != (n = hash_scan_next(&sc)))
    {
        fprintf(stderr, "%s\n", (char *)hnode_getkey(n));
    }
    fprintf(stderr, "Hash size:  %lu\n", (unsigned long) hash_size(notfound_hash));
    fprintf(stderr, "Hash count: %lu\n", (unsigned long) hash_count(notfound_hash));

    hash_scan_begin(&sc, notfound_hash);
    while (NULL != (n = hash_scan_next(&sc)))
    {
        void *data = hnode_get(n);
        free(data);
        const void *key = hnode_getkey(n);
        free((void *)key);
        hash_scan_delfree(notfound_hash, n);
    }
    hash_destroy(notfound_hash);
    return 0;
}
