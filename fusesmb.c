/*
 * SMB for FUSE
 *
 * Mount complete "Network Neighbourhood"
 *
 * Copyright (C) 2006 Vincent Wagelaar
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include "debug.h"
#include "hash.h"
#include "smbctx.h"

#define MY_MAXPATHLEN (MAXPATHLEN + 256)

/* Mutex for locking the Samba context */

/* To prevent deadlock, locking order should be:

[rwd]ctx_mutex -> cfg_mutex -> opts_mutex
[rwd]ctx_mutex -> opts_mutex
*/

static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rwd_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static SMBCCTX *ctx, *rwd_ctx;
pthread_t cleanup_thread;

/*
 * Hash for storing files/directories that were not found, an optimisation
 * for programs like konqueror and freevo that do a lot of lookups:
 * .directory, share.fxd etc..
 */
static hash_t *notfound_cache;
static pthread_mutex_t notfound_cache_mutex = PTHREAD_MUTEX_INITIALIZER;


typedef struct {
    time_t ctime;  /* Time of creation */
    int err;       /* errno variable */
} notfound_node_t;

struct fusesmb_opt {
    int global_showhiddenshares;
    int global_interval;
    int global_timeout;
    char *global_username;
    char *global_password;
};
/* Read settings from fusesmb.conf and or set default value */
config_t cfg;
pthread_mutex_t cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
struct fusesmb_opt opts;
pthread_mutex_t opts_mutex = PTHREAD_MUTEX_INITIALIZER;
char fusesmb_cache_bin[MAXPATHLEN];

static void options_read(config_t *cfg, struct fusesmb_opt *opt)
{
    if (-1 == config_read_bool(cfg, "global", "showhiddenshares", &(opt->global_showhiddenshares)))
        opt->global_showhiddenshares = 1;
    if (-1 == config_read_int(cfg, "global", "timeout", &(opt->global_timeout)))
        opt->global_timeout = 10;

    /* Timeout less then 2 seconds is not really useful */
    if(opt->global_timeout <= 2)
        opt->global_timeout = 2;

    if (-1 == config_read_int(cfg, "global", "interval", &(opt->global_interval)))
        opt->global_interval = 15;
    if (opt->global_interval <= 0)
        opt->global_interval = 0;

    if (-1 == config_read_string(cfg, "global", "username", &(opt->global_username)))
        opt->global_username = NULL;
    if (-1 == config_read_string(cfg, "global", "password", &(opt->global_password)))
        opt->global_password = NULL;
}

static void options_free(struct fusesmb_opt *opt)
{
    if (NULL != opt->global_username)
        free(opt->global_password);
    if (NULL != opt->global_password)
        free(opt->global_username);
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
            pthread_mutex_lock(&notfound_cache_mutex);
            hscan_t sc;
            hash_scan_begin(&sc, notfound_cache);
            hnode_t *n;
            while (NULL != (n = hash_scan_next(&sc)))
            {
                notfound_node_t *data = hnode_get(n);
                if (time(NULL) - data->ctime > 15 * 60) /* 15 minutes */
                {
                    const void *key = hnode_getkey(n);
                    debug("Deleting notfound node: %s", (char *)key);
                    hash_scan_delfree(notfound_cache, n);
                    free((void *)key);
                    free(data);
                }

            }
            pthread_mutex_unlock(&notfound_cache_mutex);
            count = 0;
        }
        else
        {
            count++;
        }

        char cachefile[1024];
        snprintf(cachefile, 1024, "%s/.smb/fusesmb.cache", getenv("HOME"));
        struct stat st;
        memset(&st, 0, sizeof(struct stat));

        if(opts.global_interval > 0)
        {
            if (-1 == stat(cachefile, &st))
            {
                if (errno == ENOENT)
                {
                    system(fusesmb_cache_bin);
                }
            }
            else if (time(NULL) - st.st_mtime > opts.global_interval * 60)
            {
                system("fusesmb.cache");
            }
        }


        /* Look if any changes have been made to the configfile */
        int changed;
        pthread_mutex_lock(&cfg_mutex);
        if (0 == (changed = config_reload_ifneeded(&cfg)))
        {
            /* Lookout for deadlocks !!!! (order of setting locks within locks) */
            pthread_mutex_lock(&opts_mutex);
            options_free(&opts);
            options_read(&cfg, &opts);
            pthread_mutex_unlock(&opts_mutex);
        }
        pthread_mutex_unlock(&cfg_mutex);

        /* Prevent unnecessary locks within locks */
        if (changed == 0)
        {
            pthread_mutex_lock(&ctx_mutex);
            ctx->timeout = opts.global_timeout * 1000;
            pthread_mutex_unlock(&ctx_mutex);

            pthread_mutex_lock(&rwd_ctx_mutex);
            rwd_ctx->timeout = opts.global_timeout * 1000;
            pthread_mutex_unlock(&rwd_ctx_mutex);
        }


        sleep(15);
    }
    return NULL;
}

static const char *stripworkgroup(const char *file)
{
    unsigned int i = 0, ret = 0, goodpos = 0, file_len = strlen(file);

    for (i = 0; i < file_len; i++)
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
    unsigned int i = 0, count = 0, file_len = strlen(file);

    for (i = 0; i < file_len; i++)
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
        snprintf(cache_file, 1024, "%s/.smb/fusesmb.cache", getenv("HOME"));

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
        /* Prevent connecting too often to a share because this is slow */
        if (slashcount(path) == 4)
        {
            pthread_mutex_lock(&notfound_cache_mutex);
            hnode_t *node = hash_lookup(notfound_cache, path);
            if (node)
            {
                debug("NotFoundCache hit for: %s", path);
                notfound_node_t *data = hnode_get(node);
                int err = data->err;
                data->ctime = time(NULL);
                pthread_mutex_unlock(&notfound_cache_mutex);
                return -err;
            }
            pthread_mutex_unlock(&notfound_cache_mutex);
        }

        strcat(smb_path, stripworkgroup(path));
        pthread_mutex_lock(&ctx_mutex);
        if (ctx->stat(ctx, smb_path, stbuf) < 0)
        {
            pthread_mutex_unlock(&ctx_mutex);
            if (slashcount(path) == 4)
            {
                int err = errno;
                pthread_mutex_lock(&notfound_cache_mutex);
                char *key = strdup(path);
                if (key == NULL)
                {
                    pthread_mutex_unlock(&notfound_cache_mutex);
                    return -errno;
                }
                notfound_node_t *data = (notfound_node_t *)malloc(sizeof(notfound_node_t));
                if (data == NULL)
                {
                    pthread_mutex_unlock(&notfound_cache_mutex);
                    return -errno;
                }
                data->ctime = time(NULL);
                data->err = err;

                hash_alloc_insert(notfound_cache, key, data);
                pthread_mutex_unlock(&notfound_cache_mutex);
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
    char buf[MY_MAXPATHLEN],
         last_dir_entry[MY_MAXPATHLEN] = "",
         cache_file[1024];
    FILE *fp;
    char *dir_entry;
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
        snprintf(cache_file, 1024, "%s/.smb/fusesmb.cache", getenv("HOME"));
        fp = fopen(cache_file, "r");
        if (!fp)
            return -ENOENT;
        while (!feof(fp))
        {
            if (NULL == fgets(buf, sizeof(buf), fp))
                continue;

            if (strncmp(buf, path, strlen(path)) == 0 &&
                (strlen(buf) > strlen(path)))
            {
                /* Note: strtok is safe because the static buffer is is not reused */
                if (buf[strlen(path)] == '/' || strlen(path) == 1)
                {
                    /* Path is workgroup or server */
                    if (strlen(path) > 1)
                    {
                        dir_entry = strtok(&buf[strlen(path) + 1], "/");
                        /* Look if share is a hidden share, dir_entry still contains '\n' */
                        if (slashcount(path) == 2)
                        {
                            if (dir_entry[strlen(dir_entry)-2] == '$')
                            {
                                int showhidden = 0;
                                pthread_mutex_lock(&cfg_mutex);
                                if (0 == config_read_bool(&cfg, stripworkgroup(path), "showhiddenshares", &showhidden))
                                {
                                    pthread_mutex_unlock(&cfg_mutex);
                                    if (showhidden == 1)
                                        continue;
                                }
                                pthread_mutex_unlock(&cfg_mutex);

                                pthread_mutex_lock(&opts_mutex);
                                if (opts.global_showhiddenshares == 0)
                                {
                                    pthread_mutex_unlock(&opts_mutex);
                                    continue;
                                }
                                pthread_mutex_unlock(&opts_mutex);
                            }
                        }
                    }
                    /* Path is root */
                    else
                    {
                        dir_entry = strtok(buf, "/");
                    }
                    /* Only unique workgroups or servers */
                    if (strcmp(last_dir_entry, dir_entry) == 0)
                        continue;

                    st.st_mode = DT_DIR << 12;
                    filler(h, strtok(dir_entry, "\n"), &st, 0);
                    dircount++;
                    strncpy(last_dir_entry, dir_entry, 4096);
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
        while (NULL != (pdirent = ctx->readdir(ctx, (SMBCFILE *)fi->fh)))
        {
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
            if (slashcount(path) == 4 && 
                (pdirent->smbc_type == SMBC_FILE || pdirent->smbc_type == SMBC_DIR))
            {
                /* Clear item from notfound_cache */
		pthread_mutex_lock(&notfound_cache_mutex);
                char full_entry_path[MY_MAXPATHLEN];
                snprintf(full_entry_path, sizeof(full_entry_path)-1, "%s/%s", path, pdirent->name);
                hnode_t *node = hash_lookup(notfound_cache, full_entry_path);
                if (node != NULL)
                {
                    void *data = hnode_get(node);
                    const void *key = hnode_getkey(node);
                    hash_delete_free(notfound_cache, node);
                    free((void *)key);
                    free(data);
                }
                pthread_mutex_unlock(&notfound_cache_mutex);
            }
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
  reopen:
    if ((file = rwd_ctx->open(rwd_ctx, smb_path, fi->flags, 0)) == NULL)
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
            goto reopen;
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

    if (rwd_ctx->lseek(rwd_ctx, (SMBCFILE *)fi->fh, offset, SEEK_SET) == (off_t) - 1)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
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
            goto reopen;
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

static int fusesmb_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    strcat(smb_path, stripworkgroup(path));

    int tries = 0;              //For number of retries before failing
    ssize_t ssize;              //Returned by ctx->read

    pthread_mutex_lock(&rwd_ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
    goto seek;
  reopen:
    if (NULL == (file = rwd_ctx->open(rwd_ctx, smb_path, fi->flags, 0)))
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
            goto reopen;
        }
        /* Other errors from docs cannot be recovered from so returning the error */
        pthread_mutex_unlock(&rwd_ctx_mutex);
        return -errno;

    }
    fi->fh = (unsigned long)file;
  seek:

    if (rwd_ctx->lseek(rwd_ctx, (SMBCFILE *)fi->fh, offset, SEEK_SET) == (off_t) - 1)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
        }
        else
        {
            //SMB Init failed
            pthread_mutex_unlock(&rwd_ctx_mutex);
            return -errno;
        }
    }
    if ((ssize = rwd_ctx->write(rwd_ctx, (SMBCFILE *)fi->fh, (void *) buf, size)) < 0)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
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

static int fusesmb_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    pthread_mutex_lock(&rwd_ctx_mutex);
#ifdef HAVE_LIBSMBCLIENT_CLOSE_FN
    rwd_ctx->close_fn(rwd_ctx, (SMBCFILE *)fi->fh);
#else
    rwd_ctx->close(rwd_ctx, (SMBCFILE *)fi->fh);
#endif
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
#ifdef HAVE_LIBSMBCLIENT_CLOSE_FN
    ctx->close_fn(ctx, file);
#else
    ctx->close(ctx, file);
#endif

    pthread_mutex_unlock(&ctx_mutex);
    /* Clear item from notfound_cache */
    if (slashcount(path) == 4)
    {
        pthread_mutex_lock(&notfound_cache_mutex);
        hnode_t *node = hash_lookup(notfound_cache, path);
        if (node != NULL)
        {
            const void *key = hnode_getkey(node);
            void *data = hnode_get(node);
            hash_delete_free(notfound_cache, node);
            free((void *)key);
            free(data);
        }
        pthread_mutex_unlock(&notfound_cache_mutex);
    }
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
    
    /* Clear item from notfound_cache */
    if (slashcount(path) == 4)
    {
        pthread_mutex_lock(&notfound_cache_mutex);
	hnode_t *node = hash_lookup(notfound_cache, path);
	if (node != NULL)
	{
	    void *data = hnode_get(node);
	    const void *key = hnode_getkey(node);
	    hash_delete_free(notfound_cache, node);
	    free((void *)key);
	    free(data);
	}
	pthread_mutex_unlock(&notfound_cache_mutex);
    }
    return 0;
}

static int fusesmb_utime(const char *path, struct utimbuf *buf)
{
    struct timeval tbuf[2];
    debug("path: %s, atime: %ld, mtime: %ld", path, buf->actime, buf->modtime);

    char smb_path[MY_MAXPATHLEN] = "smb:/";
    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    tbuf[0].tv_sec = buf->actime;
    tbuf[0].tv_usec = 0;
    tbuf[1].tv_sec = buf->modtime;
    tbuf[1].tv_usec = 0;

    pthread_mutex_lock(&ctx_mutex);
    if (ctx->utimes(ctx, smb_path, tbuf) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);


    return 0;
}

static int fusesmb_chmod(const char *path, mode_t mode)
{
    if (slashcount(path) <= 3)
        return -EPERM;

    char smb_path[MY_MAXPATHLEN] = "smb:/";
    strcat(smb_path, stripworkgroup(path));

    pthread_mutex_lock(&ctx_mutex);
    if (ctx->chmod(ctx, smb_path, mode) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
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

    debug("path: %s, size: %lld", path, size);
    char smb_path[MY_MAXPATHLEN] = "smb:/";
    if (slashcount(path) <= 3)
        return -EACCES;

    SMBCFILE *file;
    strcat(smb_path, stripworkgroup(path));
    if (size == 0)
    {
        pthread_mutex_lock(&ctx_mutex);
        if (NULL == (file = ctx->creat(ctx, smb_path, 0666)))
        {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
#ifdef HAVE_LIBSMBCLIENT_CLOSE_FN
        ctx->close_fn(ctx, file);
#else
        ctx->close(ctx, file);
#endif
        pthread_mutex_unlock(&ctx_mutex);
        return 0;
    }
    else
    {
         /* If the truncate size is equal to the current file size, the file
            is also correctly truncated (fixes an error from OpenOffice)
            */
         pthread_mutex_lock(&ctx_mutex);
         struct stat st;
         if (ctx->stat(ctx, smb_path, &st) < 0)
         {
             pthread_mutex_unlock(&ctx_mutex);
             return -errno;
         }
         pthread_mutex_unlock(&ctx_mutex);
         if (size == st.st_size)
         {
             return 0;
         }
    }
    return -ENOTSUP;
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

static void *fusesmb_init()
{
    debug();
    if (0 != pthread_create(&cleanup_thread, NULL, smb_purge_thread, NULL))
        exit(EXIT_FAILURE);
    return NULL;
}

static void fusesmb_destroy(void *private_data)
{
    (void)private_data;
    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);

}

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
    .write      = fusesmb_write,
    .statfs     = fusesmb_statfs,
    .release    = fusesmb_release,
    .fsync      = NULL, //fusesmb_fsync,
    .init       = fusesmb_init,
    .destroy    = fusesmb_destroy,
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

    /* Check if the directory for smbcache exists and if not so create it */
    char cache_path[1024];
    snprintf(cache_path, 1024, "%s/.smb/", getenv("HOME"));
    struct stat st;
    if (-1 == stat(cache_path, &st))
    {
        if (errno != ENOENT)
        {
            fprintf(stderr, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (-1 == mkdir(cache_path, 0777))
        {
            fprintf(stderr, strerror(errno));
            exit(EXIT_FAILURE);
       }
    }
    else if (!S_ISDIR(st.st_mode))
    {
        fprintf(stderr, "%s is not a directory\n", cache_path);
        exit(EXIT_FAILURE);
    }

    char configfile[1024];
    snprintf(configfile, 1024, "%s/.smb/fusesmb.conf", getenv("HOME"));
    if (-1 == stat(configfile, &st))
    {
        if (errno != ENOENT)
        {
            fprintf(stderr, strerror(errno));
            exit(EXIT_FAILURE);
        }
        int fd;
        /* Create configfile with read-write permissions for the owner */
        if (-1 == (fd = open(configfile, O_WRONLY | O_CREAT, 00600)))
        {
            fprintf(stderr, strerror(errno));
            exit(EXIT_FAILURE);
        }
        close(fd);
    }
    else
    {
        /* Check if configfile is only accessible by the owner */
        if ((st.st_mode & 00777) != 00700 &&
             (st.st_mode & 00777) != 00600 &&
              (st.st_mode & 00777) != 00400)
        {
            fprintf(stderr, "The config file should only be readable by the owner.\n"
                            "You can correct the permissions by executing:\n"
                            " chmod 600 %s\n\n", configfile);
            exit(EXIT_FAILURE);
        }
    }
    /* Check if fusesmb.cache can be found
       we're looking in FUSESMB_CACHE_BINDIR, $PATH or in cwd */
    if (-1 == stat(FUSESMB_CACHE_BINDIR"/fusesmb.cache", &st))
    {
        if (-1 == stat("fusesmb.cache", &st))
        {
            fprintf(stderr, "Could not find the required file fusesmb.cache.\n"
                            "This file should either be in:\n"
                            " - "FUSESMB_CACHE_BINDIR"\n"
                            " - $PATH\n"
                            " - your current working directory\n"
                            "(%s)\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        else
        {
            strncpy(fusesmb_cache_bin, "fusesmb.cache", MAXPATHLEN-1);
        }
    }
    else
    {
        strncpy(fusesmb_cache_bin, FUSESMB_CACHE_BINDIR"/fusesmb.cache", MAXPATHLEN-1);
    }

    if (-1 == config_init(&cfg, configfile))
    {
        fprintf(stderr, "Could not open config file: %s (%s)", configfile, strerror(errno));
        exit(EXIT_FAILURE);
    }

    char **my_argv = (char **) malloc((argc + 10) * sizeof(char *));
    if (my_argv == NULL)
        exit(EXIT_FAILURE);

    /* libsmbclient doesn't work with reads bigger than 32k */
    char *max_read = "-omax_read=32768";

    for (i = 0; i < argc; i++)
    {
        my_argv[i] = argv[i];
        my_argc++;
    }
    my_argv[my_argc++] = max_read;

    options_read(&cfg, &opts);

    ctx = fusesmb_new_context(&cfg, &cfg_mutex);
    rwd_ctx = fusesmb_new_context(&cfg, &cfg_mutex);

    if (ctx == NULL || rwd_ctx == NULL)
        exit(EXIT_FAILURE);

    notfound_cache = hash_create(HASHCOUNT_T_MAX, NULL, NULL);
    if (notfound_cache == NULL)
        exit(EXIT_FAILURE);

    fuse_main(my_argc, my_argv, &fusesmb_oper);

    smbc_free_context(ctx, 1);
    smbc_free_context(rwd_ctx, 1);

    options_free(&opts);
    config_free(&cfg);

    hscan_t sc;
    hnode_t *n;
    hash_scan_begin(&sc, notfound_cache);
    while (NULL != (n = hash_scan_next(&sc)))
    {
        void *data = hnode_get(n);
        const void *key = hnode_getkey(n);
        hash_scan_delfree(notfound_cache, n);
        free((void *)key);
        free(data);

    }
    hash_destroy(notfound_cache);
    exit(EXIT_SUCCESS);
}
