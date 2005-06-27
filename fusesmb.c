/*
   SMB for FUSE
   Copyright (C) 2003-2005  VIncent Wagelaar <vincent@ricardis.tudelft.nl>
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
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/vfs.h>
#include <pthread.h>
#include <libsmbclient.h>

#define MY_MAXPATHLEN (MAXPATHLEN + 256)

/* Mutex for locking the Samba context */
pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rwd_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
SMBCCTX *ctx, *rwd_ctx;

static void auth_smbc_get_data( __attribute__ ((unused)) const char *server,
			       __attribute__ ((unused)) const char *share,
			       __attribute__ ((unused)) char *workgroup,
			       __attribute__ ((unused)) int wgmaxlen,
			       char *username, __attribute__ ((unused)) int unmaxlen,
			       char *password, __attribute__ ((unused)) int pwmaxlen)
{
    char cred_file [1024];
    FILE *fp;

    snprintf(cred_file, 1024, "%s/.smb/credentials", getenv("HOME"));
    fp = fopen(cred_file, "r");
    if( fp != NULL )
    {
        char fbuf[1024];
        while( fgets( fbuf, 1024, fp ) != NULL )
        {
            if( strncmp( fbuf, "username", 8 ) == 0 )
            {
                char* begin = fbuf + 8;
                char* end;
                while ( *begin == ' ' || *begin == '\t')
                     begin++;
                if (*begin == '=')
                {
                    begin++;
                    while ( *begin == ' ' || *begin == '\t')
                        begin++;
                    strncpy( username, begin, strlen(begin));
                    end = username + strlen(username) - 1;
                    while ( *end == ' ' || *end == '\t' || *end == '\n' || *end == '\0')
                    {
                        end--;
                    }
                    end++;
                    *end = '\0';

                }
            }
            else if( strncmp( fbuf, "password", 8 ) == 0 )
            {
                char* begin = fbuf + 8;
                char* end;
                while ( *begin == ' ' || *begin == '\t')
                     begin++;
                if (*begin == '=')
                {
                    begin++;
                    while ( *begin == ' ' || *begin == '\t')
                        begin++;
                    strncpy( password, begin, strlen(begin));
                    end = password + strlen(password) - 1;
                    while ( *end == ' ' || *end == '\t' || *end == '\n' || *end == '\0')
                    {
                        end--;
                    }
                    end++;
                    *end = '\0';
                }
            }
        }
        if (!strlen(username))
        {
            char un[] = "guest";
            char pw[] = "";

            strncpy(username, un, sizeof(un));
            strncpy(password, pw, sizeof(pw));
        }
    }
    else
    {
        char un[] = "guest";
        char pw[] = "";

        strncpy(username, un, sizeof(un));
        strncpy(password, pw, sizeof(pw));
    }
}

static void auth_smbc_get_data2( __attribute__ ((unused)) const char *server,
			       __attribute__ ((unused)) const char *share,
			       __attribute__ ((unused)) char *workgroup,
			       __attribute__ ((unused)) int wgmaxlen,
			       char *username, __attribute__ ((unused)) int unmaxlen,
			       char *password, __attribute__ ((unused)) int pwmaxlen)
{
    char cred_file [1024];
    FILE *fp;

    snprintf(cred_file, 1024, "%s/.smb/credentials", getenv("HOME"));
    fp = fopen(cred_file, "r");
    if( fp != NULL )
    {
        char fbuf[1024];
        while( fgets( fbuf, 1024, fp ) != NULL )
        {
            if( strncmp( fbuf, "username", 8 ) == 0 )
            {
                char* begin = fbuf + 8;
                char* end;
                while ( *begin == ' ' || *begin == '\t')
                     begin++;
                if (*begin == '=')
                {
                    begin++;
                    while ( *begin == ' ' || *begin == '\t')
                        begin++;
                    strncpy( username, begin, strlen(begin));
                    end = username + strlen(username) - 1;
                    while ( *end == ' ' || *end == '\t' || *end == '\n' || *end == '\0')
                    {
                        end--;
                    }
                    end++;
                    *end = '\0';

                }
            }
            else if( strncmp( fbuf, "password", 8 ) == 0 )
            {
                char* begin = fbuf + 8;
                char* end;
                while ( *begin == ' ' || *begin == '\t')
                     begin++;
                if (*begin == '=')
                {
                    begin++;
                    while ( *begin == ' ' || *begin == '\t')
                        begin++;
                    strncpy( password, begin, strlen(begin));
                    end = password + strlen(password) - 1;
                    while ( *end == ' ' || *end == '\t' || *end == '\n' || *end == '\0')
                    {
                        end--;
                    }
                    end++;
                    *end = '\0';
                }
            }
        }
        if (!strlen(username))
        {
            char un[] = "guest";
            char pw[] = "";

            strncpy(username, un, sizeof(un));
            strncpy(password, pw, sizeof(pw));
        }
    }
    else
    {
        char un[] = "guest";
        char pw[] = "";

        strncpy(username, un, sizeof(un));
        strncpy(password, pw, sizeof(pw));
    }
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

static int smb_getattr(const char *path, struct stat *stbuf)
{
    char smb_path[MY_MAXPATHLEN], buf[MY_MAXPATHLEN], cache_file[1024];
    const char *goodpath;
    int path_exists = 0;
    FILE *fp;

    memset(stbuf, 0, sizeof(struct stat));

    /* Check the cache for valid workgroup, hosts and shares */
    if (slashcount(path) <= 3)
    {

	if (strlen(path) == 1 && path[0] == '/')
	    path_exists = 1;
	else
	{
	    snprintf(cache_file, 1024, "%s/.smb/smbcache", getenv("HOME"));
	    fp = fopen(cache_file, "r");
	    //free(path_cp);
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
	if (path_exists == 1)
	{
	    stbuf->st_mode = S_IFDIR | 0755;
	    stbuf->st_nlink = 2;
	    stbuf->st_size = 4096;
	    return 0;
	}
	else
	{
	    return -ENOENT;
	}
    }
    /* We're within a share here  */
    else
    {
	strcpy(smb_path, "smb:/");
	goodpath = stripworkgroup(path);
	pthread_mutex_lock(&ctx_mutex);
	if (ctx->stat(ctx, strcat(smb_path, goodpath), stbuf) < 0)
	{
	    pthread_mutex_unlock(&ctx_mutex);
	    return -errno;

	}
	else
	{
	    pthread_mutex_unlock(&ctx_mutex);
	    return 0;
	}
    }
}

static int smb_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    struct smbc_dirent *pdirent;
    SMBCFILE *dir;
    char smb_path[MY_MAXPATHLEN], buf[MY_MAXPATHLEN],
	last_string[MY_MAXPATHLEN], cache_file[1024];
    FILE *fp;
    const char *goodpath = NULL;
    char *first_token;

    goodpath = stripworkgroup(path);
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
			filler(h, strtok(first_token, "\n"), DT_DIR);
			dircount++;
			strncpy(last_string, first_token, 4096);
		    }
		}
	    }
	}
	fclose(fp);
	/* The workgroup / host and share lists don't have . and .. , so putting them in */
	if (dircount > 0)
	{
	    filler(h, ".", 0);
	    filler(h, "..", 0);
	}
	else
	{
	    return -ENOENT;
	}

	return 0;
    }
    /* Listing contents of a share */
    else
    {

	strcpy(smb_path, "smb:/");
	pthread_mutex_lock(&ctx_mutex);
	dir = ctx->opendir(ctx, strcat(smb_path, goodpath));

	/* Put in . and .. for shares */
	if (slashcount(path) == 2)
	{
	    filler(h, ".", 0);
	    filler(h, "..", 0);
	}
	while ((pdirent = ctx->readdir(ctx, dir)) != NULL)
	{
	    if (pdirent->smbc_type == SMBC_FILE_SHARE)
	    {
		/* Don't show hidden shares */
		if (pdirent->name[strlen(pdirent->name) - 1] != '$')
		    filler(h, pdirent->name, DT_DIR);
	    }
	    if (pdirent->smbc_type == SMBC_DIR)
	    {
		filler(h, pdirent->name, DT_DIR);
	    }
	    if (pdirent->smbc_type == SMBC_FILE)
	    {
		filler(h, pdirent->name, DT_REG);
	    }
	}
	ctx->closedir(ctx, dir);
	pthread_mutex_unlock(&ctx_mutex);
    }
    return 0;
}

static int smb_open(const char *path, int flags)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN];
    const char *goodpath;

    goodpath = stripworkgroup(path);
    strcpy(smb_path, "smb:/");

    /* You cannot open directories */
    if (slashcount(path) <= 3)
	return -EACCES;

    /* Not sure what this code is doing */
    //if((flags & 3) != O_RDONLY)
    //    return -ENOENT;
    pthread_mutex_lock(&rwd_ctx_mutex);
    if ((file = rwd_ctx->open(rwd_ctx, strcat(smb_path, goodpath), flags, 0)) == NULL)
    {
	pthread_mutex_unlock(&rwd_ctx_mutex);
	return -errno;
    }
    rwd_ctx->close(rwd_ctx, file);
    pthread_mutex_unlock(&rwd_ctx_mutex);
    return 0;
}

static int smb_read(const char *path, char *buf, size_t size, off_t offset)
{
    /* TODO:
       Increase read buffer size... throughput is about half of what is
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
    char smb_path[MY_MAXPATHLEN];
    char *psmb_path;
    const char *goodpath;

    //printf("%i\n", offset);
    //fflush(stdout);

    /* FIXME:
       check if path isn't longer than buffer (better use strncpy?)
     */
    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(path);
    psmb_path = strcat(smb_path, goodpath);

    int tries = 0;		//For number of retries before failing
    ssize_t ssize;		//Returned by ctx->read

    pthread_mutex_lock(&rwd_ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
  top:
    if ((file = rwd_ctx->open(rwd_ctx, psmb_path, O_RDONLY, 0)) == NULL)
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
    if ((ssize = rwd_ctx->read(rwd_ctx, file, buf, size)) < 0)
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

static int smb_write(const char *path, const char *buf, size_t size,
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
    char smb_path[MY_MAXPATHLEN];
    char *psmb_path;
    const char *goodpath;

    //printf("%i\n", offset);
    //fflush(stdout);

    /* FIXME
       check if path isn't longer than buffer (better use strncpy?)
     */
    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(path);
    psmb_path = strcat(smb_path, goodpath);

    int tries = 0;		//For number of retries before failing
    ssize_t ssize;		//Returned by ctx->read

    pthread_mutex_lock(&rwd_ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
  top:
    if ((file = rwd_ctx->open(rwd_ctx, psmb_path, O_RDWR, 0)) == NULL)
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

static int smb_mknod(const char *path, mode_t mode, __attribute__ ((unused)) dev_t rdev)
{
    char smb_path[MY_MAXPATHLEN];
    char *psmb_path;
    const char *goodpath;
    SMBCFILE *file;

    /* FIXME:
       Check which rdevs are supported, currently only a file
       is created
     */
    //if (rdev != S_IFREG)
    //	return -EACCES;
    if (slashcount(path) <= 3)
	return -EACCES;

    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(path);
    psmb_path = strcat(smb_path, goodpath);
    pthread_mutex_lock(&ctx_mutex);
    if ((file = ctx->creat(ctx, psmb_path, mode)) == NULL)
    {
	pthread_mutex_unlock(&ctx_mutex);
	return -errno;
    }
    ctx->close(ctx, file);
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int smb_statfs(struct fuse_statfs *fst)
{
    /* Returning stat of local filesystem, call is too expensive */
    struct statfs st;
    int rv = statfs("/", &st);

    if (!rv)
    {
	fst->block_size = st.f_bsize;
	fst->blocks = st.f_blocks;
	fst->blocks_free = st.f_bavail;
	fst->files = st.f_files;
	fst->files_free = st.f_ffree;
	fst->namelen = st.f_namelen;
    }
    return rv;
}

static int smb_unlink(const char *file)
{
    char smb_path[MY_MAXPATHLEN];
    char *psmb_path;
    const char *goodpath;

    if (slashcount(file) <= 3)
	return -EACCES;

    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(file);
    psmb_path = strcat(smb_path, goodpath);
    pthread_mutex_lock(&ctx_mutex);
    if (ctx->unlink(ctx, psmb_path) < 0)
    {
	pthread_mutex_unlock(&ctx_mutex);
	return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int smb_rmdir(const char *path)
{
    char smb_path[MY_MAXPATHLEN];
    char *psmb_path;
    const char *goodpath;

    if (slashcount(path) <= 3)
	return -EACCES;

    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(path);
    psmb_path = strcat(smb_path, goodpath);
    pthread_mutex_lock(&ctx_mutex);

    if (ctx->rmdir(ctx, psmb_path) < 0)
    {
	pthread_mutex_unlock(&ctx_mutex);
	return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int smb_mkdir(const char *path, mode_t mode)
{
    char smb_path[MY_MAXPATHLEN];
    char *psmb_path;
    const char *goodpath;

    if (slashcount(path) <= 3)
	return -EACCES;

    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(path);
    psmb_path = strcat(smb_path, goodpath);
    pthread_mutex_lock(&ctx_mutex);
    if (ctx->mkdir(ctx, psmb_path, mode) < 0)
    {
	pthread_mutex_unlock(&ctx_mutex);
	return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int smb_utime( __attribute__ ((unused))
		     const char *path, __attribute__ ((unused))
		     struct utimbuf *buf)
{
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}

static int smb_chmod( __attribute__ ((unused))
		     const char *path, __attribute__ ((unused)) mode_t mode)
{
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}
static int smb_chown( __attribute__ ((unused))
		     const char *path,
		     __attribute__ ((unused)) uid_t uid,
		     __attribute__ ((unused)) gid_t gid)
{
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}

static int smb_truncate( __attribute__ ((unused))
			const char *path, __attribute__ ((unused)) off_t size)
{
    /* FIXME libsmbclient has no equivalent function for this, so
       always returning succes, but it should only return success
       for a few cases
     */
    return 0;
}

static int smb_rename(const char *path, const char *new_path)
{
    char smb_path[MY_MAXPATHLEN], new_smb_path[MY_MAXPATHLEN];
    char *psmb_path, *pnew_smb_path;
    const char *goodpath, *new_goodpath;
    //SMBCCTX *ctx2;

    if (slashcount(path) <= 3 ||
         slashcount(new_path) <= 3)
         return -EACCES;

    strcpy(smb_path, "smb:/");
    goodpath = stripworkgroup(path);
    psmb_path = strcat(smb_path, goodpath);

    strcpy(new_smb_path, "smb:/");
    new_goodpath = stripworkgroup(new_path);
    pnew_smb_path = strcat(new_smb_path, new_goodpath);

    //printf("%s %s\n", psmb_path, pnew_smb_path);
    //fflush(stdout);

    pthread_mutex_lock(&ctx_mutex);
    //ctx2 = smbc_new_context();
    //ctx2->callbacks.auth_fn = auth_smbc_get_data;
    //ctx2 = smbc_init_context(ctx2);
    if (ctx->rename(ctx, psmb_path, ctx, pnew_smb_path) < 0)
    {
        //smbc_free_context(ctx2, 1);
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    //smbc_free_context(ctx2, 1);
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int smb_release(__attribute__ ((unused))const char *path, __attribute__ ((unused))int flags)
{
   //printf("File released: %s\n", path);
   //fflush(stdout);

   pthread_mutex_lock(&ctx_mutex);
   ctx->callbacks.purge_cached_fn(ctx);
   pthread_mutex_unlock(&ctx_mutex);
   pthread_mutex_lock(&rwd_ctx_mutex);
   rwd_ctx->callbacks.purge_cached_fn(rwd_ctx);
   pthread_mutex_unlock(&rwd_ctx_mutex);
   return 0;
}

static struct fuse_operations smb_oper = {
  getattr:	smb_getattr,
  readlink:	NULL,
  getdir:	smb_getdir,
  mknod:	smb_mknod,
  mkdir:	smb_mkdir,
  symlink:	NULL,
  unlink:	smb_unlink,
  rmdir:	smb_rmdir,
  rename:	smb_rename,
  link:		NULL,
  chmod:	smb_chmod,
  chown:	smb_chown,
  truncate:	smb_truncate,
  utime:	smb_utime,
  open:		smb_open,
  read:		smb_read,
  write:	smb_write,
  statfs:	smb_statfs,
  release:	smb_release
};

int main(int argc, char *argv[])
{
    /* Workaround for bug in libsmbclient:
       Limit reads to 32 kB
    */
    int my_argc=0,i=0;

    char **my_argv = (char **)malloc(argc+10 * sizeof(char *));
    char *max_read = "-omax_read=33000";

    for (i=0; i< argc; i++)
    {
       my_argv[i] = argv[i];
       my_argc++;
    }
    my_argv[my_argc++] = max_read;


    /* Initializing libsbmclient */
    ctx = smbc_new_context();
    rwd_ctx = smbc_new_context();

    ctx->callbacks.auth_fn = auth_smbc_get_data;
    rwd_ctx->callbacks.auth_fn = auth_smbc_get_data2;


    /* Timeout a bit bigger, by Jim Ramsay */
    ctx->timeout = 10000;	//10 seconds
    rwd_ctx->timeout = 10000;       //10 seconds


    /* Kerberos authentication by Esben Nielsen */
#if defined(SMB_CTX_FLAG_USE_KERBEROS) && defined(SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS)
    ctx->flags |= SMB_CTX_FLAG_USE_KERBEROS|SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS;
    rwd_ctx->flags |= SMB_CTX_FLAG_USE_KERBEROS|SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS;
#endif
    //ctx->options.one_share_per_server = 1;
    //rwd_ctx->options.one_share_per_server = 1;
    ctx = smbc_init_context(ctx);
    rwd_ctx = smbc_init_context(rwd_ctx);


    fuse_main(my_argc, my_argv, &smb_oper);
    smbc_free_context(ctx, 1);
    smbc_free_context(rwd_ctx, 1);
    return 0;
}
