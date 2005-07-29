#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smbctx.h"
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
          /*  char un[] = "guest";
            char pw[] = "";

            strncpy(username, un, unmaxlen);
            strncpy(password, pw, pwmaxlen);*/
        }
    }
    else
    {
       /* char un[] = "guest";
        char pw[] = "";

        strncpy(username, un, unmaxlen);
        strncpy(password, pw, pwmaxlen);*/
    }
}

/*
 * Create a new libsmbclient context with all necessary options
 */
SMBCCTX *fusesmb_new_context(void)
{
    /* Initializing libsbmclient */
    SMBCCTX *ctx;
    ctx = smbc_new_context();
    if (ctx == NULL)
        return NULL;

    ctx->callbacks.auth_fn = fusesmb_auth_fn;
    //ctx->debug = 4;
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
