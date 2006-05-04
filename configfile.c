/*
 * The MIT License
 *
 * Copyright (c) 2006 Vincent Wagelaar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include "stringlist.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include "configfile.h"


static char *strip_whitespace_check_comment(const char *str)
{
    char *start = (char *)str;
    char *end = start + strlen(str) -1;
    while (*start == '\t' || *start == ' ')
        start++;
    while (isspace(*end))
    {
        *end = '\0';
        end--;
    }
    if (*start == '#' || *start == ';' || *start == '\0')
        return NULL;
    return start;
}

static char *strip_whitespace(const char *str)
{
    char *start = (char *)str;
    char *end = start + strlen(str) -1;
    while (*start == '\t' || *start == ' ')
        start++;
    while (isspace(*end))
    {
        *end = '\0';
        end--;
    }
    if (*start == '\0')
        return NULL;
    return start;
}

static int config_read_file(config_t *cf)
{
    char buf[4096];
    FILE *fp = fopen(cf->file, "r");
    if (NULL == fp)
        return -1;
    sl_clear(cf->lines);
    while (!feof(fp))
    {
        if (NULL == fgets(buf, sizeof(buf), fp))
            continue;
        char *stripped_string = strip_whitespace_check_comment(buf);
        if (stripped_string == NULL)
            continue;
        /* Section */
        if (*stripped_string == '[')
        {
            stripped_string++;
            while (*stripped_string == '\t' || *stripped_string == ' ')
            {
                stripped_string++;
            }
            char *end = stripped_string + strlen(stripped_string) -1;
            while (*end == '\t' || *end == ' ' || *end == ']')
            {
                *end = '\0';
                end--;
            }
            char section_string[4096];
            snprintf(section_string, sizeof(section_string), "[%s]", stripped_string);
            if (-1 == sl_add(cf->lines, section_string, 1))
                continue;
        } /* Key */
        else
        {

            char value_string[4096];
            char *isequal = index(stripped_string, '=');
            if (isequal == NULL)
                continue;
            *isequal = '\0';
            isequal++;
            char *key = strip_whitespace(stripped_string);
            char *value = strip_whitespace(isequal);
            if (NULL == key || NULL == value)
                continue;
            snprintf(value_string, sizeof(value_string), "%s=%s", key, value);
            if (-1 == sl_add(cf->lines, value_string, 1))
                continue;
        }
    }
    fclose(fp);
    return 0;
}


/**
 * Init configuration interface
 * @return -1 on failure, 0 on success
 */
int config_init(config_t *cf, const char *file)
{
    struct stat st;
    if (-1 == stat(file, &st))
        return -1;
    cf->mtime = st.st_mtime;
    cf->lines = sl_init();
    if (cf->lines == NULL)
        return -1;
    strncpy(cf->file, file, MAXPATHLEN);
    config_read_file(cf);
    return 0;
}

/**
 * @param config_t *, pointer to config_t
 * @return -1 if not needed/failure, 0 file has changed
 */

int config_reload_ifneeded(config_t *cf)
{
    struct stat st;
    if (-1 == stat(cf->file, &st))
        return -1;
    if (cf->mtime == st.st_mtime)
        return -1;
    cf->mtime = st.st_mtime;
    return config_read_file(cf);
}
/**
 * @return -1 on failure, 0 on success
 */
int config_has_section(config_t *cf, const char *section)
{
    char buf[strlen(section)+3];
    strcpy(buf, "[");
    strcat(buf, section);
    strcat(buf, "]");
    if (NULL != sl_find(cf->lines, buf))
    {
        return 0;
    }
    return -1;
}

/**
 * @return -1 on failure, 0 on success with value now with a malloced string
 */
int config_read_string(config_t *cf, const char *section, const char *key, char **value)
{
    size_t i;
    char cmp_section[strlen(section)+3];
    char cmp_key[strlen(key)+2];
    strcpy(cmp_section, "[");
    strcat(cmp_section, section);
    strcat(cmp_section, "]");
    strcpy(cmp_key, key);
    strcat(cmp_key, "=");
    char section_found = 0;
    for (i=0; i<sl_count(cf->lines); i++)
    {
        if (0 == strncasecmp(sl_item(cf->lines, i), cmp_section, sizeof(cmp_section))
            && section_found == 0)
        {
            section_found = 1;
            i++;
        }
        /* Check if we're not over the last line */
        if (section_found == 1 && i < sl_count(cf->lines))
        {
            if (0 == strncasecmp(sl_item(cf->lines, i), "[", 1))
            {
                return -1;
            }
            if (0 == strncasecmp(sl_item(cf->lines, i), cmp_key, strlen(cmp_key)))
            {
                char *retval = index(sl_item(cf->lines, i), '=');
                if (retval == NULL)
                    return -1;
                retval++;
                if (strlen(retval))
                {
                    *value = strdup(retval);
                    return 0;
                }
                return -1;
            }
        }
    }
    return -1;
}

/**
 * @return -1 on failure, 0 on success
 */
int config_read_int(config_t *cf, const char *section, const char *key, int *value)
{
    char *str;
    if (0 == config_read_string(cf, section, key, &str))
    {
        char *p;
        int ret = strtol(str, &p, 10);
        if (*p != '\0')
            return -1;
        *value = ret;
        free(str);
        return 0;
    }
    return -1;
}

/**
 * @return -1 on failure, 0 on success
 */
int config_read_bool(config_t *cf, const char *section, const char *key, int *value)
{
    char *str;
    if (0 == config_read_string(cf, section, key, &str))
    {
        if (strcasecmp("true", str) == 0 || strcmp("1", str) == 0)
        {
            *value = 1;
            free(str);
            return 0;
        }
        if (strcasecmp("false", str) == 0 || strcmp("0", str) == 0)
        {
            *value = 0;
            free(str);
            return 0;
        }
        free(str);
    }
    return -1;
}

int config_read_stringlist(config_t *cf, const char *section, const char *key, stringlist_t **value, char sep)
{
    char *str;
    if (0 == config_read_string(cf, section, key, &str))
    {
        *value = sl_init();
        char *next, *start;
        start = str;
        while (NULL != (next = index(start, sep)))
        {
            *next = '\0';
            next++;
            /* Remove extra separators */
            while (*next == sep)
            {
                *next = '\0';
                next++;
            }
            char *stripped;
            if (NULL != (stripped = strip_whitespace(start)))
                sl_add(*value, stripped, 1);

            start = next;
        }
        if (strlen(start))
        {
            char *stripped = strip_whitespace(start);
            sl_add(*value, stripped, 1);
        }
        free(str);
        return 0;
    }
    return -1;
}
int config_read_section_keys(config_t *cf, const char *section, stringlist_t **value)
{
    size_t i;
    char cmp_section[strlen(section)+3];
    strcpy(cmp_section, "[");
    strcat(cmp_section, section);
    strcat(cmp_section, "]");
    char section_found = 0;
    *value = sl_init();
    if (NULL == *value)
        return -1;

    for (i=0; i<sl_count(cf->lines); i++)
    {
        if (0 == strncasecmp(sl_item(cf->lines, i), cmp_section, sizeof(cmp_section))
            && section_found == 0)
        {
            section_found = 1;
            i++;
        }
        if (section_found == 1)
        {
            if (0 == strncasecmp(sl_item(cf->lines, i), "[", 1))
            {
                break;
            }
            char buf[4096];
            strncpy(buf, sl_item(cf->lines, i), 4096);
            char *sep = index(buf, '=');
            if (sep == NULL)
                continue;
            *sep = '\0';
            if (strlen(buf))
            {
                if (-1 == sl_add(*value, buf, 1))
                    continue;
            }
        }
    }
    if (sl_count(*value) > 0)
        return 0;

    /* No keys found for this sections so freeing up the stringlist */
    sl_free(*value);
    *value = NULL;
    return -1;
}

void config_free(config_t *cf)
{
    sl_free(cf->lines);
}

#ifdef RUN_TEST

static void config_show_parsed(config_t *cf)
{
    size_t i;
    for (i=0; i<sl_count(cf->lines); i++)
    {
        printf("%s\n", sl_item(cf->lines, i));
    }
}


int keeprunning =1;

#include <signal.h>
#include <errno.h>
void int_handler(int sig)
{
    signal(sig, SIG_IGN);
    printf("CTRL_C pressed\n");
    keeprunning =0;
}

int main(void)
{
    signal(SIGINT, int_handler);
    config_t c;
    if (-1 == config_init(&c, "fusesmb.conf.test"))
    {
        perror("config_init");
        //fprintf(stderr, "Could not open fusesmb.conf [%s]\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    config_show_parsed(&c);
    while(keeprunning){
    char *user, *pass;
    stringlist_t *workgroups, *servers;

    int timeout, showhiddenshares;
    if (0 == config_read_string(&c, "global", "username", &user))
    {
        printf("Found username: %s\n", user);
        free(user);
    }
    else
        printf("Could not find username\n");

    if (0 == config_read_string(&c, "global", "password", &pass))
    {
        printf("Found password: %s\n", pass);
        free(pass);
    }
    else
        printf("Could not find password\n");
    if (0 == config_reload_ifneeded(&c))
        printf("Configuration has changed\n");
    if (0 == config_read_int(&c, "global", "timeout", &timeout))
        printf("Found timeout: %i\n", timeout);
    else
        printf("Could not find timeout\n");
    if (0 == config_read_bool(&c, "global", "showhiddenshares", &showhiddenshares))
        printf("Found showhiddenshares: %i\n", showhiddenshares);
    else
        printf("Could not find showhiddenshares\n");

    if (0 == config_read_stringlist(&c, "ignore", "workgroups", &workgroups, ','))
    {
        size_t i;
        printf("Found workgroups:\n");
        for (i=0; i<sl_count(workgroups); i++)
            printf(" %s\n", sl_item(workgroups, i));
        sl_free(workgroups);
    }
    else
    {
        printf("Could not find ignore workgroups\n");
    }
    if (0 == config_read_stringlist(&c, "ignore", "servers", &servers, ','))
    {
        size_t i;
        printf("Found servers:\n");
        sl_casesort(servers);
        for (i=0; i<sl_count(servers); i++)
            printf(" %s\n", sl_item(servers, i));
        char *find;
        if (NULL != (find = sl_casefind(servers, "TARdis")))
            printf("Found TARdis: %s\n", find);
        if (NULL != (find = sl_casefind(servers, "BANANA")))
            printf("Found TARdis: %s\n", find);

        sl_free(servers);
    }
    else
    {
        printf("Could not find ignore servers\n");
    }
    stringlist_t *global_keys;
    if (0 == config_read_section_keys(&c, "global", &global_keys))
    {
        size_t i;
        for (i=0; i<sl_count(global_keys); i++)
            printf("key: %s\n", sl_item(global_keys, i));
        sl_free(global_keys);
    }
    sleep(10);
    }
    printf("Cleaning up\n");
    config_show_parsed(&c);
    config_free(&c);
    exit(EXIT_SUCCESS);
}
#endif
