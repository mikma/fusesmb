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

#include "stringlist.h"
#include <strings.h>

#define NUM_ROWS_PER_MALLOC 128

static int sl_strcmp(const void *p1, const void *p2)
{
    return strcmp(*(char * const *)p1, *(char * const *)p2);
}

static int sl_strcasecmp(const void *p1, const void *p2)
{
    return strcasecmp(*(char * const *)p1, *(char * const *)p2);
}

/*
 * initialize the stringlist
 */
stringlist_t *sl_init(void)
{
    stringlist_t *sl;
    sl = (stringlist_t *)malloc(sizeof(stringlist_t));
    if (sl == NULL)
        return NULL;

    sl->lines = (char **)malloc(NUM_ROWS_PER_MALLOC * sizeof(char *));
    if (sl->lines == NULL)
        return NULL;
    sl->maxlines = NUM_ROWS_PER_MALLOC;
    sl->numlines = 0;
    sl->sorted = 0;
    return sl;
}
/*
 * free the stringlist
 */
void sl_free(stringlist_t *sl)
{
    size_t i;
    if (sl == NULL)
        return;
    if (sl->lines)
    {
        for (i=0; i < sl_count(sl); i++)
        {
            free(sl->lines[i]);
        }
        free(sl->lines);
    }
    free(sl);
}
/*
 * add string to stringlist
 * do_malloc: allocate memory for the string
 */
int sl_add(stringlist_t *sl, char *str, int do_malloc)
{
    /* resize the array if needed */
    //printf("Inserting %s %i\n", str, sl->numlines);
    if (sl->numlines == sl->maxlines)
    {
        //printf("Realloc\n");
        char **new;
        new = (char **)realloc(sl->lines, (sl->maxlines + NUM_ROWS_PER_MALLOC)*sizeof(char *));
        if (new == NULL)
        {
            //printf("Realloc failed\n");
            return -1;
        }
        sl->maxlines += NUM_ROWS_PER_MALLOC;
        sl->lines = new;
    }
    if (do_malloc)
    {
        sl->lines[sl->numlines] = (char *)malloc( (strlen(str)+1) * sizeof(char));
        if (NULL == sl->lines[sl->numlines])
        {
            return -1;
        }
        strcpy(sl->lines[sl->numlines], str);
        sl->numlines++;
        sl->sorted = 0;
        return 0;
   }
   sl->lines[sl->numlines] = str;
   sl->numlines++;
   sl->sorted = 0;
   return 0;
}

/*
 * return the number of items in the stringlist
 */
size_t sl_count(stringlist_t *sl)
{
    return sl->numlines;
}

void sl_clear(stringlist_t *sl)
{
    size_t i;
    for (i=0; i < sl_count(sl); i++)
    {
        free( sl->lines[i] );
    }
    sl->numlines = 0;
}

/*
 * return the item at the index: index
 */
char *sl_item(stringlist_t *sl, size_t index)
{
    if (sl_count(sl) == 0)
        return NULL;
    if (index >= sl_count(sl))
        return NULL;
    return sl->lines[index];
}
/*
 * search for a item in the stringlist
 */
char *sl_find(stringlist_t *sl, const char *str)
{
    /* use binary search if stringlist is sorted */
    if (sl->sorted == 1)
    {
        char **res;
        if (NULL != (res = bsearch (&str, sl->lines, sl_count(sl), sizeof(char *), sl_strcmp)))
            return *res;
        return NULL;
    }

    size_t i;
    for (i=0; i < sl_count(sl); i++)
    {
        if (strcmp(sl_item(sl, i), str) == 0)
        {
            return sl_item(sl, i);
        }
    }
    return NULL;
}

/*
 * case insensitive search
 */
char *sl_casefind(stringlist_t *sl, const char *str)
{
    /* use binary search if stringlist is case insensitively sorted */
    if (sl->sorted == 2)
    {
        char **res;
        if (NULL != (res = bsearch (&str, sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp)))
            return *res;
        return NULL;
    }

    size_t i;
    for (i=0; i < sl_count(sl); i++)
    {
        if (strcasecmp(sl_item(sl, i), str) == 0)
        {
            return sl_item(sl, i);
        }
    }
    return NULL;
}

/*
 * case sensitive sort of the stringlist
 */
void sl_sort(stringlist_t *sl)
{
    qsort(sl->lines, sl_count(sl), sizeof(char *), sl_strcmp);
    sl->sorted = 1;
}

/*
 * case insensitive sort of the stringlist
 */
void sl_casesort(stringlist_t *sl)
{
    qsort(sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp);
    sl->sorted = 2;
}
#if 0
int sl_remove(stringlist_t *sl, size_t index)
{
    if (sl_count(sl) == 0)
        return -1;
    if (index >= sl_count(sl))
        return -1;

    free(sl->lines[index]);
    sl->lines[index] = sl->lines[sl_count(sl)-1];
    sl->numlines--;
    sl->sorted = 0;
    return 0;
}


void sl_lock(stringlist_t *sl)
{
    pthread_mutex_lock(sl->mutex);
}

void sl_unlock(stringlist_t *sl)
{
    pthread_mutex_unlock(sl->mutex);
}
#endif
