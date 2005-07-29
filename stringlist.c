/*
 * Copyright (c) 2005, Vincent Wagelaar
 * All rights reserved.
 *
 * Based on stringlist implementation of Christos Zoulas (c) 1994
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Christos Zoulas.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
    sl->malloclines = 0;
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
    if (sl->malloclines == sl->maxlines -1)
    {
        char **new;
        new = (char **)realloc(sl->lines, (sl->maxlines + NUM_ROWS_PER_MALLOC)*sizeof(char *));
        if (new == NULL)
        {
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
   sl->malloclines++;
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
        return bsearch (str, sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp);
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
        return bsearch (str, sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp);
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
