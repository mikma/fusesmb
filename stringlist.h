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

#ifndef STRINGLIST_H
#define STRINGLIST_H

#include <string.h>
#include <stdlib.h>

typedef struct stringlist {
    char **lines;
    size_t numlines;
    size_t maxlines;
    char sorted;
} stringlist_t;

stringlist_t *sl_init(void);
void sl_free(stringlist_t *sl);

inline int sl_add(stringlist_t *sl, char *str, int do_malloc);
inline size_t sl_count(stringlist_t *sl);
void sl_clear(stringlist_t *sl);
char *sl_find(stringlist_t *sl, const char *str);
char *sl_casefind(stringlist_t *sl, const char *str);
inline char *sl_item(stringlist_t *sl, size_t index);

void sl_sort(stringlist_t *sl);
void sl_casesort(stringlist_t *sl);

#endif /* STRINGLIST_H */
