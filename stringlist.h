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

#ifndef STRINGLIST_H
#define STRINGLIST_H

#include <string.h>
#include <stdlib.h>

typedef struct stringlist {
    char **lines;
    size_t numlines;
    size_t maxlines;
    size_t malloclines;
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
