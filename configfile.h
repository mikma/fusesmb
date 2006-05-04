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

#ifndef CONFIGFILE_H
#define CONFIGFILE_H
#include <sys/param.h>
#include "stringlist.h"

typedef struct {
   stringlist_t *lines;
   time_t mtime;
   char file[MAXPATHLEN+1];
} config_t;

int config_init(config_t *cf, const char *file);
void config_free(config_t *cf);
int config_reload_ifneeded(config_t *cf);
int config_has_section(config_t *cf, const char *section);
int config_read_string(config_t *cf, const char *section, const char *key, char **value);
int config_read_int(config_t *cf, const char *section, const char *key, int *value);
int config_read_bool(config_t *cf, const char *section, const char *key, int *value);
int config_read_stringlist(config_t *cf, const char *section, const char *key, stringlist_t **value, char sep);
int config_read_section_keys(config_t *cf, const char *section, stringlist_t **value);

#endif
