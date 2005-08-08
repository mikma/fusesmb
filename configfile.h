/*
 * Copyright (c) 2005, Vincent Wagelaar
 * All rights reserved.
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
