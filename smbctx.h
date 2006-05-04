/*
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


#ifndef SMBCTX_H
#define SMBCTX_H
#include <libsmbclient.h>
#include <pthread.h>
#include "configfile.h"

SMBCCTX *fusesmb_cache_new_context(config_t *cf);
SMBCCTX *fusesmb_new_context(config_t *cf, pthread_mutex_t *cf_mutex);
#endif
