#ifndef SMBCTX_H
#define SMBCTX_H
#include <libsmbclient.h>
#include <pthread.h>
#include "configfile.h"

SMBCCTX *fusesmb_cache_new_context(config_t *cf);
SMBCCTX *fusesmb_new_context(config_t *cf, pthread_mutex_t *cf_mutex);
#endif
