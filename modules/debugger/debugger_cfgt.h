/**
 *
 * Copyright (C) 2015 Victor Seva (sipwise.com)
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#ifndef _DEBUGGER_CFGT_H_
#define _DEBUGGER_CFGT_H_

#include "../../locking.h"
#include "../../route_struct.h"
#include "../../str_hash.h"

#include "debugger_json.h"

#define DBG_CFGT_HASH_SIZE 32

enum _dbg_cfgt_action_type {
	DBG_CFGT_ROUTE=1,
	DBG_CFGT_DROP_E, DBG_CFGT_DROP_D, DBG_CFGT_DROP_R
};

typedef struct _dbg_cfgt_hash
{
	gen_lock_t lock;
	struct str_hash_table hash;
	str save_uuid; /* uuid to be save */
} dbg_cfgt_hash_t, *dbg_cfgt_hash_p;

typedef struct _dbg_cfgt_str_list
{
	str s;
	enum _dbg_cfgt_action_type type;
	struct _dbg_cfgt_str_list *next, *prev;
} dbg_cfgt_str_list_t, *dbg_cfgt_str_list_p;

typedef struct _dbg_cfgt_node
{
	srjson_doc_t jdoc;
	str uuid;
	int msgid;
	dbg_cfgt_str_list_p flow_head;
	dbg_cfgt_str_list_p route;
	srjson_t *in, *out, *flow;
	struct _dbg_cfgt_node *next, *prev;
} dbg_cfgt_node_t, *dbg_cfgt_node_p;

int dbg_init_cfgtest(void);
dbg_cfgt_node_p dbg_cfgt_create_node(struct sip_msg *msg);
int dbg_cfgt_process_route(struct sip_msg *msg,
		dbg_cfgt_node_p node, struct action *a);
int dbg_cfgt_filter(struct sip_msg *msg, unsigned int flags, void *bar);
int dbg_cfgt_msgint(void *data);
int dbg_cfgt_msgout(void *data);
#endif
