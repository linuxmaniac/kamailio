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

#include "../../events.h"
#include "../../lib/kcore/cmpapi.h"
#include "../../pvar.h"

#include "debugger_api.h"
#include "debugger_cfgt.h"

static str _dbg_cfgt_route_prefix[] = {
	str_init("start|"),
	str_init("exit|"),
	str_init("drop|"),
	str_init("return|"),
	{0, 0}
};
static dbg_cfgt_node_t *_dbg_cfgt_head = NULL;
static dbg_cfgt_hash_t *_dbg_cfgt_uuid = NULL;
str _dbg_cfgt_basedir = {"/tmp/", 5};
str _dbg_cfgt_hdr_name = {"P-NGCP-CFGTEST", 14};

static int shm_str_hash_alloc(struct str_hash_table *ht, int size)
{
	ht->table = shm_malloc(sizeof(struct str_hash_head) * size);

	if (!ht->table)
		return -1;

	ht->size = size;
	return 0;
}

static int _dbg_cfgt_init_hashtable(struct str_hash_table *ht)
{
	if (shm_str_hash_alloc(ht, DBG_CFGT_HASH_SIZE) != 0)
	{
		LM_ERR("Error allocating shared memory hashtable\n");
		return -1;
	}

	str_hash_init(ht);

	return 0;
}

int _dbg_cfgt_pv_parse(str *param, pv_elem_p *elem)
{
	if (param->s && param->len > 0)
	{
		if (pv_parse_format(param, elem)<0)
		{
			LM_ERR("malformed or non AVP %.*s AVP definition\n",
					param->len, param->s);
			return -1;
		}
	}
	return 0;
}
/** TODO fix clist_foreach */
void _dbg_cfgt_remove_uuid(const str *uuid)
{
	struct str_hash_head *head;
	struct str_hash_entry *entry;
	int i;

	if(_dbg_cfgt_uuid==NULL) return;
	if(uuid)
	{
		lock_get(&_dbg_cfgt_uuid->lock);
		entry = str_hash_get(&_dbg_cfgt_uuid->hash, uuid->s, uuid->len);
		if(entry)
		{
			str_hash_del(entry);
			shm_free(entry->key.s);
			shm_free(entry);
			LM_DBG("uuid[%.*s] removed from hash\n", uuid->len, uuid->s);
		}
		else LM_DBG("uuid[%.*s] not found in hash\n", uuid->len, uuid->s);
		lock_release(&_dbg_cfgt_uuid->lock);
	}
	else
	{
		lock_get(&_dbg_cfgt_uuid->lock);
		for(i=0; i<DBG_CFGT_HASH_SIZE; i++)
		{
			head = _dbg_cfgt_uuid->hash.table+i;
			clist_foreach(head, entry, prev, next)
			{
				LM_DBG("uuid[%.*s] removed from hash\n",
					entry->key.len, entry->key.s);
				str_hash_del(entry);
				shm_free(entry->key.s);
				shm_free(entry);
			}
			lock_release(&_dbg_cfgt_uuid->lock);
		}
		LM_DBG("remove all uuids. done\n");
	}
}

int _dbg_cfgt_get_uuid_id(dbg_cfgt_node_p node)
{
	struct str_hash_entry *entry;

	if(_dbg_cfgt_uuid==NULL || node==NULL || node->uuid.len == 0) return -1;
	lock_get(&_dbg_cfgt_uuid->lock);
	entry = str_hash_get(&_dbg_cfgt_uuid->hash, node->uuid.s, node->uuid.len);
	if(entry)
	{
		entry->u.n = entry->u.n + 1;
		node->msgid = entry->u.n;
	}
	else
	{
		entry = shm_malloc(sizeof(struct str_hash_entry));
		if(entry==NULL)
		{
			lock_release(&_dbg_cfgt_uuid->lock);
			LM_ERR("No shared memory left\n");
			return -1;
		}
		if (shm_str_dup(&entry->key, &node->uuid) != 0)
		{
			lock_release(&_dbg_cfgt_uuid->lock);
			shm_free(entry);
			LM_ERR("No shared memory left\n");
			return -1;
		}
		entry->u.n = 1;
		node->msgid = 1;
		LM_DBG("Add new entry[%.*s]\n", node->uuid.len, node->uuid.s);
		str_hash_add(&_dbg_cfgt_uuid->hash, entry);
	}
	lock_release(&_dbg_cfgt_uuid->lock);
	LM_DBG("msgid:[%d]\n", node->msgid);
	return 1;
}

int _dbg_cfgt_get_hdr_helper(struct sip_msg *msg, str *res, int mode)
{
	struct hdr_field *hf;

	if(msg==NULL || (mode==0 && res==NULL))
		return -1;

	/* we need to be sure we have parsed all headers */
	if(parse_headers(msg, HDR_EOH_F, 0)<0)
	{
		LM_ERR("error parsing headers\n");
		return -1;
	}

	for (hf=msg->headers; hf; hf=hf->next)
	{
		if (cmp_hdrname_str(&hf->name, &_dbg_cfgt_hdr_name)==0)
		{
			if(mode==0)
			{
				if(pkg_str_dup(res, &hf->body)<0)
				{
					LM_ERR("error copying header\n");
					return -1;
				}
				LM_DBG("cfgtest uuid:[%.*s]\n", res->len, res->s);
				return 0;
			}
			else return STR_EQ(hf->body, *res);
		}
	}
	return 1; /* not found */
}

int _dbg_cfgt_get_hdr(struct sip_msg *msg, str *res)
{
	return _dbg_cfgt_get_hdr_helper(msg, res, 0);
}

int _dbg_cfgt_cmp_hdr(struct sip_msg *msg, str *res)
{
	return _dbg_cfgt_get_hdr_helper(msg, res, 1);
}

dbg_cfgt_node_p dbg_cfgt_create_node(struct sip_msg *msg)
{
	dbg_cfgt_node_p node;

	node = (dbg_cfgt_node_p) pkg_malloc(sizeof(dbg_cfgt_node_t));
	if(node==NULL)
	{
		LM_ERR("cannot allocate cfgtest msgnode\n");
		return node;
	}
	memset(node, 0, sizeof(dbg_cfgt_node_t));
	srjson_InitDoc(&node->jdoc, NULL);
	if (msg)
	{
		node->msgid = msg->id;
		LM_DBG("msgid:%d\n", node->msgid);
		if(_dbg_cfgt_get_hdr(msg, &node->uuid)!=0 || &node->uuid.len==0)
		{
			LM_ERR("cannot get value of cfgtest uuid header!!\n");
			goto error;
		}
	}
	node->jdoc.root = srjson_CreateObject(&node->jdoc);
	if(node->jdoc.root==NULL)
	{
		LM_ERR("cannot create json root\n");
		goto error;
	}
	node->flow = srjson_CreateArray(&node->jdoc);
	if(node->flow==NULL)
	{
		LM_ERR("cannot create json object\n");
		goto error;
	}
	srjson_AddItemToObject(&node->jdoc, node->jdoc.root, "flow\0", node->flow);
	node->in = srjson_CreateArray(&node->jdoc);
	if(node->in==NULL)
	{
		LM_ERR("cannot create json object\n");
		goto error;
	}
	srjson_AddItemToObject(&node->jdoc, node->jdoc.root, "sip_in\0", node->in);
	node->out = srjson_CreateArray(&node->jdoc);
	if(node->out==NULL)
	{
		LM_ERR("cannot create json object\n");
		goto error;
	}
	srjson_AddItemToObject(&node->jdoc, node->jdoc.root, "sip_out\0", node->out);
	LM_DBG("node created\n");
	if(_dbg_cfgt_head)
	{
		clist_append(_dbg_cfgt_head, node, next, prev);
	}
	else
	{
		LM_DBG("Initial node\n");
		_dbg_cfgt_head = node;
		clist_init(_dbg_cfgt_head, next, prev);
	}
	return node;

error:
	srjson_DestroyDoc(&node->jdoc);
	pkg_free(node);
	return NULL;
}

void _dbg_cfgt_remove_node(dbg_cfgt_node_p node)
{
	if(!node) return;
	srjson_DestroyDoc(&node->jdoc);
	if(node->uuid.s) pkg_free(node->uuid.s);
	clist_rm(node, next, prev);
	while(node->route)
	{
		if(node->route->prev)
		{
			pkg_free(node->route->prev);
			node->route->prev = NULL;
		}
		if(node->route->next) node->route = node->route->next;
		else { pkg_free(node->route); node->route = NULL; }
	}
	if(dbg_get_cfgt_node() == node)
	{
		LM_DBG("cfgt_node deleted\n");
		dbg_set_cfgt_node(NULL);
	}
	pkg_free(node);
}

void _dbg_cfgt_print_node(dbg_cfgt_node_p node)
{
	char *buf = NULL;
	dbg_cfgt_str_list_p route;

	if(!node) return;
	if(node->flow_head)
	{
		route = node->flow_head;
		while(route)
		{
			if(route == node->route)
				LM_DBG("[--[%.*s][%d]--]\n", route->s.len, route->s.s, route->type);
			else LM_DBG("[%.*s][%d]\n", route->s.len, route->s.s, route->type);
			route = route->next;
		}
	}
	else LM_DBG("flow:empty\n");
	return;
	buf = srjson_PrintUnformatted(&node->jdoc, node->jdoc.root);
	if(buf==NULL)
	{
		LM_ERR("Cannot get the json string\n");
		return;
	}
	LM_DBG("node[%p]: id:[%d] uuid:[%.*s] info:[%s]\n",
		node, node->msgid, node->uuid.len, node->uuid.s, buf);
	node->jdoc.free_fn(buf);
}

int _dbg_cfgt_set_dump(struct sip_msg *msg, dbg_cfgt_node_p node, str *flow)
{
	srjson_t *f, *vars;

	if(node==NULL || flow == NULL) return -1;
	vars = srjson_CreateObject(&node->jdoc);
	if(vars==NULL)
	{
		LM_ERR("cannot create json object\n");
		return -1;
	}
	if(dbg_get_json(msg, 30, &node->jdoc, vars)<0)
	{
		LM_ERR("cannot get var info\n");
		return -1;
	}
	f = srjson_CreateObject(&node->jdoc);
	if(f==NULL)
	{
		LM_ERR("cannot create json object\n");
		srjson_Delete(&node->jdoc, vars);
		return -1;
	}
	srjson_AddStrItemToObject(&node->jdoc, f,
		flow->s, flow->len, vars);
	srjson_AddItemToArray(&node->jdoc, node->flow, f);
	LM_DBG("node[%.*s] flow created\n", flow->len, flow->s);
	return 0;
}

void _dbg_cfgt_set_type(dbg_cfgt_str_list_p route, struct action *a)
{
	switch(a->type)
	{
		case DROP_T:
			if(a->val[1].u.number&DROP_R_F)
				route->type = DBG_CFGT_DROP_D;
			if(a->val[1].u.number&RETURN_R_F)
				route->type = DBG_CFGT_DROP_R;
			else route->type = DBG_CFGT_DROP_E;
			LM_DBG("set[%.*s][%d]\n", route->s.len, route->s.s, route->type);
			break;
		case ROUTE_T:
			route->type = DBG_CFGT_ROUTE;
			LM_DBG("set[%.*s][%d]\n", route->s.len, route->s.s, route->type);
			break;
		default:
			LM_DBG("no relevant action\n");
			route->type = DBG_CFGT_DROP_R;
			break;
	}
}

int _dbg_cfgt_add_routename(dbg_cfgt_node_p node, struct action *a,
		str *routename)
{
	dbg_cfgt_str_list_p route;
	int ret = 0;

	if(!node->route) /* initial */
	{
		node->route = pkg_malloc(sizeof(dbg_cfgt_str_list_t));
		if(!node->route)
		{
			LM_ERR("No more pkg mem\n");
			return -1;
		}
		memset(node->route, 0, sizeof(dbg_cfgt_str_list_t));
		node->flow_head = node->route;
		node->route->type = DBG_CFGT_ROUTE;
		ret = 1;
	}
	else
	{
		LM_DBG("actual routename:[%.*s][%d]\n", node->route->s.len,
			node->route->s.s, node->route->type);
		if(node->route->prev)
			LM_DBG("prev routename:[%.*s][%d]\n", node->route->prev->s.len,
				node->route->prev->s.s,	node->route->prev->type);
		if(STR_EQ(*routename, node->route->s))
		{
			LM_DBG("same route\n");
			_dbg_cfgt_set_type(node->route, a);
			return 2;
		}
		else if(node->route->prev &&
				STR_EQ(*routename, node->route->prev->s))
		{
			LM_DBG("back to route[%.*s]\n", node->route->prev->s.len,
				node->route->prev->s.s);
			_dbg_cfgt_set_type(node->route->prev, a);
			return 3;
		}
		route = pkg_malloc(sizeof(dbg_cfgt_str_list_t));
		if(!route)
		{
			LM_ERR("No more pkg mem\n");
			return -1;
		}
		memset(route, 0, sizeof(dbg_cfgt_str_list_t));
		route->prev = node->route;
		node->route->next = route;
		node->route = route;
		_dbg_cfgt_set_type(node->route, a);
	}
	node->route->s.s = routename->s;
	node->route->s.len = routename->len;
	LM_DBG("add[%d] route:[%.*s]\n", ret, node->route->s.len, node->route->s.s);
	_dbg_cfgt_print_node(node);
	return ret;
}

void _dbg_cfgt_del_routename(dbg_cfgt_node_p node)
{
	LM_DBG("del route[%.*s]\n", node->route->s.len, node->route->s.s);
	node->route = node->route->prev;
	pkg_free(node->route->prev);
	node->route->next = NULL;
}
/* dest has to be freed */
int _dbg_cfgt_node_get_flowname(dbg_cfgt_str_list_p route, int *indx, str *dest)
{
	int i;
	if(route==NULL) return -1;
	LM_DBG("routename:[%.*s][%d]\n", route->s.len, route->s.s,
		route->type);
	if(indx) i = *indx;
	else i = route->type-1;
	if(str_append(&_dbg_cfgt_route_prefix[i],
		&route->s, dest)<0)
	{
		LM_ERR("Cannot create route name\n");
		return -1;
	}
	return 0;
}
int dbg_cfgt_process_route(struct sip_msg *msg,
		dbg_cfgt_node_p node, struct action *a)
{
	str routename = {a->rname, strlen(a->rname)};
	int ret = -1;
	int indx = 0;
	str flowname = STR_NULL;
	LM_DBG("route from action:[%s]\n", a->rname);
	switch(_dbg_cfgt_add_routename(node, a, &routename))
	{
		case 2: /* same name */
			return 0;
		case 1: /* initial */
			LM_DBG("Initial route[%.*s]. dump vars\n",
				node->route->s.len, node->route->s.s);
			if(_dbg_cfgt_node_get_flowname(node->route, &indx, &flowname)<0)
			{
				LM_ERR("cannot create flowname\n");
				return -1;
			}
			ret = _dbg_cfgt_set_dump(msg, node, &flowname);
			break;
		case 0: /* new */
			LM_DBG("Change from[%.*s] route to route[%.*s]. dump vars\n",
				node->route->prev->s.len, node->route->prev->s.s,
				node->route->s.len, node->route->s.s);
			if(_dbg_cfgt_node_get_flowname(node->route, &indx, &flowname)<0)
			{
				LM_ERR("cannot create flowname\n");
				return -1;
			}
			ret = _dbg_cfgt_set_dump(msg, node, &flowname);
			break;
		case 3: /* back to previous */
			if(_dbg_cfgt_node_get_flowname(node->route, 0, &flowname)<0)
			{
				LM_ERR("cannot create flowname\n");
				return -1;
			}
			ret = _dbg_cfgt_set_dump(msg, node, &flowname);
			_dbg_cfgt_del_routename(node);
			break;
		default:
			return -1;
	}
	if(flowname.s) pkg_free(flowname.s);
	return ret;
}

/*
TODO:
- parse first line, check if is SIP
- parse for header cfgtest
*/
int dbg_cfgt_msgin(void *data)
{
	dbg_cfgt_node_p node;
	srjson_t *jobj;
	str *buf = (str *) data;
	if(buf==NULL) return 0;
	LM_DBG("msg in:{%.*s}\n", buf->len, buf->s);
	node = dbg_cfgt_create_node(NULL);
	if(node)
	{
		dbg_set_cfgt_node(node);
		jobj = srjson_CreateStr(&node->jdoc, buf->s, buf->len);
		if(jobj==NULL)
		{
			LM_ERR("cannot create json object\n");
			return -1;
		}
		srjson_AddItemToArray(&node->jdoc, node->in, jobj);
		return 0;
	}
	LM_ERR("node empty\n");
	return -1;
}

/* defined later */
int _dbg_cfgt_save(str *uuid);

int dbg_cfgt_filter(struct sip_msg *msg, unsigned int flags, void *bar)
{
	unsigned int save;
	str uuid = STR_NULL;
	str unknown = {"unknown", 7};
	dbg_cfgt_node_p node;

	save = dbg_get_cfgt_save();
	if(save==2)
	{
		lock_get(&_dbg_cfgt_uuid->lock);
		if(_dbg_cfgt_uuid->save_uuid.s)
		{
			pkg_str_dup(&uuid, &_dbg_cfgt_uuid->save_uuid);
		}
		lock_release(&_dbg_cfgt_uuid->lock);
	}
	if(save!=0)
	{
		if (uuid.len>0) LM_DBG("saving [%.*s]\n", uuid.len, uuid.s);
		else LM_DBG("saving ALL\n");
		if (_dbg_cfgt_save(&uuid)<0) LM_ERR("not saved\n");
		else LM_DBG("saved\n");
	}

	node = dbg_get_cfgt_node();
	if(node)
	{
		if (node->msgid == 0)
		{
			LM_DBG("new node\n");
			if(_dbg_cfgt_get_hdr(msg, &node->uuid)!=0 || node->uuid.len==0)
			{
				LM_ERR("cannot get value of cfgtest uuid header. Using unknown\n");
				pkg_str_dup(&node->uuid, &unknown);
			}
			return _dbg_cfgt_get_uuid_id(node);
		}
		else
		{
			LM_DBG("node->uuid:[%.*s]\n", node->uuid.len, node->uuid.s);
			if(_dbg_cfgt_cmp_hdr(msg, &node->uuid))
			{
				LM_DBG("same uuid\n");
				return 1;
			}
			else { LM_DBG("different uuid\n"); }
		}
	}
	else { LM_ERR("node empty\n"); }
	node = dbg_cfgt_create_node(msg);
	if(node) {
		return (dbg_set_cfgt_node(node)!=0);
	}
	return -1;
}

int dbg_cfgt_msgout(void *data)
{
	dbg_cfgt_node_p node;
	srjson_t *jobj;
	str *buf = (str *) data;
	if(buf==NULL) return 0;
	LM_DBG("msg out:{%.*s}\n", buf->len, buf->s);
	node = dbg_get_cfgt_node();
	if(node)
	{
		jobj = srjson_CreateStr(&node->jdoc, buf->s, buf->len);
		if(jobj==NULL)
		{
			LM_ERR("cannot create json object\n");
			return -1;
		}
		srjson_AddItemToArray(&node->jdoc, node->out, jobj);
		return 0;
	}
	LM_ERR("msgnode empty\n");
	return -1;
}

int dbg_init_cfgtest(void)
{
	_dbg_cfgt_uuid = shm_malloc(sizeof(dbg_cfgt_hash_t));
	if(_dbg_cfgt_uuid==NULL)
	{
		LM_ERR("Cannot allocate shared memory\n");
		return -1;
	}
	if(!lock_init(&_dbg_cfgt_uuid->lock))
	{
		LM_ERR("cannot init the lock\n");
		shm_free(_dbg_cfgt_uuid);
		_dbg_cfgt_uuid = NULL;
		return -1;
	}
	if(_dbg_cfgt_init_hashtable(&_dbg_cfgt_uuid->hash)<0)
		return -1;
	sr_event_register_cb(SREV_NET_DATA_IN, dbg_cfgt_msgin);
	sr_event_register_cb(SREV_NET_DATA_OUT, dbg_cfgt_msgout);
	return 0;
}

int _dbg_cfgt_get_filename(int msgid, str uuid, str *dest)
{
	int i, lid, lpid;
	char buff_id[INT2STR_MAX_LEN], buff_pid[INT2STR_MAX_LEN];
	char *sid, *spid;
	if(dest==NULL || uuid.len == 0) return -1;
	sid = sint2strbuf(msgid, buff_id, INT2STR_MAX_LEN, &lid);
	spid = sint2strbuf(my_pid(), buff_pid, INT2STR_MAX_LEN, &lpid);
	dest->len = _dbg_cfgt_basedir.len + uuid.len + lid + lpid + 8;
	if(_dbg_cfgt_basedir.s[_dbg_cfgt_basedir.len-1]!='/')
		dest->len = dest->len + 1;
	dest->s = (char *) pkg_malloc(dest->len*sizeof(char));
	if(dest->s==NULL)
	{
		LM_ERR("no more memory.\n");
		return -1;
	}

	LM_DBG("id:[%.*s] pid:[%.*s] dest.len:[%d]\n", lid, sid,
		lpid, spid, dest->len);
	strncpy(dest->s, _dbg_cfgt_basedir.s, _dbg_cfgt_basedir.len);
	i = _dbg_cfgt_basedir.len;
	if(_dbg_cfgt_basedir.s[_dbg_cfgt_basedir.len-1]!='/')
	{
		strncpy(dest->s+i, "/", 1);
		i = i + 1;
	}
	strncpy(dest->s+i, uuid.s, uuid.len);
	i = i + uuid.len;
	strncpy(dest->s+i, "/", 1);
	i = i + 1;
	strncpy(dest->s+i, spid, lpid);
	i = i + lpid;
	strncpy(dest->s+i, "_", 1);
	i = i + 1;
	strncpy(dest->s+i, sid, lid);
	i = i + lid;
	strncpy(dest->s+i, ".json\0", 6);
	return 0;
}

int _dbg_cfgt_save_node(dbg_cfgt_node_p node)
{
	FILE *f = NULL;
	str filename = STR_NULL;
	char *buf = NULL;
	int res = -1;

	if(!node) return -1;
	LM_DBG("msgid:%d uuid:%.*s\n", node->msgid, node->uuid.len, node->uuid.s);
	if(_dbg_cfgt_get_filename(node->msgid, node->uuid, &filename)<0)
	{
		LM_ERR("Cannot get filename\n");
		res = -1;
		goto clean;
	}
	f = fopen ( filename.s, "w");
	if(f==NULL)
	{
		LM_ERR("Cannot open[%.*s] for write\n", filename.len, filename.s);
		res = -1;
		goto clean;
	}
	buf = srjson_PrintUnformatted(&node->jdoc, node->jdoc.root);
	if(buf==NULL)
	{
		LM_ERR("Cannot get the json string\n");
		fclose(f);
		res = -1;
		goto clean;
	}
	fwrite(buf, strlen(buf), 1, f);
	fclose(f);
	res = 0;

clean:
	if(filename.s) pkg_free(filename.s);
	if(buf) node->jdoc.free_fn(buf);
	return res;
}

int _dbg_cfgt_save(str *uuid)
{
	int res = -1;
	dbg_cfgt_node_p node;

	if(_dbg_cfgt_head==NULL || uuid == NULL) return -1;
	if(uuid->len>0)
	{
		node = _dbg_cfgt_head;
		do
		{
			LM_DBG("node->uuid[%.*s]\n", node->uuid.len, node->uuid.s);
			if(STR_EQ(node->uuid, *uuid))
			{
				res = 0;
				if(_dbg_cfgt_save_node(node)<0)
				{
					LM_ERR("Cannot save node:%p\n", node);
					_dbg_cfgt_print_node(node);
					res = res - 1;
				}
				_dbg_cfgt_remove_node(node);
			}
		} while(node->next!=_dbg_cfgt_head);
		if(res==-1) {
			LM_WARN("No node with uuid[%.*s] found\n", uuid->len, uuid->s);
		}
		else {
			_dbg_cfgt_remove_uuid(uuid);
		}
	}
	else
	{
		res = 0;
		node = _dbg_cfgt_head;
		do
		{
			if(_dbg_cfgt_save_node(node)<0)
			{
				LM_ERR("Cannot save node:%p\n", node);
				_dbg_cfgt_print_node(node);
				res = res - 1;
			}
			_dbg_cfgt_remove_node(node);
		} while(node->next!=_dbg_cfgt_head);
		_dbg_cfgt_remove_uuid(NULL);
	}
	return res;
}

int dbg_cfgt_set_save(str *uuid)
{
	if(uuid==NULL) return -1;
	lock_get(&_dbg_cfgt_uuid->lock);
	if(_dbg_cfgt_uuid->save_uuid.s)
	{
		LM_DBG("free previous uuid\n");
		shm_free(_dbg_cfgt_uuid->save_uuid.s);
		_dbg_cfgt_uuid->save_uuid.s = NULL;
		_dbg_cfgt_uuid->save_uuid.len = 0;
	}
	if(uuid->len>0)
	{
		if(shm_str_dup(&_dbg_cfgt_uuid->save_uuid, uuid) != 0)
		{
			LM_ERR("No shared memory left\n");
			lock_release(&_dbg_cfgt_uuid->lock);
			return -1;
		}
	}
	lock_release(&_dbg_cfgt_uuid->lock);
	return 0;
}
