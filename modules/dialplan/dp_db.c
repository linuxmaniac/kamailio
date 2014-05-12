/*
 * $Id$
 *
 * Copyright (C)  2007-2008 Voice Sistem SRL
 *
 * This file is part of SIP-router, a free SIP server.
 *
 * SIP-router is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * SIP-router is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2007-08-01 initial version (ancuta onofrei)
 *  2008-10-09 module is now using pcre regexp lib (juha heinanen)
 */

/*!
 * \file
 * \brief SIP-router dialplan :: database interface
 * \ingroup dialplan
 * Module: \ref dialplan
 */


#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../lib/srdb1/db.h"
#include "../../re.h"
#include "dp_db.h"
#include "dialplan.h"

str dp_db_url       =   {DEFAULT_RODB_URL, DEFAULT_RODB_URL_LEN};
str dp_table_name   =   str_init(DP_TABLE_NAME);
str dpid_column     =   str_init(DPID_COL);
str pr_column       =   str_init(PR_COL);
str match_op_column =   str_init(MATCH_OP_COL);
str match_exp_column=   str_init(MATCH_EXP_COL);
str match_len_column=   str_init(MATCH_LEN_COL);
str subst_exp_column=   str_init(SUBST_EXP_COL);
str repl_exp_column =   str_init(REPL_EXP_COL);
str attrs_column    =   str_init(ATTRS_COL); 

extern int dp_fetch_rows;

static db1_con_t* dp_db_handle    = 0; /* database connection handle */
static db_func_t dp_dbf;

#define GET_STR_VALUE(_res, _values, _index)\
	do{\
		if ( VAL_NULL((_values)+ (_index)) ) { \
			LM_ERR(" values %d is NULL - not allowed\n",_index);\
			(_res).s = 0; (_res).len = 0;\
			goto err;\
		} \
		(_res).s = VAL_STR((_values)+ (_index)).s;\
		(_res).len = strlen(VAL_STR((_values)+ (_index)).s);\
	}while(0);

int generate_pv_hash(void);
void destroy_pv_rule(dpl_pv_node_t * rule);
void destroy_pv_hash(void);
void destroy_rule(dpl_node_t * rule);
void destroy_hash(int);

dpl_node_t * build_rule(db_val_t * values);
int add_rule2hash(dpl_node_t *, int);

void list_rule(dpl_node_t * );
void list_hash(int h_index);
void list_pv_rule(dpl_pv_node_t * );
void list_pv_hash(void);
void show_pv_flags(unsigned int flag);

dpl_id_p* rules_hash = NULL;
int * crt_idx, *next_idx;
int *sh_revision;
int  pv_revision = 0;

dpl_pv_id_p rules_pv_hash = NULL;

int init_db_data(void)
{
	if(dp_table_name.s == 0){
		LM_ERR("invalid database table name\n");
		return -1;
	}

	/* Find a database module */
	if (db_bind_mod(&dp_db_url, &dp_dbf) < 0){
		LM_ERR("unable to bind to a database driver\n");
		return -1;
	}

	if(dp_connect_db() !=0)
		return -1;

	if(db_check_table_version(&dp_dbf, dp_db_handle, &dp_table_name,
				DP_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		goto error;
	}

	if(dp_load_db() != 0){
		LM_ERR("failed to load database data\n");
		goto error;
	}

	dp_disconnect_db();

	return 0;
error:

	dp_disconnect_db();
	return -1;
}


int dp_connect_db(void)
{
	if (dp_dbf.init==0){
		LM_CRIT("null dp_dbf\n");
		return -1;
	}

	if(dp_db_handle){
		LM_CRIT("BUG: connection to database already open\n");
		return -1;
	}

	if ((dp_db_handle = dp_dbf.init(&dp_db_url)) == 0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}


void dp_disconnect_db(void)
{
	if(dp_db_handle){
		dp_dbf.close(dp_db_handle);
		dp_db_handle = 0;
	}
}


int init_data(void)
{
	int *p;

	rules_hash = (dpl_id_p *)shm_malloc(2*sizeof(dpl_id_p));
	if(!rules_hash) {
		LM_ERR("out of shm memory\n");
		return -1;
	}
	rules_hash[0] = rules_hash[1] = 0;

	p = (int *)shm_malloc(3*sizeof(int));
	if(!p){
		LM_ERR("out of shm memory\n");
		return -1;
	}
	crt_idx = p;
	next_idx = p+1;
	sh_revision = p+2;
	*crt_idx = *next_idx = *sh_revision = 0;

	LM_DBG("trying to initialize data from db\n");
	if(init_db_data() != 0)
		return -1;

	return 0;
}


void destroy_data(void)
{
	if(rules_hash){
		destroy_hash(0);
		destroy_hash(1);
		shm_free(rules_hash);
		rules_hash = 0;
	}

	if(crt_idx)
		shm_free(crt_idx);
}

void destroy_pv_data(void)
{
	if(rules_pv_hash) {
		destroy_pv_hash();
		rules_pv_hash = NULL;
	}
}

int init_pv_data(void)
{
	destroy_pv_data();
	if (generate_pv_hash()<0) {
		return -1;
	}
	return 0;
}

/*load rules from DB*/
int dp_load_db(void)
{
	int i, nr_rows;
	db1_res_t * res = 0;
	db_val_t * values;
	db_row_t * rows;
	db_key_t query_cols[DP_TABLE_COL_NO] = {
		&dpid_column,	&pr_column,
		&match_op_column,	&match_exp_column,	&match_len_column,
		&subst_exp_column,	&repl_exp_column,	&attrs_column };

	db_key_t order = &pr_column;

	dpl_node_t *rule;

	LM_DBG("init\n");
	if( (*crt_idx) != (*next_idx)){
		LM_WARN("a load command already generated, aborting reload...\n");
		return 0;
	}

	if (dp_dbf.use_table(dp_db_handle, &dp_table_name) < 0){
		LM_ERR("error in use_table %.*s\n", dp_table_name.len, dp_table_name.s);
		return -1;
	}

	if (DB_CAPABILITY(dp_dbf, DB_CAP_FETCH)) {
		if(dp_dbf.query(dp_db_handle,0,0,0,query_cols, 0, 
					DP_TABLE_COL_NO, order, 0) < 0){
			LM_ERR("failed to query database!\n");
			return -1;
		}
		if(dp_dbf.fetch_result(dp_db_handle, &res, dp_fetch_rows)<0) {
			LM_ERR("failed to fetch\n");
			if (res)
				dp_dbf.free_result(dp_db_handle, res);
			return -1;
		}
	} else {
		/*select the whole table and all the columns*/
		if(dp_dbf.query(dp_db_handle,0,0,0,query_cols, 0, 
					DP_TABLE_COL_NO, order, &res) < 0){
			LM_ERR("failed to query database\n");
			return -1;
		}
	}

	nr_rows = RES_ROW_N(res);

	*next_idx = ((*crt_idx) == 0)? 1:0;
	destroy_hash(*next_idx);

	if(nr_rows == 0){
		LM_WARN("no data in the db\n");
		goto end;
	}

	do {
		for(i=0; i<RES_ROW_N(res); i++){
			rows 	= RES_ROWS(res);

			values = ROW_VALUES(rows+i);

			if((rule = build_rule(values)) ==0 )
				goto err2;

			if(add_rule2hash(rule , *next_idx) != 0)
				goto err2;

		}
		if (DB_CAPABILITY(dp_dbf, DB_CAP_FETCH)) {
			if(dp_dbf.fetch_result(dp_db_handle, &res, dp_fetch_rows)<0) {
				LM_ERR("failure while fetching!\n");
				if (res)
					dp_dbf.free_result(dp_db_handle, res);
				return -1;
			}
		} else {
			break;
		}
	}  while(RES_ROW_N(res)>0);


end:
	/*update data*/
	*crt_idx = *next_idx;
	list_hash(*crt_idx);
	dp_dbf.free_result(dp_db_handle, res);
	*sh_revision = (*sh_revision) + 1;
	LM_DBG("loaded revision:%d\n", *sh_revision);
	return 0;

err2:
	if(rule)	destroy_rule(rule);
	destroy_hash(*next_idx);
	dp_dbf.free_result(dp_db_handle, res);
	*next_idx = *crt_idx; 
	return -1;
}


int str_to_shm(str src, str * dest)
{
	if(src.len ==0 || src.s ==0)
		return 0;

	dest->s = (char*)shm_malloc((src.len+1) * sizeof(char));
	if(!dest->s){
		LM_ERR("out of shm memory\n");
		return -1;
	}

	memcpy(dest->s, src.s, src.len);
	dest->s[src.len] = '\0';
	dest->len = src.len;

	return 0;
}


/* Compile pcre pattern and return pointer to shm copy of result */
static pcre *reg_ex_comp(const char *pattern, int *cap_cnt)
{
	pcre *re, *result;
	const char *error;
	int rc, err_offset;
	size_t size;

	re = pcre_compile(pattern, 0, &error, &err_offset, NULL);
	if (re == NULL) {
		LM_ERR("PCRE compilation of '%s' failed at offset %d: %s\n",
				pattern, err_offset, error);
		return (pcre *)0;
	}
	rc = pcre_fullinfo(re, NULL, PCRE_INFO_SIZE, &size);
	if (rc != 0) {
		pcre_free(re);
		LM_ERR("pcre_fullinfo on compiled pattern '%s' yielded error: %d\n",
				pattern, rc);
		return (pcre *)0;
	}
	rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, cap_cnt);
	if (rc != 0) {
		pcre_free(re);
		LM_ERR("pcre_fullinfo on compiled pattern '%s' yielded error: %d\n",
				pattern, rc);
		return (pcre *)0;
	}
	result = (pcre *)shm_malloc(size);
	if (result == NULL) {
		pcre_free(re);
		LM_ERR("not enough shared memory for compiled PCRE pattern\n");
		return (pcre *)0;
	}
	memcpy(result, re, size);
	pcre_free(re);
	return result;
}

int check_pv_marker(str orig, str *dest)
{
	if(dest==NULL||orig.len<1) return -1;
	dest->s = orig.s;
	if(orig.s[orig.len-1]==PV_MARKER)
	{
		LM_DBG("PV_MARKER detected at the end\n");
		dest->len = orig.len - 1;
		return 1;
	}
	else
	{
		dest->len = orig.len;
		return 0;
	}
}

dpl_pv_node_t * build_pv_rule(dpl_node_t *rule)
{
	pv_elem_p match_elem = NULL, subst_elem = NULL;
	str match_exp = {NULL,0}, subst_exp = {NULL,0};
	dpl_pv_node_t * new_rule = NULL;

	if(!rule)
		return NULL;

	if(rule->pv_flags&DP_PV_MATCH)
	{
		match_exp.s = rule->match_exp.s;
		if(rule->pv_flags&DP_PV_MATCH_M){
			match_exp.len = rule->match_exp.len - 1;
		}
		else match_exp.len = rule->match_exp.len;
		if(pv_parse_format(&match_exp, &match_elem)<0){
			LM_ERR("parsing match_exp:%.*s\n",
				match_exp.len, match_exp.s);
			goto err;
		}
	}

	if(rule->pv_flags&DP_PV_SUBST)
	{
		subst_exp.s = rule->subst_exp.s;
		if(rule->pv_flags&DP_PV_SUBST_M){
			subst_exp.len = rule->subst_exp.len - 1;
		}
		else subst_exp.len = rule->subst_exp.len;
		if(pv_parse_format(&subst_exp, &subst_elem)<0){
			LM_ERR("parsing subst_exp:%.*s\n",
				subst_exp.len, subst_exp.s);
			goto err;
		}
	}

	if(rule->pv_flags&DP_PV_MASK){
		new_rule = (dpl_pv_node_t *)pkg_malloc(sizeof(dpl_pv_node_t));
		if(!new_rule){
			LM_ERR("out of pkg memory(new_rule)\n");
			goto err;
		}
		memset(new_rule, 0, sizeof(dpl_pv_node_t));
		if(rule->pv_flags&DP_PV_MATCH) {
			new_rule->match_elem = match_elem;
		}
		if(rule->pv_flags&DP_PV_SUBST) {
			new_rule->subst_elem = subst_elem;
		}
		new_rule->orig = rule;
	}
	return new_rule;

err:
	if(match_elem) pv_elem_free_all(match_elem);
	if(subst_elem) pv_elem_free_all(subst_elem);
	if(new_rule) destroy_pv_rule(new_rule);
	return NULL;
}


/*compile the expressions, and if ok, build the rule */
dpl_node_t * build_rule(db_val_t * values)
{
	pcre *match_comp, *subst_comp;
	struct subst_expr *repl_comp;
	dpl_node_t * new_rule;
	str match_exp, subst_exp, repl_exp, attrs, tmp;
	int matchop;
	int cap_cnt=0;
	unsigned int pv_flags = 0;

	matchop = VAL_INT(values+2);

	if((matchop != DP_REGEX_OP) && (matchop!=DP_EQUAL_OP)
			&& (matchop!=DP_FNMATCH_OP)){
		LM_ERR("invalid value for match operator\n");
		return NULL;
	}

	match_comp = subst_comp =0;
	repl_comp = 0;
	new_rule = 0;

	GET_STR_VALUE(match_exp, values, 3);
	if(matchop == DP_REGEX_OP){
		if(check_pv_marker(match_exp, &tmp))
			pv_flags |= DP_PV_MATCH_M;
		if(pv_check_format(&tmp)<0){
			pv_flags &= ~DP_PV_MATCH_MASK;
			match_comp = reg_ex_comp(match_exp.s, &cap_cnt);
			if(!match_comp){
				LM_ERR("failed to compile match expression %.*s\n",
						match_exp.len, match_exp.s);
				goto err;
			}
		}
		else{
			pv_flags |= DP_PV_MATCH;
			LM_DBG("match_exp DP_PV_MATCH_MASK\n");
			match_comp = NULL;
		}
	}

	LM_DBG("build_rule\n");
	GET_STR_VALUE(repl_exp, values, 6);
	if(repl_exp.len && repl_exp.s){
		repl_comp = repl_exp_parse(repl_exp);
		if(!repl_comp){
			LM_ERR("failed to compile replacing expression %.*s\n",
					repl_exp.len, repl_exp.s);
			goto err;
		}
	}

	GET_STR_VALUE(subst_exp, values, 5);
	if(subst_exp.s && subst_exp.len){
		if(check_pv_marker(subst_exp, &tmp))
			pv_flags |= DP_PV_SUBST_M;
		if(pv_check_format(&tmp)<0){
			pv_flags &= ~DP_PV_SUBST_MASK;
			subst_comp = reg_ex_comp(subst_exp.s, &cap_cnt);
			if(!subst_comp){
				LM_ERR("failed to compile subst expression %.*s\n",
						subst_exp.len, subst_exp.s);
				goto err;
			}
			if (cap_cnt > MAX_REPLACE_WITH) {
				LM_ERR("subst expression %.*s has too many sub-expressions\n",
						subst_exp.len, subst_exp.s);
				goto err;
			}
		}
		else{
			pv_flags |= DP_PV_SUBST;
			LM_DBG("subst_exp DP_PV_SUBST_MASK\n");
			subst_comp = NULL;
		}
	}

	if((pv_flags&DP_PV_MASK)==0) {
		if (repl_comp && (cap_cnt < repl_comp->max_pmatch) &&
				(repl_comp->max_pmatch != 0)) {
			LM_ERR("repl_exp %.*s refers to %d sub-expressions, but "
					"subst_exp %.*s has only %d\n",
					repl_exp.len, repl_exp.s, repl_comp->max_pmatch,
					subst_exp.len, subst_exp.s, cap_cnt);
			goto err;
		}
	}

	new_rule = (dpl_node_t *)shm_malloc(sizeof(dpl_node_t));
	if(!new_rule){
		LM_ERR("out of shm memory(new_rule)\n");
		goto err;
	}
	memset(new_rule, 0, sizeof(dpl_node_t));

	if(str_to_shm(match_exp, &new_rule->match_exp)!=0)
		goto err;

	if(str_to_shm(subst_exp, &new_rule->subst_exp)!=0)
		goto err;

	if(str_to_shm(repl_exp, &new_rule->repl_exp)!=0)
		goto err;

	/*set the rest of the rule fields*/
	new_rule->dpid		=	VAL_INT(values);
	new_rule->pr		=	VAL_INT(values+1);
	new_rule->matchlen	= 	VAL_INT(values+4);
	new_rule->matchop	=	matchop;
	GET_STR_VALUE(attrs, values, 7);
	if(str_to_shm(attrs, &new_rule->attrs)!=0)
		goto err;

	LM_DBG("attrs are %.*s\n", new_rule->attrs.len, new_rule->attrs.s);

	new_rule->match_comp = match_comp;
	new_rule->subst_comp = subst_comp;
	new_rule->repl_comp  = repl_comp;
	new_rule->pv_flags = pv_flags;

	return new_rule;

err:
	if(match_comp) shm_free(match_comp);
	if(subst_comp) shm_free(subst_comp);
	if(repl_comp) repl_expr_free(repl_comp);
	if(new_rule) destroy_rule(new_rule);
	return NULL;
}


int add_rule2hash(dpl_node_t * rule, int h_index)
{
	dpl_id_p crt_idp, last_idp;
	dpl_index_p indexp, last_indexp, new_indexp;
	int new_id;

	if(!rules_hash){
		LM_ERR("data not allocated\n");
		return -1;
	}

	new_id = 0;

	/*search for the corresponding dpl_id*/
	for(crt_idp = last_idp =rules_hash[h_index]; crt_idp!= NULL; 
			last_idp = crt_idp, crt_idp = crt_idp->next)
		if(crt_idp->dp_id == rule->dpid)
			break;

	/*didn't find a dpl_id*/
	if(!crt_idp){
		crt_idp = (dpl_id_t*)shm_malloc(sizeof(dpl_id_t));
		if(!crt_idp){
			LM_ERR("out of shm memory (crt_idp)\n");
			return -1;
		}
		memset(crt_idp, 0, sizeof(dpl_id_t));
		crt_idp->dp_id = rule->dpid;
		new_id = 1;
		LM_DBG("new dpl_id %i\n", rule->dpid);
	}

	/*search for the corresponding dpl_index*/
	for(indexp = last_indexp =crt_idp->first_index; indexp!=NULL; 
			last_indexp = indexp, indexp = indexp->next){
		if(indexp->len == rule->matchlen)
			goto add_rule;
		if((rule->matchlen!=0)&&((indexp->len)?(indexp->len>rule->matchlen):1))
			goto add_index;
	}

add_index:
	LM_DBG("new index , len %i\n", rule->matchlen);

	new_indexp = (dpl_index_t *)shm_malloc(sizeof(dpl_index_t));
	if(!new_indexp){
		LM_ERR("out of shm memory\n");
		goto err;
	}
	memset(new_indexp , 0, sizeof(dpl_index_t));
	new_indexp->next = indexp;
	new_indexp->len = rule->matchlen;

	/*add as first index*/
	if(last_indexp == indexp){
		crt_idp->first_index = new_indexp;
	}else{
		last_indexp->next = new_indexp;
	}

	indexp = new_indexp;

add_rule:
	rule->next = 0;
	if(!indexp->first_rule)
		indexp->first_rule = rule;

	if(indexp->last_rule)
		indexp->last_rule->next = rule;

	indexp->last_rule = rule;

	if(new_id){
		crt_idp->next = rules_hash[h_index];
		rules_hash[h_index] = crt_idp;
	}
	LM_DBG("added the rule id %i index %i pr %i next %p to the "
			"index with %i len\n", rule->dpid, rule->matchlen,
			rule->pr, rule->next, indexp->len);

	return 0;

err:
	if(new_id)
		shm_free(crt_idp);
	return -1;
}

int add_rule2hash_pv(dpl_pv_node_t * rule)
{
	dpl_pv_id_p crt_idp, last_idp;
	dpl_pv_index_p indexp, last_indexp, new_indexp;
	int new_id = 0;

	/*search for the corresponding dpl_id*/
	for(crt_idp = last_idp =rules_pv_hash; crt_idp!= NULL;
			last_idp = crt_idp, crt_idp = crt_idp->next)
		if(crt_idp->dp_id == rule->orig->dpid)
			break;

	/*didn't find a dpl_id*/
	if(!crt_idp){
		crt_idp = (dpl_pv_id_t*)pkg_malloc(sizeof(dpl_pv_id_t));
		if(!crt_idp){
			LM_ERR("out of pkg memory (crt_idp)\n");
			return -1;
		}
		memset(crt_idp, 0, sizeof(dpl_pv_id_t));
		crt_idp->dp_id = rule->orig->dpid;
		new_id = 1;
		LM_DBG("new dpl_pv_id %i %p\n", rule->orig->dpid, crt_idp);
	}

	/*search for the corresponding dpl_index*/
	for(indexp = last_indexp =crt_idp->first_index; indexp!=NULL;
			last_indexp = indexp, indexp = indexp->next){
		if(indexp->len == rule->orig->matchlen)
			goto add_rule;
		if((rule->orig->matchlen!=0)&&
			((indexp->len)?(indexp->len>rule->orig->matchlen):1))
			goto add_index;
	}

add_index:
	LM_DBG("new index , len %i\n", rule->orig->matchlen);

	new_indexp = (dpl_pv_index_t *)pkg_malloc(sizeof(dpl_pv_index_t));
	if(!new_indexp){
		LM_ERR("out of pkg memory\n");
		goto err;
	}
	memset(new_indexp , 0, sizeof(dpl_pv_index_t));
	new_indexp->next = indexp;
	new_indexp->len = rule->orig->matchlen;

	/*add as first index*/
	if(last_indexp == indexp){
		crt_idp->first_index = new_indexp;
	}else{
		last_indexp->next = new_indexp;
	}

	indexp = new_indexp;

add_rule:
	rule->next = 0;
	if(!indexp->first_rule)
		indexp->first_rule = rule;

	if(indexp->last_rule)
		indexp->last_rule->next = rule;

	indexp->last_rule = rule;

	if(new_id){
		crt_idp->next = rules_pv_hash;
		rules_pv_hash = crt_idp;
	}
	/*list_pv_rule(rule);*/

	return 0;

err:
	if(new_id)
		pkg_free(crt_idp);
	return -1;
}

void destroy_hash(int index)
{
	dpl_id_p crt_idp;
	dpl_index_p indexp;
	dpl_node_p rulep;

	if(!rules_hash[index])
		return;

	for(crt_idp = rules_hash[index]; crt_idp != NULL;){

		for(indexp = crt_idp->first_index; indexp != NULL;){

			for(rulep = indexp->first_rule; rulep!= NULL;){

				destroy_rule(rulep);

				indexp->first_rule = rulep->next;
				shm_free(rulep);
				rulep=0;
				rulep= indexp->first_rule;
			}
			crt_idp->first_index= indexp->next;
			shm_free(indexp);
			indexp=0;
			indexp = crt_idp->first_index;

		}

		rules_hash[index] = crt_idp->next;
		shm_free(crt_idp);
		crt_idp = 0;
		crt_idp = rules_hash[index];
	}

	rules_hash[index] = 0;
}

int generate_pv_hash(void)
{
	dpl_id_p crt_idp;
	dpl_index_p indexp;
	dpl_node_p rulep;
	dpl_pv_node_p rule_pv;
	int h_index = *crt_idx;

	if(!rules_hash[h_index])
		return -1;

	if(*sh_revision==pv_revision){
		LM_DBG("already loaded\n");
		return 0;
	}

	for(crt_idp=rules_hash[h_index]; crt_idp!=NULL; crt_idp = crt_idp->next){
		LM_DBG("DPID: %i, pointer %p\n", crt_idp->dp_id, crt_idp);
		for(indexp=crt_idp->first_index; indexp!=NULL;indexp= indexp->next){
			LM_DBG("INDEX LEN: %i\n", indexp->len);
			for(rulep = indexp->first_rule; rulep!= NULL;rulep = rulep->next){
				if(rulep->pv_flags&DP_PV_MASK){
					rule_pv = build_pv_rule(rulep);
					if(rule_pv){
						if(add_rule2hash_pv(rule_pv)<0) {
							LM_ERR("error adding pv rule\n");
							goto err;
						}
					}
					else {
						LM_ERR("error building pv rule\n");
						goto err;
					}
				}
			}
		}
	}
	pv_revision = *sh_revision;
	return 0;

err:
	if(rule_pv) {
		destroy_pv_rule(rule_pv);
		pkg_free(rule_pv);
	}
	return -1;
}

void destroy_pv_hash(void)
{
	dpl_pv_id_p crt_idp;
	dpl_pv_index_p indexp;
	dpl_pv_node_p rulep;

	if(!rules_pv_hash)
		return;

	for(crt_idp = rules_pv_hash; crt_idp != NULL;){

		for(indexp = crt_idp->first_index; indexp != NULL;){

			for(rulep = indexp->first_rule; rulep!= NULL;){

				destroy_pv_rule(rulep);

				indexp->first_rule = rulep->next;
				pkg_free(rulep);
				rulep=0;
				rulep= indexp->first_rule;
			}
			crt_idp->first_index= indexp->next;
			pkg_free(indexp);
			indexp=0;
			indexp = crt_idp->first_index;

		}

		rules_pv_hash = crt_idp->next;
		pkg_free(crt_idp);
		crt_idp = 0;
		crt_idp = rules_pv_hash;
	}

	rules_pv_hash = 0;
}

void destroy_pv_rule(dpl_pv_node_t * rule){
	if(!rule)
		return;

	LM_DBG("destroying pv_rule %i\n", rule->orig->dpid);
	if(rule->match_comp){
		pcre_free(rule->match_comp);
		rule->match_comp = NULL;
	}
	if(rule->subst_comp){
		pcre_free(rule->subst_comp);
		rule->subst_comp = NULL;
	}
	if(rule->match_elem){
		pv_elem_free_all(rule->match_elem);
		rule->match_elem = NULL;
	}
	if(rule->subst_elem){
		pv_elem_free_all(rule->subst_elem);
		rule->subst_elem = NULL;
	}
}

void destroy_rule(dpl_node_t * rule){

	if(!rule)
		return;

	LM_DBG("destroying rule with priority %i\n", 
			rule->pr);

	if(rule->match_comp)
		shm_free(rule->match_comp);

	if(rule->subst_comp)
		shm_free(rule->subst_comp);

	/*destroy repl_exp*/
	if(rule->repl_comp)
		repl_expr_free(rule->repl_comp);

	if(rule->match_exp.s)
		shm_free(rule->match_exp.s);

	if(rule->subst_exp.s)
		shm_free(rule->subst_exp.s);

	if(rule->repl_exp.s)
		shm_free(rule->repl_exp.s);

	if(rule->attrs.s)
		shm_free(rule->attrs.s);

	lock_destroy(rule->lock);
}


dpl_id_p select_dpid(int id)
{
	dpl_id_p idp;

	if(!rules_hash || !crt_idx)
		return NULL;

	for(idp = rules_hash[*crt_idx]; idp!=NULL; idp = idp->next)
		if(idp->dp_id == id)
			return idp;

	return NULL;
}

dpl_pv_id_p select_pv_dpid(int id)
{
	dpl_pv_id_p idp;

	if(*sh_revision!=pv_revision){
		LM_DBG("new revision:%d detected\n", *sh_revision);
		if(init_pv_data()<0){
			LM_ERR("error reloading pv rules\n");
			return NULL;
		}
	}

	for(idp = rules_pv_hash; idp!=NULL; idp = idp->next){
		if(idp->dp_id == id)
			return idp;
	}

	return NULL;
}

/*FOR DEBUG PURPOSE*/
void list_hash(int h_index)
{
	dpl_id_p crt_idp;
	dpl_index_p indexp;
	dpl_node_p rulep;


	if(!rules_hash[h_index])
		return;

	for(crt_idp=rules_hash[h_index]; crt_idp!=NULL; crt_idp = crt_idp->next){
		LM_DBG("DPID: %i, pointer %p\n", crt_idp->dp_id, crt_idp);
		for(indexp=crt_idp->first_index; indexp!=NULL;indexp= indexp->next){
			LM_DBG("INDEX LEN: %i\n", indexp->len);
			for(rulep = indexp->first_rule; rulep!= NULL;rulep = rulep->next){
				list_rule(rulep);
			}
		}
	}
}


void list_rule(dpl_node_t * rule)
{
	LM_DBG("RULE %p: pr %i next %p op %d match_exp %.*s, "
			"subst_exp %.*s, repl_exp %.*s and attrs %.*s\n", rule,
			rule->pr, rule->next,
			rule->matchop,
			rule->match_exp.len, rule->match_exp.s, 
			rule->subst_exp.len, rule->subst_exp.s,
			rule->repl_exp.len, rule->repl_exp.s,
			rule->attrs.len,	rule->attrs.s);

}

void list_pv_hash(void)
{
	dpl_pv_id_p crt_idp;
	dpl_pv_index_p indexp;
	dpl_pv_node_p rulep;

	for(crt_idp=rules_pv_hash; crt_idp!=NULL; crt_idp = crt_idp->next){
		LM_DBG("DPID: %i, pointer %p\n", crt_idp->dp_id, crt_idp);
		for(indexp=crt_idp->first_index; indexp!=NULL;indexp= indexp->next){
			LM_DBG("INDEX LEN: %i\n", indexp->len);
			for(rulep = indexp->first_rule; rulep!= NULL;rulep = rulep->next){
				list_pv_rule(rulep);
			}
		}
	}
}

void list_pv_rule(dpl_pv_node_t * rule)
{
	LM_DBG("PV_RULE %p: next %p match_exp %.*s, "
			"subst_exp %.*s \n", rule, rule->next,
			rule->match_exp.len, rule->match_exp.s,
			rule->subst_exp.len, rule->subst_exp.s);
}

void show_pv_flags(unsigned int flag)
{
	if(flag&DP_PV_MATCH) LM_DBG("DP_PV_MATCH\n");
	if(flag&DP_PV_MATCH_M) LM_DBG("DP_PV_MATCH_M\n");
	if(flag&DP_PV_MATCH_MASK) LM_DBG("DP_PV_MATCH_MASK\n");
	if(flag&DP_PV_SUBST) LM_DBG("DP_PV_SUBST\n");
	if(flag&DP_PV_SUBST_M) LM_DBG("DP_PV_SUBST_M\n");
	if(flag&DP_PV_SUBST_MASK) LM_DBG("DP_PV_SUBST_MASK\n");
	if(flag&DP_PV_MASK) LM_DBG("DP_PV_MASK\n");
	LM_DBG("--pv_flags:%d\n", flag);
}
