/*
 * $Id$
 *
 * Copyright (C) 2007-2008 Voice Sistem SRL
 *
 * Copyright (C) 2008 Juha Heinanen
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
 */

/*!
 * \file
 * \brief SIP-router dialplan :: database interface - reply parsing
 * \ingroup dialplan
 * Module: \ref dialplan
 */


#include <fnmatch.h>

#include "../../re.h"
#include "../../mem/shm_mem.h"
#include "dialplan.h"


void repl_expr_free(struct subst_expr *se)
{
	if(!se)
		return;

	if(se->replacement.s){
		shm_free(se->replacement.s);
		se->replacement.s = 0;
	}

	shm_free(se);
	se = 0;
}


struct subst_expr* repl_exp_parse(str subst)
{
	struct replace_with rw[MAX_REPLACE_WITH];
	int rw_no;
	struct subst_expr * se;
	int replace_all;
	char * p, *end, *repl, *repl_end;
	int max_pmatch, r;
	str shms;

	se = 0;
	replace_all = 0;
	shms.s = NULL;

	if (!(shms.s=shm_malloc((subst.len+1) * sizeof(char))) ){
		LM_ERR("out of shm memory\n");
		goto error;
	}
	memcpy(shms.s, subst.s, subst.len);
	shms.len = subst.len;
	shms.s[shms.len] = '\0';

	p = shms.s;
	end = p + shms.len;
	rw_no = 0;

	repl = p;
	if((rw_no = parse_repl(rw, &p, end, &max_pmatch, WITHOUT_SEP))< 0)
		goto error;

	repl_end=p;

	/* construct the subst_expr structure */
	se = shm_malloc(sizeof(struct subst_expr)+
			((rw_no)?(rw_no-1)*sizeof(struct replace_with):0));
	/* 1 replace_with structure is  already included in subst_expr */
	if (se==0){
		LM_ERR("out of shm memory (subst_expr)\n");
		goto error;
	}
	memset((void*)se, 0, sizeof(struct subst_expr));

	se->replacement.s = shms.s;
	shms.s = NULL;
	se->replacement.len=repl_end-repl;
	if(!rw_no){
		replace_all = 1;
	}
	/* start copying */
	LM_DBG("replacement expression is [%.*s]\n", se->replacement.len,
			se->replacement.s);
	se->re=0;
	se->replace_all=replace_all;
	se->n_escapes=rw_no;
	se->max_pmatch=max_pmatch;

	/*replace_with is a simple structure, no shm alloc needed*/
	for (r=0; r<rw_no; r++) se->replace[r]=rw[r];
	return se;

error:
	if(shms.s != NULL)
		shm_free(shms.s);
	if (se) { repl_expr_free(se);}
	return NULL;
}


#define MAX_PHONE_NB_DIGITS		127
static char dp_output_buf[MAX_PHONE_NB_DIGITS+1];
int rule_translate(struct sip_msg *msg, str string, dpl_node_t * rule,
		dpl_pv_node_p rule_pv, dpl_pv_regex_node_p subst_node,
		str *match_expr, str * result)
{
	int repl_nb, offset, match_nb, rc, cap_cnt;
	struct replace_with token;
	pcre *subst_comp;
	struct subst_expr * repl_comp;
	str match;
	str match_exp, subst_exp;
	pv_value_t sv;
	str* uri;
	int ovector[3 * (MAX_REPLACE_WITH + 1)];
	char *p;
	int size;

	dp_output_buf[0] = '\0';
	result->s = dp_output_buf;
	result->len = 0;

	if(rule_pv&&(rule!=rule_pv->orig)){
		LM_ERR("rule and rule_pv don not match\n");
		return -1;
	}

	if(rule_pv&&(rule->pv_flags&DP_PV_SUBST ||
		rule->pv_flags&DP_PV_SUBST_AVP))
	{
		if(subst_node)
		{
			subst_comp 	= subst_node->comp;
			subst_exp.len = subst_node->expr.len;
			subst_exp.s = subst_node->expr.s;
		}
		else
		{
			LM_ERR("subst_node is null\n");
			return -1;
		}
	}
	else{
		subst_comp 	= rule->subst_comp;
		subst_exp.len = rule->subst_exp.len;
		subst_exp.s = rule->subst_exp.s;
	}
	if(rule_pv&&(rule->pv_flags&DP_PV_MATCH ||
		rule->pv_flags&DP_PV_MATCH_AVP))
	{
		if(!match_expr)
		{
			LM_ERR("match_expr is null but rule_pv is DP_PV_MATCH[_AVP]\n");
			return -1;
		}
		match_exp.len = match_expr->len;
		match_exp.s = match_expr->s;
	}
	else{
		match_exp = rule->match_exp;
	}
	repl_comp = rule->repl_comp;

	if(!repl_comp){
		LM_DBG("null replacement\n");
		return 0;
	}

	if(subst_comp){
		/*just in case something went wrong at load time*/
		rc = pcre_fullinfo(subst_comp, NULL, PCRE_INFO_CAPTURECOUNT,
				&cap_cnt);
		if (rc != 0) {
			LM_ERR("pcre_fullinfo on compiled pattern yielded error: %d\n",
					rc);
			return -1;;
		}
		if(repl_comp->max_pmatch > cap_cnt){
			LM_ERR("illegal access to the %i-th subexpr of the subst expr\n",
					repl_comp->max_pmatch);
			return -1;
		}

		/*search for the pattern from the compiled subst_exp*/
		if (pcre_exec(subst_comp, NULL, string.s, string.len,
					0, 0, ovector, 3 * (MAX_REPLACE_WITH + 1)) <= 0) {
			LM_ERR("the string %.*s matched "
					"the match_exp %.*s but not the subst_exp %.*s!\n", 
					string.len, string.s, 
					match_exp.len, match_exp.s,
					subst_exp.len, subst_exp.s);
			return -1;
		}
	}

	/*simply copy from the replacing string*/
	if(!subst_comp || (repl_comp->n_escapes <=0)){
		if(!repl_comp->replacement.s || repl_comp->replacement.len == 0){
			LM_ERR("invalid replacing string\n");
			goto error;
		}
		LM_DBG("simply replace the string, subst_comp %p, n_escapes %i\n",
				subst_comp, repl_comp->n_escapes);
		memcpy(result->s, repl_comp->replacement.s,
				repl_comp->replacement.len);
		result->len = repl_comp->replacement.len;
		result->s[result->len] = '\0';
		return 0;
	}

	/* offset- offset in the replacement string */
	result->len = repl_nb = offset = 0;
	p=repl_comp->replacement.s;

	while( repl_nb < repl_comp->n_escapes){

		token = repl_comp->replace[repl_nb];

		if(offset< token.offset){
			if((repl_comp->replacement.len < offset)||
					(result->len + token.offset -offset >= MAX_PHONE_NB_DIGITS)){
				LM_ERR("invalid length\n");
				goto error;
			}
			/*copy from the replacing string*/
			size = token.offset - offset;
			memcpy(result->s + result->len, p + offset, size);
			LM_DBG("copying <%.*s> from replacing string\n",
					size, p + offset);
			result->len += size;
			offset = token.offset;
		}

		switch(token.type) {
			case REPLACE_NMATCH:
				/*copy from the match subexpression*/	
				match_nb = token.u.nmatch * 2;
				match.s =  string.s + ovector[match_nb];
				match.len = ovector[match_nb + 1] - ovector[match_nb];
				if(result->len + match.len >= MAX_PHONE_NB_DIGITS){
					LM_ERR("overflow\n");
					goto error;
				}

				memcpy(result->s + result->len, match.s, match.len);
				LM_DBG("copying match <%.*s> token size %d\n",
						match.len, match.s, token.size);
				result->len += match.len;
				offset += token.size;
				break;
			case REPLACE_CHAR:
				if(result->len + 1>= MAX_PHONE_NB_DIGITS){
					LM_ERR("overflow\n");
					goto error;
				}
				*(result->s + result->len) = token.u.c;
				LM_DBG("copying char <%c> token size %d\n",
						token.u.c, token.size);
				result->len++;
				offset += token.size;
				break;
			case REPLACE_URI:	
				if ( msg== NULL || msg->first_line.type!=SIP_REQUEST){
					LM_CRIT("uri substitution attempt on no request"
							" message\n");
					break; /* ignore, we can continue */
				}
				uri= (msg->new_uri.s)?(&msg->new_uri):
					(&msg->first_line.u.request.uri);
				if(result->len+uri->len>=MAX_PHONE_NB_DIGITS){
					LM_ERR("overflow\n");
					goto error;
				}
				memcpy(result->s + result->len, uri->s, uri->len);
				LM_DBG("copying uri <%.*s> token size %d\n",
						uri->len, uri->s, token.size);
				result->len+=uri->len;
				offset += token.size;
				break;
			case REPLACE_SPEC:
				if (msg== NULL) {
					LM_DBG("replace spec attempted on no message\n");
					break;
				}
				if (pv_get_spec_value(msg, &token.u.spec, &sv) != 0) {
					LM_CRIT("item substitution returned error\n");
					break; /* ignore, we can continue */
				}
				if(result->len+sv.rs.len>=MAX_PHONE_NB_DIGITS){
					LM_ERR("rule_translate: overflow\n");
					goto error;
				}
				memcpy(result->s + result->len, sv.rs.s,
						sv.rs.len);
				LM_DBG("copying pvar value <%.*s> token size %d\n",
						sv.rs.len, sv.rs.s, token.size);
				result->len+=sv.rs.len;
				offset += token.size;
				break;
			default:
				LM_CRIT("unknown type %d\n", repl_comp->replace[repl_nb].type);
				/* ignore it */
		}
		repl_nb++;
	}
	/* anything left? */
	if( repl_nb && offset < repl_comp->replacement.len){
		/*copy from the replacing string*/
		size = repl_comp->replacement.len - offset;
		memcpy(result->s + result->len, p + offset, size);
		LM_DBG("copying leftover <%.*s> from replacing string\n",
				size, p + offset);
		result->len += size;
	}

	result->s[result->len] = '\0';
	return 0;

error:
	result->s = 0;
	result->len = 0;
	return -1;
}

dpl_pv_node_p get_pv_rule(dpl_node_p rule, unsigned int index, unsigned int user_len)
{
	dpl_pv_id_p idp;
	dpl_pv_index_p indexp;
	dpl_pv_node_p rulep;


	idp = select_pv_dpid(index);
	if(!idp) {
		LM_ERR("no pv idp:%d\n", rule->dpid);
		return NULL;
	}
	for(indexp = idp->first_index; indexp!=NULL; indexp = indexp->next)
		if(!indexp->len || (indexp->len!=0 && indexp->len == user_len) )
			break;

	if(!indexp || (indexp!= NULL && !indexp->first_rule)){
		LM_DBG("no pv rule for len %i\n", user_len);
		return NULL;
	}

search_rule:
	for(rulep=indexp->first_rule; rulep!=NULL; rulep= rulep->next) {
		if(rulep->orig==rule) return rulep;
	}

	/*test the rules with len 0*/
	if(indexp->len){
		for(indexp = indexp->next; indexp!=NULL; indexp = indexp->next)
			if(!indexp->len)
				break;
		if(indexp)
			goto search_rule;
	}

	LM_DBG("no matching rule\n");
	return NULL;
}

/* Compile pcre pattern */
static pcre *reg_ex_comp_pv(const char *pattern, int *cap_cnt)
{
	pcre *re;
	const char *error;
	int rc, err_offset;
	size_t size;

	re = pcre_compile(pattern, 0, &error, &err_offset, NULL);
	if (re == NULL) {
		LM_ERR("PCRE compilation of '%s' failed at offset %d: %s\n",
				pattern, err_offset, error);
		return NULL;
	}
	rc = pcre_fullinfo(re, NULL, PCRE_INFO_SIZE, &size);
	if (rc != 0) {
		pcre_free(re);
		LM_ERR("pcre_fullinfo on compiled pattern '%s' yielded error: %d\n",
				pattern, rc);
		return NULL;
	}
	rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, cap_cnt);
	if (rc != 0) {
		pcre_free(re);
		LM_ERR("pcre_fullinfo on compiled pattern '%s' yielded error: %d\n",
				pattern, rc);
		return NULL;
	}
	return re;
}

void free_pv_regex_node(dpl_pv_regex_node_p *head)
{
	dpl_pv_regex_node_p n = *head;
	while(n)
	{
		if(n->comp) pcre_free(n->comp);
		if(n->expr.s) pkg_free(n->expr.s);
		*head = n->next;
		pkg_free(n);
		n = *head;
	}
}

int add_pv_regex_node(dpl_pv_regex_node_p *head, pcre *comp,
	str expr, int cap_cnt)
{
	dpl_pv_regex_node_p n;

	if(head==NULL||comp==NULL) return -1;
	n = pkg_malloc(sizeof(dpl_pv_regex_node_t));
	if(n==NULL)
	{
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memset(n, 0, sizeof(dpl_pv_regex_node_t));
	n->comp = comp;
	n->expr.len = expr.len;
	if(pkg_str_dup(&n->expr, &expr)<0) { pkg_free(n); return -1; }
	n->cap_cnt = cap_cnt;
	n->next = *head;
	*head = n;
	return 0;
}

int get_pv_avp_param(pv_elem_p regex_elem, pv_param_p *avp_param)
{
	int num, num_elem;
	pv_elem_p e;

	if(regex_elem==NULL) return -1;
	for(e = regex_elem, num=num_elem=0; e != NULL; e = e->next, num++)
	{
		if(e->spec!=NULL)
		{
			if(num_elem!=0)
			{
				LM_ERR("More than one spec\n");
				return -1;
			}
			num_elem++;
			if( e->spec->type!=PVT_AVP ||
				e->spec->pvp.pvi.type!=PV_IDX_ALL)
			{
				LM_ERR("spec not AVP or PV_IDX_ALL\n");
				return -1;
			}
			*avp_param = &(e->spec->pvp);
		}
	}
	return 0;
}

void dlp_print_elem(pv_elem_p elem)
{
	pv_elem_p e;
	int num;
	for(e=elem, num=0; e!=NULL; e=e->next, num++)
	{
		LM_DBG("elem[%d][%p][%.*s][%p]\n", num, e, e->text.len,
			e->text.s, e->spec);
	}
}

int build_pv_regex_comp_helper(struct sip_msg *msg,
	dpl_pv_regex_node_p *regex_comp, pv_elem_p elem)
{
	pcre *comp = NULL;
	str expr = STR_NULL;
	int cap_cnt = 0;

	if(pv_printf_s(msg, elem, &expr)<0){
		LM_ERR("Can't get regex expression value\n");
		return -1;
	}
	/*LM_DBG("final expr:[%.*s]\n", expr.len, expr.s);*/
	comp = reg_ex_comp_pv(expr.s, &cap_cnt);
	if(!comp){
		LM_ERR("failed to compile regex expression %.*s\n",
				expr.len, expr.s);
		return -1;
	}
	if(add_pv_regex_node(regex_comp, comp, expr, cap_cnt)<0)
	{
		LM_ERR("Can't add regex node\n");
		return -1;
	}
	LM_DBG("expr:[%.*s][%d] added\n", expr.len, expr.s, cap_cnt);
	return 0;
}

int build_pv_regex_comp(struct sip_msg *msg, dpl_pv_regex_node_p *node,
	str expr, pv_elem_p elem, int flag[3])
{
	struct usr_avp *avp;
	unsigned short name_type;
	int_str avp_name;
	int_str avp_value;
	struct search_state state;
	pv_param_p avp_param = NULL;
	pv_elem_p regex_elem;
	str regex_exp_orig;
	str num_index = STR_NULL;
	char orig_base_buf[256];
	str regex_exp = STR_NULL;
	int num = 0;
	int t[3];
	char *index;

	if(flag[0]) /* DP_PV_[MATCH|SUBST] */
	{
		LM_DBG("simple regex\n");
		if(build_pv_regex_comp_helper(msg, node, elem)<0)
			return -1;
	}
	else if(flag[2]) /* DP_PV_[MATCH|SUBST]_AVP */
	{
		LM_DBG("avp regex\n");
		if(get_pv_avp_param(elem, &avp_param)<0)
		{
			LM_DBG("cannot get avp_param from elem[%p]\n", elem);
			dlp_print_elem(elem);
			return -1;
		}
		if(pv_get_avp_name(msg, avp_param, &avp_name, &name_type)!=0)
		{
			LM_ERR("invalid avp name\n");
			return -1;
		}
		regex_exp_orig.len = expr.len;
		if(flag[1]) regex_exp_orig.len--; /* DP_PV_[MATCH|SUBST]_MATCH */
		regex_exp_orig.s = expr.s;
		LM_DBG("regex_exp[%.*s]\n", regex_exp_orig.len, regex_exp_orig.s);
		index = strstr( regex_exp_orig.s,  "[*]");
		if(!index)
		{
			LM_ERR("Cannot find [*] at regex_exp\n");
			return -1;
		}
		t[0] = index+1-regex_exp_orig.s;
		t[2] = regex_exp_orig.s + regex_exp_orig.len - (index+2);
		strncpy(orig_base_buf, regex_exp_orig.s, t[0]);
		regex_exp.s = orig_base_buf;
		regex_exp.len = t[0];
		avp = search_first_avp(name_type, avp_name, &avp_value, &state);
		while(avp)
		{
			num_index.s = int2str(num, &(num_index.len));
			strncpy(orig_base_buf+t[0], num_index.s, num_index.len);
			t[1] = t[0] + num_index.len;
			regex_exp.len = t[1];
			strncpy(orig_base_buf+regex_exp.len, index+2, t[2]);
			regex_exp.len = t[0] + num_index.len + t[2];
			/*LM_DBG("final regex_exp[%.*s]\n", regex_exp.len, regex_exp.s);*/
			if(pv_parse_format(&regex_exp, &regex_elem)<0){
				LM_ERR("parsing regex_exp:%.*s\n",
					regex_exp.len, regex_exp.s);
				return -1;
			}
			if(build_pv_regex_comp_helper(msg, node, regex_elem)<0) return -1;
			pv_elem_free_all(regex_elem);
			avp = search_next_avp(&state, &avp_value);
			num++;
		}
	}
	return 0;
}

int build_pv_comp(struct sip_msg *msg, dpl_pv_node_p rule)
{
	struct subst_expr *repl_comp;
	dpl_pv_regex_node_p n;
	int flags[2][3] = {
		{
			rule->orig->pv_flags&DP_PV_MATCH,
			rule->orig->pv_flags&DP_PV_MATCH_M,
			rule->orig->pv_flags&DP_PV_MATCH_AVP
		},
		{
			rule->orig->pv_flags&DP_PV_SUBST,
			rule->orig->pv_flags&DP_PV_SUBST_M,
			rule->orig->pv_flags&DP_PV_SUBST_AVP
		}
	};
	if(!rule)
		return -1;

	if(rule->orig->pv_flags&DP_PV_MATCH||rule->orig->pv_flags&DP_PV_MATCH_AVP)
	{
		if(rule->match) free_pv_regex_node(&rule->match);
		if(build_pv_regex_comp(msg, &rule->match, rule->orig->match_exp,
			rule->match_elem, flags[0])<0) return -1;
	}

	if(rule->orig->pv_flags&DP_PV_SUBST||rule->orig->pv_flags&DP_PV_SUBST_AVP)
	{
		if(rule->subst) free_pv_regex_node(&rule->subst);
		if(build_pv_regex_comp(msg, &rule->subst, rule->orig->subst_exp,
			rule->subst_elem, flags[1])<0) return -1;
		repl_comp = rule->orig->repl_comp;
		for(n=rule->subst;n!=NULL;n=n->next)
		{
			if (n->cap_cnt > MAX_REPLACE_WITH) {
				LM_ERR("subst expression %.*s has too many sub-expressions\n",
						n->expr.len, n->expr.s);
				return -1;
			}
			if (repl_comp && (n->cap_cnt < repl_comp->max_pmatch) &&
					(repl_comp->max_pmatch != 0)) {
				LM_ERR("repl_exp %.*s refers to %d sub-expressions, but "
						"subst_exp %.*s has only %d\n",
						rule->orig->repl_exp.len, rule->orig->repl_exp.s,
						repl_comp->max_pmatch, n->expr.len,
						n->expr.s, n->cap_cnt);
				return -1;
			}
		}
	}

	return 0;
}

#define DP_MAX_ATTRS_LEN	128
static char dp_attrs_buf[DP_MAX_ATTRS_LEN+1];
int translate(struct sip_msg *msg, str input, str *output, dpl_id_p idp,
		str *attrs)
{
	dpl_node_p rulep;
	dpl_pv_node_p rule_pv;
	dpl_index_p indexp;
	dpl_pv_regex_node_p n;
	str *match_expr;
	int user_len, rez;
	char b;

	if(!input.s || !input.len) {
		LM_ERR("invalid input string\n");
		return -1;
	}

	user_len = input.len;
	for(indexp = idp->first_index; indexp!=NULL; indexp = indexp->next)
		if(!indexp->len || (indexp->len!=0 && indexp->len == user_len) )
			break;

	if(!indexp || (indexp!= NULL && !indexp->first_rule)){
		LM_DBG("no rule for len %i\n", input.len);
		return -1;
	}

search_rule:
	for(rulep=indexp->first_rule; rulep!=NULL; rulep= rulep->next) {
		match_expr = NULL;
		switch(rulep->matchop) {

			case DP_REGEX_OP:
				LM_DBG("regex operator testing\n");
				if(rulep->pv_flags&DP_PV_MATCH||rulep->pv_flags&DP_PV_MATCH_AVP)
				{
					if(!msg) {
						LM_ERR("Cannot translate using a regex match with pv "
							"without message\n");
						continue;
					}
					rule_pv = get_pv_rule(rulep, idp->dp_id, user_len);
					if(rule_pv) {
						if(rulep->pv_flags&(DP_PV_MATCH_AVP|DP_PV_SUBST_AVP) &&
							(!rule_pv->match_elem || !rule_pv->subst_elem))
						{
							LM_ERR("AVP match_elem[%p] or subst_elem[%p] are null."
								" Skip this\n", rule_pv->match_elem,
								rule_pv->subst_elem);
							continue;
						}
						if(build_pv_comp(msg, rule_pv)<0){
							LM_ERR("error rule regex comp. Skip this\n");
							continue;
						}
						n = rule_pv->match;
						while(n)
						{
							LM_DBG("match check: [%.*s][%p]\n", n->expr.len,
								n->expr.s, n->comp);
							rez = pcre_exec(n->comp, NULL, input.s,
									input.len, 0, 0, NULL, 0);
							if(rez >= 0)
							{
								match_expr = &(n->expr);
								n = NULL;
							}
							else n = n->next;
						}
					}
					else {
						LM_ERR("pv rule not found.Skip this\n");
						continue;
					}
				}
				else
				{
					rez = pcre_exec(rulep->match_comp, NULL, input.s, input.len,
						0, 0, NULL, 0);
				}
				break;

			case DP_EQUAL_OP:
				LM_DBG("equal operator testing\n");
				if(rulep->match_exp.len != input.len) {
					rez = -1;
				} else {
					rez = strncmp(rulep->match_exp.s,input.s,input.len);
					rez = (rez==0)?0:-1;
				}
				break;

			case DP_FNMATCH_OP:
				LM_DBG("fnmatch operator testing\n");
				b = input.s[input.len];
				input.s[input.len] = '\0';
				rez = fnmatch(rulep->match_exp.s, input.s, 0);
				input.s[input.len] = b;
				rez = (rez==0)?0:-1;
				break;

			default:
				LM_ERR("bogus match operator code %i\n", rulep->matchop);
				return -1;
		}
		if(rez >= 0)
			goto repl;
	}
	/*test the rules with len 0*/
	if(indexp->len){
		for(indexp = indexp->next; indexp!=NULL; indexp = indexp->next)
			if(!indexp->len)
				break;
		if(indexp)
			goto search_rule;
	}

	LM_DBG("no matching rule\n");
	return -1;

repl:
	if(!match_expr) match_expr = &(rulep->match_exp);
	LM_DBG("found a matching rule %p: pr %i, match_exp %.*s pv_flags:%d\n",
			rulep, rulep->pr, match_expr->len, match_expr->s,
			rulep->pv_flags);

	if(attrs) {
		attrs->len = 0;
		attrs->s = 0;
		if(rulep->attrs.len>0) {
			LM_DBG("the rule's attrs are %.*s\n",
					rulep->attrs.len, rulep->attrs.s);
			if(rulep->attrs.len >= DP_MAX_ATTRS_LEN) {
				LM_ERR("out of memory for attributes\n");
				return -1;
			}
			attrs->s = dp_attrs_buf;
			memcpy(attrs->s, rulep->attrs.s, rulep->attrs.len*sizeof(char));
			attrs->len = rulep->attrs.len;
			attrs->s[attrs->len] = '\0';

			LM_DBG("the copied attributes are: %.*s\n",
					attrs->len, attrs->s);
		}
	}

	if(!(rulep->pv_flags&DP_PV_MASK))
		rule_pv = NULL;

	if(rulep->pv_flags&DP_PV_SUBST||rulep->pv_flags&DP_PV_SUBST_AVP)
	{
		for(n=rule_pv->subst;n!=NULL;n=n->next)
		{
			LM_DBG("subst check: [%.*s]\n", n->expr.len, n->expr.s);
			if(rule_translate(msg, input, rulep, rule_pv, n, match_expr,
				output)==0) return 0;
		}
		LM_ERR("could not build the output\n");
		return -1;
	}
	else
	{
		if(rule_translate(msg, input, rulep, rule_pv, 0, match_expr,
			output)!=0)
		{
			LM_ERR("could not build the output\n");
			return -1;
		}
	}
	return 0;
}
