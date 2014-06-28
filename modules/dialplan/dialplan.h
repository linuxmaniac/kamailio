
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
 */

/*!
 * \file
 * \brief SIP-router dialplan :: Module interface
 * \ingroup dialplan
 * Module: \ref dialplan
 */


#ifndef _DP_DIALPLAN_H
#define _DP_DIALPLAN_H

#include <pcre.h>
#include "../../pvar.h"
#include "../../parser/msg_parser.h"

#define DP_EQUAL_OP		0
#define DP_REGEX_OP		1
#define DP_FNMATCH_OP	2

#define DP_PV_MATCH		(1 << 0)
#define DP_PV_MATCH_M	(1 << 1) /* PV_MARKER at the end */
#define DP_PV_MATCH_AVP (1 << 2) /* AVP WITH AVP_INDEX_ALL */
#define DP_PV_SUBST		(1 << 3)
#define DP_PV_SUBST_M	(1 << 4) /* PV_MARKER at the end */
#define DP_PV_SUBST_AVP (1 << 5) /* AVP WITH AVP_INDEX_ALL */

#define DP_PV_MASK (DP_PV_MATCH|DP_PV_SUBST|DP_PV_MATCH_AVP|DP_PV_SUBST_AVP)
#define DP_PV_MATCH_MASK (DP_PV_MATCH|DP_PV_MATCH_M)
#define DP_PV_SUBST_MASK (DP_PV_SUBST|DP_PV_SUBST_M)

#define MAX_REPLACE_WITH	10

typedef struct dpl_node{
	int dpid;
	int pr;
	int matchop;
	int matchlen;
	str match_exp, subst_exp, repl_exp; /*keeping the original strings*/
	pcre *match_comp, *subst_comp; /*compiled patterns*/
	struct subst_expr * repl_comp; 
	str attrs;
	unsigned int pv_flags;

	struct dpl_node * next; /*next rule*/
}dpl_node_t, *dpl_node_p;

/*For every distinct length of a matching string*/
typedef struct dpl_index{
	int len;
	dpl_node_t * first_rule;
	dpl_node_t * last_rule;

	struct dpl_index * next; 
}dpl_index_t, *dpl_index_p;

/*For every DPID*/
typedef struct dpl_id{
	int dp_id;
	dpl_index_t* first_index;/*fast access :rules with specific length*/
	struct dpl_id * next;
}dpl_id_t,*dpl_id_p;

typedef struct dpl_pv_regex_node
{
	pcre *comp;
	str expr;
	int cap_cnt;
	struct dpl_pv_regex_node *next;
}dpl_pv_regex_node_t, *dpl_pv_regex_node_p;

typedef struct dpl_pv_node{
	pv_elem_p match_elem, subst_elem;
	dpl_pv_regex_node_p match; /* list of match regex compiled */
	dpl_pv_regex_node_p subst; /* list of subst regex compiled */

	struct dpl_pv_node * next; /* next rule */
	struct dpl_node * orig; /* shared rule */
}dpl_pv_node_t, *dpl_pv_node_p;

/*For every distinct length of a matching string*/
typedef struct dpl_pv_index{
	int len;
	dpl_pv_node_t * first_rule;
	dpl_pv_node_t * last_rule;

	struct dpl_pv_index * next;
}dpl_pv_index_t, *dpl_pv_index_p;

/*For every DPID*/
typedef struct dpl_pv_id{
	int dp_id;
	dpl_pv_index_t* first_index;/*fast access :rules with specific length*/
	struct dpl_pv_id * next;
}dpl_pv_id_t,*dpl_pv_id_p;

#define DP_VAL_INT		0
#define DP_VAL_SPEC		1

typedef struct dp_param{
	int type;
	union {
		int id;
		pv_spec_t* sp[2];
	} v;
}dp_param_t, *dp_param_p;

int init_data();
void destroy_data();
int dp_load_db();

dpl_id_p select_dpid(int id);
dpl_pv_id_p select_pv_dpid(int id);

struct subst_expr* repl_exp_parse(str subst);
void repl_expr_free(struct subst_expr *se);
int translate(struct sip_msg *msg, str user_name, str* repl_user, dpl_id_p idp, str *);
int rule_translate(struct sip_msg *msg, str , dpl_node_t * rule,
	dpl_pv_node_t * rule_pv, dpl_pv_regex_node_p subst_node,
	str *match_expr, str *);
#endif
