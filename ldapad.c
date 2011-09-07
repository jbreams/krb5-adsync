/*
 Copyright 2011 The Trustees of Columbia University
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>
#include <krb5/kadm5_hook_plugin.h>
#include <errno.h>
#include "krb5sync.h"
#ifdef ENABLE_SASL_GSSAPI
#include <sasl/sasl.h>
#include <gssapi/gssapi_krb5.h>

static int
do_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *_interact)
{
	char *authzid = (char *) defaults;
	sasl_interact_t *interact = (sasl_interact_t *) _interact;
	
	while (interact->id != SASL_CB_LIST_END)
    {
		if (interact->id == SASL_CB_USER)
		{
			interact->result = "";
			interact->len = 0;
		}
		else
		{
			return LDAP_PARAM_ERROR;
		}
		interact++;
    }
	return LDAP_SUCCESS;
}
#endif

LDAP * get_ldap_conn(struct k5scfg * cx) {
	int rc, option = LDAP_VERSION3, i = 0;
	LDAP * ldConn;
#ifdef ENABLE_SASL_GSSAPI
	unsigned int gsserr;
	const char * oldccname;
#endif

	if(cx->ldConn)
			return cx->ldConn;

	cx->ldConn = NULL;
	rc = ldap_initialize(&ldConn, cx->ldapuri);
	if(rc != 0) {
		com_err("kadmind", rc, "Error initializing LDAP: %s",
			ldap_err2string(rc));
		return NULL;
	}
	
	rc = ldap_set_option(ldConn, LDAP_OPT_PROTOCOL_VERSION, &option);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting protocol version: %s",
			ldap_err2string(rc));
		return NULL;
	}
	
	ldap_set_option(ldConn, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	
#ifdef ENABLE_SASL_GSSAPI
	if(!cx->binddn) {
		rc = get_creds(cx);
		if(rc != 0) {
			com_err("kadmind", rc, "Error getting credentials for LDAP bind");
			return rc;
		}

		if(gss_krb5_ccache_name(&gsserr, CACHE_NAME, &oldccname) != GSS_S_COMPLETE) {
			com_err("kadmind", rc,  "Error setting credentials cache.");
			return NULL;
		}
	}
#endif

	do {
#ifdef ENABLE_SASL_GSSAPI
		if(cx->binddn)
#endif
			rc = ldap_simple_bind_s(ldConn, cx->binddn, cx->password);
#ifdef ENABLE_SASL_GSSAPI
		else
			rc = ldap_sasl_interactive_bind_s(ldConn, NULL, "GSSAPI",
				NULL, NULL, LDAP_SASL_QUIET, do_sasl_interact, NULL);
#endif
	} while(++i < cx->ldapretries && rc != 0);
	
#ifdef ENABLE_SASL_GSSAPI
	if(!cx->binddn)
		gss_krb5_ccache_name(&gsserr, oldccname, NULL);
#endif
	if(rc != 0) {
		com_err("kadmind", rc, "Error connecting to LDAP server: %s",
			ldap_err2string(rc));
		return NULL;
	}
	
	cx->ldConn = ldConn;
	return ldConn;
}

int check_update_okay(struct k5scfg * cx, char * principal, LDAP ** ldOut, char ** dnout) {
	char * tmp, *filter, * dn;
	int parts = 1, i = 0, rc, cp;
	LDAP * ldConn = get_ldap_conn(cx);
	LDAPMessage * msg = NULL;
	char * noattrs[2] = { "1.1", NULL };
	FILE * adobjects = NULL;
	struct dnokay * curdn;
			
	filter = malloc(sizeof("(userPrincipalName=)") + strlen(principal) + 1);
	sprintf(filter, "(userPrincipalName=%s)", principal);
	rc = ldap_search_ext_s(ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter,
		noattrs, 0, NULL, NULL, NULL, 0, &msg);

	if(rc == LDAP_SERVER_DOWN || rc == LDAP_TIMELIMIT_EXCEEDED) {
		ldOut = get_ldap_conn(cx);
		if(ldOut == NULL)
			return -1;
		rc = ldap_search_ext_s(ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter,
			noattrs, 0, NULL, NULL, NULL, 0, &msg);
	}
	free(filter);
	if(rc != 0) {
		if(ldOut)
			*ldOut = NULL;
		com_err("kadmind", rc, "Error searching for %s: %s",
			principal, ldap_err2string(rc));
		return rc;
	}
	
	if(ldap_count_entries(ldConn, msg) == 0)
		return 0;
	msg = ldap_first_entry(ldConn, msg);
	dn = ldap_get_dn(ldConn, msg);
	ldap_msgfree(msg);
	if(ldOut)
		*ldOut = ldConn;

	if(cx->updatefor == NULL && !cx->adobjects) {
		if(dnout)
			*dnout = dn;
		else
			ldap_memfree(dn);
		return 1;
	}
	else if(cx->updatefor && cx->dncount) {
		i = 0;
		curdn = &cx->updatefor[i];
	}
	else if(cx->adobjects) {
		adobjects = fopen(cx->adobjects, "r");
		if(adobjects == NULL) {
			rc = errno;
			com_err("kadmind", rc, "Error opening objects file: %s (%s)",
				strerror(rc), cx->adobjects);
			ldap_memfree(dn);
			return 0;
		}
		curdn = malloc(sizeof(struct dnokay));
		rc = get_next_dn(curdn, adobjects);
		if(rc != 0) {
			com_err("kadmind", rc, "Error reading DN from objects file: %s (%s)",
				strerror(rc), cx->adobjects);
			ldap_memfree(dn);
			return 0;
		}
	}
	
	rc = 0;
	tmp = dn;
	while (*tmp != 0) {
		if(*tmp == ',')
			parts++;
		else
			*tmp = tolower(*tmp);
		tmp++;
	}

	do {
		int c = parts;
		if(c < curdn->parts)
			goto next_obj;
		tmp = dn;
		while(c > curdn->parts) {
			while(*tmp != ',') 
				tmp++;
			tmp++;
			c--;
		}

		if(strcmp(tmp, curdn->dn) == 0) {
			rc = 1;
			break;
		}

next_obj:
		if(adobjects) {
			free(curdn->dn);
			c = get_next_dn(curdn, adobjects);
			if(c != 0) {
				com_err("kadmind", rc, "Error reading DN from objects file: %s (%s)",
					strerror(rc), cx->adobjects);
				ldap_memfree(dn);
				return 0;
			}
		}
		else
			curdn = &cx->updatefor[++i];
	} while(curdn->dn);
	
	if(dnout)
		*dnout = dn;
	else
		ldap_memfree(dn);
	if(adobjects) {
		fclose(adobjects);
		free(curdn);
	}

	return rc; 
}
