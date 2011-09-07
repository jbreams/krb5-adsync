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
#include <sasl/sasl.h>
#include <gssapi/gssapi_krb5.h>
#include "krb5sync.h"

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

int check_update_okay(struct k5scfg * cx, char * principal, LDAP ** ldOut, char ** dnout) {
	char * tmp, *filter, * dn, *dntocheck = NULL;
#ifdef ENABLE_SASL_GSSAPI
	unsigned int gsserr;
	const char * oldccname;
#endif
	int parts = 1, i = 0, rc, option = LDAP_VERSION3;
	LDAP * ldConn = NULL;
	LDAPMessage * msg = NULL;
	char * noattrs[2] = { "1.1", NULL };
	FILE * adobjects = NULL;
		
#ifdef ENABLE_SASL_GSSAPI
	if(!cx->binddn) {
		rc = get_creds(cx);
		if(rc != 0) {
			com_err("kadmind", rc, "Error getting credentials for LDAP bind");
			return rc;
		}
	}
#endif
	
	rc = ldap_initialize(&ldConn, cx->ldapuri);
	if(rc != 0) {
		com_err("kadmind", rc, "Error initializing LDAP: %s",
			ldap_err2string(rc));
		return rc;
	}
	
	rc = ldap_set_option(ldConn, LDAP_OPT_PROTOCOL_VERSION, &option);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting protocol version: %s",
			ldap_err2string(rc));
		return rc;
	}
	
	ldap_set_option(ldConn, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	
#ifdef ENABLE_SASL_GSSAPI
	if(!cx->binddn) {
		if(gss_krb5_ccache_name(&gsserr, CACHE_NAME, &oldccname) != GSS_S_COMPLETE) {
			com_err("kadmind", rc,  "Error setting credentials cache.");
			return rc;
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
		return rc;
	}
	
	filter = malloc(sizeof("(userPrincipalName=)") + strlen(principal) + 1);
	sprintf(filter, "(userPrincipalName=%s)", principal);
	
	rc = ldap_search_ext_s(ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter,
		noattrs, 0, NULL, NULL, NULL, 0, &msg);
	if(rc != 0) {
		ldap_unbind_ext_s(ldConn, NULL, NULL);
		if(ldOut)
			*ldOut = NULL;
		com_err("kadmind", rc, "Error searching for %s: %s",
			principal, ldap_err2string(rc));
		return rc;
	}
	
	free(filter);
	if(ldap_count_entries(ldConn, msg) == 0)
		return 0;
	msg = ldap_first_entry(ldConn, msg);
	dn = ldap_get_dn(ldConn, msg);
	ldap_msgfree(msg);
	if(ldOut)
		*ldOut = ldConn;
	else
		ldap_unbind_ext_s(ldConn, NULL, NULL);
	
	if(cx->updatefor == NULL && !cx->adobjects) {
		if(dnout)
			*dnout = dn;
		else
			ldap_memfree(dn);
		return 1;
	}
	else if(cx->updatefor && cx->dncount) {
		i = 0;
		dntocheck = cx->updatefor[i].dn;
	}
	else if(cx->adobjects) {
		adobjects = fopen(cx->adobjects, "r");
		if(adobjects == NULL) {
			rc = ernno;
			com_err("kadmind", rc, "Error opening objects file: %s (%s)",
				strerror(rc), cx->adobjects);
			ldap_memfree(dn);
			return 0;
		}
		dntocheck = malloc(4096);
		dntocheck = fgets(dntocheck, 4096, adobjects);
	}
	
	rc = 0;
	tmp = dn;
	while (*tmp != 0) {
		if(*tmp == ',')
			parts++;
		tmp++;
	}

	do {
		int cp, c;
		if(adobjects) {
			char * tmp2 = dntocheck;
			while(*tmp2 != 0) {
				if(*tmp2 == ',')
					cp++;
				tmp2++;
			}
		} else
			cp = cx->updatefor[i].parts;

		if(c < cp)
			continue;
		tmp = dn;
		while(c > cp) {
			while(*tmp != ',') tmp++;
			tmp++;
			c--;
		}

		if(strcmp(tmp, dntocheck) == 0) {
			rc = 1;
			break;
		}

		if(adobjects)
			dntocheck = fgets(dntocheck, 4096, adobjects);
		else {
			if(++i > cx->dncount)
				dntocheck = NULL;
			else
				dntocheck = cx->updatefor[i].dn;
		}
	} while(dntocheck);
	
	if(dnout)
		*dnout = dn;
	else
		ldap_memfree(dn);
	if(adobjects) {
		fclose(adobjects);
		free(dntocheck);
	}

	return rc; 
}
