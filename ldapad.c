/*
 Copyright 2011 The Trustees of Columbia University in the City of New York
 
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

int get_ldap_conn(struct k5scfg * cx) {
	int rc, i = 0, option = LDAP_VERSION3;
#ifdef ENABLE_SASL_GSSAPI
	unsigned int gsserr;
	const char * oldccname;
#endif

	if(cx->ldConn)
		ldap_unbind_s(cx->ldConn);
	rc = ldap_initialize(&cx->ldConn, cx->ldapuri);
	if(rc != 0) {
		com_err("kadmind", rc, "Error initializing LDAP: %s",
				ldap_err2string(rc));
		return rc;
	}

	rc = ldap_set_option(cx->ldConn, LDAP_OPT_PROTOCOL_VERSION, &option);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting protocol version: %s",
				ldap_err2string(rc));
		return rc;
	}
	ldap_set_option(cx->ldConn, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_set_option(cx->ldConn, LDAP_OPT_TIMEOUT, &cx->ldtimeout);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting timeout to %d seconds: %s",
				cx->ldtimeout.tv_sec, ldap_err2string(rc));
		return rc;
	}
	
#ifdef ENABLE_SASL_GSSAPI
	if(!cx->binddn) {
		rc = get_creds(cx);
		if(rc != 0) {
			com_err("kadmind", rc, "Error getting credentials for LDAP bind");
			return rc;
		}

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
			rc = ldap_simple_bind_s(cx->ldConn, cx->binddn, cx->password);
#ifdef ENABLE_SASL_GSSAPI
		else
			rc = ldap_sasl_interactive_bind_s(cx->ldConn, NULL, "GSSAPI",
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

	return 0;
}

int check_update_okay(struct k5scfg * cx, char * principal, char ** dnout) {
	char * tmp, *filter, * dn;
	int parts = 1, i = 0, rc, cp;
	LDAPMessage * msg = NULL;
	char * noattrs[2] = { "1.1", NULL };
	FILE * adobjects = NULL;
	struct dnokay * curdn;

	filter = malloc(sizeof("(userPrincipalName=)") + strlen(principal) + 1);
	sprintf(filter, "(userPrincipalName=%s)", principal);
	rc = ldap_search_ext_s(cx->ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter,
		noattrs, 0, NULL, NULL, NULL, 0, &msg);

	if(rc == LDAP_SERVER_DOWN || rc == LDAP_TIMELIMIT_EXCEEDED) {
		com_err("kadmind", rc, "LDAP connection has died (%s), attempting to "
			"reconnect to active directory", ldap_err2string(rc));
		rc = get_ldap_conn(cx);
		if(rc != 0) {
			free(filter);
			return rc;
		}
		rc = ldap_search_ext_s(cx->ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter,
			noattrs, 0, NULL, NULL, NULL, 0, &msg);
	}
	free(filter);
	if(rc != 0) {
		com_err("kadmind", rc, "Error searching for %s: %s",
			principal, ldap_err2string(rc));
		return rc;
	}
	
	if(ldap_count_entries(cx->ldConn, msg) == 0)
		return 0;
	msg = ldap_first_entry(cx->ldConn, msg);
	dn = ldap_get_dn(cx->ldConn, msg);
	ldap_msgfree(msg);

	if(cx->updatefor == NULL && !cx->adobjects) {
		if(dnout)
			*dnout = dn;
		else
			ldap_memfree(dn);
		return 1;
	}
	else if(cx->updatefor) {
		curdn = cx->updatefor;
	}
	else if(cx->adobjects) {
		adobjects = fopen(cx->adobjects, "r");
		if(adobjects == NULL) {
			com_err("kadmind", KADM5_FAILURE, "Error opening objects file: %m (%s)", cx->adobjects);
			ldap_memfree(dn);
			return 0;
		}
		curdn = malloc(sizeof(struct dnokay));
		rc = get_next_dn(curdn, adobjects);
		if(rc < 0) {
			com_err("kadmind", KADM5_FAILURE, "Error reading DN from objects file: %m (%s)",
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

		if(strcasecmp(tmp, curdn->dn) == 0) {
			rc = 1;
			break;
		}

next_obj:
		if(adobjects) {
			c = get_next_dn(curdn, adobjects);
			if(c < 1) {
				if(c == -2)
					com_err("kadmind", KADM5_FAILURE, "DN read from file is invalid: %s",
						curdn->dn);
				break;
			}
		}
		else
			curdn = curdn->next;
	} while(curdn);
	
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
