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

LDAP * get_ldap_conn(struct k5scfg * cx) {
	LDAP * ldConn;
	unsigned int gsserr;
	int rc, option = LDAP_VERSION3;
	const char * oldccname = NULL;
	
	rc = ldap_initialize(&ldConn, cx->ldapuri);
	if(rc != 0) {
		krb5_set_error_message(cx->kcx, rc, "Error initializing LDAP: %s",
							   ldap_err2string(rc));
		return NULL;
	}
	
	rc = ldap_set_option(ldConn, LDAP_OPT_PROTOCOL_VERSION, &option);
	if(rc != 0) {
		krb5_set_error_message(cx->kcx, rc, "Error setting protocol version: %s",
							   ldap_err2string(rc));
		return NULL;
	}
	
	ldap_set_option(ldConn, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	
	if(gss_krb5_ccache_name(&gsserr, CACHE_NAME, &oldccname) != GSS_S_COMPLETE) {
		krb5_set_error_message(cx->kcx, rc, "Error setting credentials cache.");
		return NULL;
	}
	
	rc = ldap_sasl_interactive_bind_s(ldConn, NULL, "GSSAPI",
					  NULL, NULL, LDAP_SASL_QUIET,
					  do_sasl_interact, NULL);
	gss_krb5_ccache_name(&gsserr, oldccname, NULL);
	if(rc != LDAP_SUCCESS)
		return NULL;
	return ldConn;
}

int check_update_okay(struct k5scfg * cx, char * principal, LDAP ** ldOut) {
	char * tmp, *filter, * dn;
	struct dnokay * x;
	int parts = 1, i, rc;
	LDAP * ldConn = NULL;
	LDAPMessage * msg = NULL;
	char * noattrs[2] = { "1.1", NULL };
	
	ldConn = get_ldap_conn(cx);
	if(ldConn == NULL)
		return -1;
	
	filter = malloc(sizeof("(userPrincipalName=)") + strlen(principal) + 1);
	sprintf(filter, "(userPrincipalName=%s)", principal);
	
	rc = ldap_search_ext_s(ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter,
			   noattrs, 0, NULL, NULL, NULL, 0, &msg);
	if(rc != 0) {
		ldap_unbind_ext_s(ldConn, NULL, NULL);
		if(ldOut)
			*ldOut = NULL;
		krb5_set_error_message(cx->kcx, rc, "Error searching for %s: %s",
							   principal, ldap_err2string(rc));
		return -1;
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
	tmp = dn;
	
	if(cx->updatefor == NULL)
		return 1;
	
	while (*tmp != 0) {
		if(*tmp == ',')
			parts++;
		tmp++;
	}
	
	for(i = 0; cx->updatefor[i] != NULL; i++) {
		int c = parts;
		x = cx->updatefor[i];
		tmp = dn;
		if(c < x->parts)
			continue;
		while(c > parts) {
			while(*tmp != ',') tmp++;
			tmp++;
			c--;
		}
		
		if(strcmp(tmp, x->dn) == 0) {
			ldap_memfree(dn);
			return 1;
		}
	}
	ldap_memfree(dn);
	return 0;
}
