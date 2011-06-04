#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>
#include <krb5/kadm5_hook_plugin.h>
#include <sasl/sasl.h>
#include "krb5sync.h"

#define UF_ACCOUNTDISABLE 0x02

static int
do_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *_interact)
{
	char *authzid = (char *) defaults;
	sasl_interact_t *interact = (sasl_interact_t *) _interact;
	
	while (interact->id != SASL_CB_LIST_END)
    {
		if (interact->id == SASL_CB_USER)
		{
			if (authzid != NULL)
			{
				interact->result = authzid;
				interact->len = strlen (authzid);
			}
			else if (interact->defresult != NULL)
			{
				interact->result = interact->defresult;
				interact->len = strlen (interact->defresult);
			}
			else
			{
				interact->result = "";
				interact->len = 0;
			}
		}
		else
		{
			return LDAP_PARAM_ERROR;
		}
		interact++;
    }
	return LDAP_SUCCESS;
}

int check_update_okay(struct k5scfg * cx, char * dn) {
	char * tmp = dn;
	struct dnokay * x;
	int parts = 1, i;
	
	if(cx->updatefor == NULL)
		return 0;
	
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
		
		if(strcmp(tmp, x->dn) == 0)
			return 1;
	}
	return 0;
}

LDAP * get_ldap_conn(struct k5scfg * cx) {
	LDAP * ldConn;
	int rc, option = LDAP_VERSION3, gsserr;
	const char * oldccname = NULL;
	
	if(get_creds(cx) != 0)
		return NULL;
	
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
	
	if(gss_krb5_ccache_name(&gsserr, CACHE_NAME, &oldccname) != GSS_S_COMPLETE) {
		krb5_set_error_message(cx->kcx, rc, "Error setting credentials cache.");
		return NULL;
	}
	
	rc = ldap_sasl_interactive_bind_s(ldConn, cx->ldapuserdn, "GSSAPI",
									  NULL, NULL, LDAP_SASL_QUIET,
									  do_sasl_interact, (void*)cx->ldapuserpassword);
	gss_krb5_ccache_name(&gsserr, oldccname, NULL);
	if(rc != LDAP_SUCCESS)
		return NULL;
	return ldConn;
}

int get_ad_ldap_obj(struct k5scfg * cx, char * upn, struct ldcx * ldapout) {
	LDAP * ldConn;
	LDAPMessage * res;

	BerValue **uacValues;
	char * filter, *attrs[] = { "userAccountControl", NULL };
	char * dn = NULL;
	int rc;
	
	ldConn = get_ldap_conn(cx);
	if(ldConn == NULL)
		return -1;
	
	filter = malloc(sizeof("(userPrincipalName=)") + strlen(upn) + 1);
	sprintf(filter, "(userPrincipalName=%s)", upn);
	
	
	rc = ldap_search_ext_s(ldConn, cx->basedn, LDAP_SCOPE_SUBTREE,
						   filter, NULL, 0, NULL, NULL, NULL, 0, &res);
	
	if(rc != LDAP_SUCCESS) {
		com_err("kadmind", rc, "Error searching for user %s: %s",
				upn, ldap_err2string(rc));
		goto done;
	}
	
	res = ldap_first_entry(ldConn, res);
	dn = ldap_get_dn(ldConn, res);
	
	if(!check_update_okay(cx, dn)) {
		rc = -2;
		com_err("kadmind", rc, "Password sync for %s excluded by rules", upn);
		goto done;
	}
	
	if(ldapout == NULL) {
		rc = 0;
		goto done;
	}
	
	uacValues = ldap_get_values_len(ldConn, res, "userAccountControl");
	if(uacValues != NULL) {
		struct berval * uacValue = uacValues[0];
		ldapout->userAccountControl = strtoul(uacValue->bv_val, NULL, 10);
		ldap_value_free_len(uacValues);
	}
	
done:
	if(ldapout == NULL || rc < 0) {
		if(dn)
			ldap_memfree(dn);
		if(ldConn)
			ldap_unbind_ext_s(ldConn, NULL, NULL);
	}
	else {
		ldapout->dn = dn;
		ldapout->ldConn = ldConn;
	}
	ldap_msgfree(res);
	return rc;
}



kadm5_ret_t handle_modify(krb5_context kx, kadm5_hook_modinfo * modinfo,
						  int stage, kadm5_principal_ent_t pin, long mask) {
	LDAPMod * mods[3], disallow, expireTimeMod;
	int counter = 0;
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	krb5_principal targetPrincipal = get_ad_principal(cx, pin->principal);
	char * targetUnparsed = NULL, uacValue[32], expireValue[32];
	char * svals_uac[2] = {uacValue, NULL}, *svals_exp[2] = { expireValue, NULL };
	struct ldcx ld;

	if(targetPrincipal) {
		krb5_unparse_name(cx->kcx, targetPrincipal, &targetUnparsed);
		krb5_free_principal(cx->kcx, targetPrincipal);
	}
	if(!targetUnparsed)
		return 0;
	
	if(get_creds(cx) != 0)
		return -1;
	
	if(get_ad_ldap_obj(cx, targetUnparsed, &ld) != 0) {
		krb5_free_unparsed_name(cx->kcx, targetUnparsed);
		return 0;
	}

	if(mask & KADM5_ATTRIBUTES && 
	   pin->attributes & KRB5_KDB_DISALLOW_ALL_TIX &&
	   ld.userAccountControl & ~UF_ACCOUNTDISABLE) {
		disallow.mod_op = LDAP_MOD_REPLACE;
		disallow.mod_type = "userAccountControl";
		sprintf(uacValue, "%lu", ld.userAccountControl | UF_ACCOUNTDISABLE);
		disallow.mod_values = svals_uac;
		mods[counter++] = &disallow;
	} else if(mask & KADM5_ATTRIBUTES && 
			  !(pin->attributes & KRB5_KDB_DISALLOW_ALL_TIX) &&
			  ld.userAccountControl & UF_ACCOUNTDISABLE) {
		LDAPMod disallow;
		disallow.mod_op = LDAP_MOD_REPLACE;
		disallow.mod_type = "userAccountControl";
		sprintf(uacValue, "%lu", ld.userAccountControl & ~UF_ACCOUNTDISABLE);
		disallow.mod_values = svals_uac;
		mods[counter++] = &disallow;
	}
	
	if(mask & KADM5_PRINC_EXPIRE_TIME) {
		uint64_t expireTime = pin->princ_expire_time;
		expireTime += 11644473600;
		expireTime *= 10000000;
		
		sprintf(expireValue, "%llu", expireTime);
		expireTimeMod.mod_op = LDAP_MOD_REPLACE;
		expireTimeMod.mod_type = "accountExpires";
		expireTimeMod.mod_values = svals_exp;
		mods[counter++] = &expireTimeMod;
	}
	mods[counter] = NULL;
	
	if(counter > 0)
		ldap_modify_ext_s(ld.ldConn, ld.dn, mods, NULL, NULL);

	ldap_memfree(ld.dn);
	ldap_unbind_ext_s(ld.ldConn, NULL, NULL);
	krb5_free_unparsed_name(cx->kcx, targetUnparsed);

	return 0;
}
