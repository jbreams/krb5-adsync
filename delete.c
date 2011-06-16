#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <com_err.h>
#include <krb5/krb5.h>
#include <krb5/kadm5_hook_plugin.h>
#include "krb5sync.h"

/* The flag value used in Active Directory to indicate a disabled account. */
#define UF_ACCOUNTDISABLE 0x02

kadm5_ret_t handle_remove(krb5_context lkcx, kadm5_hook_modinfo * modinfo,
						  int stage, krb5_principal lprinc) {
	if(stage == KADM5_HOOK_STAGE_PRECOMMIT)
		return 0;
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	if(cx->ondelete == 0)
		return 0;
	
	krb5_principal targetPrincipal = get_ad_principal(cx, lprinc);
	char * targetUnparsed = NULL;
	char * dn = NULL;
	LDAP * ldConn;
	int rc;
	
	krb5_unparse_name(cx->kcx, targetPrincipal, &targetUnparsed);
	rc = check_update_okay(cx->kcx, lkcx, targetUnparsed, &ldConn, &dn);
	if(rc != 1)
		goto finished;
	
	if(cx->ondelete == 1) {
		rc = ldap_delete_s(ldConn, dn);
		if(rc != 0)
			com_err("kadmind", rc, "Error deleting %s: %s",
					targetUnparsed, ldap_err2string(rc));
	}
	else
		do_disable(ldConn, dn, 1);
	
finished:
	ldap_memfree(dn);
	ldap_unbind_ext_s(ldConn, NULL, NULL);
	krb5_free_principal(cx->kcx, targetPrincipal);
	krb5_free_unparsed_name(cx->kcx, targetUnparsed);
	return 0;
}

void do_disable(LDAP * ldConn, char * dn, int disable) {
	LDAPMessage * res = NULL;
	LDAPMod mod, *modarray[2];
	const char *attrs[] = { "userAccountControl", NULL };
	char modstring[15], *modstrs[2];
	struct berval ** vals = NULL;
	unsigned int acctcontrol, newacctcontrol;
	int rc;
	
	rc = ldap_search_ext_s(ldConn, dn, LDAP_SCOPE_BASE, "(objectClass=*)",
						   (char**)attrs, 0, NULL, NULL, NULL, 0, &res);
	
	if(rc != 0) {
		com_err("kadmind", rc, "Error getting userAccountControl for %s: %s",
				dn, ldap_err2string(rc));
		return;
	}
	
	res = ldap_first_entry(ldConn, res);
	vals = ldap_get_values_len(ldConn, res, "userAccountControl");
	ldap_msgfree(res);
	if(ldap_count_values_len(vals) != 1) {
		com_err("kadmind", rc, "userAccountControl not returned from AD.");
		ldap_value_free_len(vals);
		return;
	}
	
	acctcontrol = strtoul(vals[0]->bv_val, NULL, 10);
	ldap_value_free_len(vals);
	
	newacctcontrol = acctcontrol;
	if(disable)
		newacctcontrol |= UF_ACCOUNTDISABLE;
	else
		newacctcontrol &= ~UF_ACCOUNTDISABLE;
		
	if(newacctcontrol == acctcontrol)
		return;

	memset(&mod, 0, sizeof(mod));
	mod.mod_op = LDAP_MOD_REPLACE;
	mod.mod_type = "userAccountControl";
	snprintf(modstring, 15, "%u", newacctcontrol);
	modstrs[0] = modstring;
	modstrs[1] = NULL;
	mod.mod_vals.modv_strvals = modstrs;
	modarray[0] = &mod;
	modarray[1] = NULL;
	
	rc = ldap_modify_ext_s(ldConn, dn, modarray, NULL, NULL);
	if(rc != 0) {
		com_err("kadmind", rc, "Error modifying %s with new UAC %x: %s",
				dn, newacctcontrol, ldap_err2string(rc));
	}
}