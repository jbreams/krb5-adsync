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

#ifdef ENABLE_MODIFY_HOOK

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <com_err.h>
#include <krb5/krb5.h>
#include <krb5/kadm5_hook_plugin.h>
#include "krb5sync.h"

kadm5_ret_t handle_modify(krb5_context kcx, kadm5_hook_modinfo * modinfo,
	int stage, kadm5_principal_ent_t pin, long mask) {

	if(stage == KADM5_HOOK_STAGE_POSTCOMMIT)
		return 0;
	
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	if(!(cx->syncdisable || cx->syncexpire))
		return 0;
	
	krb5_principal targetPrincipal = get_ad_principal(kcx, cx, pin->principal);
	char * targetUnparsed = NULL;
	char * dn = NULL;
	LDAP * ldConn = NULL;
	int rc;
	
	krb5_unparse_name(kcx, targetPrincipal, &targetUnparsed);
	rc = check_update_okay(cx, targetUnparsed, &ldConn, &dn);
	if(rc != 1)
		goto finished;
	
	if(mask & KADM5_ATTRIBUTES && cx->syncdisable) {
		if(pin->attributes & KRB5_KDB_DISALLOW_ALL_TIX)
			do_disable(ldConn, dn, 1);
		else
			do_disable(ldConn, dn, 0);
	}
	
	if(mask & KADM5_PRINC_EXPIRE_TIME && cx->syncexpire &&
	   pin->princ_expire_time > 0) {
		LDAPMod mod, *modarray[2];
		char modstring[15], *modstrs[2];
		uint64_t expireTime = pin->princ_expire_time;
		// Converts from UNIX timestamp to Windows Filetime
		expireTime += 11644473600;
		expireTime *= 10000000;
		
		mod.mod_op = LDAP_MOD_REPLACE;
		mod.mod_type = "accountExpires";
		sprintf(modstring, "%llu", expireTime);
		modstrs[0] = modstring;
		modstrs[1] = NULL;
		mod.mod_vals.modv_strvals = modstrs;
		modarray[0] = &mod;
		modarray[1] = NULL;
		
		rc = ldap_modify_ext_s(ldConn, dn, modarray, NULL, NULL);
		if(rc != 0)
			com_err("kadmind", rc, "Error setting expire time to %llu for %s: %s",
				expireTime, dn, ldap_err2string(rc));
	}
	
finished:
	if(dn)
		ldap_memfree(dn);
	krb5_free_principal(kcx, targetPrincipal);
	krb5_free_unparsed_name(kcx, targetUnparsed);
	return 0;
}

#endif
