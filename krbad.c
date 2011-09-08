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
#include "krb5sync.h"

krb5_principal get_ad_principal(krb5_context kcx, struct k5scfg * cx, krb5_principal pin) {
	krb5_principal pout;
	krb5_data *realm, oldrealm; 
	if(krb5_copy_principal(kcx, pin, &pout) != 0)
		return NULL;
	
	krb5_copy_data(kcx, krb5_princ_realm(kcx, cx->ad_principal), &realm);
	krb5_princ_set_realm(kcx, pout, realm);
	return pout;
}

int get_creds(krb5_context kcx, struct k5scfg * cx) {
	krb5_ccache id;
	krb5_creds creds;
	int rc;
	
	rc = krb5_cc_resolve(kcx, CACHE_NAME, &id);
	if(rc != 0) {
		krb5_set_error_message(kcx, rc, "Cannot resolve ccache.");
		return rc;
	}

	rc = krb5_get_renewed_creds(kcx, &creds, cx->ad_principal, id, NULL);
	if(rc != 0) {		
		rc = krb5_cc_initialize(kcx, id, cx->ad_principal);
		if(rc != 0) {
			krb5_set_error_message(kcx, rc, "Cannot initialize ccache for %s",
				cx->ad_princ_unparsed);
			krb5_cc_close(kcx, id);
			return rc;
		}
#ifdef ENABLE_SASL_GSSAPI	
		if(cx->keytab)
			rc = krb5_get_init_creds_keytab(kcx, &creds, cx->ad_principal,
				cx->keytab, 0, NULL, NULL);
		else
#endif
			rc = krb5_get_init_creds_password(kcx, &creds, cx->ad_principal,
				cx->password, NULL, NULL, 0, NULL, NULL);
		if(rc != 0) {
			krb5_set_error_message(kcx, rc, "Cannot get credentials for %s", 
				cx->ad_princ_unparsed);
			krb5_cc_close(kcx, id);
			return rc;
		}
	}
	
	rc = krb5_cc_store_cred(kcx, id, &creds);
	krb5_free_cred_contents(kcx, &creds);
	
	if(rc != 0) {
		krb5_set_error_message(kcx, rc, "Cannot store credentials for %s", 
			cx->ad_princ_unparsed);
		krb5_cc_close(kcx, id);
		return rc;
	}
	
	krb5_cc_close(kcx, id);
	return 0;
}

kadm5_ret_t handle_chpass(krb5_context kcx,
       kadm5_hook_modinfo *modinfo,
       int stage,
       krb5_principal princ, krb5_boolean keepold,
       int n_ks_tuple,
       krb5_key_salt_tuple *ks_tuple,
       const char *newpass)
{
	if(stage == KADM5_HOOK_STAGE_POSTCOMMIT)
		return 0;
	
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	krb5_principal targetPrincipal = get_ad_principal(kcx, cx, princ);
	krb5_creds creds;
	char * targetUnparsed = NULL;
	int rc, result_code;
	krb5_data result_code_string, result_string;
	
	memset(&result_code_string, 0, sizeof(krb5_data));
	memset(&result_string, 0, sizeof(krb5_data));
	
	krb5_unparse_name(kcx, targetPrincipal, &targetUnparsed);
	
	rc = check_update_okay(cx, targetUnparsed, NULL, NULL);
	if(rc != 1)
		goto finished;
#ifdef ENABLE_SASL_GSSAPI	
	if(cx->keytab)
		rc = krb5_get_init_creds_keytab(kcx, &creds, cx->ad_principal,
			cx->keytab, 0, "kadmin/changepw", NULL);
	else
#endif
		rc = krb5_get_init_creds_password(kcx, &creds, cx->ad_principal,
			cx->password, NULL, NULL, 0, "kadmin/changepw", NULL);
	if(rc != 0) {
		krb5_set_error_message(kcx, rc, "Error getting credentials for kadmin/changepw");
		krb5_free_principal(kcx, targetPrincipal);
		krb5_free_unparsed_name(kcx, targetUnparsed);
		return rc;
	}

	rc = krb5_set_password(kcx, &creds,
		(char*)newpass, targetPrincipal, &result_code, 
		&result_code_string, &result_string);
	krb5_free_cred_contents(kcx, &creds);
	if(rc != 0 || result_code != 0)
		krb5_set_error_message(kcx, rc, "Error setting password for %s: %s %s",
			targetUnparsed, result_code_string.data, result_string.data);
	
finished:
	krb5_free_principal(kcx, targetPrincipal);
	krb5_free_unparsed_name(kcx, targetUnparsed);
	if(result_string.data)
		free(result_string.data);
	if(result_code_string.data)
		free(result_code_string.data);
    return rc;
}
