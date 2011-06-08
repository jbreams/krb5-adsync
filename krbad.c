#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>
#include <krb5/kadm5_hook_plugin.h>
#include "krb5sync.h"

krb5_principal get_ad_principal(struct k5scfg * cx, krb5_principal pin) {
	krb5_principal pout;
	krb5_data *realm, oldrealm; 
	if(krb5_copy_principal(cx->kcx, pin, &pout) != 0)
		return NULL;
	
	krb5_copy_data(cx->kcx, krb5_princ_realm(cx->kcx, cx->ad_principal), &realm);
	krb5_princ_set_realm(cx->kcx, pout, realm);
	return pout;
}

int get_creds(struct k5scfg * cx) {
	krb5_ccache id;
	krb5_creds creds;
	int rc;
	
	rc = krb5_cc_resolve(cx->kcx, CACHE_NAME, &id);
	if(rc != 0) {
		krb5_set_error_message(cx->kcx, rc, "Cannot resolve ccache.");
		return rc;
	}
	
	rc = krb5_get_renewed_creds(cx->kcx, &creds, cx->ad_principal, id, NULL);
	if(rc != 0) {
		rc = krb5_cc_initialize(cx->kcx, id, cx->ad_principal);
		if(rc != 0) {
			krb5_set_error_message(cx->kcx, rc, "Cannot initialize ccache for %s",
								   cx->ad_princ_unparsed);
			krb5_cc_close(cx->kcx, id);
			return rc;
		}
		rc = krb5_get_init_creds_password(cx->kcx, &creds, cx->ad_principal,
						  cx->password, NULL, NULL,
						  0, NULL, NULL);
	}
	
	if(rc != 0) {
		krb5_set_error_message(cx->kcx, rc, "Cannot get credentials for %s", 
							   cx->ad_princ_unparsed);
		krb5_cc_close(cx->kcx, id);
		return rc;
	}
	
	rc = krb5_cc_store_cred(cx->kcx, id, &creds);
	
	krb5_free_cred_contents(cx->kcx, &creds);
	krb5_cc_close(cx->kcx, id);
	
	if(rc != 0) {
		krb5_set_error_message(cx->kcx, rc, "Error storing credentials for %s", 
							   cx->ad_princ_unparsed);
		return rc;
	}
	
	return 0;
}

kadm5_ret_t handle_chpass(krb5_context context,
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
	krb5_principal targetPrincipal = get_ad_principal(cx, princ);
	krb5_ccache id;
	char * targetUnparsed = NULL;
	int rc, result_code;
	krb5_data result_code_string, result_string;
	
	if(get_creds(cx) != 0)
		return KRB5_NOCREDS_SUPPLIED;
	
	krb5_unparse_name(cx->kcx, targetPrincipal, &targetUnparsed);
	
	if(check_update_okay(cx, targetUnparsed, NULL) != 1) {
		krb5_free_principal(cx->kcx, targetPrincipal);
		krb5_free_unparsed_name(cx->kcx, targetUnparsed);
		return 0;
	}
	
	krb5_cc_resolve(cx->kcx, CACHE_NAME, &id);
	rc = krb5_set_password_using_ccache(cx->kcx, id,
		(char*)newpass, targetPrincipal, &result_code, 
		&result_code_string, &result_string);
	krb5_cc_close(cx->kcx, id);
	if(rc != 0)
		krb5_set_error_message(context, rc, "Error setting password for %s: %s %s",
				targetUnparsed, result_code_string.data, result_string.data);
	
	krb5_free_principal(cx->kcx, targetPrincipal);
	krb5_free_unparsed_name(cx->kcx, targetUnparsed);
	free(result_string.data);
	free(result_code_string.data);
    return rc;
}
