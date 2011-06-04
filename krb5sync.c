#include <krb5/kadm5_hook_plugin.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <ldap.h>
#include "krb5sync.h"

void cleanup(krb5_context cxin, kadm5_hook_modinfo * modinfo);

static void
config_string(krb5_context ctx, const char *opt, char **result)
{
    const char *defval = "";
	
    krb5_appdefault_string(ctx, "krb5-sync", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}

void cleanup(krb5_context cxin, kadm5_hook_modinfo * modinfo) {
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	if(cx->basedn)
		free(cx->basedn);
	if(cx->ldapuri)
		free(cx->ldapuri);
	if(cx->ad_principal)
		krb5_free_principal(cx->kcx, cx->ad_principal);
	if(cx->ad_princ_unparsed)
		free(cx->ad_princ_unparsed);
	if(cx->kcx)
		krb5_free_context(cx->kcx);
	if(cx->ldapuserpassword) {
		memset(cx->ldapuserpassword, 0, 128);
		free(cx->ldapuserpassword);
	}
	if(cx)
		free(cx);
}


kadm5_ret_t handle_init(krb5_context cxin, kadm5_hook_modinfo ** modinfo) {
	struct k5scfg * cx = malloc(sizeof(struct k5scfg));
	char * passwdpath = NULL;
	FILE * passwdfile = NULL;
	int rc;
	
	if(cx == NULL)
		return -ENOMEM;
	
	cx->kcx = cxin;
	*modinfo = (kadm5_hook_modinfo *)cx;
	config_string(cx->kcx, "basedn", &cx->basedn);
	config_string(cx->kcx, "ldapuri", &cx->ldapuri);
	config_string(cx->kcx, "syncuser", &cx->ad_princ_unparsed);
	config_string(cx->kcx, "password", &passwdpath);
	if(!cx->basedn || !cx->ldapuri || !strlen(cx->ad_princ_unparsed)) {
		cleanup(cxin, *modinfo);
		krb5_set_error_message(cxin, EINVAL, "Must specify both basedn and ldapuri.");
		return -1;
	}
	
	rc = krb5_parse_name(cx->kcx, username, &cx->ad_principal);
	if(rc != KRB5_SUCCESS) {
		krb5_set_error_message(cxin, rc, "Error parsing %s", cx->ad_princ_unparsed);
		cleanup(cxin, *modinfo);
		return -1;
	}
	
	passwdfile = fopen(passwdpath, "r");
	cx->password = malloc(128);
	*cx->password = 0;
	fgets(cx->password, 128, passwdfile);
	fclose(passwdfile);
	if(!cx->password || strlen(cx->password) == 0) {
		cleanup(cxin, *modinfo);
		krb5_set_error_message(cxin, EINVAL, "Must specify a password to connect to AD");
		return -1;
	}
	rc = get_creds(cx);
	if(rc != 0)
		return -1;
	
	return 0;
}

krb5_error_code kadm5_hook_krb5sync_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{
    kadm5_hook_vftable_1 *vt = (kadm5_hook_vftable_1 *) vtable;
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
	
    vt->name = "krb5sync";
    vt->chpass = handle_chpass;
//    vt->modify = handle_modify;
	vt->init = handle_init;
	vt->fini = cleanup;
    return 0;
}
