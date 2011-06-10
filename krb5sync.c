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
	if(cx->password) {
		memset(cx->password, 0, 128);
		free(cx->password);
	}
	if(cx->kcx)
		krb5_free_context(cx->kcx);
	if(cx->updatefor) {
		int i;
		for(i = 0; i < cx->dncount; i++) {
			if(cx->updatefor[i].dn)
				free(cx->updatefor[i].dn);
		}
		free(cx->updatefor);
	}
	if(cx)
		free(cx);
}


kadm5_ret_t handle_init(krb5_context cxin, kadm5_hook_modinfo ** modinfo) {
	struct k5scfg * cx = malloc(sizeof(struct k5scfg));
	char * path = NULL, *buffer;
	FILE * file = NULL;
	int rc, i;
	
	if(cx == NULL)
		return -ENOMEM;
	
	krb5_init_context(&cx->kcx);
	*modinfo = (kadm5_hook_modinfo *)cx;
	config_string(cx->kcx, "basedn", &cx->basedn);
	config_string(cx->kcx, "ldapuri", &cx->ldapuri);
	config_string(cx->kcx, "syncuser", &cx->ad_princ_unparsed);
	config_string(cx->kcx, "password", &path);
	config_string(cx->kcx, "ldapconnectretries", &buffer);
	if(!cx->basedn || !cx->ldapuri || !strlen(cx->ad_princ_unparsed)) {
		cleanup(cxin, *modinfo);
		krb5_set_error_message(cxin, EINVAL, "Must specify both basedn and ldapuri.");
		return -EINVAL;
	}
	
	rc = krb5_parse_name(cx->kcx, cx->ad_princ_unparsed, &cx->ad_principal);
	if(rc != 0) {
		krb5_set_error_message(cxin, rc, "Error parsing %s", cx->ad_princ_unparsed);
		cleanup(cxin, *modinfo);
		return rc;
	}
	
	file = fopen(path, "r");
	free(path);
	path = NULL;
	cx->password = malloc(128);
	*cx->password = 0;
	fgets(cx->password, 128, file);
	fclose(file);
	rc = strlen(cx->password) - 1;
	if(cx->password[rc] == '\n')
		cx->password[rc] = 0;
	if(!cx->password || strlen(cx->password) == 0) {
		cleanup(cxin, *modinfo);
		krb5_set_error_message(cxin, EINVAL, "Must specify a password to connect to AD");
		return rc;
	}
	
	rc = get_creds(cx);
	if(rc != 0)
		return rc;
	
	if(buffer) {
		cx->ldapretries = atoi(buffer);
		free(buffer);
	} else
		cx->ldapretries = 3;
	
	config_string(cx->kcx, "adobjects", &path);
	cx->dncount = 0;
	if(!path) {
		cx->updatefor = NULL;
		return 0;
	}
	file = fopen(path, "r");
	free(path);
	if(file == NULL) {
		rc = errno;
		krb5_set_error_message(cxin, rc, "Cannot open AD objects file.");
		cleanup(cxin, *modinfo);
		return 0;
	}
	buffer = malloc(4096);
	do {
		memset(buffer, 0, 4096);
		rc = fread(buffer, 4096, 1, file);
		for(i = 0; buffer[i] != 0; i++) {
			if(buffer[i] == '\n')
				cx->dncount++;
		}
	} while(rc > 0);
	
	cx->updatefor = malloc(sizeof(struct dnokay) * cx->dncount);
	memset(cx->updatefor, 0, sizeof(struct dnokay) * cx->dncount);
	rewind(file);
	i = 0;
	while(fgets(buffer, 4096, file)) {
		size_t bufLen = strlen(buffer);
		int j;
		if(buffer[bufLen - 1] == '\n') {
			buffer[bufLen - 1] = 0;
			bufLen--;
		}
		cx->updatefor[i].dn = strdup(buffer);
		cx->updatefor[i].parts = 1;
		for(j = 0; j < bufLen; j++) {
			if(buffer[j] == ',')
				cx->updatefor[i].parts++;
		}
	}
	free(buffer);
	
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
