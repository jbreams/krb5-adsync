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

#include <krb5/kadm5_hook_plugin.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <ldap.h>
#include "krb5sync.h"

void cleanup(krb5_context kcx, kadm5_hook_modinfo * modinfo);

void config_string(krb5_context kcx, const char *opt, char **result)
{
    const char *defval = "";
	
    krb5_appdefault_string(kcx, "krb5-sync", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}

void cleanup(krb5_context kcx, kadm5_hook_modinfo * modinfo) {
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	if(cx->basedn)
		free(cx->basedn);
	if(cx->ldapuri)
		free(cx->ldapuri);
	if(cx->ad_principal)
		krb5_free_principal(kcx, cx->ad_principal);
	if(cx->ad_princ_unparsed)
		free(cx->ad_princ_unparsed);
	if(cx->binddn)
		free(cx->binddn);
	if(*cx->password) {
		memset(cx->password, 0, 128);
	}
	if(cx->keytab)
		krb5_kt_close(kcx, cx->keytab);
	if(cx->updatefor) {
		struct dnokay * lock = cx->updatefor->next;
		do {
			free(cx->updatefor);
			cx->updatefor = lock;
			lock = cx->updatefor->next;
		} while(cx->updatefor);
	}
	if(cx->ldConn)
		ldap_unbind_s(cx->ldConn);
	if(cx)
		free(cx);
}

int get_next_dn(struct dnokay * out, FILE * in) {
	char *check;
	size_t len, i = 0, valid = 0;
	
	check = fgets(out->dn, sizeof(out->dn), in);
	if(check == NULL) {
		if(ferror(in)) {
			com_err("kadmind", 0, "Error reading from DN file. %m");
			return -1;
		}
		return 0;
	}

	if((len = strlen(out->dn)) < 4) // Shortest possible dn o=o\n
		return -2;
	if(out->dn[len - 1] != '\n')
		return -2;
	out->dn[len - 1] = 0;
	out->parts = 1;
	do {
		if(out->dn[i] == ',')
			out->parts++;
		else if(out->dn[i] == '=')
			valid = 1;
	} while(out->dn[++i] != 0);

	if(!valid)
		return -2;
	return 1;
}

kadm5_ret_t handle_init(krb5_context kcx, kadm5_hook_modinfo ** modinfo) {
	struct k5scfg * cx = malloc(sizeof(struct k5scfg));
	char * path = NULL, *buffer, *ktpath;
	FILE * file = NULL;
	int rc, i, dncount = 0;
	
	if(cx == NULL)
		return KADM5_FAILURE;
	
	memset(cx, 0, sizeof(struct k5scfg));

	*modinfo = (kadm5_hook_modinfo *)cx;
	config_string(kcx, "basedn", &cx->basedn);
	config_string(kcx, "ldapuri", &cx->ldapuri);
	config_string(kcx, "syncuser", &cx->ad_princ_unparsed);
	config_string(kcx, "password", &path);
	config_string(kcx, "binddn", &cx->binddn);
	config_string(kcx, "keytab", &ktpath);
	if(!cx->basedn || !cx->ldapuri || !strlen(cx->ad_princ_unparsed)) {
		cleanup(kcx, *modinfo);
		com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify both basedn and ldapuri.");
		return KADM5_MISSING_KRB5_CONF_PARAMS;
	}
	
	rc = krb5_parse_name(kcx, cx->ad_princ_unparsed, &cx->ad_principal);
	if(rc != 0) {
		com_err("kadmind", rc, "Error parsing %s", cx->ad_princ_unparsed);
		cleanup(kcx, *modinfo);
		return rc;
	}
	
	if(ktpath) {
		rc = krb5_kt_resolve(kcx, ktpath, &cx->keytab);
		free(ktpath);
		if(rc != 0) {
			com_err("kadmind", rc, "Error opening keytab for AD user");
			cleanup(kcx, *modinfo);
			return rc;
		}
	} else if(path) {
		file = fopen(path, "r");
		free(path);
		path = NULL;
		*cx->password = 0;
		fgets(cx->password, 128, file);
		fclose(file);
		rc = strlen(cx->password) - 1;
		if(cx->password[rc] == '\n') {
			cx->password[rc] = 0;
			rc--;
		}
		if(rc == 0) {
			cleanup(kcx, *modinfo);
			com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify a password to connect to AD");
			return KADM5_MISSING_KRB5_CONF_PARAMS;
		}
	}
	else {
		com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify either a password file or a keytab");
		cleanup(kcx, *modinfo);
		return KADM5_MISSING_KRB5_CONF_PARAMS;
	}

	rc = get_creds(kcx, cx);
	if(rc != 0)
		return rc;

	config_string(kcx, "ldapconnectretries", &buffer);
	if(buffer) {
		cx->ldapretries = atoi(buffer);
		free(buffer);
	} else
		cx->ldapretries = 3;

	config_string(kcx, "ldaptimeout", &buffer);
	if(buffer) {
		cx->ldtimeout.tv_sec = atoi(buffer);
		free(buffer);
	} else
		cx->ldtimeout.tv_sec = -1;

	rc = get_ldap_conn(cx);
	if(rc != 0) {
		com_err("kadmind", rc, "Failed to initialize LDAP connection to active directory. Cannot continue.");
		cleanup(kcx, *modinfo);
		return KADM5_NO_SRV;
	}

#ifdef ENABLE_DELETE_HOOK	
	config_string(kcx, "ondelete", &buffer);
	if(buffer) {
		if(strcmp(buffer, "delete") == 0)
			cx->ondelete = 1;
		else if(strcmp(buffer, "disable") == 0)
			cx->ondelete = 2;
		else
			cx->ondelete = 0;
		free(buffer);
	}
#endif
#ifdef ENABLE_MODIFY_HOOK	
	krb5_appdefault_boolean(kcx, "krb5-sync", NULL, "syncdisable", 0, &cx->syncdisable);
	krb5_appdefault_boolean(kcx, "krb5-sync", NULL, "syncexpire", 0, &cx->syncexpire);
#endif
	krb5_appdefault_boolean(kcx, "krb5-sync", NULL, "failopen", 0, &cx->failopen);
	krb5_appdefault_boolean(kcx, "krb5-sync", NULL, "liveadobjects", 0, &rc);
	
	config_string(kcx, "adobjects", &path);
	if(!path) {
		cx->updatefor = NULL;
		return 0;
	}
	if(rc) {
		cx->updatefor = NULL;
		cx->adobjects = path;
		return 0;
	}

	file = fopen(path, "r");
	free(path);
	if(file == NULL) {
		rc = errno;
		krb5_set_error_message(kcx, rc, "Cannot open AD objects file.");
		cleanup(kcx, *modinfo);
		return 0;
	}

	do {
		struct dnokay * curdn = malloc(sizeof(struct dnokay));
		if(!curdn) {
			com_err("kadmind", KADM5_FAILURE, "Unable to allocate memory for DN structure.");
			cleanup(kcx, *modinfo);
			return KADM5_FAILURE;
		}

		rc = get_next_dn(curdn, file);
		if(rc == 1) {
			curdn->next = cx->updatefor;
			cx->updatefor = curdn;
		}
		else {
			if(rc == -2)
				com_err("kadmind", KADM5_FAILURE, "DN from file is invalid: %s", curdn->dn);
			free(curdn);
		}
	} while(rc == 1);
	fclose(file);

	if(rc != 0) {
		cleanup(kcx, *modinfo);
		return KADM5_MISSING_KRB5_CONF_PARAMS;
	}
	return 0;
}

krb5_error_code kadm5_hook_krb5sync_initvt(krb5_context kcx, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{
    kadm5_hook_vftable_1 *vt = (kadm5_hook_vftable_1 *) vtable;
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
	
    vt->name = "krb5sync";
    vt->chpass = handle_chpass;
#ifdef ENABLE_MODIFY_HOOK
    vt->modify = handle_modify;
#endif
#ifdef ENABLE_DELETE_HOOK
	vt->remove = handle_remove;
#endif
	vt->init = handle_init;
	vt->fini = cleanup;
    return 0;
}
