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
	if(cx->password) {
		memset(cx->password, 0, 128);
		free(cx->password);
	}
#ifdef ENABLE_SASL_GSSAPI
	if(cx->keytab)
		krb5_kt_close(kcx, cx->keytab);
#endif
	if(cx->updatefor) {
		int i;
		for(i = 0; cx->updatefor[i].dn; i++)
			free(cx->updatefor[i].dn);
		free(cx->updatefor);
	}
	if(cx->ldConn)
		ldap_unbind_s(cx->ldConn);
	if(cx)
		free(cx);
}

int get_next_dn(struct dnokay * out, FILE * in) {
	char * buffer = malloc(4096);
	size_t len, i = 0, valid = 0;
	if(!fgets(buffer, 4096, in)) {
		free(buffer);
		return errno;
	}
	if(feof(in)) {
		free(buffer);
		out->dn = NULL;
		return 0;
	}

	len = strlen(buffer);
	if(len < 3) { // Minimum length of a valid DN (o=o)
		free(buffer);
		return -EINVAL;
	}
	out->dn = buffer;
	out->parts = 1;
	do {
		if(out->dn[i] == '\n')
			out->dn[i] = 0;
		else if(out->dn[i] == ',')
			out->parts++;
		else if(out->dn[i] == '=')
			valid = 1;
		else
			out->dn[i] = tolower(out->dn[i]);
	} while(out->dn[++i] != 0);

	if(!valid) {
		free(out->dn);
		return -EINVAL;
	}
	
	return 0;
}

kadm5_ret_t handle_init(krb5_context kcx, kadm5_hook_modinfo ** modinfo) {
	struct k5scfg * cx = malloc(sizeof(struct k5scfg));
	char * path = NULL, *buffer, *ktpath;
	FILE * file = NULL;
	int rc, i, dncount = 0;
	
	if(cx == NULL)
		return -ENOMEM;
	
	memset(cx, 0, sizeof(struct k5scfg));

	*modinfo = (kadm5_hook_modinfo *)cx;
	config_string(kcx, "basedn", &cx->basedn);
	config_string(kcx, "ldapuri", &cx->ldapuri);
	config_string(kcx, "syncuser", &cx->ad_princ_unparsed);
	config_string(kcx, "password", &path);
	config_string(kcx, "binddn", &cx->binddn);
	config_string(kcx, "ldapconnectretries", &buffer);
#ifdef ENABLE_SASL_GSSAPI
	config_string(kcx, "keytab", &ktpath);
#endif
	if(!cx->basedn || !cx->ldapuri || !strlen(cx->ad_princ_unparsed)) {
		cleanup(kcx, *modinfo);
		com_err("kadmind", KADM5_MISSING_CONF_PARAMS, "Must specify both basedn and ldapuri.");
		return KADM5_MISSING_CONF_PARAMS;
	}
	
	rc = krb5_parse_name(kcx, cx->ad_princ_unparsed, &cx->ad_principal);
	if(rc != 0) {
		com_err("kadmind", rc, "Error parsing %s", cx->ad_princ_unparsed);
		cleanup(kcx, *modinfo);
		return rc;
	}
	
#ifdef ENABLE_SASL_GSSAPI
	if(ktpath) {
		rc = krb5_kt_resolve(kcx, ktpath, &cx->keytab);
		free(ktpath);
		if(rc != 0) {
			com_err("kadmind", rc, "Error opening keytab for AD user");
			cleanup(kcx, *modinfo);
			return rc;
		}
	} else if(path) {
#else
	if(path) {
#endif
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
			cleanup(kcx, *modinfo);
			com_err("kadmind", KADM5_MISSING_CONF_PARAMS, "Must specify a password to connect to AD");
			return KADM5_MISSING_CONF_PARAMS;
		}
	}
	else {
		com_err("kadmind", KADM5_MISSING_CONF_PARAMS, "Must specify either a password file or a keytab");
		cleanup(kcx, *modinfo);
		return KADM5_MISSING_CONF_PARAMS;
	}

	rc = get_creds(kcx, cx);
	if(rc != 0)
		return rc;
	
	if(buffer) {
		cx->ldapretries = atoi(buffer);
		free(buffer);
	} else
		cx->ldapretries = 3;

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
	buffer = malloc(4096);
	do {
		memset(buffer, 0, 4096);
		rc = fread(buffer, 4096, 1, file);
		for(i = 0; buffer[i] != 0; i++) {
			if(buffer[i] == '\n')
				dncount++;
		}
	} while(rc > 0);
	free(buffer);
	
	cx->updatefor = malloc(sizeof(struct dnokay) * (dncount + 1));
	rewind(file);
	i = 0;
	while((rc = get_next_dn(&cx->updatefor[i], file)) == 0 && cx->updatefor[i].dn)
		i++;
	fclose(file);

	if(rc != 0) {
		com_err("kadmind", rc, "Error reading DN objects file: %s",
			strerror(rc));
		cleanup(kcx, *modinfo);
		return KADM5_MISSING_CONF_PARAMS;
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
