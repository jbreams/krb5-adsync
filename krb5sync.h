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

#include "config.h"
#define CACHE_NAME "MEMORY:krb5_sync"

struct dnokay {
	char * dn;
	int parts;
};

struct k5scfg {
	krb5_principal ad_principal;
	char * ad_princ_unparsed;
	char * ldapuri;
	char * binddn;
	char * basedn;
	char * password;
	char * adobjects;
#ifdef ENABLE_SASL_GSSAPI
	krb5_keytab keytab;
#endif
	struct dnokay * updatefor;
	int ldapretries;
#ifdef ENABLE_DELETE_HOOK
	short ondelete;
#endif
#ifdef ENABLE_MODIFY_HOOK
	short syncdisable;
	short syncexpire;
#endif
	LDAP * ldConn;
};

krb5_principal get_ad_principal(krb5_context kcx, struct k5scfg * cx, krb5_principal pin);
int check_update_okay(struct k5scfg * cx, char * principal, LDAP ** ldOut, char ** dnout);
#ifdef ENABLE_MODIFY_HOOK || ENABLE_DELETE_HOOK
void do_disable(LDAP * ldConn, char * dn, int disable);
#endif
int get_next_dn(struct dnokay * out, FILE * in);

#ifdef ENABLE_MODIFY_HOOK
kadm5_ret_t handle_modify(krb5_context kx, kadm5_hook_modinfo * modinfo,
	int stage, kadm5_principal_ent_t pin, long mask);
#endif
kadm5_ret_t handle_chpass(krb5_context context,
	kadm5_hook_modinfo *modinfo,
	int stage,
	krb5_principal princ, krb5_boolean keepold,
	int n_ks_tuple,
	krb5_key_salt_tuple *ks_tuple,
	const char *newpass);
#ifdef ENABLE_DELETE_HOOK
kadm5_ret_t handle_remove(krb5_context lkcx, kadm5_hook_modinfo * modinfo,
	int stage, krb5_principal lprinc);
#endif
