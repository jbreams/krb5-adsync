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

#define CACHE_NAME "MEMORY:krb5_sync"

struct dnokay {
	char * dn;
	int parts;
};

struct k5scfg {
	krb5_context kcx;
	krb5_principal ad_principal;
	char * ad_princ_unparsed;
	char * ldapuri;
	char * binddn;
	char * basedn;
	char * password;
	krb5_keytab keytab;
	struct dnokay * updatefor;
	unsigned int dncount;
	int ldapretries;
	short ondelete;
	short syncdisable;
	short syncexpire;
};

krb5_principal get_ad_principal(struct k5scfg * cx, krb5_principal pin);
int get_creds(struct k5scfg * cx);
int check_update_okay(struct k5scfg * cx, krb5_context tc, 
	char * principal, LDAP ** ldOut, char ** dnout);
void do_disable(LDAP * ldConn, char * dn, int disable);

kadm5_ret_t handle_modify(krb5_context kx, kadm5_hook_modinfo * modinfo,
	int stage, kadm5_principal_ent_t pin, long mask);
kadm5_ret_t handle_chpass(krb5_context context,
	kadm5_hook_modinfo *modinfo,
	int stage,
	krb5_principal princ, krb5_boolean keepold,
	int n_ks_tuple,
	krb5_key_salt_tuple *ks_tuple,
	const char *newpass);
kadm5_ret_t handle_remove(krb5_context lkcx, kadm5_hook_modinfo * modinfo,
	int stage, krb5_principal lprinc);

