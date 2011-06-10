
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
	char * basedn;
	char * password;
	struct dnokay * updatefor;
	unsigned int dncount;
	int ldapretries;
};

krb5_principal get_ad_principal(struct k5scfg * cx, krb5_principal pin);
int get_creds(struct k5scfg * cx);
int check_update_okay(struct k5scfg * cx, char * principal, LDAP ** ldOut);

kadm5_ret_t handle_modify(krb5_context kx, kadm5_hook_modinfo * modinfo,
						  int stage, kadm5_principal_ent_t pin, long mask);
kadm5_ret_t handle_chpass(krb5_context context,
						  kadm5_hook_modinfo *modinfo,
						  int stage,
						  krb5_principal princ, krb5_boolean keepold,
						  int n_ks_tuple,
						  krb5_key_salt_tuple *ks_tuple,
						  const char *newpass);
