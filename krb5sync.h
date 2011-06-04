
#define CACHE_NAME "MEMORY:krb5_sync"

struct dnokay {
	char * dn;
	int parts;
};

struct k5scfg {
	krb5_context kcx;
	krb5_principal ad_principal;
	char * ad_princ_unparsed;
	int ad_princ_len;
	char * ldapuri;
	char * basedn;
	char * ldapuserdn;
	char * ldapuserpassword;
	struct dnokay ** updatefor;
};

struct ldcx {
	LDAP * ldConn;
	char * dn;
	char * upn;
	unsigned long userAccountControl;
};

int get_ad_ldap_obj(struct k5scfg * cx, char * upn, struct ldcx * ldapout);
krb5_principal get_ad_principal(struct k5scfg * cx, krb5_principal pin);
int get_creds_init(struct k5scfg * cx, char * keytab_path, char * princ_name);
int get_creds(struct k5scfg * cx);

kadm5_ret_t handle_modify(krb5_context kx, kadm5_hook_modinfo * modinfo,
						  int stage, kadm5_principal_ent_t pin, long mask);
kadm5_ret_t handle_chpass(krb5_context context,
						  kadm5_hook_modinfo *modinfo,
						  int stage,
						  krb5_principal princ, krb5_boolean keepold,
						  int n_ks_tuple,
						  krb5_key_salt_tuple *ks_tuple,
						  const char *newpass);
