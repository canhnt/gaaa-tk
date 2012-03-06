package org.aaaarch.config;

public class ConstantsXACMLprofileGrid {

	///// Constants
	public static final String DELIM_URN = ":";
	public static final String DELIM_URl = "/";

	/// AuthZ Interop namespace
	//public static final String AUTHZ_INTEROP_XACML20_NS = "http://authz-interop.org/xacml/2.0";
	//public static final String AUTHZ_INTEROP_AAA_NS = "http://authz-interop.org/AAA";
	//public static final String AUTHZ_INTEROP_AAA_XACML = AUTHZ_INTEROP_AAA_NS + "/" + "xacml/2.0";	
	
	// AttributeId enumeration constants

	/// XACML

	/// S-R-A-E AuthZ-Interop namespaces for XACML
	
	public  static final String SUBJECT_X509_ID = "subject-x509-id";
	public  static final String SUBJECT_CONDOR_CANONICAL_NAME_ID = "subject-condor-canonical-name-id";
	public  static final String SUBJECT_X509_ISSUER = "subject-x509-issuer";
	public  static final String VO = "vo";
	public  static final String VOMS_SIGNING_SUBJECT = "voms-signing-subject";
	public  static final String VOMS_SIGNING_ISSUER = "voms-signing-issuer";
	public  static final String VOMS_FQAN = "voms-fqan";
	
	public  static final String VOMS_PRIMARY_FQAN = "voms-primary-fqan";
	public  static final String CERTIFICATE_SERIAL_NUMBER = "certificate-serial-number";
	public  static final String CA_SERIAL_NUMBER = "ca-serial-number";
	public  static final String VOMS_DNS_PORT = "voms-dns-port";
	public  static final String CA_POLICY_ID = "ca-policy-id";
	public  static final String CERT_CHAIN = "cert-chain";

	public  static final String ACTION_ID = "action-id";
	public  static final String ACTION_RSL_STRING = "rsl-string";
	
	public  static final String ACTION_TYPE_QUEUE = "action-type/queue";
	public  static final String ACTION_TYPE_EXECUTE_NOW = "action-type/execute-now";
	public  static final String ACTION_TYPE_ACCESS = "action-type/access";

	public  static final String RESOURCE_ID = "resource-id";
	public  static final String RESOURCE_DNS_HOST_NAME = "dns-host-name";
	public  static final String RESOURCE_X509_ID = "resource-x509-id";
	public  static final String RESOURCE_X509_ISSUE = "resource-x509-issuer";

	public  static final String RESOURCE_TYPE_CE = "resource-type/access";
	public  static final String RESOURCE_TYPE_WN = "resource-type/access";
	public  static final String RESOURCE_TYPE_SE = "resource-type/access";
	
	public  static final String ENVIRONMENT_OBLIG_SUPPORTED = "environment-oblig-supported";
	public  static final String ENVIRONMENT_PILOT_JOB_INFO = "pilot-job-info";
	
	/// Obligation Id's
	public  static final String OBLIGATION_ID_UID_GID = "uidgid";
	public  static final String OBLIGATION_ID_SECONDARY_GIDS = "secondary-gids";
	
	public  static final String OBLIGATION_ATTR_ID_POSIX_UID = "attribute/posix-uid";
	public  static final String OBLIGATION_ATTR_ID_POSIX_GID = "attribute/posix-gid";
	
	public  static final String OBLIGATION_ID_USERNAME = "username";
	public  static final String OBLIGATION_ATTR_ID_USERNAME = "attribute/username";
	
	public  static final String OBLIGATION_ID_AFS_TOKEN = "afs-token";
	public  static final String OBLIGATION_ATTR_ID_AFS_TOKEN = "attribute/afs-token";

	public  static final String OBLIGATION_ID_ROOT_AND_HOME_PATH = "root-and-home-paths";
	public  static final String OBLIGATION_ATTR_ID_ROOT_PATH = "attribute/rootpath";
	public  static final String OBLIGATION_ATTR_ID_HOME_PATH = "attribute/homepath";
	
	public  static final String OBLIGATION_ID_STORAGE_ACCESS_PRIORITY = "storage-access-priority";
	public  static final String OBLIGATION_ATTR_ID_STORAGE_PRIORITY = "attribute/storage-priority";
	
	public  static final String OBLIGATION_ID_ACCESS_PERMISSIONS = "storage-access-priority";
	public  static final String OBLIGATION_ATTR_ID_ACCESS_PERMISSIONS = "storage-access-priority";
	public  static final String OBLIGATION_ATTR_VALUE_ACCESS_PERMISSION_READ_ONLY = "read-only";
	public  static final String OBLIGATION_ATTR_VALUE_ACCESS_PERMISSION_READ_WRITE = "read-write";
	
}
