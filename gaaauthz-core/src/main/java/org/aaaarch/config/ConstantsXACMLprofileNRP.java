package org.aaaarch.config;

public class ConstantsXACMLprofileNRP {

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
	
	public  static final String SUBJECT_CONFDATA = "subject-confdata";
	public  static final String SUBJECT_CONTEXT = "subject-context";
	public  static final String SUBJECT_ROLE = "subject-role";
	
	// Major Resource attrributes 
	// (these attributes are used for policy selection)
	public  static final String RESOURCE_TYPE = "resource-type";
	public  static final String RESOURCE_REALM = "resource-realm"; // i.e namespace	
	public  static final String RESOURCE_DOMAIN = "resource-domain";
	public  static final String RESOURCE_SUBDOMAIN = "resource-subdomain";
	// DomainId is full id/name for the domain e.g. domainId = "http://testbed.ist-phosphorus.eu/harmony" 
	public  static final String DOMAIN_ID = "domain-id";	
	
	// Network parameters
	public  static final String RESOURCE_VLAN = "resource-vlan";
	public  static final String RESOURCE_TNA = "resource-tna";
	public  static final String RESOURCE_LINK = "resource-link";
	public  static final String RESOURCE_PORT = "resource-port";
	public  static final String RESOURCE_SOURCE = "source";//"resource-source";
	public  static final String RESOURCE_TARGET = "target";//"resource-target";	
	
	// Resource type values for "resource-id"
	public  static final String RESOURCE_TYPE_NSP = "resource-type/nsp";
	public  static final String RESOURCE_TYPE_NRPS = "resource-type/nrps";
	public  static final String RESOURCE_TYPE_NE = "resource-type/ne";
		
	// Resource description and topology types
	public  static final String TOPOLOGY_FORMAT_NSP = "topology-format-nsp";
	public  static final String TOPOLOGY_FORMAT_NDL = "topology-format-ndl";
	public  static final String TOPOLOGY_FORMAT_OSCARS = "topology-format-oscars";
	public  static final String TOPOLOGY_FORMAT_NML = "topology-format-nml";
	
	/// Action attribute identifiers
	// Action ID attribute can use standard XACML namespace
	//ConstantsXACML.XACML_ACTION_ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
	public  static final String ACTION_ID = "action-id"; 

	// Enumerated values for Action type
	public  static final String ACTION_CREATE_PATH = "action-type/create-path";
	public  static final String ACTION_ACTIVATE_PATH = "action-type/activate-path";
	public  static final String ACTION_CANCEL = "action-type/cancel";
	public  static final String ACTION_ACCESS = "action-type/access";

	/// Environment Id's
	public  static final String ENVIRONMENT_OBLIG_SUPPORTED = "environment-oblig-supported";
	
	/// Obligation Id's
	
	public  static final String OBLIGATION_ID_NETWORK_PATH = "network-path";
	public  static final String OBLIGATION_ATTRIBUTE_ID_PREFERRED_PATH = "attribute/netwokr-path-preferred";
	public  static final String OBLIGATION_ATTRIBUTE_ID_PROHIBIT_PATH = "attribute/netwokr-path-prohibit";
	
	public  static final String OBLIGATION_ID_DELEGATION_ACCESS = "delegation-access";
	public  static final String OBLIGATION_ATTRIBUTE_ID_DELEGATION_ACCESS_SUBJECT = "delegation-access-subject";
	public  static final String OBLIGATION_ATTRIBUTE_ID_DELEGATION_ACCESS_GROUP = "delegation-access-group";
	
	// Session related attributes
	public static final String GRI ="gri";
	public static final String SESSION_KEY ="session-key";
	public static final String TOKEN_NOTBEFORE = "notBefore";
	public static final String TOKEN_NOTONORAFTER = "notOnOrAfter";
	
	/// Extended Resource attributes for TVS AuthzToken
	public  static final String TVS_RESOURCE_ID = "resource-id";
	public  static final String TVS_RESOURCE_TYPE = "resource-type";
	public  static final String TVS_RESOURCE_PORT = "resource-port";
	public  static final String TVS_RESOURCE_TOKEN = "resource-token";
	public  static final String TVS_RESOURCE_TOKEN_KEY = "resource-token-key";
	
}
