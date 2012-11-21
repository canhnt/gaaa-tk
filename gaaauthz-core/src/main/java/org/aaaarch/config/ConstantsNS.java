package org.aaaarch.config;

public class ConstantsNS {

	///// Constants
	public static final String DELIM_URN = ":";
	public static final String DELIM_URL = "/";
	public static final String CSV_PATTERN =
		"\"([^\"\\\\]*(\\\\.[^\"\\\\]*)*)\",?|([^,]+),?|,";
	// Namespace constants

	// Namespace types
	public static final String NS_TYPE_URL = "ns-type-url"; // Starts with "http://"
	public static final String NS_TYPE_URN = "ns-type-urn"; // Starts with "urn:"
	public static final String NS_TYPE_URN_X = "ns-type-urn-proprietary"; // Starts with "x-urn:"
	public static final String NS_TYPE_URN_OASIS = "ns-type-urn-oasis"; // Starts with "urn:oasis:names:tc:"
	public static final String NS_TYPE_URL_INTEROP_AUTHZ = "ns-type-url-interop"; // Start with "http://authz-interop.org/"

	/// XACML - basic NS contants
	public static final String XACML10_NS = "urn:oasis:names:tc:xacml:1.0";
	public static final String XACML20_NS = "urn:oasis:names:tc:xacml:2.0";
	public static final String XACML_CONTEXT_NS = XACML10_NS + ":" + "context";
	public static final String XACML_SUBJECT = XACML10_NS + ":" + "subject";
	public static final String XACML_RESOURCE = XACML10_NS + ":" + "resource";
	public static final String XACML_ACTION = XACML10_NS + ":" + "action";
	public static final String XACML_ENVIRONMENT = XACML10_NS + ":" + "environment";
	public static final String XACML_RESPONSE_STATUS = XACML10_NS + ":" + "status";

	/// SAML - NS constants
	public final static String SAML10_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    public final static String SAMLP10_NS = "urn:oasis:names:tc:SAML:1.0:protocol";
	public static final String SAML10_ACTION = "urn:oasis:names:tc:SAML:1.0:action";

	/// AuthZ Interop namespaces
	public static final String AUTHZ_INTEROP_XACML_NS = "http://authz-interop.org/xacml";
	public static final String AUTHZ_INTEROP_XACML_GRID_NS = "http://authz-interop.org/xacml";
	public static final String AUTHZ_INTEROP_XACML_NRP_NS = "http://authz-interop.org//nrp/xacml";
	public static final String AUTHZ_INTEROP_AAA_NS = "http://authz-interop.org/AAA";
	public static final String AUTHZ_INTEROP_AAA_XACML = AUTHZ_INTEROP_AAA_NS + "/" + "xacml";	
	
	// AAA Namespace identifiers
 	public static final String AAA_NS_URN = "x-urn:aaa";
 	public static final String AAA_NS_URN_XACML = AAA_NS_URN + ":" + "xacml";
 	public static final String AAA_NS_URL = "http://www.aaauthreach.org/ns/AAA";
 	public static final String AAA_NS_PREFIX = "AAA";

	// AAA AuthZ Policy
 	public static final String AAA_POLICY_PREFIX = "AAA";

	// AuthZ Tickets/Tokens
	
	public static final String TAG_AZTOKEN = AAA_NS_PREFIX + ":" + "AuthzToken";
	public static final String TAG_AZTICKET = AAA_NS_PREFIX + ":" + "AuthzTicket";
	public static final String TAG_AZTICKET_SAML = "Assertion";
	
	public static final String GAAAPI_NS_URN_PREFIX = "x-urn:aaa:gaaapi";
	public static final String TICKET_NS_URN_PREFIX = "x-urn:aaa:gaaapi:ticket";
	public static final String GAAAPI_NS_URL_PREFIX = "http://authz-interop.org/AAA/gaaapi";
	public static final String TICKET_NS_URL_PREFIX = "http://authz-interop.org/AAA/ticket";
	
 	/// S-R-A-E AAA namespaces for XACML
 	public static final String AAA_SUBJECT = AAA_NS_URN_XACML + ":" + "subject";
	//public static final String AAA_SUBJECT_ATTRIBUTE = AAA_SUBJECT_NS + ":" + "attributes";
	public static final String AAA_RESOURCE = AAA_NS_URN_XACML + ":" + "resource";
	public static final String AAA_ACTION = AAA_NS_URN_XACML + ":" + "action";
	public static final String AAA_ENVIRONMENT = AAA_NS_URN_XACML + ":" + "environment";

	/// S-R-A-E AuthZ-Interop namespaces for XACML
 	public static final String AAA_INTEROP_SUBJECT = AUTHZ_INTEROP_AAA_XACML + "/" + "subject";
	public static final String AAA_INTEROP_RESOURCE = AUTHZ_INTEROP_AAA_XACML + "/" + "resource";
	public static final String AAA_INTEROP_ACTION = AUTHZ_INTEROP_AAA_XACML + "/" + "action";
	public static final String AAA_INTEROP_ENVIRONMENT = AUTHZ_INTEROP_AAA_XACML + "/" + "environment";
	
	public  static final String SUBJECT_SUBJECT_ID = "subject-id";
	public  static final String SUBJECT_CONFDATA = "subject-confdata";
	public  static final String SUBJECT_CONTEXT = "subject-context";
	public  static final String SUBJECT_ROLE = "subject-role";
	public  static final String RESOURCE_RESOURCE_ID = "resource-id";
	public  static final String RESOURCE_RESOURCE_TYPE = "resource-type";
	public  static final String ACTION_ACTION_ID = "action-id";
	public  static final String ENVIRONMENT = "environment";

	
}
