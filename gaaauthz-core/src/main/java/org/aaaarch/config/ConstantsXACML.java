package org.aaaarch.config;

public class ConstantsXACML {

	///// Constants
	public static final String DELIM_URI = ":";
	public static final String DELIM_URL = "/";
	//public static final String CSV_PATTERN = "\"([^\"\\\\]*(\\\\.[^\"\\\\]*)*)\",?|([^,]+),?|,";

	/// XACML - basic NS contants
	public static final String XACML10_NS = "urn:oasis:names:tc:xacml:1.0";
	public static final String XACML20_NS = "urn:oasis:names:tc:xacml:2.0";
	public static final String XACML_CONTEXT_NS = XACML10_NS + ":" + "context";
	public static final String XACML_SUBJECT = XACML10_NS + ":" + "subject";
	public static final String XACML_RESOURCE = XACML10_NS + ":" + "resource";
	public static final String XACML_ACTION = XACML10_NS + ":" + "action";
	public static final String XACML_ENVIRONMENT = XACML10_NS + ":" + "environment";
	public static final String XACML_RESPONSE_STATUS = XACML10_NS + ":" + "status";

	/// XACML - Subject ID and attribute constants
	// Subject category
	public static final String XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
	public static final String XACML_SUBJECT_CATEGORY_RECIPIENT_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";
	public static final String XACML_SUBJECT_CATEGORY_INTERMEDIATE_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject";
	public static final String XACML_SUBJECT_CATEGORY_CODEBASE = "urn:oasis:names:tc:xacml:1.0:subject-category:codebase";
	public static final String XACML_SUBJECT_CATEGORY_REQUESTING_MACHINE = "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine";

	// Subject Attributes
	public static final String XACML_SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
	public static final String XACML_SUBJECT_ID_QUALIFIER = "urn:oasis:names:tc:xacml:1.0:subject:subject-id-qualifier";
	public static final String XACML_SUBJECT_AUTHN_TIME = "urn:oasis:names:tc:xacml:1.0:subject:authentication-time";
	public static final String XACML_SUBJECT_AUTHN_METHOD = "urn:oasis:names:tc:xacml:1.0:subject:authentication-method";
	public static final String XACML_SUBJECT_KEY_INFO = "urn:oasis:names:tc:xacml:1.0:subject:key-info"; 
	public static final String XACML_SUBJECT_REQUEST_TIME = "urn:oasis:names:tc:xacml:1.0:subject:request-time";
	public static final String XACML_SUBJECT_SESSION_START_TIME = "urn:oasis:names:tc:xacml:1.0:subject:session-start-time";
	public static final String XACML_SUBJECT_AUTHN_LOCALITY_IP_ADDRESS = "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:ip-address";
	public static final String XACML_SUBJECT_AUTHN_LOCALITY_DNS_NAME = "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:dns-name";	
	
	/// XACML - Resource ID and attribute constants
	public static final String XACML_ATTR_RESOURCE_RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
	public static final String XACML_ATTR_RESOURCE_TARGET_NAMESPACE = "urn:oasis:names:tc:xacml:1.0:resource:target-namespace";
	
	/// XACML - Action ID and attribute constants
	public  static final String XACML_ACTION_ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
		
	/// XACML - Environment ID and attribute constants
	public static final String XACML_ENVIRONMENT_CURRENT_DATE = "urn:oasis:names:tc:xacml:1.0:environment:current-date";
	public static final String XACML_ENVIRONMENT_CURRENT_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
}
