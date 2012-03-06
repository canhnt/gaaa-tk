/*
 * Created on Nov 29, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.aaaarch.gaaapi.test.saml;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.namespace.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.*;

import org.aaaarch.config.ConstantsNS;
import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.impl.saml.SAML11ConditionAuthzSession;
import org.aaaarch.utils.HelpersReadWrite;

/**
 * @author demch
 *
 */
public class TestCreateSAML11Assertion {
	
	protected SAMLNameIdentifier nameId = null;
	protected static ArrayList confirmationMethods = new ArrayList();
	protected static KeyInfo keyInfo = null;
	
	static String outdir = "x-output/"; 
	
	public static final String DELIM_URI = ":";
	
	public final static String SAML_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    public final static String SAMLP_NS = "urn:oasis:names:tc:SAML:1.0:protocol";
	public static final String SAML_ACTION_NS = "urn:oasis:names:tc:SAML:1.0:action";

	// Subject Identifier format
	/**  Unspecified Format Identifier */    
	public final static String FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
	
	/**  Email Format Identifier */    
	public final static String FORMAT_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
	
	/**  X.509 Subject Format Identifier */    
	public final static String FORMAT_X509 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
	
	/**  Windows Domain Format Identifier */    
	public final static String FORMAT_WINDOWS = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";

	// Authentication methods 
    /** The authentication was performed by means of a password. */
    public static final String AuthenticationMethod_Password = "urn:oasis:names:tc:SAML:1.0:am:password";
	
	/** The authentication was performed by means of the Kerberos protocol [RFC 1510], 
	 * an instantiation of the Needham-Schroeder symmetric key authentication mechanism [Needham78]. */
	public static final String AuthenticationMethod_Kerberos = "urn:ietf:rfc:1510"; 
	
	/** The authentication was performed by means of Secure Remote Password protocol as specified in [RFC 2945]. */
	public static final String AuthenticationMethod_SRP = "urn:ietf:rfc:2945";
	
	/** The authentication was performed by means of an unspecified hardware token. */
	public static final String AuthenticationMethod_HardwareToken = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";
	
	/** The authentication was performed using either the SSL or TLS protocol with certificate based client 
	 * authentication. TLS is described in [RFC 2246]. */
	public static final String AuthenticationMethod_SSL_TLS_Client = "urn:ietf:rfc:2246";

	/** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of an 
	 * X.509 PKI [X.500][PKIX]. It may have been one of the mechanisms for which a more specific identifier 
	 * has been defined. */
	public static final String AuthenticationMethod_X509_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";
	
	/** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of 
	 * a PGP web of trust [PGP]. It may have been one of the mechanisms for which a more specific identifier 
	 * has been defined. */
	public static final String AuthenticationMethod_PGP_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:PGP";
	
	/** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of a 
	 * SPKI PKI [SPKI]. It may have been one of the mechanisms for which a more specific identifier has been 
	 * defined. */
	public static final String AuthenticationMethod_SPKI_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:SPKI";
	
	/** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of a 
	 * XKMS trust service [XKMS]. It may have been one of the mechanisms for which a more specific identifier 
	 * has been defined. */
	public static final String AuthenticationMethod_XKMS_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:XKMS";
	
	/** The authentication was performed by means of an XML digital signature [RFC 3075]. */
	public static final String AuthenticationMethod_XML_DSig = "urn:ietf:rfc:3075";
	
	/** The authentication was performed by an unspecified means. */
	public static final String AuthenticationMethod_Unspecified = "urn:oasis:names:tc:SAML:1.0:am:unspecified";
	
	// Namespace identifiers
	public static final String CNL_NS = "urn:cnl";
	public static final String CNL_SUBJECT_NS = "cnl:subject";
	public static final String CNL_SUBJECT_ATTRIBUTE_NS = "cnl:subject:attributes";
	public static final String CNL_RESOURCE_NS = "cnl:resource";
	public static final String CNL_ACTION_NS = "cnl:action";
	
	public  static final String CNL_SUBJECT_SUBJECT_ID = "subject-id";
	public  static final String CNL_SUBJECT_TOKEN = "token";
	public  static final String CNL_SUBJECT_JOBID = "job-id";
	public  static final String CNL_SUBJECT_ROLE = "role";
	public  static final String CNL_RESOURCE_RESOURCE_ID = "resource-id";
	public  static final String CNL_ACTION_ACTION_ID = "action-id";
	public  static final String CNL_ENVIRONMENT_ISSUE_TIME = "issue-time";
	
	
	// Create SAMLAuthNAssertion of input data
	// TODO: Clarify SubjectLocality
	public static SAMLAssertion createSAMLAuthnAssertion (String subjid) 
		//		(String insubj, String inact, String inres, String inrole){ 
	throws Exception{ 

		Date startDate = new Date();
		Date endDate = new Date();
		
		HashSet conditions = new HashSet();
		HashSet statements = new HashSet();
		HashSet advice = new HashSet();
		HashSet confirmationMethod = new HashSet();
		HashSet bindings = new HashSet();
		
		// create XML document instance
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		
		//SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// create a new document
		org.w3c.dom.Document doc = db.newDocument();

		/* conditions
		 * atributes: startDate, endDate 
		 * <!ELEMENT Conditions (AudienceRestrictionCondition | DoNotCacheCondition | Condition)*>
		 */
		
		// setting validity period
		String date1 = "2004-12-05"; 
		String date2 = "2004-12-22T22:22:22Z"; 
		startDate = dateformat(date1);
		endDate = dateformat(date2);
		
		//conditions.add((Object)"staff@collaboratory.nl");
		
		/*Creating SAML Subject
		 * <!ELEMENT Subject ((NameIdentifier, SubjectConfirmation?) | SubjectConfirmation)>
		 * <!ELEMENT SubjectConfirmation (ConfirmationMethod+, SubjectConfirmationData?, KeyInfo?)>
		 */

		// SAMLNameIdentifier using e-mail format	
		SAMLNameIdentifier nameId = new SAMLNameIdentifier( subjid, 
				(CNL_SUBJECT_NS + DELIM_URI + "customer"), 
				SAMLNameIdentifier.FORMAT_EMAIL);
		
		// ConfirmationMethod's, e.g. authntoken, or authntoken-signed	
		confirmationMethods.add("authntoken-signed");
		//confirmationMethods.add("password");
		confirmationMethods.add("email");
		
		// Creating ds:KeyInfo element
		// TODO: possibility to add XMLSig KeyInfo i.e. public key or Cert
		keyInfo = null;
		
		// SubjectConfirmationData Element
        Element confirmationData = doc.createElementNS( ConstantsNS.SAML10_NS, "SubjectConfirmationData");
		confirmationData.appendChild(doc.createTextNode("put-crypto-value-here"));
		
		// Building Subject
		SAMLSubject subject = new SAMLSubject(nameId, confirmationMethods, confirmationData, null);
		
		// Building SAMLAuthenticationStatement
		//(subject, authMethod, authInstant, subjectIP, subjectDNS, bindings)
		
		String authMethod = "AuthenticationMethod_X509_PublicKey"; 
		Date authInstant = new Date();
 		String  subjectIP = "192.30.180.22"; 
		String subjectDNS = "dns.collaboratory.nl";
		bindings = null;
		SAMLAuthenticationStatement authnStatement = 
			new SAMLAuthenticationStatement (subject, authMethod, authInstant, subjectIP, subjectDNS, bindings);
		statements.add(authnStatement);
		SAMLAssertion assertionAuthN = 
			new SAMLAssertion((CNL_SUBJECT_NS + DELIM_URI + "CNLAAAauthority"), 
					startDate, endDate, conditions, advice, statements);
		
		return assertionAuthN;	
		
	}
	
	// Create SAMLAttrAssertion of input data
	public static  SAMLAssertion createSAMLAttrAssertion (String subjid, Collection attrvals )
		//		(String insubj, String inact, String inres, String inrole){ 
	throws Exception{ 
		
		Date startDate = new Date();
		Date endDate = new Date();
		
		HashSet conditions = new HashSet();
		HashSet statements = new HashSet();
		HashSet advice = new HashSet();
		HashSet confirmationMethod = new HashSet();
		HashSet attributes = new HashSet();
		//HashSet attrvals = new HashSet();
		
		// create XML document instance
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		
		//SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// create a new document
		org.w3c.dom.Document doc = db.newDocument();

		/* conditions
		 * atributes: startDate, endDate 
		 * <!ELEMENT Conditions (AudienceRestrictionCondition | DoNotCacheCondition | Condition)*>
		 */
		
		// setting validity period
		String date1 = "2004-12-05"; 
		String date2 = "2004-12-22T22:22:22Z"; 
		startDate = dateformat(date1);
		endDate = dateformat(date2);
		
		//conditions.add((Object)"staff@collaboratory.nl");
		
		/*Creating SAML Subject
		 * <!ELEMENT Subject ((NameIdentifier, SubjectConfirmation?) | SubjectConfirmation)>
		 * <!ELEMENT SubjectConfirmation (ConfirmationMethod+, SubjectConfirmationData?, KeyInfo?)>
		 */

		// SAMLNameIdentifier using e-mail format	
		SAMLNameIdentifier nameId = new SAMLNameIdentifier( subjid, 
				(CNL_SUBJECT_NS + DELIM_URI + "customer"), 
				SAMLNameIdentifier.FORMAT_EMAIL);
		
		// ConfirmationMethod's, e.g. authntoken, or authntoken-signed	
		confirmationMethods.add("authntoken-signed");
		//confirmationMethods.add("password");
		//confirmationMethods.add("email");
		
		// Creating ds:KeyInfo element
		keyInfo = null;

		// SubjectConfirmationData Element
        Element confirmationData = doc.createElementNS( ConstantsNS.SAML10_NS, "SubjectConfirmationData");
		confirmationData.appendChild(doc.createTextNode("put-crypto-value-here"));

		// Building Subject
		SAMLSubject subject = new SAMLSubject(nameId, confirmationMethods, confirmationData, null);
		
		// Building AttributeStatement
		
		//SAMLAttribute(String name, String namespace, QName type, long lifetime, Collection values)
		//remaining problem with QName type
		// check also "long"
		QName qname = new QName(CNL_NS, "subject");
		SAMLAttribute attr1 = new SAMLAttribute("AttributeSubject1", CNL_NS, qname, 300, attrvals);
		//SAMLAttribute attr2 = new SAMLAttribute("AttributeSubject2", CNL_NS, qname, 9999, attrvals);
		attributes.add(attr1);
		//attributes.add(attr2);
		
		SAMLAttributeStatement attrStatement = 
			new SAMLAttributeStatement (subject, attributes);
		statements.add(attrStatement);
		SAMLAssertion assertionAttr = 
			new SAMLAssertion((CNL_SUBJECT_NS + DELIM_URI + "CNLAAAauthority"), 
					startDate, endDate, conditions, advice, statements);
		
		return assertionAttr;	
	}
	
	// Create SAMLAuthZAssertion of input data
	public static SAMLAssertion createSAMLAuthzAssertion (String subjid, Collection evidence) 
	//(String insubj, String inact, String inres, String inrole) 
	throws Exception{ 
		
		Date startDate = new Date();
		Date endDate = new Date();
		
		HashSet conditions = new HashSet();
		HashSet statements1 = new HashSet();
		HashSet statements2 = new HashSet();
		HashSet advice = new HashSet();
		HashSet actions = new HashSet();
		//HashSet evidence = new HashSet();
		HashSet confirmationMethod = new HashSet();
		HashSet attributes = new HashSet();
		HashSet attrvals = new HashSet();
		
		// create XML document instance
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		
		//SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// create a new document
		org.w3c.dom.Document doc = db.newDocument();

		/* conditions
		 * atributes: startDate, endDate 
		 * <!ELEMENT Conditions (AudienceRestrictionCondition | DoNotCacheCondition | Condition)*>
		 */
		
		// setting validity period
		String date1 = "2004-12-05"; 
		String date2 = "2004-12-22T22:22:22Z"; 
		startDate = dateformat(date1);
		endDate = dateformat(date2);

		//conditions.add((Object)"staff@collaboratory.nl");
		
		/* Creating SAML Subject
		 * <!ELEMENT Subject ((NameIdentifier, SubjectConfirmation?) | SubjectConfirmation)>
		 * <!ELEMENT SubjectConfirmation (ConfirmationMethod+, SubjectConfirmationData?, KeyInfo?)>
		 */

		// SAMLNameIdentifier using e-mail format	
		SAMLNameIdentifier nameId = new SAMLNameIdentifier(subjid, 
				(CNL_SUBJECT_NS + DELIM_URI + "customer"), 
				SAMLNameIdentifier.FORMAT_EMAIL);
		
		//SAMLNameIdentifier nameId1 = new SAMLNameIdentifier("WHO740@users.collaboratory.nl", 
		//		(CNL_SUBJECT_NS + DELIM_URI + "analyst"), SAMLNameIdentifier.FORMAT_EMAIL);
		
		// ConfirmationMethod's, e.g. authntoken, or authntoken-signed	
		confirmationMethods.add("authntoken-signed");
		//confirmationMethods.add("password");
		confirmationMethods.add("email");
		
		// Creating ds:KeyInfo element
		keyInfo = null;
		
		// SubjectConfirmationData Element
        Element confirmationData = doc.createElementNS( ConstantsNS.SAML10_NS, "SubjectConfirmationData");
		confirmationData.appendChild(doc.createTextNode("put-crypto-value-here"));

		// Building Subject
		SAMLSubject subject = new SAMLSubject(nameId, confirmationMethods, confirmationData, null);
		// Building SubjectStatement
		
		// SAML Action
		SAMLAction action1 = new SAMLAction((SAML_ACTION_NS + DELIM_URI + CNL_ACTION_NS), "CNLaction01: 2Dscan");
		SAMLAction action2 = new SAMLAction((SAML_ACTION_NS + DELIM_URI + CNL_ACTION_NS), "CNLaction02: zoom");
		actions.add(action1);
		actions.add(action2);
		
		// attributes resourceId and decision
		// this limitation doesn't allow to simply use XACML Req/Resp
		// as evidence
		String resourceId = "http://resources.collaboratory.nl/Phillips_XPS1";
		String decision = "@Resource;Permit";
		
		// evidence Object/Element: only Strings or SAMLAssertions
		//evidence.add(subject);
		//evidence.add("@resourceId;Permit");
		//evidence.add(assertionAttr);
		//
		SAMLAuthorizationDecisionStatement authzDecisionStatement =  
			new SAMLAuthorizationDecisionStatement(subject, resourceId, decision, actions, evidence);
		statements2.add(authzDecisionStatement);
		SAMLAssertion assertionAuthz = 
			new SAMLAssertion((CNL_SUBJECT_NS + DELIM_URI + "CNLAAAauthority"), 
					startDate, endDate, conditions, advice, statements2);
		
		return assertionAuthz;
	}
	public static SAMLAssertion createSAMLAuthZAssertion 
		(String subjid, Collection evidence, HashSet conditions, Collection advice) 
	//(String insubj, String inact, String inres, String inrole) 
	throws Exception{ 

		Date startDate = new Date();
		Date endDate = new Date();
		
		//HashSet conditions = new HashSet();
		HashSet statements1 = new HashSet();
		HashSet statements2 = new HashSet();
		HashSet advice1 = new HashSet();
		HashSet actions = new HashSet();
		//HashSet evidence = new HashSet();
		HashSet confirmationMethod = new HashSet();
		HashSet attributes = new HashSet();
		HashSet attrvals = new HashSet();
		
		// create XML document instance
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		
		//SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// create a new document
		org.w3c.dom.Document doc = db.newDocument();

		/* conditions
		 * atributes: startDate, endDate 
		 * <!ELEMENT Conditions (AudienceRestrictionCondition | DoNotCacheCondition | Condition)*>
		 */
		
		// setting validity period
		String date1 = "2004-12-05"; 
		String date2 = "2004-12-22T22:22:22Z"; 
		startDate = dateformat(date1);
		endDate = dateformat(date2);

		//conditions.add((Object)"staff@collaboratory.nl");
		
		/* Creating SAML Subject
		 * <!ELEMENT Subject ((NameIdentifier, SubjectConfirmation?) | SubjectConfirmation)>
		 * <!ELEMENT SubjectConfirmation (ConfirmationMethod+, SubjectConfirmationData?, KeyInfo?)>
		 */

		// SAMLNameIdentifier using e-mail format	
		SAMLNameIdentifier nameId = new SAMLNameIdentifier(subjid, 
				(CNL_SUBJECT_NS + DELIM_URI + "customer"), 
				SAMLNameIdentifier.FORMAT_EMAIL);
		
		//SAMLNameIdentifier nameId1 = new SAMLNameIdentifier("WHO740@users.collaboratory.nl", 
		//		(CNL_SUBJECT_NS + DELIM_URI + "analyst"), SAMLNameIdentifier.FORMAT_EMAIL);
		
		// ConfirmationMethod's, e.g. authntoken, or authntoken-signed	
		confirmationMethods.add("authntoken-signed");
		//confirmationMethods.add("password");
		confirmationMethods.add("email");
		
		// Creating ds:KeyInfo element
		keyInfo = null;

		// SubjectConfirmationData Element
        Element confirmationData = doc.createElementNS( ConstantsNS.SAML10_NS, "SubjectConfirmationData");
		confirmationData.appendChild(doc.createTextNode("put-crypto-value-here"));

		// Building Subject
		SAMLSubject subject = new SAMLSubject(nameId, confirmationMethods, confirmationData, null);
		// Building SubjectStatement
		
		// SAML Action
		SAMLAction action1 = new SAMLAction((SAML_ACTION_NS + DELIM_URI + CNL_ACTION_NS), "CNLaction01: 2Dscan");
		SAMLAction action2 = new SAMLAction((SAML_ACTION_NS + DELIM_URI + CNL_ACTION_NS), "CNLaction02: zoom");
		actions.add(action1);
		actions.add(action2);
		
		// attributes resourceId and decision
		// this limitation doesn't allow to simply use XACML Req/Resp
		// as evidence
		String resourceId = "http://resources.collaboratory.nl/Phillips_XPS1";
		String decision = "@Resource;Permit";
		
		// evidence Object/Element: only Strings or SAMLAssertions
		//evidence.add(subject);
		//evidence.add("@resourceId;Permit");
		//evidence.add(assertionAttr);

		////+ create element for advice
        Iterator i = advice.iterator();
        while (i.hasNext()) {
		org.w3c.dom.Element obligadvice = doc.createElementNS("xmlns:xacml" , "PolicyObligation");
		obligadvice.appendChild(doc.createTextNode(i.next().toString()));
		obligadvice.setAttribute("ObligationId", "urn:oasis:names:tc:xacml:1.0:obligation");
		obligadvice.setAttribute("FulfillOn", "Permit");
        advice1.add(obligadvice);
        }

        // conditions
        /* 
        //Element condition1 = doc.createElementNS( ConstantsNS.SAML_NS, "Condition");
        Element condition1 = doc.createElement("Condition");
		condition1.setAttribute("SessionId", "put-sessionId-here");
        //Element condition2 = doc.createElementNS( ConstantsNS.SAML_NS, "Condition");
        Element condition2 = doc.createElement("Condition");
        condition2.setAttribute("PolicyURIs", "put-Policyref-here");       
        conditions.add(condition1);
        conditions.add(condition2);
        */
        ArrayList sessiondata = new ArrayList();
        sessiondata.add("session Ctx1");
        
        String sessionId = "session-id";
		String policyRef = "policy-ref";
		SAML11ConditionAuthzSession azsessionconds = 
        	new SAML11ConditionAuthzSession(sessionId, policyRef, sessiondata);
		conditions.add(azsessionconds);
        //
		SAMLAuthorizationDecisionStatement authzDecisionStatement =  
			new SAMLAuthorizationDecisionStatement
					(subject, resourceId, decision, actions, evidence);
		statements2.add(authzDecisionStatement);
		SAMLAssertion assertionAuthz = 
			new SAMLAssertion((CNL_SUBJECT_NS + DELIM_URI + "CNLAAAauthority"), 
					startDate, endDate, conditions, advice1, statements2);
		
		/*// start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		//
		"xmlns", XML.SAML_NS);
		//((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
		//((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
		//((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
		//((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
		//
		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// create a new document
		org.w3c.dom.Document doc = db.newDocument();
		////+ create element for advice
        Iterator i = advice.iterator();
        while (i.hasNext()) {
		org.w3c.dom.Element obligadvice = doc.createElementNS("xmlns:xsi" , "Obligation");
		obligadvice.appendChild(doc.createTextNode(i.next().toString()));
        advice1.add(obligadvice);
        }
		*///-
		return assertionAuthz;
	}
	
	public static org.w3c.dom.Document docSAML (SAMLAssertion assertion) 
		throws ParserConfigurationException, SAMLException {
		
		// create XML document instance
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		
		//SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// create a new document
		org.w3c.dom.Document doc = db.newDocument();

		org.w3c.dom.Node assertionNode = assertion.toDOM(doc);
		doc.appendChild(assertionNode);
		return doc;
	}
	
	
	public static Date dateformat (String dateTime) throws ParseException {
        SimpleDateFormat formatter = null;
        //String dateTime = "2002-02-02T22:22:22Z";
        //String dateTime = "2002-02-02";
        int dot = dateTime.indexOf('.');
        int col = dateTime.indexOf(':');
        if (col > 0) {
        if (dot > 0) {
            formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        }
        else {
            formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        }} else{
            formatter = new SimpleDateFormat("yyyy-MM-dd");
        }
        //formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        Date dt = formatter.parse(dateTime);
		return dt;
	}
	
	public static void printDOMdoc(org.w3c.dom.Document doc) throws Exception {
		// print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
	}
	public static void printDOMdoc(org.w3c.dom.Node element) throws Exception {
		//print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(element, f);
		f.close();
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
	}
	
	public static void saveDOMdoc(org.w3c.dom.Document doc, String filename)
	throws Exception {
		//save file from DOM doc
		FileOutputStream f = new FileOutputStream(filename);
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		//System.out.println("Wrote echo DOM doc to " + filename);
	}
	
	public static void main(String[] args) throws Exception 
	{
		org.apache.xml.security.Init.init();
		
		HashSet conditions = new HashSet();
		//ArrayList conditions = new ArrayList();
		HashSet statements1 = new HashSet();
		HashSet statements2 = new HashSet();
		HashSet advice = new HashSet();
		HashSet actions = new HashSet();
		HashSet evidence1 = new HashSet();
		HashSet evidence2 = new HashSet();
		HashSet confirmationMethod = new HashSet();
		
		HashSet attributes = new HashSet();
		HashSet attrvals = new HashSet();
		
        //String dateTime = "2002-02-02T22:22:22Z";
        String dateTime = "2002-02-02";
        
		// parameters
		String infile = "saml11test.xml";
		String outfile = "saml11test.xml";
		String subjid1 = "WHO740@users.collaboratory.nl";
		String subjid2 = "HEIS007@staff.collaboratory.nl";

		//Receive parameters for the keystore
		String keyalias = "cnl01";
		List checkconfsec = new ArrayList();
		List keyset = KeyStoreConfig.getConfigKeys(keyalias);
		
		
		// components input test block
		/*
		 System.out.println("Initial test block\n");
		 System.out.println("\nread file and print DOM doc\n");
		 org.w3c.dom.Document doc1 = readFileToDOM (infile);
		 printDOMdoc(doc1);
		 String docstr = readFileToString (infile);
		 */
		// call methods to create different types of Assertions

		attrvals.add("jobID");
		attrvals.add("cnl:subject:role");
		attrvals.add("@cnl:subject:role:manager");

		// evidence Object/Element: only Strings or SAMLAssertions
		// TODO: check the meaning of "subjectAuthnToken"
		String subjectAuthnToken = "2355789adcebb";
		String assertionIDRef = "Issuer@" + "da5d37721a7568f250efc6e2f1a4aec3";
		evidence1.add(assertionIDRef);
		
		try {   	
			System.out.println("\nCreate different types of SAML 1.1 Assertions");
			System.out.println("Select sssertion type ( " +
					"1 - AuthN Assertion, 2 - Attribute Assertion, \n" +
					"3 - Simple AuthZ Assertion, 4 - AuthZ Assertion with Evidence,\n" +
					"5 - AuthZ Assertion with Condition/Obligation" +
					")");
			
			int s = HelpersReadWrite.readStdinInt();			
			switch(s) {
			case 1: {
				outfile = outdir + "saml11test03authn.xml";
				SAMLAssertion assertion = createSAMLAuthnAssertion(subjid1); 
				// save and print
				org.w3c.dom.Document doc = docSAML (assertion);
				saveDOMdoc(doc, outfile);
				printDOMdoc(doc);
				return;}
			case 2: {
				outfile = outdir + "saml11test02attr.xml";
				SAMLAssertion assertion = createSAMLAttrAssertion(subjid1, attrvals);  
				// save and print
				org.w3c.dom.Document doc = docSAML (assertion);
				saveDOMdoc(doc, outfile);
				printDOMdoc(doc);
				return;}
			case 3: {
				outfile = outdir + "saml11test00authz.xml";
				SAMLAssertion assertion = createSAMLAuthzAssertion(subjid1, null); 
				// save and print
				org.w3c.dom.Document doc = docSAML (assertion);
				saveDOMdoc(doc, outfile);
				printDOMdoc(doc);
				return;}
			case 4: {
				outfile = outdir + "saml11test01authz-evidence.xml";				
				SAMLAssertion assertionAttr = createSAMLAttrAssertion(subjid2, attrvals);
				evidence1.add(assertionAttr);
				SAMLAssertion assertion = createSAMLAuthzAssertion(subjid1, evidence1); 
				// save and print
				org.w3c.dom.Document doc = docSAML (assertion);
				saveDOMdoc(doc, outfile);
				printDOMdoc(doc);
				return;}
			case 5: {
				outfile = outdir + "saml11test01authz-condition-evidence.xml";
				//outfile = outdir + "saml11test01authz-condition.xml";				
				SAMLAssertion assertionAttr = createSAMLAttrAssertion(subjid2, attrvals);
				advice.add("Policy obligation (1): Action cost = 100 EUR");
				advice.add("Policy obligation (2): Request data logging");
				evidence1.add(assertionAttr);
				SAMLAssertion assertion = createSAMLAuthZAssertion(subjid1, evidence1, conditions, advice); 
				// save and print
				org.w3c.dom.Document doc = docSAML (assertion);
				saveDOMdoc(doc, outfile);
				printDOMdoc(doc);
				return;}
			} 
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
	
}
