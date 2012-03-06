/*
 * Created on May 3, 2004
 * Modified on April 21, 2008
 * SNEG at UvA
 */
package org.aaaarch.gaaapi.test;

import java.io.*;
//import java.util.ArrayList;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.pdp.XACMLPDP;
import org.aaaarch.pdp.impl.SimpleSAMLXACMLPDPImpl;
import org.aaaarch.pdp.impl.SimpleXACMLPDPImpl;
import org.aaaarch.policy.impl.PolicyResolver;
import org.aaaarch.utils.HelpersHexConverter;
import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;

import org.aaaarch.config.ConfigDomainsPhosphorus;
import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.config.ConfigTrustDomains;
import org.aaaarch.config.ConstantsNS;
import org.aaaarch.config.ConstantsXACMLprofileNRP;
import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.config.KeyStoreIF;
import org.aaaarch.crypto.CryptoData;
import org.aaaarch.crypto.HMACprocessor;
import org.aaaarch.gaaapi.ActionSet;
import org.aaaarch.gaaapi.MalformedResourceIdException;
import org.aaaarch.gaaapi.NotAuthenticatedException;
import org.aaaarch.gaaapi.NotAuthorizedException;
import org.aaaarch.gaaapi.NotAvailablePDPException;
import org.aaaarch.gaaapi.NotCorrectOrUnknownNSException;
import org.aaaarch.gaaapi.ResourceHelper;
import org.aaaarch.gaaapi.SubjectSet;
import org.aaaarch.gaaapi.authn.AuthenticateSubject;
import org.aaaarch.gaaapi.pep.AuthorizationRequest;
import org.aaaarch.gaaapi.pep.AuthorizationResponse;
import org.aaaarch.gaaapi.pep.PEP;
import org.aaaarch.gaaapi.pep.XACMLPDPProxy;
import org.aaaarch.gaaapi.pep.impl.AuthorizationRequestImpl;
import org.aaaarch.gaaapi.pep.impl.LocalSAMLPDPProxyImpl;
import org.aaaarch.gaaapi.pep.impl.LocalXACMLPDPProxyImpl;
import org.aaaarch.gaaapi.pep.impl.PEPImpl;
import org.aaaarch.gaaapi.pep.impl.PEPLocal;
import org.aaaarch.gaaapi.pep.impl.PEPgenRequest;
import org.aaaarch.gaaapi.pep.impl.PEPsimple;
import org.aaaarch.gaaapi.ticktok.AuthzTicketType;
import org.aaaarch.gaaapi.ticktok.AuthzToken;
import org.aaaarch.gaaapi.ticktok.AuthzTokenType;
import org.aaaarch.gaaapi.tvs.GRIgenerator;
import org.aaaarch.gaaapi.tvs.MalformedXMLTokenException;
import org.aaaarch.gaaapi.tvs.NotValidAuthzTokenException;
import org.aaaarch.gaaapi.tvs.TVS;
import org.aaaarch.gaaapi.tvs.TokenBuilder;
import org.aaaarch.gaaapi.tvs.TokenKey;
import org.aaaarch.gaaapi.tvs.XMLTokenType;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Yuri Demchenko
 * 
 */
public class TestGAAAPI {

	public PEPLocal _pep;

	public TestGAAAPI() {
		_pep = new PEPLocal();
	}

	public static void main(String args[]) throws IOException {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		TestGAAAPI test = new TestGAAAPI();

		test.doTest();
	}

	private void doTest() {
		try {
			System.out
					.println("Running test for PEP/PDP Authorisation components (aaauthreach prj)");
			System.out
					.println("Options (12 - view security configuration; * - optionally supported):\n"
							+ "0 - test GAAAPI: Simple test PEP & TestPDPlocal (hard-coded policy); \n"
							+ "1 - test GAAAPI: Test PDPXACML & booleanPEP (simple ResourceId); \n"
							+ "2 - test GAAAPI: Test PDPXACML & booleanPEP (complex ResourceId); \n"
							+ "3 - test PEP-TVS (Stage 1&2 - Reservation && Deployment): Request PEP-XACMLPDPD -> create XMLToken -> Program TVS \n"
							+ "4 - test PEP-TVS (Stage 3 - Access): Request PEP-XACMLPDPD with AuthzToken \n"
							+ "5 - AuthZ Session Mngnt with AuthzToken: (1) AuthzReq & return AuthzToken; (2) AuthzReq w. AuthzToken\n"
							+ "6* - AuthZ Session with AuthzTicket: AuthzRequest with Azticket & Evaluate AuthzTicket w. Triage & Return Azticket; \n"
							+ "7* - AuthZ Session with AuthzTicket: AuthzRequest with Azticket & Evaluate AuthzTicket w. Triage & Return Aztoken;; \n"
							+ "8* - test GAAAPI: Test PDPXACML & azticktokPEP(token) & PEP-Triage; \n"
							+ "10 - interactive test generate Request;\n"
							+ "21 - Canh's test UC-1: simple authz request");
			int s = readStdinInt();

			switch (s) {
			// "0 - test GAAAPI: Simple test PEP & TestPDPlocal (hard-coded
			// policy);
			case 0:
				testGAAAPIRequestPDPlocal();
				break;

			case 1:
				runTestCase1();
				break;

			case 2:
				runTestCase2();
				break;

			case 3:
				runTestCase3();
				break;

			case 4:
				runTestCase4();
				break;

			case 5:
				runTestCase5();
				break;

			case 6:
				runTestCase6();
				break;

			case 7:
				runTestCase7();
				break;

			case 8:
				runTestCase8();
				break;

			case 10:
				interactiveTestGenerateRequest();
				break;

			case 11:
				WP1testAAAtestDifferentAPICalls();
				break;

			case 12:
				checkConfigSecurity();
				break;

			case 21:
				runTestCase21();
				break;
			
			case 22:
				runTestCase22();
				break;
			}
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void runTestCase22() throws Exception{
		System.out.println("\nCanh's test case 2: XACML PEP to XACML PDP\n");

		String resourceInputURI = "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.3.1.16/target=10.7.3.13";
		
		HashMap<String, String> subjmap = SubjectSet.getSubjSetTest();

		// extracting subject attrs from the subjmap
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID);

		String anystring = CryptoData.doEncryptDataHex(subjectId,
				CryptoData.getKeyPassTest());
		anystring = AuthenticateSubject.getSubjectAuthnCrypto(subjectId,
				AuthenticateSubject.AUTHN_SUBJECT_METHOD_DES, null);

		String decrypted = CryptoData.doDecryptDataHex(anystring,
				CryptoData.getKeyPassTest());
		System.out.println("\nTest GAAAPI: " + "subjectId = " + subjectId
				+ "\nencrypted = " + anystring + "\ndecrypted = " + decrypted);

		subjmap.put(ConstantsNS.SUBJECT_CONFDATA, anystring);
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);

		HashMap resmap = ResourceHelper.parseResourceURI(resourceInputURI);
		
		HashMap<String, String> actmap = new HashMap<String, String>();

		String action = ActionSet.NSP_CREATE_PATH;
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);
		
		AuthorizationRequest authzRequest = new AuthorizationRequestImpl();
		authzRequest.getSubject().putAll(subjmap);
		authzRequest.getResource().putAll(resmap);
		authzRequest.getAction().putAll(actmap);
		
		//OpenSAML boostrap

		
		// Using SAML-XACML profile to communicate with a SAML-XACML PDP, using SAML-XACML PDP Proxy		
		// create a local SAML-XACML PDP
		SAMLXACMLPDP pdp = new SimpleSAMLXACMLPDPImpl();
		
		// create a local SAML-XACML proxy to connect to the PDP
		XACMLPDPProxy pdpProxy = new LocalSAMLPDPProxyImpl(pdp);		
				
		// create PEP to consume this proxy
		PEP myPEP = new PEPImpl(pdpProxy);
		
		// evaluation
		AuthorizationResponse resp = myPEP.authorizeAction(authzRequest);
		
		//boolean decision = _pep.authorizeAction(authzRequest);
		
		System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
				+ (resp.getDecision() ? "Permit" : "Deny") + "\"");
		
	}

	private void runTestCase21() throws Exception {
		System.out.println("\nCanh's test case 1: XACML PEP to XACML PDP\n");

		String resourceInputURI = "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.3.1.16/target=10.7.3.13";
		// //
		// // Test parameters
		// String subjectId = "WHO740@users.testbed.ist-phosphorus.eu";
		// String subjconfdata = "2SeDFGVHYTY83ZXxEdsweOP8Iok";
		// String roles = "researcher";
		// String roles = "admin";
		// String subjctx = "demo001";

		HashMap<String, String> subjmap = SubjectSet.getSubjSetTest();

		// extracting subject attrs from the subjmap
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID);
//		String subjconfdata = subjmap.get(ConstantsNS.SUBJECT_CONFDATA);
//		String roles = subjmap.get(ConstantsNS.SUBJECT_ROLE);
//		String subjctx = subjmap.get(ConstantsNS.SUBJECT_CONTEXT);

		// subjmap.put(ConstantsNS.SUBJECT_SUBJECT_ID,
		// "CN=Test2, OU=Test2, O=Test, L=Test, ST=Test, C=TE");
		// subjmap.put(ConstantsNS.SUBJECT_SUBJECT_ID,
		// "CN=Test2,OU=Test2,O=Test,L=Test,ST=Test,C=TE");

		// Cryptostring DES or HMAC
		// String anystring =
		// HelpersHexConverter.byteArrayToHex(HMACprocessor.computeHMAC(subjectId,
		// HMACprocessor.getCrypto4hashTest(), null));
		String anystring = CryptoData.doEncryptDataHex(subjectId,
				CryptoData.getKeyPassTest());
		anystring = AuthenticateSubject.getSubjectAuthnCrypto(subjectId,
				AuthenticateSubject.AUTHN_SUBJECT_METHOD_DES, null);

		String decrypted = CryptoData.doDecryptDataHex(anystring,
				CryptoData.getKeyPassTest());
		System.out.println("\nTest GAAAPI: " + "subjectId = " + subjectId
				+ "\nencrypted = " + anystring + "\ndecrypted = " + decrypted);

		subjmap.put(ConstantsNS.SUBJECT_CONFDATA, anystring);
		// subjmap.put(ConstantsNS.SUBJECT_CONFDATA, "verkeerde_string");

		System.out.println("\nTest GAAAPI: " + subjmap);
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);

		HashMap resmap = ResourceHelper.parseResourceURI(resourceInputURI);
		
		HashMap<String, String> actmap = new HashMap<String, String>();

		String action = ActionSet.NSP_CREATE_PATH;
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);
		
		//boolean decision = _pep.authorizeAction(resourceInputURI, actions, subjmap);
		
		AuthorizationRequest authzRequest = new AuthorizationRequestImpl();
		authzRequest.getSubject().putAll(subjmap);
		authzRequest.getResource().putAll(resmap);
		authzRequest.getAction().putAll(actmap);
		
		//////////////////////////
		//// Using SAML-XACML profile to communicate with a SAML-XACML PDP, using SAML-XACML PDP Proxy
		
//		// create a local SAML-XACML PDP
//		SAMLXACMLPDP pdp = new SimpleSAMLXACMLPDPImpl();
//		
//		// create a local proxy (XACML or SAML) to connect to the PDP
//		XACMLPDPProxy pdpProxy = new LocalSAMLPDPProxyImpl(pdp);

		//***********
		// Using XACML PDP, create a XACML PDP proxy 
		XACMLPDP pdp = new SimpleXACMLPDPImpl();
		XACMLPDPProxy pdpProxy = new LocalXACMLPDPProxyImpl(pdp);
		
				
		// create PEP to consume this proxy
		PEP myPEP = new PEPImpl(pdpProxy);
		
		// evaluation
		AuthorizationResponse resp = myPEP.authorizeAction(authzRequest);
		
		//boolean decision = _pep.authorizeAction(authzRequest);
		
		System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
				+ (resp.getDecision() ? "Permit" : "Deny") + "\"");
	}

	private void runTestCase8() throws Exception {
		{ // AuthZ session with AuthzToken
			boolean retticket = true;
			String resourceId;
			resourceId = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
			// resourceId =
			// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
			String sessionCreds = ConfigTrustDomains.SESSION_TOKEN;
			testGAAAPITriagePDPXACML(resourceId, retticket, sessionCreds);
			return;
		}
	}

	private void runTestCase7() throws Exception {
		// AuthZ session with AuthzTicket
		boolean retticket = true;
		String resourceId;
		resourceId = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		String sessionCreds = ConfigTrustDomains.SESSION_TICKET_AAA;
		testGAAAPITriagePDPXACML(resourceId, retticket, sessionCreds);
	}

	private void runTestCase6() throws Exception {
		// AuthZ session with AuthzTicket
		boolean retticket = false;
		String resourceId;
		resourceId = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		String sessionCreds = ConfigTrustDomains.SESSION_TICKET_AAA;
		testGAAAPITriagePDPXACML(resourceId, retticket, sessionCreds);
	}

	private void runTestCase5() throws Exception,
			NotCorrectOrUnknownNSException, MalformedResourceIdException,
			NotAuthenticatedException, NotAuthorizedException,
			NotAvailablePDPException, IOException {
		// AuthZ session management with AuthzToken: intr- and
		// inter-domain
		boolean retticket = false;
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);
		String resourceInputURI;
		String domainViola = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_VIOLA;
		String domainI2CAT = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_I2CAT;
		// String domainId = domainViola;

		// range (10.3.*, 10.4.*, 10.7.*, 10.8.*)
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceInputURI =
		// "http://testbed.ist-phosphorus.eu/resource-type/viola";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.3.1.16/target=10.7.3.13";
		resourceInputURI = domainViola + "/harmony/"
				+ "source=10.3.1.16/target=10.7.3.13";
		// no policy for I2CAT
		// resourceInputURI = domainI2CAT + "/harmony/" +
		// "source=10.3.1.16/target=10.7.3.13";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus/experiment=demo010";

		HashMap resmap = ResourceHelper.parseResourceURI(resourceInputURI);
		HashMap<String, String> actmap = new HashMap<String, String>();
		HashMap<String, String> subjmap = new HashMap<String, String>();
		subjmap = SubjectSet.getSubjSetTest();

		String action = ActionSet.NSP_CREATE_PATH;
		// action = "cancel";
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);
		// some modifications for experiments
		// subjmap.put(ConstantsNS.SUBJECT_ROLE, "student");
		// subjmap.put(ConstantsNS.SUBJECT_CONTEXT, "demo001");
		subjmap.put(ConstantsNS.SUBJECT_CONTEXT, "demo041");
		//
		System.out.println("\nResMap = " + resmap);
		System.out.println("\nSubjMap = " + subjmap);
		//

		// resmap.put(ConstantsXACMLprofileNRP.RESOURCE_REALM, "null");
		// resmap.put(ConstantsXACMLprofileNRP.DOMAIN_ID,
		// "http://testbed.ist-phosphorus.eu/viola/");
		System.out.println("\nResMap = " + resmap);
		String polfile = PolicyResolver.getPolicyFile(resmap, subjmap);
		System.out.println("\nPolicy file = " + polfile);
		// /
		String localdir = "x-output/";
		int delegtype;
		int sescredtype;
		int renew;
		//
		/*
		 * // METHOD #7 - intra-domain delegation, boolean test delegtype = 3;
		 * String tokenfile7 = "tvs-aztoken00-full.xml"; //String tokenfile7 =
		 * "tvs-aztoken01-pilot03-previous.xml"; //String tokenfile7 =
		 * "tvs-aztoken01-pilot01.xml"; //String tokenfile7 =
		 * "tvs-aztoken01-pilot02-viola.xml"; String sescredtoken7 =
		 * HelpersReadWrite.readFileToString(localdir + tokenfile7);
		 * System.out.println(
		 * "\nMethod#7: Start testing boolean PEP.authorizeActionSession(token)"
		 * ); System.out.println("\nSession creds token: \n" + sescredtoken7);
		 * //gri=e71e2d52f6aac48255e059b7bd01df68ae6a2ceb //boolean decision =
		 * PEP.authorizeActionSession (sescredtoken7, null, delegtype, resmap,
		 * actmap, subjmap); boolean decision = PEP.authorizeActionSession
		 * (sescredtoken7, null, delegtype, resmap, actmap, null); //boolean
		 * decision = PEP.authorizeActionSession (sescredtoken7,
		 * "e71e2d52f6aac48255e059b7bd01df68ae6a2ceb", delegtype, resmap,
		 * actmap, subjmap); System.out.println(
		 * "\nMethod#7: Result boolean PEP.authorizeActionSession(token): " +
		 * "PDP decision is \"" + (decision ? "Permit" : "Deny") + "\"\n");
		 */// ///
			// METHOD #8 - intra-domain delegation and token return test
		sescredtype = 2;
		delegtype = 3;
		// String tokenfile8 = "tvs-aztoken00-full.xml";
		System.out
				.println("\nMethod#8: Start testing String PEP.authorizeActionSession(token) "
						+ "\n Step 1. Token=null, Requesting PDP decision and a token");
		// gri=e71e2d52f6aac48255e059b7bd01df68ae6a2ceb
		// String returnToken1 = PEP.authorizeActionSession (null, null,
		// delegtype, sescredtype, resmap, actmap, subjmap);
		String returnToken1 = _pep.authorizeActionSession(null,
				"e71e2d52f6aac48255e059b7bd01df68ae6a2ceb", delegtype,
				sescredtype, resmap, actmap, subjmap);
		// String returnToken = PEP.authorizeActionSession
		// (sescredtoken8, delegtype, sescredtype, resmap, actmap,
		// subjmap);
		// saving token for next use
		String tokenfile8 = "tvs-aztoken8-pilot10-full.xml";
		// String tokenfile8 = "tvs-aztoken01-pilot02-viola.xml";
		HelpersReadWrite.writeToFile(returnToken1, (localdir + tokenfile8));
		System.out
				.println("\nMethod#8 (1): Result String PEP.authorizeActionSession(token): Returned token\n"
						+ returnToken1);
		// //
		String sescredtoken8 = HelpersReadWrite.readFileToString(localdir
				+ tokenfile8);
		delegtype = 3;
		System.out
				.println("\nMethod#8: Continue testing String PEP.authorizeActionSession(token) "
						+ "\nStep 2. Token is not null, Requesting PDP decision");
		System.out.println("\nSession creds token: \n" + sescredtoken8);
		// String returnToken2 = PEP.authorizeActionSession
		// (sescredtoken8, "1" +
		// "e71e2d52f6aac48255e059b7bd01df68ae6a2ceb", delegtype,
		// sescredtype, resmap, actmap, subjmap);
		// String returnToken2 = PEP.authorizeActionSession
		// (sescredtoken8, null, delegtype, sescredtype, resmap, actmap,
		// subjmap);
		String returnToken2 = _pep.authorizeActionSession(sescredtoken8, null,
				delegtype, sescredtype, resmap, actmap, subjmap);
		System.out
				.println("\nMethod#8 (2): Result String PEP.authorizeActionSession(token): Returned token\n =="
						+ returnToken2 + "==");
		// //
		// METHOD #9 - inter-domain delegation and token return/relay
		// test
		sescredtype = 2;
		delegtype = 3;
		renew = 1;
		// String tokenfile9 = "tvs-aztoken9-pilot02-i2cat.xml";
		// String tokenfile9 = "tvs-aztoken9-pilot10-full.xml";
		String tokenfile9 = "tvs-aztoken01-pilot02-viola.xml";
		System.out
				.println("\n\nMethod#9: Start testing String PEP.authorizeActionSession(token) "
						+ "\n Step 1. Token=null, Requesting PDP decision and a nextToken");
		// System.out.println("\nSession creds token: \n" +
		// sescredtoken9);
		// gri = "e71e2d52f6aac48255e059b7bd01df68ae6a2ceb";
		String returnNextToken1 = _pep.authorizeActionSession(null,
				"e71e2d52f6aac48255e059b7bd01df68ae6a2ceb", delegtype,
				sescredtype, renew, resmap, actmap, subjmap);
		// String returnNextToken1 = PEP.authorizeActionSession (null,
		// null, delegtype, sescredtype, renew, resmap, actmap,
		// subjmap);
		// String tokenfile9 = "tvs-aztoken9-pilot10-full.xml";
		HelpersReadWrite.writeToFile(returnNextToken1, (localdir + tokenfile9));
		System.out
				.println("\nMethod#9 (1): Result String PEP.authorizeActionSession(token): Returned token\n"
						+ returnNextToken1);
		//
		System.out
				.println("\nMethod#9: Continue testing String PEP.authorizeActionSession(token) "
						+ "\nStep 2. Token is not null, Requesting PDP decision");
		tokenfile9 = "tvs-aztoken01-pilot02-i2cat.xml";
		String sescredtoken9 = HelpersReadWrite.readFileToString(localdir
				+ tokenfile9);
		System.out.println("\nMethod#9: Session creds token: \n"
				+ sescredtoken9);
		// String returnTokenNext = PEP.authorizeActionSession (null,
		// null, delegtype, sescredtype, renew, resmap, actmap,
		// subjmap);
		// String returnTokenNext = PEP.authorizeActionSession (null,
		// "e71e2d52f6aac48255e059b7bd01df68ae6a2ceb", delegtype,
		// sescredtype, renew, resmap, actmap, subjmap);
		String returnTokenNext = _pep.authorizeActionSession(sescredtoken9,
				"e71e2d52f6aac48255e059b7bd01df68ae6a2ceb", delegtype,
				sescredtype, renew, resmap, actmap, subjmap);
		System.out
				.println("\nMethod#9: Result renew String PEP.authorizeActionSession(token): Returned/Relayed token\n =="
						+ returnTokenNext + "==");
	}

	private void runTestCase4() throws Exception,
			NotCorrectOrUnknownNSException, MalformedResourceIdException,
			IOException, MalformedXMLTokenException,
			NotValidAuthzTokenException, NotAuthenticatedException,
			NotAuthorizedException, NotAvailablePDPException {
		// 4 - test PEP-TVS (2): Request PEP-XACMLPDP with
		// AuthzToken
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);
		String resourceInputURI;
		String domainViola = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_VIOLA;
		// TODO: URN resourceId doesn't work
		// range (10.3.*, 10.4.*, 10.7.*, 10.8.*)
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/harmony";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/viola/harmony/" +
		// "source=10.3.1.16/target=10.7.3.13";
		resourceInputURI = domainViola + "/harmony/"
				+ "source=10.3.1.16/target=10.7.3.13";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus/experiment=demo010";
		// resourceId =
		// "x-urn:nrp:testbed.ist-phosphorus.eu:resource-context:phosphorus:test=demo001";

		HashMap resmap = ResourceHelper.parseResourceURI(resourceInputURI);
		HashMap<String, String> actmap = new HashMap<String, String>();
		HashMap<String, String> subjmap = new HashMap<String, String>();
		subjmap = SubjectSet.getSubjSetTest();

		String action = ActionSet.NSP_CREATE_PATH;
		// action = "cancel";
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);
		// some modifications for experiments
		// subjmap.put(ConstantsNS.SUBJECT_ROLE, "student");
		subjmap.put(ConstantsNS.SUBJECT_CONTEXT, "demo041");
		System.out.println("\nTestGAAAPI: ResMap = " + resmap);
		System.out.println("\nTestGAAAPI: SubjMap = " + subjmap);

		String tokenfile = "tvs-aztoken00-pep-tvs.xml";
		String localdir = "x-output/";
		String aztstr = HelpersReadWrite.readFileToString(localdir + tokenfile);
		System.out.println("\nTestGAAAPI: Token file to read: "
				+ (localdir + tokenfile));
		Document tokendoc = HelpersReadWrite
				.readFileToDOM(localdir + tokenfile);
		HelpersXMLsecurity.printDOMdoc(tokendoc);

		// Checking token validity is optional for this test case
		XMLTokenType token = new XMLTokenType(tokendoc);

		boolean timevalid = token.isTimeValid(token);
		System.out.println("\nTest PEP-TVS: Token validity time: "
				+ (timevalid ? "=VALID=" : "=INVALID="));

		boolean validToken = TVS.validateXMLToken(tokendoc, null);
		System.out.println("Token elements: TokenId = " + token.getTokenid()
				+ "; SessionId = " + token.getSessionid() + "; Issuer = "
				+ token.getIssuer() + "\nValid from " + token.getNotBefore()
				+ " to " + token.getNotOnOrAfter() + "\nTokenValue = "
				+ token.getTokenValue() + "\nTokenDomain = "
				+ token.getTokenDomain() + "\nTokenType = "
				+ token.getTokenType());
		System.out.println("\nSimple Token validation by TVS: Token validity: "
				+ (validToken ? "=VALID=" : "=INVALID="));

		System.out
				.println("\n(Stage 3 - Access): Request PEP-XACMLPDP with AuthzToken. \n"
						+ "Validating AuthZ Request against Token provided using session context stored by TVS");

		boolean confirmed = TVS.validateAuthzRequestByToken(aztstr, resmap,
				actmap, subjmap);
		System.out
				.println("\nAuthZ request validated by TVS against XMLToken:\n"
						+ "PEP-TVS result is \""
						+ (confirmed ? "Confirmed" : "Failed") + "\"\n");

		boolean decision = _pep
				.authorizeAction(aztstr, resmap, actmap, subjmap);
		System.out
				.println("\nAuthZ request validated by TVS against XMLToken:\n"
						+ "TVS result is \"" + (decision ? "Permit" : "Deny")
						+ "\"\n");
	}

	private void runTestCase3() throws Exception,
			NotCorrectOrUnknownNSException, MalformedResourceIdException,
			IOException {
		// "3 - test PEP-TVS (1): Request PEP-XACMLPDPD -> Program TVS -> create XMLToken "
		boolean retticket = false;
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);
		String resourceInputURI;
		String domainViola = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_VIOLA;
		// TODO: URN resourceId doesn't work
		// range (10.3.*, 10.4.*, 10.7.*, 10.8.*)
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/harmony";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/viola/harmony/" +
		// "source=10.3.1.16/target=10.7.3.13";
		resourceInputURI = domainViola + "/harmony/"
				+ "source=10.3.1.16/target=10.7.3.13";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus/experiment=demo010";
		// resourceId =
		// "x-urn:nrp:testbed.ist-phosphorus.eu:resource-context:phosphorus:test=demo001";

		HashMap resmap = ResourceHelper.parseResourceURI(resourceInputURI);
		HashMap<String, String> actmap = new HashMap<String, String>();
		HashMap<String, String> subjmap = new HashMap<String, String>();
		subjmap = SubjectSet.getSubjSetTest();

		String action = ActionSet.NSP_CREATE_PATH;
		// action = "cancel";
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);
		// some modifications for experiments
		// subjmap.put(ConstantsNS.SUBJECT_ROLE, "student");
		// subjmap.put(ConstantsNS.SUBJECT_CONTEXT, "demo001");
		subjmap.put(ConstantsNS.SUBJECT_CONTEXT, "demo041");
		System.out.println("\nResMap = " + resmap);
		System.out.println("\nSubjMap = " + subjmap);

		// boolean decision = PEP.authorizeAction (resourceId, actions,
		// subjectId, subjconfdata, roles, subjctx);
		//
		boolean decision0 = _pep.authorizeAction(resmap, actmap, subjmap);
		// + testing Exist policy reposirory
		String PolicyId = "http://testbed.ist-phosphorus.eu/viola/harmony/demo010/policy2:tna";
		// System.out.println(PolicyId);
		// boolean decision0 = PEP.authorizeAction (resmap, actmap,
		// subjmap, PolicyId);
		// -

		System.out
				.println("\nTest PEP-TVS (Stage 1 - Reservation ): Request PEP-XACMLPDPD -> create XMLToken");
		System.out.println("\nTest PEP-TVS: Step 1 - Request PEP-XACMLPDPD: \n"
				+ "PDP decision is \"" + (decision0 ? "Permit" : "Deny")
				+ "\"\n");
		//
		int validtime = 24 * 60 * 60; // 24 hrs
		boolean simple = false;
		String gri = sessionId;
		if (!decision0) {
			System.out
					.println("\nAuthZ decision is Deny. No SessionCtx to saved, no XML token created. "
							+ "Check AuthZ attributes or policy.");
			return;
		}

		// Saving session context
		// DomainId is created from resmap and next based on DomainId
		// the TVS token authority is resolved
		// String domainId =
		// TokenBuilder.getTokenDomain(ConfigTrustDomains.AAA_TOKEN_ISSUER);
		String domainId = domainViola;
		Vector sessionCtx = TVS.getSessionCtxVector(domainId, gri, resmap,
				actmap, subjmap);

		TVS.setEntryTVSTable(domainId, gri, sessionCtx);
		// / This is test with Exist DB
		// TVS.setEntryToExist(domainId, gri, sessionCtx);

		System.out
				.println("\nTest PEP-TVS (Stage 2 - Deployment):  -> Program TVS && create XMLToken");
		System.out
				.println("\nTest PEP-TVS: Step 2 - Saved Session/GRI context in TVSTable: \n"
						+ "DomainId = " + domainId + "\nGRI = " + gri + "\n");
		String tablefile = TVS.getTVSTableFile();
		Document tabdoc = HelpersXMLsecurity.readFileToDOM(tablefile);
		HelpersXMLsecurity.printDOMdoc(tabdoc);

		//
		String tokenxml = TokenBuilder.getXMLToken(domainId, gri, null,
				validtime, simple);
		String tokenfile = "tvs-aztoken00-pep-tvs.xml";
		String localdir = "x-output/";
		HelpersReadWrite.writeToFile(tokenxml, (localdir + tokenfile));

		System.out
				.println("\nTest PEP-TVS: Step 3 - Created XMLToken and saved in file\n"
						+ (localdir + tokenfile) + " \n\n" + tokenxml);

		// XMLTokenType xmltok = new XMLTokenType (tokenxml);
		// String domainId = xmltok.getTokenDomain();

	}

	private void runTestCase2() throws Exception {
		// 2 - test GAAAPI: Test PDPXACML & booleanPEP (complex
		// ResourceId)
		boolean retticket = false;
		String resourceId;
		// range (10.3.*, 10.4.*, 10.7.*, 10.8.*)
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/harmony";
		resourceId = "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.3.1.16/target=10.7.2.13";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus/experiment=demo010";
		// TODO: URN resourceId doesn't work
		// resourceId =
		// "x-urn:nrp:testbed.ist-phosphorus.eu:resource-context:phosphorus:test=demo001";
		// ResourceHelper.parseResourceURI(resourceId);
		String subjctx0 = null;
		subjctx0 = "demo047";
		String subjrole = null;
		// subjrole = "student";
		// subjrole = "admin";
		String action = null;
		// action = "activate-path";
		// Note: This is calling intermediate method to request PEP.
		// For the PEP request use refer to internal of
		// testGAAAPIRequestXACMLPDP() method
		testGAAAPIRequestXACMLPDP(resourceId, subjctx0, subjrole, action,
				retticket);
	}

	private void runTestCase1() throws Exception {
		// "1 - test GAAAPI: Test PDPXACML & booleanPEP (simple
		// ResourceId);
		boolean retticket = false;
		String resourceInputURI;
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/harmony";
		resourceInputURI = "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.3.1.16/target=10.7.3.13";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
		// resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-context/phosphorus/experiment=demo001";
		// TODO: URN resourceId doesn't work
		// resourceId =
		// "x-urn:nrp:testbed.ist-phosphorus.eu:resource-context:phosphorus:test=demo001";
		// HelpersXMLsecurity.isStringXML("ajajajaj");

		testGAAAPIRequestXACMLPDPSimple(resourceInputURI, retticket);
	}

	private void Initialize() {
		_pep = new PEPLocal();

	}

	public void WP1testAAAtestDifferentAPICalls() throws Exception {
		boolean result;
		HashMap subjmap = new HashMap();
		HashMap resmap = new HashMap();
		HashMap<String, String> actmap = new HashMap<String, String>();
		/* setup configuration ---------------------------------------------- */
		String resourceIdURI = "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.7.12.2/target=10.3.17.3";
		subjmap = SubjectSet.getSubjSetTest();
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID)
				.toString();
		String subjectConfdata = subjmap.get(ConstantsNS.SUBJECT_CONFDATA)
				.toString();
		String subjectRole = subjmap.get(ConstantsNS.SUBJECT_ROLE).toString();
		String subjectContext = subjmap.get(ConstantsNS.SUBJECT_CONTEXT)
				.toString();
		String action = ActionSet.NSP_CREATE_PATH;
		action = "cancel";
		resmap = ResourceHelper.parseResourceURI(resourceIdURI);
		String resourceId = resmap.get(ConstantsNS.RESOURCE_RESOURCE_ID)
				.toString();

		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);
		System.out.println("\nSubjMap = " + subjmap);
		System.out.println("\nResMap = " + resmap);
		System.out.println("\nActMap = " + actmap);
		/* ------------------------------------------------------------------ */

		/* get the decisions ------------------------------------------------ */
		result = _pep.authorizeAction(resourceIdURI, action, subjmap);

		result = _pep.authorizeAction(resmap, actmap, subjmap);

		// Assert.assertTrue("Method SSM should return true", result);

		// FIXME: this throws an PDPResponceException("NotApplicable")
		// result = PEP.authorizeAction(resourceId, action, subjectId,
		// subjectConfdata, subjectRole, subjectContext);
		// Assert.assertTrue("Method SSSSSS should return true", result);
		/* ------------------------------------------------------------------ */
		System.out.println("Decision = " + result);
	}

	// Simplest test to track Request generation, parsing and PDPLocal decision
	public void testGAAAPIRequestPDPlocal() throws Exception {
		// //
		// // Static parameters
		String sessionId = "sessionIDtest";
		String subjectId = "WHO740@users.collaboratory.nl";
		String subjconfdata = "SeDFGVHYTY83ZXxEdsweOP8Iok";
		// Note, role must be in small leters
		String roles = "analyst";
		// String roles = "customer";
		String jobId = "JobID-XPS1-212";
		String subjctx = jobId;
		String resourceId = "http://resources.collaboratory.nl/Phillips_XPS1";
		// Note, for TestPDPLocaluse actions semantic as above
		// String actions = Action.CONTROL_INSTRUMENT;
		String actions = "ControlInstrument";

		// System.out.println("\nTest subjectId = " + subjectId);
		boolean decision = _pep.authorizeActionTest(resourceId, actions,
				subjectId, subjconfdata, roles, subjctx);

		// boolean decision = PEP.authorizeActionBoolean(null, sessionId,
		// resourceId, actions, subjectId, subjconfdata, roles, subjctx);
		System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
				+ (decision ? "Permit" : "Deny") + "\"");

	}

	public void testGAAAPIRequestXACMLPDPSimple(String resourceId,
			boolean retticket) throws Exception {
		// //
		// // Test parameters
		// String subjectId = "WHO740@users.testbed.ist-phosphorus.eu";
		// String subjconfdata = "2SeDFGVHYTY83ZXxEdsweOP8Iok";
		// String roles = "researcher";
		// String roles = "admin";
		// String subjctx = "demo001";
		HashMap<String, String> subjmap = SubjectSet.getSubjSetTest();
		// extracting subject attrs from the subjmap
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID).toString();
		
		String subjconfdata = subjmap.get(ConstantsNS.SUBJECT_CONFDATA).toString();
		
		String roles = subjmap.get(ConstantsNS.SUBJECT_ROLE).toString();
		
		String subjctx = subjmap.get(ConstantsNS.SUBJECT_CONTEXT).toString();

		// subjmap.put(ConstantsNS.SUBJECT_SUBJECT_ID,
		// "CN=Test2, OU=Test2, O=Test, L=Test, ST=Test, C=TE");
		// subjmap.put(ConstantsNS.SUBJECT_SUBJECT_ID,
		// "CN=Test2,OU=Test2,O=Test,L=Test,ST=Test,C=TE");

		// test modify subjmap
		String fileSigned1 = "x-output/uc6-assertion01-signed.xml";
		String fileSigned2 = "x-output/uc6-assertion02-signed2validate.xml";
		String fileSigned3 = "x-output/uc6-assertion03-signed2validate.xml";
		// String anystring = HelpersXMLsecurity.readFileToString(fileSigned1);
		// String anystring = AuthenticateSubject.AUTHN_SUBJECT_CONFIRMED;

		// Cryptostring DES or HMAC
		// String anystring =
		// HelpersHexConverter.byteArrayToHex(HMACprocessor.computeHMAC(subjectId,
		// HMACprocessor.getCrypto4hashTest(), null));
		String anystring = CryptoData.doEncryptDataHex(subjectId, CryptoData.getKeyPassTest());
		anystring = AuthenticateSubject.getSubjectAuthnCrypto(subjectId,
				AuthenticateSubject.AUTHN_SUBJECT_METHOD_DES, null);

		String decrypted = CryptoData.doDecryptDataHex(anystring,
				CryptoData.getKeyPassTest());
		System.out.println("\nTest GAAAPI: " + "subjectId = " + subjectId
				+ "\nencrypted = " + anystring + "\ndecrypted = " + decrypted);

		subjmap.put(ConstantsNS.SUBJECT_CONFDATA, anystring);
		// subjmap.put(ConstantsNS.SUBJECT_CONFDATA, "verkeerde_string");

		System.out.println("\nTest GAAAPI: " + subjmap);
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);
		// String resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		String actions = ActionSet.NSP_CREATE_PATH;
		// actions = "cancel";

		if (!retticket) {
			// boolean decision = PEP.authorizeAction (resourceId, actions,
			// subjectId, subjconfdata, roles, subjctx);
			boolean decision = _pep.authorizeAction(resourceId, actions,
					subjmap);
			System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
					+ (decision ? "Permit" : "Deny") + "\"");
		} else {
			// String azticket = PEP.authorizeActionTicket(null, sessionId,
			// actions, resourceId, roles, subjectId, subjconfdata, subjctx);
			String azticket = _pep.authorizeAction(null, sessionId, resourceId, actions, subjmap);
			
			System.out.println("\nTestGAAAPI TestPDPlocal: AuthzTicket returned:\n" + azticket);
		}

	}

	public void testGAAAPIRequestXACMLPDP(String resourceId, String subjctx0,
			String subjrole, String action, boolean retticket) throws Exception {
		// //
		HashMap<String, String> subjmap = new HashMap<String, String>();
		HashMap resmap = new HashMap();
		HashMap actmap = new HashMap();

		//
		subjmap = SubjectSet.getSubjSetTest();
		// extracting subject attrs from the subjmap
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID)
				.toString();
		String subjconfdata = subjmap.get(ConstantsNS.SUBJECT_CONFDATA)
				.toString();
		String roles = subjmap.get(ConstantsNS.SUBJECT_ROLE).toString();
		String subjctx = subjmap.get(ConstantsNS.SUBJECT_CONTEXT).toString();
		// modifying subjctx for experiments
		if (subjrole != null) {
			subjmap.put(ConstantsNS.SUBJECT_ROLE, subjrole);
		}
		// subjmap.put(ConstantsNS.SUBJECT_SUBJECT_ID,
		// "WHO750@users.testbed.ist-phosphorus.eu");
		if (subjctx0 != null) {
			subjmap.put(ConstantsNS.SUBJECT_CONTEXT, subjctx0);
		}

		System.out.println("\nSubjMap = " + subjmap);

		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);
		// String resourceId =
		// "http://testbed.ist-phosphorus.eu/resource-type/nsp";
		resmap = ResourceHelper.parseResourceURI(resourceId);

		if (action == null) {
			action = ActionSet.NSP_CREATE_PATH;
		}

		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);

		if (!retticket) {
			// boolean decision = PEP.authorizeAction (resourceId, actions,
			// subjectId, subjconfdata, roles, subjctx);
			boolean decision = _pep.authorizeAction(resmap, actmap, subjmap);
			// boolean decision = PEP.authorizeAction(resourceId, action,
			// subjmap);
			System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
					+ (decision ? "Permit" : "Deny") + "\"");
		} else {
			// String azticket = PEP.authorizeActionTicket(null, sessionId,
			// actions, resourceId, roles, subjectId, subjconfdata, subjctx);
			String azticket = _pep.authorizeAction(null, sessionId, resourceId,
					action, subjmap);
			System.out
					.println("\nTestGAAAPI TestPDPlocal: AuthzTicket returned:\n"
							+ azticket);
		}

	}

	// PEP is configured to return the same type of session creds as included
	// into request
	// If no session creds are included, the AuthzTicket is returned as default
	// confguration
	// TODO: working with AuthzToken will require changing initiation of the PEP
	// configured to return AuthzToken
	public void testGAAAPITriagePDPXACML(String resourceId, boolean retticket,
			String sessionCreds) throws Exception {
		// //
		String azticket = null;
		String aztoken = null;
		String azticktok = null;
		boolean decision = false;

		// // Static parameters
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);

		HashMap subjmap = SubjectSet.getSubjSetTest();

		// String resourceId =
		// "http://resources.collaboratory.nl/Phillips_XPS1";

		// TODO: Define actions semantic "cnl:actions:ControlInstrument"
		String actions = ActionSet.NSP_CREATE_PATH;

		// //// TODO: This part should move to TAConfig
		String configId = ConfigSecurity.getSecurityConfigId();
		String pdpdecisionTicket = "permit";

		// String trustdomain = ConfigTrustDomains.TRUSTDOMAIN_PEP;
		// Init Config/Environment for ticket generation
		// TODO: decide on Ticket authority - who issues the AuthzTicket?
		// tickauth = "tickauth:pep" or "tickauth:pdp"
		// String tickauth = ConfigSecurity.getTicketAuthority (configId,
		// trustdomain);
		// System.out.println("PEP.authoriseActionTicket: configId=" + configId
		// + "; trustdomain=" + trustdomain + "; ticketauth=" + tickauth);

		// Receive parameters for the pubkey keystore for cnl02 test profile
		List keyconf = KeyStoreConfig.getConfigKeysPEP(configId);
		Key privkey = KeyStoreIF.getPrivKey(keyconf);
		// Key pubkey = KeyStoreIF.getPublicKey(keyconf);
		List uri2sign = null; /* signing whole document */

		// Time validity: startms - in ms; endhrs - hrs
		Date startDate = new Date();
		Date endDate = new Date();
		// Setting validity for 24 hrs
		long startms = 0;
		long endhrs = 24;
		startDate = new Date(startDate.getTime() + startms);
		endDate = new Date(startDate.getTime() + (endhrs * 60 * 60 * 1000));
		// ////

		// extracting subject attrs from the subjmap
		String subjectid = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID)
				.toString();
		String subjconfdata = subjmap.get(ConstantsNS.SUBJECT_CONFDATA)
				.toString();
		String roles = subjmap.get(ConstantsNS.SUBJECT_ROLE).toString();
		String subjctx = subjmap.get(ConstantsNS.SUBJECT_CONTEXT).toString();

		// Resolse PolicyIDRef on ResourceId and ExperimentId
		String experimentId = subjctx; // temporary TODO: to beplaced with
		// subjctx or attr NS
		String policyIDRef = PolicyResolver.getPolicyIDRef(resourceId,
				experimentId);

		// System.out.println("\n\nPEP.authorizeAction(TicketToken) input subjset check \n"
		// + subjectid + ", " + subjconfdata + ", " + experimentId + ", " +
		// roles + "\n\n");

		// composing actset as HashSet
		// String action = "cnl:actions:CtrlInstr";
		Collection actset = ActionSet.getActionSet(actions);

		// //////////

		// This is how the AuthzTicket is created and signed
		/*
		 * Document azticketdoc = AuthzTicketType.createSimpleTicket(sessionId,
		 * policyIDRef, pdpdecisionTicket, resourceId, startDate, endDate,
		 * subjmap, actset); azticketdoc =
		 * AuthzTicketType.signTicket(azticketdoc, uri2sign, privkey); Document
		 * aztokendoc = AuthzTokenType.createTokenSigned(azticketdoc, null);
		 */

		String azticktok1 = _pep.authorizeAction(null, sessionId, resourceId,
				actions, subjmap);
		Document azticketdoc = HelpersXMLsecurity.readStringToDOM(azticktok1);

		// Document aztokendoc = AuthzTokenType.createTokenSigned(azticketdoc,
		// null);
		// String aztoken1 = HelpersXMLsecurity.convertDOMToString(aztokendoc);

		if (sessionCreds.equals(ConfigTrustDomains.SESSION_TOKEN)) {
			Document aztokendoc = AuthzTokenType.createTokenSigned(azticketdoc,
					null);
			azticktok1 = HelpersXMLsecurity.convertDOMToString(aztokendoc);
		}

		System.out
				.println("\nTest GAAAPI Triage: AuthzTicketToken created(1):\n"
						+ azticktok1);

		if (retticket) {
			aztoken = _pep.authorizeAction(azticktok1, sessionId, resourceId,
					actions, subjmap);
			System.out
					.println("\nTestGAAAPI Triage TestPDPlocal: CNLAuthzTicket returned(2):\n"
							+ aztoken);
		} else {
			// PEP.AuthoriseActionDefault(userId, jobId, roles, resourceId,
			// actions);
			// PEP.requestPDPdecision (sessionID, actions, resourceID, roles,
			// subjectID, authnToken, jobID);
			azticktok = _pep.authorizeAction(azticktok1, sessionId, resourceId,
					actions, subjmap);
			if (aztoken.equals(null)) {
				decision = false;
			} else {
				decision = true;
			}

			System.out
					.println("\nTest GAAAPI TestPDPlocal with AuthzTicket: PDP decision is \""
							+ (decision ? "Permit" : "Deny") + "\"");
		}
	}

	public void interactiveTestGenerateRequest() throws Exception {
		// Roles list
		System.out
				.println("Input separated by comma (with no space) "
						+ "list of values for [userId, subjctx/jobId, role, resourceId, actionId] :");
		// System.out.println("Suggested list of Roles: 1 - analyst, 2 - customer, 3 - guest, 4 - admin");
		// System.out.println("Suggested list of Actions: 1 - CtrInstr, 2 - CtrExp, 3 - ViewExp, 4 - ViewArch, 5 - AdminTsk");
		System.out
				.println("    Suggested roles: analyst, customer, guest, admin");
		System.out
				.println("    Suggested actions: ContrInstr, ContrExp, ViewExp, ViewArch, AdminTsk");
		ArrayList<String> cin = readIn(1);
		Object[] ocin = cin.toArray();
		int kk = ocin.length;
		String[] reqparams = (String[]) cin.toArray(new String[kk]);
		// System.out.println("I received this Roles list: " + drollist[0] );
		// TODO: dynamic array initialisation
		String[] parlist = new String[10];
		int a = 0;

		for (int i = 0; i < kk; i++) {
			String dtoken = new String();
			int n = 0;
			StringTokenizer st = new StringTokenizer(reqparams[i], ",", true);

			while (st.hasMoreTokens()) {
				String atom = st.nextToken();
				//
				// if (atom == null) {atom = "0";}
				if (!atom.equals(",")) {
					dtoken = atom;
					parlist[n] = dtoken;
					n++;
				}
				a = n;
				// System.out.println("Policy atom: " + n + " " + atom + " " +
				// actlist[n-1]);
			}
		}
		//
		System.out.println("Request parameters list contains " + a
				+ " parameters:");
		for (int i = 0; i < a; i++) {
			System.out.println(parlist[i]);
		}
		String userId = parlist[0];
		String subjctx = parlist[1];
		String roles = parlist[2];
		String resourceId = parlist[3];
		String actions = parlist[4];
		// End of input code
		String request = PEPgenRequest.generateXACMLRequest(userId, null,
				roles, subjctx, resourceId, actions);
		System.out.println("\nRequest generated:\n" + request);
	}

	public static void testGenerateRequest() throws Exception {
		// //NOTE: simplified semantics for actions
		String[] actlist = { "create-path", "activate-path", "cancel",
				"access", "AdminTask", };
		String[] rollist = { "admin", "researcher", "professor", "student", };
		// // Static parameters
		String userId = "WHO740@users.testbed.ist-phosphorus.eu";
		String subjconfdata = "2SeDFGVHYTY83ZXxEdsweOP8Iok"; // dummy authnToken
		// Note, role must be in small leters
		String roles = "researcher";
		// String roles = "customer";
		String subjctx = "demo001";
		// String resourceId =
		// "http://resources.collaboratory.nl/Phillips_XPS1";
		String resourceId = "http://testbed.ist-phosphorus.eu/resource-type/nsp";

		// Note, use actions semantic as above
		String actions = "create-path";

		PEPgenRequest.generateXACMLRequest(userId, subjconfdata, roles,
				subjctx, resourceId, actions);
	}

	private static Vector getSessionCtxVector(String domainId,
			String sessionId, HashMap resmap, HashMap actmap,
			HashMap<String, String> subjmap) throws Exception {
		Vector<Comparable> sessionCtxT = new Vector<Comparable>();
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID)
				.toString();
		// String subjconfdata =
		// subjmap.get(ConstantsNS.SUBJECT_CONFDATA).toString();
		String subjectRole = subjmap.get(ConstantsNS.SUBJECT_ROLE).toString();
		String subjectContext = subjmap.get(ConstantsNS.SUBJECT_CONTEXT)
				.toString();
		//
		String resourceId = (String) resmap
				.get(ConstantsNS.RESOURCE_RESOURCE_ID);
		String resourceSource = (String) resmap.get("source");
		String resourceTarget = (String) resmap.get("target");

		//
		String actionId = (String) actmap.get(ConstantsNS.ACTION_ACTION_ID);
		//
		String keyInfo = TokenKey.getTokenPublic(domainId, sessionId);
		//
		int validminutes = 60;
		// List validTime = getValidityTimeDefault();
		Date notBefore = new Date();
		Date notOnOrAfter = new Date(notBefore.getTime()
				+ (validminutes * 60 * 1000));
		// Date notOnOrAfter = (Date) validTime.get(1);

		sessionCtxT.add(notBefore);
		sessionCtxT.add(notOnOrAfter);
		sessionCtxT.add(actionId);
		sessionCtxT.add(subjectId);
		sessionCtxT.add(subjectRole);
		sessionCtxT.add(subjectContext);
		sessionCtxT.add(resourceId);
		sessionCtxT.add(resourceSource);
		sessionCtxT.add(resourceTarget);
		sessionCtxT.add(keyInfo);

		return sessionCtxT;
	}

	private static void checkConfigSecurity() throws Exception {
		//
		String domainlocal = ConfigDomainsPhosphorus.getDomainLocal();
		System.out.print("\n" + "DomainLocal = " + domainlocal);
		//
		List confsec = new ArrayList();

		// J-
		// All the parameters for the keystore

		String keystoreType = "JKS";
		String keystoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE
				+ "/xmlsec/keystore1xmlsec.jks";
		String keystorePass = "xmlsecurity";
		String privateKeyAlias = "cnl01";
		String privateKeyPass = "xmlsecurity";
		String certificateAlias = "cnl01";

		// /
		confsec.add(keystoreType);
		confsec.add(keystoreFile);
		confsec.add(keystorePass);
		confsec.add(privateKeyAlias);
		confsec.add(privateKeyPass);
		confsec.add(certificateAlias);

		System.out.print("\n" + "keystoreType=" + confsec.get(0).toString()
				+ "\n" + "keystoreFile=" + confsec.get(1).toString() + "\n"
				+ "keystorePass=" + confsec.get(2).toString() + "\n"
				+ "privateKeyAlias=" + confsec.get(3).toString() + "\n"
				+ "privateKeyPass=" + confsec.get(4).toString() + "\n"
				+ "certificateAlias=" + confsec.get(5).toString() + "\n");

		// File signatureFile = new File("testsig01cnl.xml");
		// J+
		KeyStore ks = KeyStore.getInstance(keystoreType);
		FileInputStream fis = new FileInputStream(keystoreFile);

		// //FileOutputStream fus = new FileOutputStream(outFile);
		// //System.out.print(fis.toString());

		// load the keystore
		ks.load(fis, keystorePass.toCharArray());

		// get the private key for signing.
		PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias,
				privateKeyPass.toCharArray());

		System.out.print("\n###Private key: \n" + privateKey.toString()); // ***

	}

	public static String getSessionId(boolean prefix) throws Exception {
		String griprefix = "nsp-domain.uob";

		if (!prefix) {
			griprefix = "";
		}
		String sessionId = GRIgenerator.generateGRI(32, griprefix);
		return sessionId;
	}

	public static List getConfigValidityTime(String domainId, Date startdate,
			int validminutes) throws Exception {
		Date notBefore = new Date();
		Date notOnOrAfter = new Date();
		List<Date> validDates = null;

		if (startdate != null) {
			notBefore = startdate;
		}
		if (validminutes == 0) {
			validminutes = TVS.VALID_TIME_DEFAULT; // 24 hours
		}

		// System.out.println("\nDate = " +
		// HelpersDateTime.datetostring(notBefore));
		notOnOrAfter = new Date(notBefore.getTime()
				+ (validminutes * 60 * 1000));
		validDates.add(notBefore);
		validDates.add(notOnOrAfter);

		return validDates;
	}

	public static List getValidityTimeDefault() throws Exception {

		return getConfigValidityTime(null, null, 0);
	}

	public static void write(String fileName, String text) throws IOException {
		PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(
				fileName)));
		out.print(text);
		out.close();
	}

	// //////////////////////////////
	// Read test File as string

	public static String read(String fileName) throws IOException {
		StringBuffer sb = new StringBuffer();
		BufferedReader in = new BufferedReader(new FileReader(fileName));
		String s;
		while ((s = in.readLine()) != null) {
			sb.append(s);
			sb.append("\n");
		}
		in.close();
		return sb.toString();
	}

	// //////////////////////////////
	// Replace oldstr with newstr in instring

	public static String subst(String oldStr, String newStr, String inString) {

		int start = inString.indexOf(oldStr);
		if (start == -1) {
			return inString;
		}
		StringBuffer sb = new StringBuffer();
		sb.append(inString.substring(0, start));
		sb.append(newStr);
		sb.append(inString.substring(start + oldStr.length()));
		return sb.toString();
	}

	// //////////////////////////////
	// Input roles list

	public static ArrayList<String> readIn(int n) {

		ArrayList<String> lines = new ArrayList<String>();

		for (int i = 0; i < n; i++) {

			String line = null;
			int val = 0;
			try {
				BufferedReader is = new BufferedReader(new InputStreamReader(
						System.in));
				line = is.readLine();
				// val = Integer.parseInt(line);
			}
			// catch (NumberFormatException ex)
			// {System.err.println("Not a valid number: " + line);}
			catch (IOException e) {
				System.err.println("Unexpected IO ERROR: " + e);
			}
			lines.add(line);
			// System.out.println("I read this line: " + line);
		}
		return lines;
	}

	// //////////////////////////////
	// Input menu number (integer)

	public static int readStdinInt() {
		String line = null;
		int val = 0;
		try {
			BufferedReader is = new BufferedReader(new InputStreamReader(
					System.in));
			line = is.readLine();
			val = Integer.parseInt(line);
		} catch (NumberFormatException ex) {
			System.err.println("Not a valid number: " + line);
		} catch (IOException e) {
			System.err.println("Unexpected IO ERROR: " + e);
		}
		// System.out.println("I read this number: " + val);
		return val;
	}

}
