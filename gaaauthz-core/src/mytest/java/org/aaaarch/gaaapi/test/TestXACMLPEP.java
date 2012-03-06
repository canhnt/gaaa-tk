/**
 * @author CanhNT
 *  
 * Created on Feb 09, 2011
 * SNE at UvA
 */
package org.aaaarch.gaaapi.test;

import java.io.*;
import java.util.HashMap;
import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.pdp.XACMLPDP;
import org.aaaarch.pdp.impl.SimpleSAMLXACMLPDPImpl;
import org.aaaarch.pdp.impl.SimpleXACMLPDPImpl;
import org.aaaarch.tvs.TVS;
import org.aaaarch.tvs.impl.TVSImpl;
import org.aaaarch.config.ConstantsNS;
import org.aaaarch.crypto.CryptoData;
import org.aaaarch.gaaapi.ActionSet;
import org.aaaarch.gaaapi.ResourceHelper;
import org.aaaarch.gaaapi.SubjectSet;
import org.aaaarch.gaaapi.authn.AuthenticateSubject;
import org.aaaarch.gaaapi.pep.AuthorizationRequest;
import org.aaaarch.gaaapi.pep.AuthorizationResponse;
import org.aaaarch.gaaapi.pep.AuthorizationToken;
import org.aaaarch.gaaapi.pep.PEP;
import org.aaaarch.gaaapi.pep.XACMLPDPProxy;
import org.aaaarch.gaaapi.pep.impl.AuthorizationRequestImpl;
import org.aaaarch.gaaapi.pep.impl.LocalSAMLPDPProxyImpl;
import org.aaaarch.gaaapi.pep.impl.LocalXACMLPDPProxyImpl;
import org.aaaarch.gaaapi.pep.impl.PEPImpl;
import org.aaaarch.gaaapi.pep.impl.PEPLocal;
import org.aaaarch.gaaapi.tvs.GRIgenerator;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

public class TestXACMLPEP {

	public TestXACMLPEP() {
	}

	public static void main(String args[]) throws IOException {

		
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		TestXACMLPEP test = new TestXACMLPEP();

		test.doTest();
	}

	private void doTest() {
		try {
			System.out
			.println("Running test for PEP/PDP Authorisation components (aaauthreach prj)");
			System.out
			.println("0 - Simple authz request using XACML Request/Response\n"
					+ "1 - Simple authz using XADQ/XADS between PEP-PDP\n"
					+ "2 - authz request using XADQ/XADS and return token\n");
			int s = readStdinInt();
			switch (s) {
			// "0 - test GAAAPI: Simple test PEP & TestPDPlocal (hard-coded
			// policy);
			case 0:
				runTestCase0();
				break;

			case 1:
				runTestCase1();
				break;
				
			case 2:
				runTestCase2();
				break;
			}
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void runTestCase2() throws Exception {
		System.out.println("\nCanh's test case 2: XACML PEP to XACML PDP\n");

		String resourceInputURI = "http://testbed.ist-phosphorus.eu/viola/harmony/source=10.3.1.16/target=10.7.3.13";

		HashMap<String, String> subjmap = SubjectSet.getSubjSetTest();

		// extracting subject attrs from the subjmap
		String subjectId = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID);

		String anystring = CryptoData.doEncryptDataHex(subjectId, CryptoData.getKeyPassTest());
		anystring = AuthenticateSubject.getSubjectAuthnCrypto(subjectId, AuthenticateSubject.AUTHN_SUBJECT_METHOD_DES, null);

		String decrypted = CryptoData.doDecryptDataHex(anystring, CryptoData.getKeyPassTest());
		System.out.println("\nTest GAAAPI: " + "subjectId = " + subjectId
				+ "\nencrypted = " + anystring + "\ndecrypted = " + decrypted);

		subjmap.put(ConstantsNS.SUBJECT_CONFDATA, anystring);
		boolean griprefix = false;
		String sessionId = getSessionId(griprefix);

		HashMap<String, String> resmap = (HashMap<String, String>)ResourceHelper.parseResourceURI(resourceInputURI);

		HashMap<String, String> actmap = new HashMap<String, String>();

		String action = ActionSet.NSP_CREATE_PATH;
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);

		AuthorizationRequest authzRequest = new AuthorizationRequestImpl(subjmap, resmap, actmap, true);

		// OpenSAML boostrap

		// Using SAML-XACML profile to communicate with a SAML-XACML PDP, using
		// SAML-XACML PDP Proxy
		// create a local SAML-XACML PDP
		SAMLXACMLPDP pdp = new SimpleSAMLXACMLPDPImpl();

		// create a local SAML-XACML proxy to connect to the PDP
		XACMLPDPProxy pdpProxy = new LocalSAMLPDPProxyImpl(pdp);
		TVS tvs = new TVSImpl();
		
		// create PEP to consume this proxy
		PEP myPEP = new PEPImpl(pdpProxy, tvs);

		// evaluation
		AuthorizationResponse authzResp = myPEP.authorizeAction(authzRequest);

		// boolean decision = _pep.authorizeAction(authzRequest);

		System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
				+ (authzResp.getDecision() ? "Permit" : "Deny") + "\"");
		
		AuthorizationToken authzToken = authzResp.getToken();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		authzToken.encode(os);
		System.out.println("Token: " + os.toString()); 
		
		//verifying token
		authzRequest.setAuthzToken(authzToken);
		System.out.println("Evaluate authz-request with the authz-token:");
		myPEP.authorizeAction(authzRequest);
	}

	private void runTestCase1() throws Exception {
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

		HashMap<String, String> resmap = (HashMap<String, String>)ResourceHelper.parseResourceURI(resourceInputURI);

		HashMap<String, String> actmap = new HashMap<String, String>();

		String action = ActionSet.NSP_CREATE_PATH;
		actmap.put(ConstantsNS.ACTION_ACTION_ID, action);

		AuthorizationRequest authzRequest = new AuthorizationRequestImpl(subjmap, resmap, actmap, false);

		// OpenSAML boostrap

		// Using SAML-XACML profile to communicate with a SAML-XACML PDP, using
		// SAML-XACML PDP Proxy
		// create a local SAML-XACML PDP
		SAMLXACMLPDP pdp = new SimpleSAMLXACMLPDPImpl();

		// create a local SAML-XACML proxy to connect to the PDP
		XACMLPDPProxy pdpProxy = new LocalSAMLPDPProxyImpl(pdp);
		TVS tvs = new TVSImpl();
		
		// create PEP to consume this proxy
		PEP myPEP = new PEPImpl(pdpProxy, tvs);

		// evaluation
		AuthorizationResponse authzResp = myPEP.authorizeAction(authzRequest);

		// boolean decision = _pep.authorizeAction(authzRequest);

		System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
				+ (authzResp.getDecision() ? "Permit" : "Deny") + "\"");

	}

	private void runTestCase0() throws Exception {
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
		// String subjconfdata = subjmap.get(ConstantsNS.SUBJECT_CONFDATA);
		// String roles = subjmap.get(ConstantsNS.SUBJECT_ROLE);
		// String subjctx = subjmap.get(ConstantsNS.SUBJECT_CONTEXT);

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

		// boolean decision = _pep.authorizeAction(resourceInputURI, actions,
		// subjmap);

		AuthorizationRequest authzRequest = new AuthorizationRequestImpl(subjmap, resmap, actmap, false);

		// ////////////////////////
		// // Using SAML-XACML profile to communicate with a SAML-XACML PDP,
		// Using XACML PDP, create a XACML PDP proxy
		XACMLPDP pdp = new SimpleXACMLPDPImpl();
		XACMLPDPProxy pdpProxy = new LocalXACMLPDPProxyImpl(pdp);
		TVS tvs = new TVSImpl();
		
		// create PEP to consume this proxy
		PEP myPEP = new PEPImpl(pdpProxy, tvs);

		// evaluation
		AuthorizationResponse authzResp = myPEP.authorizeAction(authzRequest);

		// boolean decision = _pep.authorizeAction(authzRequest);

		System.out.println("\nTest GAAAPI TestPDPlocal: PDP decision is \""
				+ (authzResp.getDecision() ? "Permit" : "Deny") + "\"");
	}

	public static String getSessionId(boolean prefix) throws Exception {
		String griprefix = "nsp-domain.uob";

		if (!prefix) {
			griprefix = "";
		}
		String sessionId = GRIgenerator.generateGRI(32, griprefix);
		return sessionId;
	}

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
