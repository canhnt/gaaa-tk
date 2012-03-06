/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package org.aaaarch.gaaapi.test.unicore6;

//import eu.unicore.security.TestBase;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;


import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.impl.unicore.MalformedUnicoreAssertionException;
import org.aaaarch.impl.unicore.UC6AssertionUtils;
import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;
import org.apache.xmlbeans.XmlException;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.samples.utils.resolver.OfflineResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xpath.XPathAPI;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import sun.security.rsa.RSAPublicKeyImpl;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import eu.unicore.samly2.exceptions.SAMLParseException;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.security.dsig.StandaloneCanonizer;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.user.UserAssertion;

import junit.framework.TestCase;

/**
* @author K. Benedyczak
*/
public class TestUC6Security extends TestBaseUC6 {

	static String tIssuerDN1 = "issuerDN1"; 
	static String tIssuerDN2 = "issuerDN2";
	static String file = "x-output/uc6-assertion00-test01.xml";
	static String fileSigned1 = "x-output/uc6-assertion01-signed.xml";
	static String fileSigned2 = "x-output/uc6-assertion02-signed2validate.xml";
	static String fileSigned3 = "x-output/uc6-assertion03-signed2validate.xml";
	static List keystoreset = null;

	final static String signatureSchemaFile = "data/schemas/xmldsig-core-schema.xsd";

	private static final Logger log = LoggerFactory.getLogger(TestUC6Security.class);

	public static void testUC6CreateAssertion() throws Exception
	  {
	    String issuerAlias = "mykey";
	    String issuerJKSPath = "etc/security/keystore/unicore6/store1.jks";
	    char[] issuerJKSPass = "asdfasdf".toCharArray();
	
	    String subjectAlias = "mykey";
	    String subjectJKSPath = "etc/security/keystore/unicore6/store2.jks";
	    char[] subjectJKSPass = "asdfasdf".toCharArray();
	
	    // Issuer
	    String issuerDN = "null";
	    X509Certificate issuerX509 = null;
	
	    KeyStore issuerJKS = KeyStore.getInstance(KeyStore.getDefaultType());
	    issuerJKS.load(new FileInputStream(new File(issuerJKSPath)), issuerJKSPass);
	
	    PrivateKey issuerPrivKey = (PrivateKey) issuerJKS.getKey(issuerAlias, issuerJKSPass);

	    Certificate issuerCert = issuerJKS.getCertificate(issuerAlias);
	    if (issuerCert instanceof X509Certificate)
	    {
	      issuerX509 = (X509Certificate) issuerCert;
	      issuerDN = issuerX509.getSubjectDN().getName();
	      //log.info("Issuer DN: " + issuerDN);
	    }
		X509Certificate[] issuerCerts = new X509Certificate[] {issuerX509};
	    
	    // Subject == server, i.e. local/client Cert
	    String subjectDN = "null";
	    KeyStore subjectJKS = KeyStore.getInstance(KeyStore.getDefaultType());
	    subjectJKS.load(new FileInputStream(new File(subjectJKSPath)), subjectJKSPass);
	    Certificate serverCert = subjectJKS.getCertificate(subjectAlias);
	    
	    log.info("Server cert: " + serverCert);
	    
	    if (serverCert instanceof X509Certificate)
	    {
	      X509Certificate serverX509 = (X509Certificate) serverCert;
	      subjectDN = serverX509.getSubjectDN().getName();
	      log.info("Server DN: " + subjectDN);
	    }

	    ETDApi engine = UnicoreSecurityFactory.getETDEngine();
	    Calendar until = Calendar.getInstance();
	    until.add(Calendar.MONTH, 1);
	    DelegationRestrictions dr = new DelegationRestrictions(Calendar.getInstance().getTime(), until.getTime(), 10);

	    TrustDelegation td = 
			engine.generateTD(issuerDN, issuerCerts, issuerPrivKey, subjectDN, dr);
	
	    log.info(td.getXML().toString());
	    HelpersReadWrite.writeToFile(td.getXML().xmlText(), fileSigned3);	    
	    
	    System.out.println("Assertion is created:\n" +
	    		"for issuerDN = " + issuerDN + "\nsubjectDN = " + subjectDN + "\n" + td.getXML().xmlText());
	  }

	public static void testUC6UserAsDN()
	{
		try
		{
			//UserAssertion token = new UserAssertion(issuerDN1, issuerDN2);
			UserAssertion token = new UserAssertion(tIssuerDN1, tIssuerDN2);
			//
			//String file = "uc6-saml2-test01.xml";
			System.out.println("-------------------------------------------\n" + 
				"User token:");
			writerFile(token.getXML().xmlText(xmlOpts), file);
			System.out.println(token.getXML().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXML();
			UserAssertion parsedToken = new UserAssertion(doc);
			System.out.println("-------------------------------------------\n" + 
				"Parsed user token:");
			System.out.println(parsedToken.getXML().xmlText(xmlOpts));

		} catch (Exception e)
		{
			e.printStackTrace();
			//fail(e.getMessage());
			System.out.println("Test is Failed");
		}
		//assertTrue(true);
		System.out.println("Test is OK");
	}

	public void testUC6UserAsCert()
	{
		try
		{
			UserAssertion token = new UserAssertion(tIssuerDN1, issuerCert2);
			System.out.println("-------------------------------------------\n" + 
				"User token:");
			System.out.println(token.getXML().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXML();
			UserAssertion parsedToken = new UserAssertion(doc);
			
			System.out.println("-------------------------------------------\n" + 
				"Parsed user token:");
			System.out.println(parsedToken.getXML().xmlText(xmlOpts));
			System.out.println("User's certificate parsed: " + 
					parsedToken.getUserCertificate());

		} catch (Exception e)
		{
			e.printStackTrace();
			//fail(e.getMessage());
			System.out.println("Test is Failed");
		}
		System.out.println("Test is OK");
	}

	/// DigiSign tests
	public static void testUC6SignVerify(List keyset, String file2)
	{
		//String file = "x-output/uc6-assertion01-test01.xml";
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = readFileToDOM(file2);
			System.out.println("\nSssertion to sign:\n");
			HelpersXMLsecurity.printDOMdoc(doc);			
			
			Node node = doc.getDocumentElement().getChildNodes().item(1);
			
			// get PublicKey and PrivateKey -> from GAAA-TK 
			
			X509Certificate[] tIssuerCert = getCertStored(keyset);
			//X509Certificate[] tIssuerCert = new X509Certificate[1];
			
			PublicKey tPubKey = tIssuerCert[0].getPublicKey();
			PrivateKey tPrivKey = getPrivKeyStored(keyset);
			//
			dsigEngine.genEnvelopedSignature(tPrivKey, tPubKey, tIssuerCert, 
				doc, node);

			HelpersXMLsecurity.writeToFile(doc, fileSigned1);
			System.out.println("\nSigned assertion saved to file:" + fileSigned1 + "\n");
			HelpersXMLsecurity.printDOMdoc(doc);
			//doc = HelpersXMLsecurity.readFileToDOM(fileSigned1);
			
			//assertTrue(dsigEngine.verifyEnvelopedSignature(doc, pubKey));
			boolean result = dsigEngine.verifyEnvelopedSignature(doc, tPubKey);
			//assertTrue(result);
			System.out.println("\nTest result is \"" + result + "\"");
			
		} catch (Exception e)
		{
			e.printStackTrace();
			//fail(e.getMessage());
			System.out.println("(a2) Test is Failed");
		}
		System.out.println("Test is OK");
		//assertTrue(true);
	}
	
	public static void testUC6VerifySigned(String file) throws Exception {
		
		PublicKey pubKey = null;
		
		Document doc = readFileToDOM(file);
		// Extract UC6 Assertion info: 
		// Issuer, Subject/NameID, Attribute@TrustDelegationOfUser/AttributeValue
		List assertdata = getUC6AssertionData(doc);		
		System.out.println("\nDebug: UC6 Assertion data:\n" + assertdata);					
				
		//BigInteger modulus = new BigInteger("163747238822666015285329706279830595411974064586059702871587099431512157455719495774518770867278091194963281647181853106959836263061780091305987288645684760669758102471364248456086999347113921145640831970575719191169166816785623263506972893282383928337258596366986798122055894688767641149446988631156789299337");
		//BigInteger exponent = new BigInteger("65557");
		//PublicKey pubKey = new RSAPublicKeyImpl(modulus, exponent);
		// get public key stored
		/* String configId = "gaaa-nrp";
	   	List keyset = KeyStoreConfig.getConfigKeysDefault(configId);
		X509Certificate[] tIssuerCert = getCertStored(keyset);
		PublicKey pubKey =  tIssuerCert[0].getPublicKey();
		//get public key from the signed doc
		*/
		List signCreds = getSignatureCreds(doc, true);

		if (signCreds.get(0).equals("null")) {
			System.out.println("\nDebug: Signature doesn't contain key information: retrieving stored trusted Cert\n");					
			String configId = "gaaa-uc6";
		   	List keyset = KeyStoreConfig.getConfigKeys(configId);
			X509Certificate[] tIssuerCert = getCertStored(keyset);
			pubKey =  tIssuerCert[0].getPublicKey();
			
		} else {
		if (signCreds.get(0) instanceof X509Certificate) {
		    //X509Certificate[] signCerts = new X509Certificate[1];
		    //signCert[0] = (X509Certificate) signCerts;
			pubKey  = (PublicKey) ( (X509Certificate) signCreds.get(0)).getPublicKey();
		} else {
			if (signCreds.get(0) instanceof PublicKey) {
				pubKey  = (PublicKey) signCreds.get(0);			
			}
			}
		}
		System.out.println("\nDebug: Public Key extracted from Signature: \n" +pubKey);		
		
		// Start verification procedure 
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
	
			boolean result = dsigEngine.verifyEnvelopedSignature(doc, pubKey);
			//assertTrue(result);
			System.out.println("\n\nTest result is \"" + result + "\"");
		} catch (Exception e)
		{
			e.printStackTrace();
			System.out.println("(b2) Test is Failed");
			//fail(e.getMessage());
		}
		//System.out.println("Test is OK");
		//assertTrue(true);
	}

	public static void testUC6VerifyAssertionETD(String fileSigned2) throws XmlException, IOException, SAMLParseException, KeyStoreException, NoSuchAlgorithmException, CertificateException
		  {
		    String issuerAlias = "mykey";
		    String issuerJKSPath = "etc/security/keystore/unicore6/store1.jks";
		    char[] issuerJKSPass = "asdfasdf".toCharArray();
	
		    String subjectAlias = "mykey";
		    String subjectJKSPath = "etc/security/keystore/unicore6/store2.jks";
		    char[] subjectJKSPass = "asdfasdf".toCharArray();
	
		    KeyStore issuerJKS = KeyStore.getInstance(KeyStore.getDefaultType());
		    issuerJKS.load(new FileInputStream(new File(issuerJKSPath)), issuerJKSPass);
	
		    String issuerDN = "null";
		    X509Certificate issuerX509 = null;
	
		    Certificate issuerCert = issuerJKS.getCertificate(issuerAlias);
		    if (issuerCert instanceof X509Certificate)
		    {
		      issuerX509 = (X509Certificate) issuerCert;
		      issuerDN = issuerX509.getSubjectDN().getName();
		      log.info("Issuer DN: " + issuerDN);
		      System.out.println("\nIssuer DN: " + issuerDN);
		    }
	
		    KeyStore subjectJKS = KeyStore.getInstance(KeyStore.getDefaultType());
		    subjectJKS.load(new FileInputStream(new File(subjectJKSPath)), subjectJKSPass);
		    Certificate subjectCert = subjectJKS.getCertificate(subjectAlias);
		    //    log.info("Server cert: " + subjectCert);
		    String subjectDN = "null";
		    if (subjectCert instanceof X509Certificate)
		    {
		      X509Certificate subjectX509 = (X509Certificate) subjectCert;
		      subjectDN = subjectX509.getSubjectDN().getName();
		      log.info("Subject DN: " + subjectDN);
		      System.out.println("\nSubject DN: " + subjectDN);
		    }
	
		    /// starting with checking signed assertion
		    InputStream is = new FileInputStream(new File(fileSigned2));
	
		    AssertionDocument ad = AssertionDocument.Factory.parse(is);
		    // Assertion is added to TrustDelegation
		    TrustDelegation td = new TrustDelegation(ad);
		    List<TrustDelegation> tds = new ArrayList<TrustDelegation>();
		    tds.add(td);
	
		    ETDApi engine = UnicoreSecurityFactory.getETDEngine();
		    X509Certificate[] subjectCerts = new X509Certificate[1];
		    subjectCerts[0] = (X509Certificate) subjectCert;
	
		    X509Certificate[] issuerCerts = new X509Certificate[1];
		    issuerCerts[0] = (X509Certificate) issuerCert;
	
	//	    ValidationResult vr = engine.isTrustDelegated(tds, subjectCerts, issuerCerts);
		    ValidationResult vr = engine.isTrustDelegated(tds, subjectDN, issuerDN);
		    //ValidationResult vr = engine.isTrustDelegated(tds, issuerDN, subjectDN);
	//	    ValidationResult vr = engine.validateTD(td, (X509Certificate) issuerCert, issuerCerts, subjectCerts);
	//	    ValidationResult vr = engine.validateTD(td, issuerDN, issuerDN, subjectDN);
	
		    if (vr.isValid())
		    {
		      log.info("Delegation is valid");
		      System.out.println("\nDelegation is valid");
		    }
		    else
		    {
		      log.error("Delegation is invalid: " + vr.getInvalidResaon());
		      System.out.println("\nDelegation is invalid: " + vr.getInvalidResaon());
		    }
		  }

	public static void testVerifySignedAssertion(String file) throws Exception {
		
		Document doc = readFileToDOM(file);
		
		// Extract SAML assertion info: 
		// Issuer, Subject/NameID, Attribute@TrustDelegationOfUser/AttributeValue
		
		// Signature validation part
		boolean schemaValidate = true;
		boolean result = validateSignedDoc (doc, schemaValidate);
		
		System.out.println("\n\nTest result is \"" + result + "\"");
		/*
		String configId = "gaaa-nrp";
	   	List keyset = KeyStoreConfig.getConfigKeysDefault(configId);
		X509Certificate[] tIssuerCert = getCert(keyset);
		PublicKey pubKey =  tIssuerCert[0].getPublicKey();

		//org.apache.xml.security.signature.XMLSignature
		 */
	}

	public static boolean validateSignedDoc(org.w3c.dom.Document doc, boolean schemaValidate) throws Exception {
		boolean validSig = false;
	    XMLSignature signature = null;
		//final String signatureSchemaFile = "data/schemas/xmldsig-core-schema.xsd";
		//final String signatureSchemaFile = "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd";
	
		if (schemaValidate) {
			System.out.println("Schema validation is TRUE");
		}
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
	
		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/features/validation/schema", Boolean.TRUE);
			dbf.setAttribute("http://apache.org/xml/features/dom/defer-node-expansion",	Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
		}
	
		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);
	
		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation", Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}
	
		try {
			Element nscontext = XMLUtils.createDSctx(doc, "ds",
					Constants.SignatureSpecNS);
			Element sigElement = (Element) XPathAPI.selectSingleNode
							(doc, "//ds:Signature", nscontext);
			///
			System.out.println("Signature element extracted.\n");
			///
			signature = new XMLSignature((Element)sigElement, null);
			signature.addResourceResolver(new OfflineResolver());
	
			KeyInfo ki = signature.getKeyInfo();
			if (ki != null) {
				if (ki.containsX509Data()) {
					System.out.println("Found a X509Data element in the KeyInfo. Verifying...");
				}
	
				X509Certificate cert = signature.getKeyInfo().getX509Certificate();
	
				if (cert != null) {
					System.out.println("Now is validating...\n");
					validSig = signature.checkSignatureValue(cert);
				} else {
	
					PublicKey pk = signature.getKeyInfo().getPublicKey();
					if (pk != null) {
						System.out
								.println("Found a public key in the KeyInfo. Verifying...");
						validSig = signature.checkSignatureValue(pk);
					} else {
						System.out.println("Did not find a X509Data either public key, " +
								"so can't verify the signature");
					}
				}
			} else {
				System.out.println("Did not find a KeyInfo");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return validSig;
	}

	// Extract SAML assertion info: 
	// Issuer, Subject/NameID, Attribute@TrustDelegationOfUser/AttributeValue
	public static List getUC6AssertionData(org.w3c.dom.Document adoc) throws Exception {
		
		List assertinfo = new ArrayList();
		
		String asstype = adoc.getFirstChild().getNodeName().toString();
		System.out.println("\nUC6 Assertion: root element = " + asstype);
		if (!asstype.equals("urn:Assertion")) {
			throw new MalformedUnicoreAssertionException ("No root elemenet urn:Assertion found");
			//return assertinfo;
		}
		Element root = (Element) adoc.getElementsByTagName("urn:Assertion").item(0);
		
		// Issuer
		Element issuer =  (Element) root.getElementsByTagName("urn:Issuer").item(0);
		String issuerDN = issuer.getTextContent();
		System.out.println("\nUC6 Assertion: IssuerDN = " + issuerDN);
		//
		//Subject/NameID, Attribute@TrustDelegationOfUser/AttributeValue
		//String subjectDN = ((Element) root.getElementsByTagName("urn:Subject").item(0)).
			//getElementsByTagName("urn:NameID").item(0).getTextContent();
		String subjectDN = root.getElementsByTagName("urn:NameID").item(0).getTextContent();
 
		System.out.println("\nUC6 Assertion: SubjectDN = " + subjectDN);
		
		if (root.getElementsByTagName("urn:AttributeValue").item(0) == null) {
			System.out.println("\nUC6 Assertion: There is no AttrValue");
			throw new MalformedUnicoreAssertionException ("Malformed UC6 Assertion: No urn:AttributeValue found");
		}
		String attrValue = root.getElementsByTagName("urn:AttributeValue").item(0).getTextContent();
		System.out.println("\nUC6 Assertion: attrValue = " + attrValue);
		
		List creds = getSignatureCreds(adoc, true);		
		
		assertinfo.add(issuerDN);
		assertinfo.add(subjectDN);
		assertinfo.add(attrValue);
		assertinfo.add(creds.get(0));//returns PublicKey
		
		return assertinfo;
	}
	
	public static List getSignatureCreds(org.w3c.dom.Document doc, boolean schemaValidate) throws Exception {
		//boolean validSig = false;
		List creds = new ArrayList();		
	    XMLSignature signature = null;

		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/features/validation/schema", Boolean.TRUE);
			dbf.setAttribute("http://apache.org/xml/features/dom/defer-node-expansion",	Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
		}

		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation", Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}

		try {
			Element nscontext = XMLUtils.createDSctx(doc, "ds",
					Constants.SignatureSpecNS);
			Element sigElement = (Element) XPathAPI.selectSingleNode
							(doc, "//ds:Signature", nscontext);
			///
			signature = new XMLSignature((Element)sigElement, null);
			signature.addResourceResolver(new OfflineResolver());

			KeyInfo ki = signature.getKeyInfo();
			if (ki != null) {

				X509Certificate cert = signature.getKeyInfo().getX509Certificate();
				creds.add(cert);
				if (cert != null) {
					System.out.println("\nFound a X509 Cert in the KeyInfo. Extracted Cert:\n" + cert);
				} else {
					PublicKey pk = signature.getKeyInfo().getPublicKey();
					if (pk != null) {
						creds.add(pk);
						System.out.println("\nFound a X509 PublicKey in the KeyInfo. Extracted public key:" + pk);
					} else {
						creds.add(null);
						System.out.println("Did not find a X509Data either public key");
					}
				}
			} else {
				System.out.println("Did not find a KeyInfo");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		//creds.set(0, "null");
		return creds;
	}

	public static void main(String args[]) throws IOException {
		try {
			System.out.println("Running test for PEP/PDP Authorisation components (aaauthreach prj)");
			System.out.println( 
				"1 - test UC6 Security: User as DN\n" +
				"2 - test UC6 Security: User as Cert\n" +
				"3 - test Create Assertion: Trust delegation (signed Attribute Assertion)\n" +
				"4 - test Verify signed Assertion with Apache XMLSec library\n" +
				"5 - test UC6 Sign&Verify simple Assertion (no ETD attribute statement) \n" +
				"6 - test UC6 Verify signed Assertion with UC6 Security library\n" +
				"7 - test Validate signed Assertion: \n" +
				"");
		int s = readStdinInt();			
		switch(s) {
			case 0: { 
				return;}
			case 1: { 
				testUC6UserAsDN();
				return;}
			case 2: { 
				testUC6UserAsDN();
				return;}

			case 3: { 
				System.out.println("case 3 - Create signed asssertion with ETD"); 
				testUC6CreateAssertion();
				// with UC6 utils
				String assertionETD = UC6AssertionUtils.createUC6Assertion();
				System.out.println("Created signed asssertion with ETD\n" + assertionETD);
				return;}
			case 4: { 
				System.out.println("case 4 - Verify signed asssertion with XMLSec"); 
			   	testVerifySignedAssertion (fileSigned1);
			   	testVerifySignedAssertion (fileSigned2);
			   	testVerifySignedAssertion (fileSigned3);
				Document doc = HelpersXMLsecurity.readFileToDOM(fileSigned3);
				boolean result = UC6AssertionUtils.verifyGenericAssertionSigned(doc);
				System.out.println("\nTest UC6AssertionUtils: Test result is \"" + result + "\"");
			return;}
			case 5: { 
				System.out.println("case 5 - testSignVerify (simple assertion)"); 
				//String configsecId = ConfigSecurity.SECURITYCONFIG_DEFAULT;
				String configId = "gaaa-nrp";
			   	List keyset = KeyStoreConfig.getConfigKeysDefault(configId);
			   	System.out.println(keyset);
			   	testUC6SignVerify(keyset, file);
			return;}
			case 6: { 
				System.out.println("case 5 - testVerifySigned asssertion with UC6 security (no ETD)"); 
			   	testUC6VerifySigned (fileSigned2);
				// with UC6 utils
				Document doc = HelpersXMLsecurity.readFileToDOM(fileSigned3);
			   	boolean result = UC6AssertionUtils.verifyUC6AssertionSigned(doc);
			   	System.out.println("\nTest direct Assertion validity with UC6AssertionUtils: Test result is \"" + result + "\"");
			return;}
		case 7: {  // 
			System.out.println("case 7 - validate signed SAML assertion and Trust Delegation"); 
			testUC6VerifyAssertionETD(fileSigned3);
			Document doc = HelpersXMLsecurity.readFileToDOM(fileSigned3);
			UC6AssertionUtils.verifyUC6AssertionETD(doc);
			return;} 
			}
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	  }
	
	////////////////////////////////	
	// Input menu number (integer)

	public void testUC6StandaloneCanonizer() {
		  
		StandaloneCanonizer instance;
		try
		{
			instance = new StandaloneCanonizer();
			//Document doc =	readDoc("/docSigned.xml");
			Document doc = readFileToDOM(fileSigned2);
			String res = instance.fireCanon(doc, false);
			
			
			System.out.println("\n\nCanonized document:\n" + res);
			
			//assertFalse(res.contains("<!--COMMENT-TO-REMOVE-->"));
		} catch (Exception e)
		{
			e.printStackTrace();
			//fail(e.getMessage());
			System.out.println("Test is Failed");
	
		}
	}

	public static int readStdinInt (){
		String line = null;
		int val = 0;
		try {
			BufferedReader is = new BufferedReader(
				new InputStreamReader(System.in));
				line = is.readLine();
				val = Integer.parseInt(line);
			} 
		catch (NumberFormatException ex) 
		{
		System.err.println("Not a valid number: " + line);
		} 
		catch (IOException e) 
		{
		System.err.println("Unexpected IO ERROR: " + e);
		}
		//System.out.println("I read this number: " + val);
		return val;
	}
	
	public static void saveDOMdoc (org.w3c.dom.Document doc, String filename) throws Exception {
	    // save file from DOM doc
	    FileOutputStream f = new FileOutputStream(filename);
	    XMLUtils.outputDOMc14nWithComments(doc, f);
	    f.close();
	    //System.out.println("Wrote echo DOM doc to " + filename);
	}

	public static void writerFile(String text, String fileName) throws IOException {
		PrintWriter out =
			new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
		out.print(text);
		out.close();
	}	

	public static org.w3c.dom.Document readFileToDOM (String filename) throws Exception {
       // start xml document processing part
       javax.xml.parsers.DocumentBuilderFactory dbf =
          javax.xml.parsers.DocumentBuilderFactory.newInstance();

       //XML Signature needs to be namespace aware
       dbf.setNamespaceAware(true);

       javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
       //org.w3c.dom.Document docnew = db.newDocument();

       // reading document
       System.out.print("file to read " + filename + "\n");
       org.w3c.dom.Document doc = db.parse(filename);

       // save echo file after parsing
       //String echoDOM = "echoDOMparse.xml";
       //saveDOMdoc (doc, echoDOM);
       //System.out.println("Wrote echo after parsing to DOM to " + echoDOM);

       // print echo file after parsing
      	//printDOMdoc(doc);
       return doc;
	}	
	public static PrivateKey getPrivKeyStored (List keyset) throws Exception {

		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
 	    String keystoreType = (String) keyset.get(0);
 	    String keystoreFile = (String) keyset.get(1);
 	    String keystorePass = (String) keyset.get(2);
 	    String privateKeyAlias = (String) keyset.get(3);
 	    String privateKeyPass = (String) keyset.get(4);
 	    String certificateAlias = (String) keyset.get(5);

       // Retrieving key information
       KeyStore ks = KeyStore.getInstance(keystoreType);
       FileInputStream fis = new FileInputStream(keystoreFile);
       //load the keystore
       ks.load(fis, keystorePass.toCharArray());
       //get the private key for signing.
       PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias,
                                              privateKeyPass.toCharArray());
        System.out.print("\n###Private key: \n" + privateKey.toString());
       return privateKey;
	
	} 
	public static X509Certificate[] getCertStored (List keyset) throws Exception {

		X509Certificate[] issuerCert;
		//PublicKey pubkey;

		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
 	    String keystoreType = (String) keyset.get(0);
 	    String keystoreFile = (String) keyset.get(1);
 	    String keystorePass = (String) keyset.get(2);
 	    String privateKeyAlias = (String) keyset.get(3);
 	    String privateKeyPass = (String) keyset.get(4);
 	    String certificateAlias = (String) keyset.get(5);

 	    // Retrieving key information
       KeyStore ks = KeyStore.getInstance(keystoreType);
       FileInputStream fis = new FileInputStream(keystoreFile);
       //load the keystore
       ks.load(fis, keystorePass.toCharArray());
       //get the private key for signing.
       //PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias, privateKeyPass.toCharArray());
        //System.out.print("\n###Private key: \n" + privateKey.toString());
       //Add in the KeyInfo for the certificate that we used the private key of
       //X509Certificate cert = (X509Certificate) ks.getCertificate(certificateAlias);
       //X509Certificate[] certs = (X509Certificate) ks.getCertificateChain(certificateAlias);
		issuerCert = convertChain(ks.getCertificateChain(certificateAlias));
		//
			
       //PublicKey pubbkey = cert.getPublicKey();
       
       return issuerCert;
	        
	} 

	private static X509Certificate[] convertChain(Certificate[] chain)
	{
		X509Certificate[] ret = new X509Certificate[chain.length];
		for (int i=0; i<chain.length; i++)
			ret[i] = (X509Certificate) chain[i];
		return ret;
	}
}
