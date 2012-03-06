/*
 * Created on Feb 5, 2005
 *
 */
package org.aaaarch.gaaapi.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.aaaarch.utils.HelpersDateTime;
import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.config.ConfigTrustDomains;
import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.config.KeyStoreIF;
import org.aaaarch.gaaapi.SubjectSet;
import org.aaaarch.gaaapi.authn.AuthenticateSubject;
import org.aaaarch.gaaapi.ticktok.AuthnTicketType;
import org.aaaarch.gaaapi.ticktok.AuthnTokenType;
import org.aaaarch.gaaapi.ticktok.AuthzTicketType;
import org.aaaarch.gaaapi.ticktok.AuthzTokenType;
import org.aaaarch.gaaapi.ticktok.CachedAuthzTicket;
import org.aaaarch.gaaapi.ticktok.ResolverAuthzTicket;
import org.aaaarch.gaaapi.ticktok.SAML11AuthnTicket;
import org.aaaarch.gaaapi.ticktok.SAML11AuthzTicket;
//import org.aaaarch.utils.HelpersXMLsecurity;
import org.aaaarch.impl.signature.VerifySignature;

/**
 * @author demch
 *
 */
public class TestAuthnTicket {	
    public static void main (String unused[]) throws Exception {

		ArrayList validtime = new ArrayList();
		//ArrayList subjset = new ArrayList();
		HashSet attributes = new HashSet();

		String tickfile = "x-output/authnticket01simple.xml";
		String tickfilesigned =  "x-output/signed-authnticket01simple.xml";
		String tokfile = "x-output/authntoken01.xml";

		// Preparing data for SimpleTicket format
		/* <!ELEMENT Validity>
		 * atributes: startDate, endDate 
		 */
		Date startDate = new Date();
		Date endDate = new Date();
		//Setting validity for 24 hrs
		long hrs24 = 24;
		endDate = new Date(startDate.getTime() + (hrs24*60*60*1000));
		//System.out.println("test date formatter: " + HelpersDateTime.datetostring(endDate));
		
		// setting fixed validity period
		//String date1 = "2005-01-01"; 
		//String date2 = "2005-05-05T22:22:22Z"; 
		//endDate = dateformat(date2);
		//startDate = dateformat(date1);

		// Subject attributes
        String subjectid = "WHO740@users.collaboratory.nl";
        String confdata = "SeDFGVHYTY83ZXxEdsweOP8Iok";
        String jobid = "CNL2-XPS1-2005-02-02";
        String role = "analyst@JobID;expert@JobID";
        attributes.add(jobid);
        attributes.add(role);
        
        HashMap subjmap = SubjectSet.getSubjSetTest();
        
        //////////////////////////////////////////////
  		//Receive parameters for the pubkey keystore for xmlsec test profile
  	  	//String keyalias = "cnl01";
  	   	//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
  	   	//Key privkey = getPrivKey (keyset);
  	   	//Key pubkey = getPublicKey (keyset);
        //Key pubkek = pubkey;

  		//Receive parameters for the pubkey keystore for cnl02 test profile
        String configId = ConfigSecurity.getSecurityConfigId();
  	   	//List keyconf = KeyStoreConfig.getConfigKeysPEP(configId);
	   	List keyconf = KeyStoreConfig.getConfigKeysDefault(configId);
  	   	
  	   	//System.out.print("\nTest AuthnTicket: \n" + configId + "\n" + keyconf);

  	   	Key privkey = KeyStoreIF.getPrivKey(keyconf);
  	   	Key pubkey = KeyStoreIF.getPublicKey(keyconf);
  	   	
  	   	///// using trust domain config for key access - some problems
  	   	//Key privkey = KeyStoreIF.getSigningKey(ConfigTrustDomains.TRUSTDOMAIN_PEP_PDP);
  	   	//Key pubkey = KeyStoreIF.getTrustedKey(ConfigTrustDomains.TRUSTDOMAIN_PEP_PDP);
  	   	///// using keyconfig for key access - no problems but need config knowledge

  	   	//System.out.print("\n###Private key: \n" + privkey.toString() + "\nPublic key: \n" + pubkey.toString());
  	   	
        // uri to sign - list of 
		String uri2sign0 = "";
		String uri2sign1 = "#subject";
		List uri2sign = new ArrayList();
		uri2sign.add(uri2sign0);
		//uri2sign.add(uri2sign1);
        
        //Type/Algorithm for Data encryption key
  	   	String jceAlgoData = "AES";
        Key symmetricKey = GenerateDataEncryptionKey(jceAlgoData);
        Key sdek = symmetricKey;
           	
        //Type/Algorithm for Key encryption key
  	   	String jceAlgoKey = "DESede";
        
        //Method/Algorithm for Data encryption key
        String algodataURI = XMLCipher.AES_128;
        
  	   	//Method/Algorithm for encryption Data encryption key
        String algokekURI = XMLCipher.TRIPLEDES_KeyWrap;
        
       	try {   	
       	   	System.out.println("Running Examples for AuthnTicket:\n");
       		System.out.println("Select ticket generation option ( \n" + 
       				"1 - Simple ticket with variable parameters (using constructor AuthzTicket)\n" +
       				"2 - Create and sign simple ticket, and extract signed AuthnToken\n" +
       				"3 - Receive, validate and process external anticket\n" +  
       				"4 - Create and sign a ticket in SAML1.1 format, and extract signed AuthnToken\n" +
       				//"5 - generate signed AuthnToken\n" +
       				"6 - Receive, validate and process external antoken\n" +
       				"8 - Create AuthnTicket as AuthN credential\n" +
       				"9 - Create UC6 Assertion" +  
					"");
       		int s = HelpersReadWrite.readStdinInt();			
       		switch(s) {
       		//Simple ticket with variable parameters using constructor CNLAuthzTicket
   			case 1: {
				AuthnTicketType ant = new AuthnTicketType(subjmap, startDate, endDate);
				Document docticket = ant.createSimpleTicket();
		        // save echo file before signing
		        HelpersXMLsecurity.saveDOMdoc(docticket, tickfile);
		        System.out.println("\nWrote doc before signing to " + tickfile);
				printDOMdoc(docticket);
   		        //CachedAuthzTicket.cacheTicket(docticket);
		     return;}
   			//Create and sign simple ticket, and extract signed AuthnToken
			case 2: {
		        //Document docticket =AuthnTicket.createSimpleTicket(subjectid, confdata, 
			    //		startDate, endDate, attributes);
				AuthnTicketType ant = new AuthnTicketType(subjmap, startDate, endDate);
				Document docticket = ant.createSimpleTicket();
				Document docsigned = AuthnTicketType.signTicket(docticket, uri2sign, privkey);
   		        Node signode = docticket.getElementsByTagNameNS(
   		        		"http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0);
   		        /*z->n*/
   		        CachedAuthzTicket.cacheTicket(docsigned);
   		        //printDOMdoc(docsigned);
		        HelpersXMLsecurity.saveDOMdoc(docticket, tickfile);
		        System.out.println("\nWrote doc before signing to " + tickfile);
				printDOMdoc(docticket);
		        //
				HelpersXMLsecurity.saveDOMdoc(docticket, tickfilesigned);
   		        System.out.println("\nWrote AuthnTicket signed to file");
   		        // token generation part
   		        //String intickfile = "signed-anticket.xml";
   		        //String intokfile = "signed-antoken.xml";
				Key tokenprivkey = null;
				System.out.println("\nGenerating AuthnToken out of AuthnTicket");
				//
				//AuthnToken antok = new AuthnToken(readFileToDOM(infile), tokenprivkey);
				Document antoken = AuthnTokenType.createTokenSigned(readFileToDOM(tickfilesigned), tokenprivkey);
				//Document antoken = antok.createTokenSigned();
				if (antoken == null) {
					System.out.println("\nAuthnToken is null");
					return;}
				HelpersXMLsecurity.saveDOMdoc(antoken, tokfile);
				System.out.println("\nSigned XML AuthnToken is generated successfully!");
				HelpersXMLsecurity.printDOMdoc(antoken);			
				//
				/*System.out.println("\nChecking AuthnTicket in cache");
				//Document anticketfromcache = ResolverAuthzTicket.getTicketByTicket(docsigned);
				Document anticketfromcache = ResolverAuthzTicket.getTicketByToken(antoken);
				//printDOMdoc(anticketfromcache);			
				System.out.println("\nValidating ticket from cache...");
				boolean validSig = CNLAuthnTicket.validateTicket(anticketfromcache, pubkey, false);
				System.out.println("Retrieved from cache ticket is " + (validSig ? "=VALID=" : "=INVALID="));
				*/
				//CNLAuthnToken.verifyTokenSigned(antoken);
				AuthnTokenType.verifyTokenSigned(readFileToDOM(tokfile));
   		        System.out.println("\nAuthnToken: get TicketId = " + AuthnTokenType.getTokenid());
   		        System.out.println("\nAuthnToken: get TokenValue = " + AuthnTokenType.getSubjconfdata());
				boolean validTok = AuthnTokenType.verifyTokenSigned(antoken);
				System.out.println("Token is " + (validTok ? "=VALID=" : "=INVALID="));

			return;}
			// process external ticket
			case 3: {
   		        // read signed ticket to DOM and extract all data
   		        String infile = "signed-anticket.xml";
				Document inantik = readFileToDOM(infile);
				printDOMdoc(inantik);
				System.out.println("\nValidating received ticket...");
				boolean validSig = AuthzTicketType.validateTicket(inantik, pubkey, false);
				System.out.println("Recieved ticket is " + (validSig ? "=VALID=" : "=INVALID="));
				AuthnTicketType ant = new AuthnTicketType(inantik);
   		        System.out.println("\nAuthnTicket: get Issuer = " + ant.getIssuer());
   		        System.out.println("\nAuthnTicket: get TicketId = " + ant.getTicketid());
   		        System.out.println("\nAuthnTicket: get NotBefore = " + ant.getNotBefore());
   		        System.out.println("\nAuthnTicket: get NotOnOrAfter = " + ant.getNotOnOrAfter());
   		        System.out.println("\nAuthnTicket: get SubjectId = " + ant.getSubjectid());
   		        System.out.println("\nAuthnTicket: get ConfirmationData = " + ant.getConfdata());
   		        System.out.println("\nAuthnTicket: get SubjectAtributes all = " + ant.getSubjectAttributes());
   		        //System.out.println("\nCNLAuthnTicket: get Attributes = " + ((String) i.next()).toString());}
		     return;}
			// SAML ticket
			case 4: {       	   	
		        Document samldocticket = SAML11AuthnTicket.createAssertion(subjectid, confdata, 
			    		startDate, endDate, attributes);
		        printDOMdoc(samldocticket);
				Document docsigned = AuthzTicketType.signTicket(samldocticket, uri2sign, privkey);
   		        Node signode = samldocticket.getElementsByTagNameNS(
   		        		"http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0);
		        printDOMdoc(samldocticket);
   		        System.out.println(signode.getTextContent().toString());
				return;}
			// generate AuthzToken
			case 5: {
				String infile = "signed-ticket.xml";
				Key tokenprivkey = null;
				System.out.println("\nGenerating AuthzToken out of AuthzTicket");
				AuthzTokenType.createTokenSigned(readFileToDOM(infile), tokenprivkey);
				System.out.println("\nSigned XML AuthzToken is generated successfully ");
				return;
			}
			// process external token
			case 6: {
   		        // read signed tioken to DOM and extract all data
   		        String infile0 = "signed-antoken00.xml";
   		        String infile1 = "signed-antoken01ext.xml";
				Document inantok = readFileToDOM(infile1);
				printDOMdoc(inantok);
				System.out.println("\nValidating received token...");
				boolean validTok = AuthnTokenType.verifyTokenSigned(inantok);
				System.out.println("Recieved token is " + (validTok ? "=VALID=" : "=INVALID="));
				AuthnTokenType antok = new AuthnTokenType(inantok);
   		        System.out.println("\nAuthnTicket: get Issuer = " + antok.getIssuer());
   		        System.out.println("\nAuthnTicket: get TicketID = " + antok.getTokenid());
   		        System.out.println("\nAuthnTicket: get NotBefore = " + antok.getNotBefore());
   		        System.out.println("\nAuthnTicket: get NotOnOrAfter = " + antok.getNotOnOrAfter());
   				
		     return;}
   			case 8: {
				//AuthnTicketType ant = new AuthnTicketType(subjmap, startDate, endDate);
				//String authnticket = AuthenticateSubject.getSubjectAuthnXML(subjmap, "3", null);
				String authnticket = AuthenticateSubject.getSubjectAuthnXML(subjmap, "3", null);
   		        System.out.println("\nAuthnTicket as AuthN cred\n" + authnticket);
   				return;}
   			case 9: {
				String authnticket = AuthenticateSubject.getSubjectAuthnXML(subjmap, "10", null);
   		        System.out.println("\nAuthnTicket as AuthN cred\n" + authnticket);
   				return;}
   		}
   		System.out.println("OK");
   		System.exit(0);
   	   	} catch (Exception e) {
   	   		e.printStackTrace();
   	   		System.exit(1);
   	   		}

    }
	public static PrivateKey getPrivKey (List keyset) throws Exception {
		
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
		    //System.out.print("\n###Private key: \n" + privateKey.toString() + "\n");
		    return privateKey;
		}

	public static PublicKey getPublicKey (List keyset) throws Exception {
		
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
	         X509Certificate cert =
	            (X509Certificate) ks.getCertificate(certificateAlias);

	         //System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
	         
		    PublicKey pubKey = (PublicKey) cert.getPublicKey();
		    //System.out.print("\n###Public key: \n" + pubKey.toString() + "\n");
		    return pubKey;
		}

	private static void outputDocToFile(Document doc, String fileName)
        throws Exception {
        File encryptionFile = new File(fileName);
        FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(f);
        transformer.transform(source, result);

        f.close();
        System.out.println(
            "Wrote document containing encrypted data to " +
            encryptionFile.toURL().toString());
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

        return doc;
 	}	
	
 	public static void printKeyInfo (String keyalias) throws Exception {
 	   	List checkconfsec = new ArrayList();

 	   	checkconfsec = KeyStoreConfig.getConfigKeys(keyalias);

 		String keystoreType = (String) checkconfsec.get(0);
 		String keystoreFile = (String) checkconfsec.get(1);
 		String keystorePass = (String) checkconfsec.get(2);
 		String privateKeyAlias = (String) checkconfsec.get(3);
 		String privateKeyPass = (String) checkconfsec.get(4);
 		String certificateAlias = (String) checkconfsec.get(5);
 		//

 		System.out.print ("\n###Echo Key information\n" 
 				+ "keystoreType=" + keystoreType + "\n" 
 				+ "keystoreFile=" + keystoreFile + "\n" 
 				+ "keystorePass=" + keystorePass + "\n"
 				+ "privateKeyAlias=" + privateKeyAlias + "\n"
 				+ "privateKeyPass=" + privateKeyPass + "\n"
 				+ "certificateAlias=" + certificateAlias + "\n\n"); 		
 	}

 	public static void printDOMdoc (org.w3c.dom.Document doc) throws Exception {
        // print DOM doc
        ByteArrayOutputStream f = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, f);
        f.close();
        System.out.println("\n" + f);
 	}
 	
 	public static void printDOMelem (org.w3c.dom.Element elem) throws Exception {
        // print DOM doc
        ByteArrayOutputStream f = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments((Node)elem, f);
        f.close();
        System.out.println("\n" + f);
 	}
 	
 	public static void saveDOMdoc (org.w3c.dom.Document doc, String filename) throws Exception {
        // save file from DOM doc
        FileOutputStream f = new FileOutputStream(filename);
        XMLUtils.outputDOMc14nWithComments(doc, f);
        f.close();
        //System.out.println("Wrote echo DOM doc to " + filename);
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
    private static SecretKey GenerateAndStoreKeyEncryptionKey(String jceAlgorithmName, String kekfname)
    throws Exception {

    String kekpath = ConfigSecurity.LOCAL_DIR_SYMKEYSTORE + kekfname;
	//String jceAlgorithmName = "DESede";
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(jceAlgorithmName);
    SecretKey kek = keyGenerator.generateKey();

    byte[] keyBytes = kek.getEncoded();
    File kekFile = new File(kekpath);
    FileOutputStream f = new FileOutputStream(kekFile);
    f.write(keyBytes);
    f.close();
    System.out.println(
        "Key encryption key stored in " + kekFile.toURL().toString());

    return kek;
}

private static SecretKey GenerateDataEncryptionKey(String jceAlgorithmName) throws Exception {

    //String jceAlgorithmName = "AES";
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(jceAlgorithmName);
    keyGenerator.init(128);
    return keyGenerator.generateKey();
}
static {
	org.apache.xml.security.Init.init();
}

}
