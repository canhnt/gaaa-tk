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
import org.aaaarch.gaaapi.ticktok.AuthnTokenType;
import org.aaaarch.gaaapi.ticktok.AuthzTicketType;
import org.aaaarch.gaaapi.ticktok.AuthzTokenType;
import org.aaaarch.gaaapi.ticktok.CachedAuthzTicket;
import org.aaaarch.gaaapi.ticktok.ResolverAuthzTicket;
import org.aaaarch.gaaapi.ticktok.SAML11AuthzTicket;
//import org.aaaarch.utils.HelpersXMLsecurity;
import org.aaaarch.impl.signature.VerifySignature;

/**
 * @author demch
 *
 */
public class TestAuthzTicket {	
	
    public static void main (String unused[]) throws Exception {

		ArrayList validtime = new ArrayList();
		HashMap subjmap = new HashMap();
		ArrayList sessiondata = new ArrayList();
		ArrayList delegates = new ArrayList();
		HashSet actions = new HashSet();
		HashSet obligations = new HashSet();
		HashSet communities = new HashSet();

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
        /*String subjectid = "WHO740@users.collaboratory.nl";
        String subjconfdata = "SeDFGVHYTY83ZXxEdsweOP8Iok";
        String jobid = "CNL2-XPS1-2005-02-02";
        String role = "analyst@JobID;expert@JobID";
        subjset.add(subjectid);
        subjset.add(subjconfdata);
        subjset.add(jobid);
        subjset.add(role);
        ////////
        //subjmap.put("subjectid", "WHO740@users.collaboratory.nl");
        //subjmap.put("subjconfdata", "SeDFGVHYTY83ZXxEdsweOP8Iok");
        //subjmap.put("jobid", "CNL2-XPS1-2005-02-02");
        //subjmap.put("role", "analyst@JobID;expert@JobID");
		*/
		subjmap = SubjectSet.getSubjSetTest();

        
        
        // Actions list
        String action2 = "cnl:actions:CtrlExper";
        String action1 = "cnl:actions:CtrlInstr";
        actions.add(action1);
        actions.add(action2);
        
        // Create document
		//Document document = createSimpleSample();
        //String sessionid, String pdpdecision, String resources, 
		//Collection validtime, Collection subjset, Collection actset
        String sessionid = "Demo001-2008-06-16";
        String policyref = "nsp-policy-demo001";
        String pdpdecision = "Permit"; 
        String resources = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
        //Document document = createSimpleTicket(sessionid, pdpdecision, resources, 
        //		startDate, endDate, subjset, actions);
        //printDOMdoc(document);

        //////////////////////////////////////////////
  		//Receive parameters for the pubkey keystore for xmlsec test profile
  	  	//String keyalias = "cnl01";
  	   	//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
  	   	//Key privkey = getPrivKey (keyset);
  	   	//Key pubkey = getPublicKey (keyset);
        //Key pubkek = pubkey;

  		//Receive parameters for the pubkey keystore for cnl02 test profile
        String configId = ConfigSecurity.getSecurityConfigId();
  	   	List keyconf = KeyStoreConfig.getConfigKeysPEP(configId);
  	   	///// using trust domain config for key access - some problems
  	   	//Key privkey = KeyStoreIF.getSigningKey(ConfigTrustDomains.TRUSTDOMAIN_PEP_PDP);
  	   	//Key pubkey = KeyStoreIF.getTrustedKey(ConfigTrustDomains.TRUSTDOMAIN_PEP_PDP);
  	   	///// using keyconfig for key access - no problems but need config knowledge
  	   	Key privkey = KeyStoreIF.getPrivKey(keyconf);
  	   	Key pubkey = KeyStoreIF.getPublicKey(keyconf);
	    //System.out.print("\n###Private key: \n" + privkey.toString() + "\n");
  	   	
        // uri to sign - list of 
		String uri2sign0 = "";
		String uri2sign1 = "#subject";
		String uri2sign2 = "#xpointer(id('subject'))";
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
        
        ////////// initial debug block
        // Note: this block also changes the document content 
        /*Document docext0 = readFileToDOM (inputFile); 
	    Key skek0 = GenerateAndStoreKeyEncryptionKey(jceAlgoKey, "kek1");
		Document docencr0 = encryptDocSymmetric (document, skek0, sdek, algodataURI);
		printDOMdoc(docencr0);
		printDOMdoc(document);
        */
       	try {   	
       	   	System.out.println("Running Examples for GAAAPI AuthZ/AuthN ticket handling:\n");
       		System.out.println("Select ticket generation option ( \n" + 
       				"0 - AuthzTicket: sample simple ticket with fixed parameters\n" + 
       				"1 - AAA AuthzTicket: generate ticket with variable parameters (using constructor AuthzTicketType)\n" +
       				"2 - AAA AuthzTicket: Create and sign simple ticket, and extract signed AuthzToken\n" +
       				"3 - AAA AuthzTicket: Receive, validate and process external azticket\n" +  
       				"4 - SAMLAuthzTicket: Receive, validate and process external SAML azticket\n" +
       				"5 - SAMLAuthzTicket: Create and sign a ticket in SAML1.1 format, and extract signed AuthzToken\n" +
       				"6 - AuthzToken: generate signed AuthzToken\n" +
       				"7 - AuthzToken: Receive, validate and process external aztoken\n" +
       				"9 - AAA AuthzTicket: generate (full) ticket with AuthZ session data and delegation" +  
					"");
       		int s = HelpersReadWrite.readStdinInt();			
       		//printKeyInfo (keyalias); 
       		switch(s) {
       		// Simple ticket sample fixed
       		case 0: {
   				Document docticket = AuthzTicketType.createSimpleSample();
   				System.out.println("\nAuthZ Ticket created (AuthzTicketType.createSimpleSample())");
   			    printDOMdoc(docticket);
   			String savefile = "x-output/azticket00-sample-cnl.xml";
   	        HelpersXMLsecurity.saveDOMdoc(docticket, savefile);
   	        System.out.println("\nWrote AuthzTikect to " + savefile);
   			return;}
       		//Simple ticket with variable parameters using constructor AuthzTicket
   			case 1: {
				AuthzTicketType azt = new AuthzTicketType(sessionid, policyref, pdpdecision, resources, 
		        		startDate, endDate, subjmap, actions);
				Document docticket = azt.createSimpleTicket();
				System.out.println("\nPrinting AuthzTicket as doc");
				printDOMdoc(docticket);
   		        //CachedAuthzTicket.cacheTicket(docticket);
		    	String savefile = "x-output/azticket01-simple.xml";
	    	    HelpersXMLsecurity.saveDOMdoc(docticket, savefile);
	    	    //
	            System.out.println("\nWrote AuthzTicket doc to " + savefile);
   		        System.out.println("\nAuthzTicket: get Issuer = " + azt.getIssuer());
   		        System.out.println("\nAuthzTicket: get NotBefore = " + azt.getNotBefore());
   		        System.out.println("\nAuthzTicket: get getNotOnOrAfter = " + azt.getNotOnOrAfter());
   		        System.out.println("\nAuthzTicket: get Resources = " + azt.getResources());
   		        System.out.println("\nAuthzTicket: get PDPdecision = " + azt.getPdpdecision());
   		        System.out.println("\nAuthzTicket: get PolicyURIs = " + azt.getPolicyref());
		     return;}
   			//Create and sign simple ticket, and extract signed AuthzToken
			case 2: {
   		        String intickfile = "x-output/azticket02-signed.xml";
   		        String tokenfile = "x-output/aztoken02-signed.xml";
		        Document docticket = AuthzTicketType.createSimpleTicket(sessionid, policyref, pdpdecision, resources, 
		        		startDate, endDate, subjmap, actions);
				Document docsigned = AuthzTicketType.signTicket(docticket, uri2sign, privkey);
	    	    HelpersXMLsecurity.saveDOMdoc(docticket, intickfile);
	    	    System.out.println("\nTestAuthzTicket: Saved AuthzTicket doc to " + intickfile);
	    	    
				Node signode = docticket.getElementsByTagNameNS(
   		        		"http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0);
   		        //printDOMdoc(docsigned);
   		        CachedAuthzTicket.cacheTicket(docsigned);
   		        System.out.println("\nTestAuthzTicket: Wrote AuthzTicket doc to cache");
   		        // token generation part
   		        Key tokenprivkey = null;
				System.out.println("\nTestAuthzTicket: Generating AuthzToken out of AuthzTicket");
				//AuthzToken aztok = new AuthzToken(readFileToDOM(infile), tokenprivkey);
				//Document aztoken = AuthzToken.createTokenSigned(readFileToDOM(intickfile), tokenprivkey);
				Document aztoken = AuthzTokenType.createTokenSigned(readFileToDOM(intickfile), tokenprivkey);
				System.out.println("\nSigned XML AuthzToken is generated successfully!");
		        HelpersXMLsecurity.saveDOMdoc(aztoken, tokenfile);
		        System.out.println("\nWrote AuthzToken doc to " + tokenfile);		        
		        HelpersXMLsecurity.printDOMdoc(aztoken);			
				//				
				System.out.println("\nChecking AuthzTicket in cache");
				//Document azticketfromcache = ResolverAuthzTicket.getTicketByTicket(docsigned);
				Document azticketfromcache = ResolverAuthzTicket.getTicketByToken(aztoken);
		        System.out.println("\nRetrieved AuthzTicket by AuthzToken from cache");				
				printDOMdoc(azticketfromcache);			
				//
				System.out.println("\nTestAuthzTicket: Validating ticket from cache...");
				boolean validSig = AuthzTicketType.validateTicket(azticketfromcache, pubkey, false);
				System.out.println("Retrieved from cache ticket is " + (validSig ? "=VALID=" : "=INVALID="));
				//
				System.out.println("\nTestAuthzTicket: Validating token...");
				HelpersXMLsecurity.printDOMdoc(aztoken);
   		        System.out.println("\nAuthzToken: get TicketID = " + AuthzTokenType.getTokenid());
   		        System.out.println("\nAuthzToken: get TokenValue = " + AuthzTokenType.getTokenValue());
				boolean validTok = AuthzTokenType.verifyTokenSigned(aztoken);
				System.out.println("Token is " + (validTok ? "=VALID=" : "=INVALID="));

			return;}
			// process external ticket
			case 3: {
   		        // read signed ticket to DOM and extract all data
   		        String infile = "x-output/azticket02-signed.xml";
				Document inaztikdoc = readFileToDOM(infile);
				System.out.println("\nTestAuthzTicket: Received external AuthzTicket");
				HelpersXMLsecurity.printDOMdoc(inaztikdoc);
				System.out.println("\nValidating received ticket...");
				boolean validSig = AuthzTicketType.validateTicket(inaztikdoc, pubkey, false);
				System.out.println("Recieved ticket is " + (validSig ? "=VALID=" : "=INVALID="));
				// new doc type
				System.out.println("\nTestAuthzTicket: Parsing external AuthzTicket");
				//AuthzTicket azt = new AuthzTicket();
				AuthzTicketType azt = new AuthzTicketType(inaztikdoc);
   		        //
				System.out.println("\nAuthzTicket: get Issuer = " + azt.getIssuer());
   		        System.out.println("\nAuthzTicket: get TicketId = " + azt.getTicketid());
   		        System.out.println("\nAuthzTicket: get SessionId = " + azt.getSessionid());
   		        System.out.println("\nAuthzTicket: get PolicyURIs = " + azt.getPolicyref());
   		        System.out.println("\nAuthzTicket: get Resources = " + azt.getResources());
   		        System.out.println("\nAuthzTicket: get PDPdecision = " + azt.getPdpdecision());
   		        System.out.println("\nAuthzTicket: get NotBefore = " + azt.getNotBefore());
   		        System.out.println("\nAuthzTicket: get NotOnOrAfter = " + azt.getNotOnOrAfter());
   		        System.out.println("\nAuthzTicket: get Subject map = " + azt.getSubjmap());
   		        System.out.println("\nAuthzTicket: get Actions set = " + azt.getActset());
   				
		     return;}
			// Generate SAMLAuthzTicket and token
			case 4: {       
				String outfile = "x-output/azticket03saml-azsession01.xml";
				sessionid = "Demo001-2008-06-16-saml";
		        pdpdecision = "Permit"; 
		        resources = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
				policyref = "PolicyRef-GAAA-RBAC-test001saml";
				sessiondata.add("put-session-data-Ctx-here");
				obligations.add("put-policy-obligation(1)-here");
				obligations.add("put-policy-obligation(2)-here");
		        Document samldocticket = SAML11AuthzTicket.createSAMLAssertion
		        	(sessionid, policyref, pdpdecision, resources, startDate, endDate, 
		        			subjmap, actions, obligations, sessiondata);
				HelpersXMLsecurity.saveDOMdoc(samldocticket, outfile);
		        printDOMdoc(samldocticket);
				//Document docsigned = AuthzTicketType.signTicket(samldocticket, uri2sign, privkey);
   		        //Node signode = samldocticket.getElementsByTagNameNS(
   		        //		"http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0);
		        //printDOMdoc(samldocticket);
   		        //System.out.println(signode.getTextContent().toString());
				return;}
			// Process SAMLAuthzTicket
			case 5: {
   				String aztickfile = "x-output/azticket03saml-azsession02.xml";
   				Document samltickdoc = readFileToDOM(aztickfile);
				printDOMdoc(samltickdoc);
				SAML11AuthzTicket samlaztick = new SAML11AuthzTicket(samltickdoc);
				//String id = SAMLAuthzTicket(samltickdoc).
   				//printDOMdoc(docencr);
   				return;}
			// generate signed AuthzToken
			case 6: {
				String infile = "x-output/aztoken04-signed.xml";
				Key tokenprivkey = null;
				System.out.println("\nGenerating AuthzToken out of AuthzTicket");
				AuthzTokenType.createTokenSigned(readFileToDOM(infile), tokenprivkey);
				System.out.println("\nSigned XML AuthzToken is generated successfully ");
				return;
			}
			// process external token
			case 7: {
   		        // read signed tioken to DOM and extract all data
				// TODO: [Fatal Error] aztoken-signed01ext.xml:1:63: The prefix "cnl" for element "cnl:CNLAuthzToken" is not bound.
   		        String infile0 = "x-output/aztoken04-signed00.xml";
   		        String infile1 = "x-output/aztoken04-signed01ext.xml";
				Document inaztok = readFileToDOM(infile1);
				printDOMdoc(inaztok);
				System.out.println("\nValidating received token...");
				boolean validTok = AuthzTokenType.verifyTokenSigned(inaztok);
				System.out.println("Recieved token is " + (validTok ? "=VALID=" : "=INVALID="));
				// new doc type
				//AuthzTicket azt = new AuthzTicket();
				AuthzTokenType aztok = new AuthzTokenType(inaztok);
				//Document aztoken = AuthzToken.createTokenSigned(readFileToDOM(infile), tokenprivkey);
				//Document aztoken = aztok.createTokenSigned(); AuthzToken (doc aztok)
				//System.out.println("\nSigned XML AuthzToken is generated successfully!");
				//System.out.println("\nChecking AuthzTicket in cache");
				//Document azticketfromcache = ResolverAuthzTicket.getTicketByTicket(docsigned);
				//Document azticketfromcache = ResolverAuthzTicket.getTicketByToken(docsigned);
				//printDOMdoc(azticketfromcache);			
				//CNLAuthzToken.verifyTokenSigned(aztoken);
   		        System.out.println("\nAuthzTicket: get Issuer = " + aztok.getIssuer());
   		        System.out.println("\nAuthzTicket: get TicketID = " + aztok.getTokenid());
   		        System.out.println("\nAuthzTicket: get SessionID = " + aztok.getSessionid());
   		        System.out.println("\nAuthzTicket: get NotBefore = " + aztok.getNotBefore());
   		        System.out.println("\nAuthzTicket: get NotOnOrAfter = " + aztok.getNotOnOrAfter());
   				
		     return;}
			/// AAATicket
			/* Document createAAATicket(String sessionid, String policyref, 
		    		String pdpdecision, String resources, Date notBefore, Date notOnOrAfter, 
					HashMap subjmap, Collection actset, Collection obligations, 
					Collection sessiondata, Boolean renewal, ArrayList delegates)
   			*/
   			case 9: { 
				sessionid = "Demo001-2008-06-16";
		        pdpdecision = "Permit"; 
		        resources = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
				policyref = "PolicyRef-GAAA-RBAC-test001";
				sessiondata.add("put-session-data-Ctx-here");
				obligations.add("put-policy-obligation(1)-here");
				obligations.add("put-policy-obligation(2)-here");
   				Boolean renewal = new Boolean(false);
   				delegates.add("3");
   				//communities.add("VO1-Escience2006");
   				//communities.add("VO2-SC2006");
   				delegates.add(communities);
   				HashSet dlgsubjects = new HashSet();
   				dlgsubjects.add("team-member-1");
   				dlgsubjects.add("team-member-2");
   				delegates.add(dlgsubjects);
		        Document docticket = AuthzTicketType.createAAATicket(sessionid, policyref, pdpdecision, resources, 
		        		startDate, endDate, subjmap, actions, 
		        		obligations, sessiondata, renewal, delegates);
				String outfile = "x-output/azticket05-azsession.xml";
				HelpersXMLsecurity.saveDOMdoc(docticket, outfile);
				System.out.println("\nPrinting AuthzTicket as doc");
				printDOMdoc(docticket);
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

}
