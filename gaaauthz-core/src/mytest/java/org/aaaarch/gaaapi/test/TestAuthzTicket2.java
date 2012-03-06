/*
 * Created on July 2007
 *
 */
package org.aaaarch.gaaapi.test;

import java.util.ArrayList;
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
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.config.KeyStoreIF;
import org.aaaarch.gaaapi.ResourceHelper;
import org.aaaarch.gaaapi.ResourceSet;
import org.aaaarch.gaaapi.SubjectSet;
import org.aaaarch.gaaapi.ticktok.AuthzTicketTypeV2;
import org.aaaarch.gaaapi.ticktok.AuthzTokenType;
import org.aaaarch.gaaapi.ticktok.CachedAuthzTicket;
import org.aaaarch.gaaapi.ticktok.ResolverAuthzTicket;
import org.aaaarch.gaaapi.ticktok.AuthzTicketResource;

import org.aaaarch.gaaapi.ticktok.AuthzTicketDecision;

/**
 * @author demch
 * draft-gaaa-azticket-022.xsd
 */
public class TestAuthzTicket2 {	
	
	
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
	System.out.println("*** Print DOM doc ***");
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
	
	
	//print data on AuthzTicketType2 (attributes)
	private static void print_data_simple_ticket(AuthzTicketTypeV2 azt)
	{
		System.out.println("******** Print infos attributes simple ticket *********\n");
	    System.out.println("\nget Issuer = " + azt.getIssuer());
	    System.out.println("\nget NotBefore = " + azt.getNotBefore());
	    System.out.println("\nget getNotOnOrAfter = " + azt.getNotOnOrAfter());
	    System.out.println("\nget ResourceID = " + azt.getResourceID());
	    azt.printResult();
	    azt.printPolicyRef();
	   // System.out.println("\nGet result number 2 : " + azt.getResult(2));
	   // System.out.println("\nGet policy ref number 2 : " + azt.getPolicyRef(2));
	    System.out.println("\nget ResourceType = " + azt.getResourceType());
        System.out.println("\nget ID Subject = " + azt.getID());
        
        System.out.println("\n******** Print infos about actions, obligations and resource (port, token, tokenky) *********\n");
        HashSet action = azt.getActset();
        Iterator i=action.iterator(); 
        while(i.hasNext())
        {
        	System.out.println("Get Action : "+i.next());
        }
        
        HashSet obligations = azt.getObligationset();
        Iterator it=obligations.iterator(); 
        while(it.hasNext())
        {
        	System.out.println("Get obligation : "+it.next());
        }

        HashMap resource = azt.getresourcemap();
        Set cles = resource.keySet();
        Iterator iterator = cles.iterator();
        while (iterator.hasNext()) {
        	Object cle = iterator.next();
        	Object valeur = resource.get(cle);
        	if(cle == "resource-port")System.out.println("Get Port : "+ valeur);
        	if(cle == "resource-token")System.out.println("Get Token : "+ valeur);
        	if(cle == "resource-token-key") System.out.println("Get Token Key : "+ valeur);
        }
	}	
	
    
	// print decision with HashSet
	public static void print_decision_hashset(HashSet<AuthzTicketDecision> decision)
	{
		System.out.println("Decision has "+decision.size()+" element(s)");
		
		if(decision.size() != 0){
		int incr = 1;
		for(AuthzTicketDecision dec: decision){
			System.out.println(" -> Element number "+incr);
			dec.print_decision();
			incr++;
		}
		}
		else{
			System.out.println("No Element");
		}
	}
	
    public static void main (String unused[]) throws Exception {

    	//directory
	    String dir = "authz-22/";
	
	    //Array for the elements and the attributes
		HashMap subjmap = new HashMap();
		ArrayList sessiondata = new ArrayList();
		ArrayList delegates = new ArrayList();
		HashSet actions = new HashSet();
		HashSet obligations = new HashSet();
		HashSet communities = new HashSet();
		ArrayList resourceset = new ArrayList();
		HashMap resourcemap = new HashMap();
		
		/* PART on the decisions*/
		AuthzTicketDecision decision1 = new AuthzTicketDecision("Permit","CNL2policy01");
		AuthzTicketDecision decision2 = new AuthzTicketDecision("Deny","CNL2policy02");
		HashSet<AuthzTicketDecision> decision = new HashSet<AuthzTicketDecision>();
		decision.add(decision1);
		decision.add(decision2);
		print_decision_hashset(decision);	
		
		// Attributes (except conditions)
        // @result, @resourceid, @policyref, @resourcetype, @sessionin, @id
        String result = "Permit"; 
        String policyref = "CNL2policy01";
        String sessionid = "JobXPS1-2005-001";
        String id = "id_subject";
        String method = "SubjectConfMethod";
        String resourcetype ="resourcetype";        
         
		// Preparing data for SimpleTicket format (attributes conditions)
		Date startDate = new Date();
		Date endDate = new Date();
		//Setting validity for 24 hrs
		long hrs24 = 24;
		endDate = new Date(startDate.getTime() + (hrs24*60*60*1000));
		
		//Subject
		subjmap = SubjectSet.getSubjSetTest();
		
		//resource with resourceid
		resourcemap = ResourceSet.getResourceSetTest();
		
        // Actions list
        String action2 = "cnl:actions:CtrlExper";
        String action1 = "cnl:actions:CtrlInstr";
        actions.add(action1);
        actions.add(action2);
        
        // Obligations list
        String obligation1 =  "here oligation 1";
        String obligation2 =  "here oligation 2";
        obligations.add(obligation1);
        obligations.add(obligation2);
        
  		//Receive parameters for the pubkey keystore for cnl02 test profile
        String configId = ConfigSecurity.getSecurityConfigId();
  	   	List keyconf = KeyStoreConfig.getConfigKeysPEP(configId);
  	   	
  	   	// !!! using trust domain config for key access - some problems
  	   	//Key privkey = KeyStoreIF.getSigningKey(ConfigTrustDomains.TRUSTDOMAIN_PEP_PDP);
  	   	//Key pubkey = KeyStoreIF.getTrustedKey(ConfigTrustDomains.TRUSTDOMAIN_PEP_PDP);
  	   	// !!! using keyconfig for key access - no problems but need config knowledge
  	   	Key privkey = KeyStoreIF.getPrivKey(keyconf);
  	   	Key pubkey = KeyStoreIF.getPublicKey(keyconf);
	   
        // uri to sign - list of 
		String uri2sign0 = "";
		List uri2sign = new ArrayList();
		uri2sign.add(uri2sign0);
        
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
       	   	System.out.println("Running Examples for GAAAPI AuthZ ticket/Authz token (Version 02.2):\n");
       		System.out.println("Select ticket generation option : \n" +
       				"1 - AAA AuthzTicket: Get simple ticket and save\n"+
       				"2 - AAA AuthzTicket: Create et save simple ticket (with constructor)\n" +
       				"3 - AAA AuthzTicket (full): Create, save simple ticket - Generate and validate Authztoken\n" +  
       				"4 - AAA AuthzTicket: Read XML file doc, validate and get ticket\n" +
       				"5 - AuthzToken: generate signed CNLAuthzToken\n" +
       				"6 - Read signed tioken to DOM and extract all data (error!!)\n" +
       				"7 - Create AAA Ticket: generate (full) ticket with AuthZ session data and delegation" +  
					"");
       		int s = HelpersReadWrite.readStdinInt();			
       		switch(s) {
       		
       		//sample of simple ticket
       		case 1:{
       				System.out.println("******** Get a simple ticket sample and save it *********\n");
       				Document docticket = AuthzTicketTypeV2.createSimpleSample();
       			    printDOMdoc(docticket);
       			    return;
       		}
       		
       		//simple ticket AuthzTicket
       		case 2:{
       				System.out.println("******** Create simple ticket *********\n");
       				System.out.println("******** Using constructor AuthzTicketType2 *********\n");
       				AuthzTicketTypeV2 azt = new AuthzTicketTypeV2(startDate, endDate, sessionid, 
       						id, decision, subjmap, actions,obligations, resourcemap);
    				
       				System.out.println("******** Save simple ticket as doc*********\n");
       				Document docticket = azt.createSimpleTicket();
       				printDOMdoc(docticket);
       		        
       				//print data
       				print_data_simple_ticket(azt);
    		     return;
       		}
       		
   			//Create and sign simple ticket, and extract signed AuthzToken
			case 3: {
				System.out.println("******** Create simple ticket *********\n");
		        Document docticket = AuthzTicketTypeV2.createSimpleTicket(startDate, endDate, 
		        		sessionid, id, decision, subjmap, actions, obligations, resourcemap);
				
		        System.out.println("\n******** Sign simple ticket *********\n");
				Document docsigned = AuthzTicketTypeV2.signTicket(docticket, uri2sign, privkey);
				
   		        //printDOMdoc(docsigned);
				CachedAuthzTicket.cacheTicket(docsigned);
				System.out.println("\n******** Wrote CNLAuthzTicket doc to cache ********");  
				
   		        // token generation part
   		        String intickfile = dir+"azticket-simple-v2-signed.xml";
   		        Key tokenprivkey = null;
				System.out.println("\n******** Generating CNLAuthzToken out of CNLAuthzTicket ********");
				Document aztoken = AuthzTokenType.createTokenSigned(readFileToDOM(intickfile), tokenprivkey);
				System.out.println("\n******** Signed XML CNLAuthzToken is generated successfully! ********");
				System.out.println("\n******** Checking CNLAuthzTicket in cache ********");
				Document azticketfromcache = ResolverAuthzTicket.getTicketByToken(aztoken);
				printDOMdoc(azticketfromcache);		
				
				System.out.println("\n******** Validating ticket from cache... ********");
				boolean validSig = AuthzTicketTypeV2.validateTicket(azticketfromcache, pubkey, false);
				System.out.println("-Retrieved from cache ticket is " + (validSig ? "=VALID=" : "=INVALID="));
				AuthzTokenType.verifyTokenSigned(aztoken);
   		        System.out.println("\n- CNLAuthzToken: get TicketID = " + AuthzTokenType.getTokenid());
   		        System.out.println("\n - CNLAuthzToken: get TokenValue = " + AuthzTokenType.getTokenValue());
				boolean validTok = AuthzTokenType.verifyTokenSigned(aztoken);
				System.out.println(" ===> Token is " + (validTok ? "=VALID=" : "=INVALID="));
			return;}
			
			// process external ticket
			case 4: {
   		        // read signed ticket to DOM and extract all data
   		        String infile = dir+"azticket-simple-v2-signed.xml";
				Document inaztik = readFileToDOM(infile);
				printDOMdoc(inaztik);
				System.out.println("\nValidating received ticket...");
				boolean validSig = AuthzTicketTypeV2.validateTicket(inaztik, pubkey, false);
				System.out.println("Recieved ticket is " + (validSig ? "=VALID=" : "=INVALID="));

				AuthzTicketTypeV2 azt = new AuthzTicketTypeV2(inaztik);

				//print data
				print_data_simple_ticket(azt);
		        return;}
			
			// generate signed CNLAuthzToken
			case 5: {
				String infile = dir+"azticket-simple-v2-signed.xml";
				Key tokenprivkey = null;
				System.out.println("\n******* Generating AuthzToken out of AuthzTicket ******");
				AuthzTokenType.createTokenSigned(readFileToDOM(infile), tokenprivkey);
				System.out.println("\n******* nSigned XML AuthzToken is generated successfully *******");
				return;
			}
			
			// process external token
			case 6: {
   		        // read signed tioken to DOM and extract all data
				// TODO: [Fatal Error] aztoken-signed01ext.xml:1:63: The prefix "cnl" for element "cnl:CNLAuthzToken" is not bound.
   		        String infile1 = "aztoken-signed01ext.xml";
				Document inaztok = readFileToDOM(infile1);
				printDOMdoc(inaztok);
				System.out.println("\nValidating received token...");
				boolean validTok = AuthzTokenType.verifyTokenSigned(inaztok);
				System.out.println("Recieved token is " + (validTok ? "=VALID=" : "=INVALID="));

				AuthzTokenType aztok = new AuthzTokenType(inaztok);

   		        System.out.println("\nCNLAuthzTicket: get Issuer = " + aztok.getIssuer());
   		        System.out.println("\nCNLAuthzTicket: get TicketID = " + aztok.getTokenid());
   		        System.out.println("\nCNLAuthzTicket: get SessionID = " + aztok.getSessionid());
   		        System.out.println("\nCNLAuthzTicket: get NotBefore = " + aztok.getNotBefore());
   		        System.out.println("\nCNLAuthzTicket: get NotOnOrAfter = " + aztok.getNotOnOrAfter());				
		     return;}
			
			//AAATicket
			case 7: { 
				sessionid = "JobXPS1-2006-001";
		        result = "Permit"; 
				policyref = "PolicyRef-GAAA-RBAC-test001";
				sessiondata.add("put-session-data-Ctx-here");
				obligations.add("put-policy-obligation(1)-here");
				obligations.add("put-policy-obligation(2)-here");
   				Boolean renewal = new Boolean(false);
   				delegates.add("3");
   				delegates.add(communities);
   				HashSet dlgsubjects = new HashSet();
   				dlgsubjects.add("team-member-1");
   				dlgsubjects.add("team-member-2");
   				delegates.add(dlgsubjects);
   				resourceset.add("resource1");
   				resourceset.add("resource2");
   				
		       Document docticket = AuthzTicketTypeV2.createAAATicket(result, 
		    		policyref, resourcetype, startDate, endDate, sessionid, id, method,
		    		subjmap, actions, resourcemap, obligations, sessiondata, renewal, delegates, resourceset);
				
		       	String outfile = dir+"aaaticket-v2.xml";
				HelpersXMLsecurity.saveDOMdoc(docticket, outfile);
				System.out.println("\n****** Printing AuthzTicket as doc *******");
				printDOMdoc(docticket);
   				return; 
   				}
   		}
   		System.out.println("OK");
   		System.exit(0);
   	   	} 
       	catch (Exception e) {
   	   		e.printStackTrace();
   	   		System.exit(1);
   	   		}
    }
}
