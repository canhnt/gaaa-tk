package org.aaaarch.gaaapi.tvs.test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;
import java.util.Vector;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.aaaarch.config.ConfigDomainsPhosphorus;
import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.config.ConfigTrustDomains;
import org.aaaarch.config.ConstantsNS;
import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.gaaapi.ActionSet;
import org.aaaarch.gaaapi.IDgenerator;
import org.aaaarch.gaaapi.ResourceHelper;
import org.aaaarch.gaaapi.SubjectSet;
import org.aaaarch.gaaapi.tvs.TVSConfig;
import org.aaaarch.gaaapi.tvs.GRIgenerator;
import org.aaaarch.gaaapi.tvs.TVS;
import org.aaaarch.gaaapi.tvs.TVSTable;
import org.aaaarch.gaaapi.tvs.TokenBuilder;
import org.aaaarch.gaaapi.tvs.TokenKey;
import org.aaaarch.gaaapi.tvs.XMLTokenType;
import org.aaaarch.utils.HelpersDateTime;
import org.aaaarch.utils.HelpersHexConverter;
import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
 
public class TestTVS {

	static String tokenKey = new String();
	static String localdir = "x-output/";
	
    public static void main (String unused[]) throws Exception {

    	String tokenfile = "tvs-aztoken00.xml";
		String tokenhexfile = "tvs-tokenhex00.txt";
		// Preparing data for SimpleTicket format
		/* <!ELEMENT Conditions>
		 * atributes: startDate, endDate 
		 */
		// consider timezone IssueInstant="2008-10-17T17:15:27.921000000+02:00"
		Date startDate = new Date();
		Date endDate = new Date();
		//Setting validity for 24 hrs
		long hrs24 = 24;
		endDate = new Date(startDate.getTime() + (hrs24*60*60*1000));
		
		// Checking timezone
		// get Calendar instance
	    Calendar now = Calendar.getInstance();
	   
	    //get current TimeZone using getTimeZone method of Calendar class
	    TimeZone timeZone = now.getTimeZone();
	   
	    //display current TimeZone using getDisplayName() method of TimeZone class
	    System.out.println("\nCurrent TimeZone is : " + timeZone.getDefault() + 
	    		"\n Display format " + timeZone.getDisplayName());
		//+++
	    System.out.println("\nGood TimeZone from Calendar : " +
	            Calendar.getInstance().getTimeZone().getID());
	  DateFormat df = DateFormat.getDateInstance();
	  System.out.println("Bad TimeZone from DateFormat : " +
	            df.getTimeZone().getID());
	  //	    fix the TimeZone          
	  df.setCalendar(Calendar.getInstance());
	  System.out.println("Good TimeZone from DateFormat : " + df.getTimeZone().getID());
	  //---
		// end timezone
		
		// Defualt values for Token
		Date notBefore = startDate; 
		Date notOnOrAfter = endDate; // valid for 24 hrs
		
		// dummy GRI 
		String gri16bytes = "0000112233445566778899aabbccddeeff";
		String gri32bytes = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
				
   	try {   	
   	   	System.out.println("Running interactive test examples for TVS API:\n" + 
			"0 - TVS-TB: generate token of GRI - TokenBuilder.getBinaryToken (GRI, TokenKey or null)" +
			"\n    (uses internal TokenKey or default token generation convention)\n" +
			"1 - TVS: validate binary token - TVS.ValidateBinaryToken (GRI, TokenValue, TokenKey?))\n" +
			"2 - TVS-TB: generate XMLtoken of GRI - TokenBuilder.getXMLToken(GRI, TokenKey||null)\n" +
			"3 - TVS: validate XML token (generated in option 2) - TVS.validateXMLToken (XMLToken, TokenKey||null))\n" +
			"4 - PEP-TVS: Validate Service/PEP Request with XMLToken (generated in option 2)\n" +  
			"5 - TVS-TB: generate Pilot XMLtoken types 1-3 - TokenBuilder.generatePilotXMLToken(gri, domainId, validtime, tokenKey, toktyoe, tokPrevs)\n" +
			"6 - TVS: validate and process pilot XML token (generated in option 5) - TVS.validateXMLToken (XMLToken, TokenKey||null))\n" +
			"7 - Programming TVS(table): Create and fill in TVStable (GRI, DomainId, sessionCtx) \n" +
			"8 - Programming TVS(table) via API: add/delete entry, purge; \n" +
			"10* - Programming TVS(table) via WS/XML message: MessageSetTVS (GRI, ResourceID, (TokenValue | TokenKey)?, NotBefore?, NotOnOrAfter?)\n" +  
			"");
   		int s = HelpersReadWrite.readStdinInt();			
   		//
   		switch(s) {
   		// Simple ticket sample fixed
   		case 0: {
			//String tokenhexfile = "tvs-tokenhex01.txt";
   			String gri = gri32bytes;
   			//System.out.println("Token Key Secret: \"" + TokenKey.getTokenSecret() + "\"");
   			byte[] tokenkey = TokenKey.generateTokenKey(gri);
   			byte[] token = TokenBuilder.getBinaryToken(gri, null);
			System.out.println("GRI/LRI = " + gri + "\nTokenKey = " + HelpersHexConverter.byteArrayToHex(tokenkey) +
			"\nToken = " + HelpersHexConverter.byteArrayToHex(token));
			String tokenhex = HelpersHexConverter.byteArrayToHex(token);
			//write((localdir + tokenhexfile), tokenhex);
			//write(tokenhexfile, tokenhex);
			writeToFile(tokenhex, (localdir + tokenhexfile));
			return;}
   		case 1: {//TVS: validate binary token - ValidateBinaryToken (GRI, TokenValue, TokenKey?)
   			String gri = gri32bytes; // GRI must be extracted from token!
			String token = readFileToString(localdir + tokenhexfile);
			//System.out.println("Read Token: " + token);
   			boolean valid = TVS.validateBinaryToken (token, gri, null);
   			System.out.println("Token is " + (valid ? "=VALID=" : "=INVALID=")); 
		return;}
   		case 2: {//TVS-TB: generate XMLtoken of GRI
   			System.out.println("TVSConfig: " + "\n" + ConfigSecurity.getTVSConfigData());
   			//int validtime1 = Integer.parseInt(ConfigSecurity.getTVSConfigData().get("validtime").toString());
   			int validtime1 = TVSConfig.getValidityTimeConfig();
   			System.out.println("TVSConfig: validtime = " + validtime1);
   			System.out.println("Select token type: 0 - simple token; 1 - full token (valid 24 hrs)\n" +
					"(use option <<1>> to create a token for validation test from general menu option 4)");
			//System.out.println("Input token validity time in minutes: 0 - no validity time");
   	   		int tok = HelpersReadWrite.readStdinInt();			
   	   		boolean simple = true;
			//tokenfile = "tvs-aztoken01.xml";
   	   		int validtime = 0; // 
   	   		//if (tok != 0) {validtime = 1440*60; simple = false;} // valid 24 hrs
   	   		if (tok != 0) {validtime = TVSConfig.getValidityTimeConfig (); simple = false;} // valid 24 hrs
   	   		String domainId = null;
   			String gri = GRIgenerator.generateGRI(20).toString();
   			String tokenxml = TokenBuilder.getXMLToken(domainId, gri, null, validtime, simple);
			System.out.println("XMLToken: " + "\n" + tokenxml);
			//String tokenVal = TokenBuilder.getXMLTokenValue(gri, null);
			// "tvs-aztoken01.xml"
			writeToFile(tokenxml, (localdir + tokenfile));
		return;}
   		case 3: { // Validate XMLToken from option 2
   			Document tokendoc = readFileToDOM(localdir + tokenfile);
   			HelpersXMLsecurity.printDOMdoc(tokendoc);
			XMLTokenType token = new XMLTokenType (tokendoc);
			boolean timevalid = token.isTimeValid(token);
			System.out.println("\nToken time validity: " + (timevalid ? "=VALID=" : "=INVALID="));
			System.out.println("Token elements: TokenId = " + token.getTokenid() + 
					"; SessionId = " + token.getSessionid() + "; Issuer = " + token.getIssuer() +
					"\nValid from " + token.getNotBefore() + " to " + token.getNotOnOrAfter() +
					"\nTokenValue = " + token.getTokenValue() +
					"\nTokenDomain = " + token.getTokenDomain() + "\nTokenType = " + token.getTokenType());
			boolean valid = TVS.validateXMLToken (tokendoc, null);
   			System.out.println("Token is " + (valid ? "=VALID=" : "=INVALID="));			
   			return;}
		case 4: {//"5 - PEP-TVS: Validate Service/PEP Request with XMLToken (uses XMLToken generated in option 2)	
			String resourceInputURI;
			// TODO: URN resourceId doesn't work
			// range (10.3.*, 10.4.*, 10.7.*,  10.8.*)
			//resourceId = "http://testbed.ist-phosphorus.eu/resource-type/nsp";
			//resourceId = "http://testbed.ist-phosphorus.eu/resource-type/harmony";
			resourceInputURI = "http://testbed.ist-phosphorus.eu/viola/harmony/" +
					"source=10.1.1.16/target=10.7.3.13";
			//resourceId = "http://testbed.ist-phosphorus.eu/resource-context/phosphorus";
			//resourceId = "http://testbed.ist-phosphorus.eu/resource-context/phosphorus/experiment=demo010";
			//resourceId = "x-urn:nrp:testbed.ist-phosphorus.eu:resource-context:phosphorus:test=demo001";			
			
			HashMap resmap = ResourceHelper.parseResourceURI(resourceInputURI);
			HashMap<String, String> actmap = new HashMap<String, String>();
			HashMap<String, String> subjmap = new HashMap<String, String>();
			subjmap = SubjectSet.getSubjSetTest();
			
		    String action = ActionSet.NSP_CREATE_PATH;		
		   //action = "cancel";
		    actmap.put(ConstantsNS.ACTION_ACTION_ID, action); 
	    	// some modifications for experiments
			//subjmap.put(ConstantsNS.SUBJECT_ROLE, "student");
	    	subjmap.put(ConstantsNS.SUBJECT_CONTEXT, "demo041");		
	    	System.out.println("\nInput ResourceURI = " + resourceInputURI);
	    	System.out.println("\nResMap = " + resmap);
		    System.out.println("\nSubjMap = " + subjmap);
		    
   			//tokenfile = "tvs-aztoken01-pilot00-type2.xml";
   			String aztstr = readFileToString(localdir + tokenfile);
   			System.out.println("\nReceived AuthzToken from file = " + (localdir + tokenfile) + "\n" + aztstr);

			boolean confirmed = TVS.validateAuthzRequestByToken (aztstr, resmap, actmap, subjmap);
			
			System.out.println("\nAuthZ request validated against XMLToken:\n" +
					"TVS result is \"" + (confirmed ? "Confirmed" : "Failed") + "\"\n");
		return;}

   		case 5: { // Create pilot token: simple (GRI) and advanced (GRI, tokenValue, chain) 
  	   	//String TokenBuilder.getXMLTokenPilot(String domainId, String gri, String domain, 
   	   	//int validtime, byte[] tokenKey, int ptokentype, String tokenCtx) 
			System.out.println("Select token type: 0 - access token (not supported); 1 - pilot token type0 (GRI container); " +
					"2 - pilot token type2 (source authenticating); 3 - pilot token type3 (path/domain ctx tracking)");
   	   		int tt = HelpersReadWrite.readStdinInt();			
			tokenfile = localdir + "tvs-aztoken01-pilot0" + tt + ".xml";
   			//String domainId = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_DEFAULT;
   			// current local domain is "viola"
			String domainId = ConfigDomainsPhosphorus.getDomainLocal();
   			//String domainId = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_VIOLA;
   			//String domainId = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_I2CAT;
   			//int validtime = 60*60; // 60 min 
   			int validtime = 24*60*60; // 24 hrs
   			byte[] tokenKey = null; 
   			String gri = GRIgenerator.generateGRI(20).toString();
   			switch(tt) {
   	   		// Simple ticket sample fixed
   	   		case 0: {
   	   			System.out.println("Token type=0 is not supported in this test. Please use test 2"); 
   	 		return;}
   	   	case 1: {
   	   	   		String tokenxml = TokenBuilder.getXMLPilotToken(domainId, gri, 0, tokenKey, tt, null);
   	   	   		writeToFile(tokenxml, (tokenfile));
   				System.out.println("\n\nTestTVS: PilotXMLToken type = " + tt + " created and saved to file:\n" + tokenfile + "\n\n" + tokenxml);
   	 		return;}
   	   	case 2: {
   	   	   		String tokenxml = TokenBuilder.getXMLPilotToken(domainId, gri, validtime, tokenKey, tt, null);
   	   	   		writeToFile(tokenxml, (tokenfile));
   				System.out.println("\n\nTestTVS: PilotXMLToken type = " + tt + " created and saved to file:\n" + tokenfile + "\n\n" + tokenxml);
   	 		return;}
   	   	case 3: {
   				// tokenCtx - previous token or previous AuthzTicket
   				String tokenfilePrevious = localdir + "tvs-aztoken01-pilot03-previous.xml";
   	 			String tokenPrevious = HelpersReadWrite.readFileToString(tokenfilePrevious);
   	   	   		String tokenxml = TokenBuilder.getXMLPilotToken(domainId, gri, validtime, tokenKey, tt, tokenPrevious);
   	   	   		writeToFile(tokenxml, (tokenfile));
   	 			System.out.println("\n\nTestTVS: PilotXMLToken type = " + tt + " created and saved to file:\n" + tokenfile + "\n\n" + tokenxml);
   	 		return;}
   			}
   			return;}
   		case 6: { // Process and validate pilot XML token type 2 and 3
   			tokenfile = "tvs-aztoken01-pilot02.xml";
   			//String tokenfile0 = "tvs-aztoken01-pilot02-viola.xml";
   			String tokenfile0 = "tvs-aztoken01-pilot02-i2cat.xml";
   			String tokenString = readFileToString(localdir + tokenfile0);
   			System.out.println("\nPilot Token to validate\n" + tokenString);
			XMLTokenType token = new XMLTokenType (tokenString);
			boolean timevalid = token.isTimeValid(token);
			System.out.println("\nToken time validity: " + (timevalid ? "=VALID=" : "=INVALID="));
			System.out.println("Token elements: TokenId = " + token.getTokenid() + 
					"; SessionId = " + token.getSessionid() + "; Issuer = " + token.getIssuer() +
					"\nValid from " + token.getNotBefore() + " to " + token.getNotOnOrAfter() +
					"\nTokenValue = " + token.getTokenValue() +
					"\nTokenDomain = " + token.getTokenDomain() + "\nTokenType = " + token.getTokenType());
			
			//String tdomain = token.getDomainsContext()
   			HashMap domainsCtx = token.getDomainsContext();
   			if (domainsCtx != null) {
   				System.out.println("\nChecking Domains Context");
   			//}
 			for (Iterator i=domainsCtx.keySet().iterator(); i.hasNext();){
 	 	          String ikey = i.next().toString();
 	 	         //System.out.println("\nXMLTokenType: i = " + i + "\nikey = " + ikey + "\nToken received: \n");
 	 	          Vector vdomain = (Vector) domainsCtx.get(ikey);
 	  			//for (Iterator m=vdomain.iterator(); m.hasNext();){
 	 	          String keyinfo = "";
 	 	        Iterator m=vdomain.iterator();
 	 	      String domainId = (String) m.next();
 	 	        //String domainId = vdomain.get(0).toString();
 	 	          //if (vdomain.get(1) != null) { 	 	         
	 	        //keyinfo = vdomain.get(1).toString();
 	 	      if (m.hasNext()) {  
 	 	        keyinfo = (String) m.next();
 	 	      }
 	 	      //}
	 	      System.out.println("DomainContext: \ndomain = " + domainId + 
	 	    		  "\nKeyInfo = " + keyinfo);
 	 	      //Document tokdoc = null;
 	 	      //if (vdomain.get(2) != null) { 	 	         
 	 	 	  if (m.hasNext()) {  
 	 	 	      XMLTokenType tokenObj = (XMLTokenType) vdomain.get(2);
 	 	 	      Document tokdoc = tokenObj.getXMLToken();
 		 	      System.out.println("DomainContext: token = "); 	 	 	          
 		 	      HelpersXMLsecurity.printDOMdoc(tokdoc);
 	  	 	  	}
 	 	      } //    
 	  		}// end domainsCtx processing
   			
   			//Processing if no tokenCtx 
   			String tokenNext = TVS.validateAndRelayPilotToken (tokenString, null);
   			if (tokenNext != null) {
			System.out.println("Token is " + "=VALID=" 
					+ "\nNew token to send to the next domain:\n" + tokenNext);
   			writeToFile(tokenNext, (localdir + tokenfile));
   			} else {
   				System.out.println("Token is " + "=INVALID=" + " and will not be relayed");
   			}
   			return;}
		case 7: {//	"7 - placeholder
   			return;}
		
		case 8: {//	"8 - Programming TVS(table): Create and fill in TVStable (GRI, DomainId, sessionCtx)
 			String domainId = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_DEFAULT; 
			String gri = GRIgenerator.generateGRI(20).toString(); 
			String gri1 = GRIgenerator.generateGRI(20).toString(); 
			String gri2 = GRIgenerator.generateGRI(20).toString(); 
			//String domainId = "http://testbed.ist-phosphorus.eu/viola"; 
			String domainId1 = "http://testbed.ist-phosphorus.eu/i2cat"; 
			//Date notBefore = new Date(); 
			//Date notOnOrAfter = new Date(); 
			String actionId = "create-path"; 
			String resourceId = "http://testbed.ist-phosphorus.eu/viola/harmony"; 
			String resourceSource = "10.8.1.102"; 
			String resourceTarget = "10.7.3.23"; 
			String subjectId = "WHO540@testbed.ist-phosphorus.eu"; 
			String subjectRole = "researcher"; 
			String subjectContext = "demo011";
			String keyinfo = "keyinfo011"; // String keyinfo = TokenKey.getTokenPublic(domainId, gri)

			HashMap<String, HashMap<String, Vector<Comparable>>> domainsT = new HashMap<String, HashMap<String, Vector<Comparable>>>();
			HashMap<String, Vector<Comparable>> sessionsT = new HashMap<String, Vector<Comparable>>();
			Vector<Comparable> sessionCtxT = new Vector<Comparable>();
            sessionCtxT.add(notBefore);
            sessionCtxT.add(notOnOrAfter);
            sessionCtxT.add(actionId);
            sessionCtxT.add(subjectId);
            sessionCtxT.add(subjectRole);
            sessionCtxT.add(subjectContext);
            sessionCtxT.add(resourceId);
            sessionCtxT.add(resourceSource);
            sessionCtxT.add(resourceTarget);
            sessionCtxT.add(null); //keyinfo 

            sessionsT.put(gri, sessionCtxT);
            sessionsT.put(gri1, sessionCtxT);
            sessionsT.put(gri2, sessionCtxT);
    		
    		domainsT.put(domainId, sessionsT);
			
			
			/*Document tvsdoc = TVSTable.buildTVSTable (domainId, gri, notBefore, notOnOrAfter,
					actionId, resourceId, resourceSource, resourceTarget, 
					subjectId, subjectRole, subjectContext);
			*/
    		Document tvsdoc = TVSTable.buildTVSTable (domainsT);
			String tvsfile =  TVS.getTVSTableFile ();
			
			TVSTable tb = new TVSTable(tvsdoc);
			System.out.println("\nChecking TVS entry: DomainId = " + domainId + 
					"; SessionId/GRI = " + gri +
					"\nValid from " + tb.getGRIContextVector(domainId, gri).get(0) + 
					" to " + tb.getGRIContextVector(domainId, gri).get(1) +
					 "\nAction = " + tb.getGRIContextVector(domainId, gri).get(2));
    		String tablefile = TVS.getTVSTableFile ();
   			Document tokendoc = readFileToDOM(tablefile);
   			HelpersXMLsecurity.printDOMdoc(tokendoc);
		return;}

   		case 9: {
   			//"10 - Programming TVS via API: add/delete/purg" 
			String gri = GRIgenerator.generateGRI(20).toString(); 
			String gri1 = GRIgenerator.generateGRI(20).toString(); 
			String gri2 = GRIgenerator.generateGRI(20).toString(); 
			String gri3 = GRIgenerator.generateGRI(20).toString(); 
			String domainId = "http://testbed.ist-phosphorus.eu/viola"; 
			String domainId1 = "http://testbed.ist-phosphorus.eu/i2cat"; 
			//Date notBefore = new Date(); 
			//Date notOnOrAfter = new Date(); 
			String actionId = "create-path"; 
			String resourceId = "http://testbed.ist-phosphorus.eu/viola/harmony"; 
			String resourceSource = "10.8.1.102"; 
			String resourceTarget = "10.7.3.23"; 
			String subjectId = "WHO540@testbed.ist-phosphorus.eu"; 
			String subjectRole = "researcher"; 
			String subjectContext = "demo011";
			String keyinfo = "keyinfo011"; // String keyinfo = TokenKey.getTokenPublic(domainId, gri)

			HashMap<String, HashMap<String, Vector<Comparable>>> domainsT = new HashMap<String, HashMap<String, Vector<Comparable>>>();
			HashMap<String, Vector<Comparable>> sessionsT = new HashMap<String, Vector<Comparable>>();
			Vector<Comparable> sessionCtxT = new Vector<Comparable>();
            sessionCtxT.add(notBefore);
            sessionCtxT.add(notOnOrAfter);
            sessionCtxT.add(actionId);
            sessionCtxT.add(subjectId);
            sessionCtxT.add(subjectRole);
            sessionCtxT.add(subjectContext);
            sessionCtxT.add(resourceId);
            sessionCtxT.add(resourceSource);
            sessionCtxT.add(resourceTarget);
            sessionCtxT.add(null);

            sessionsT.put(gri, sessionCtxT);
            sessionsT.put(gri1, sessionCtxT);
            sessionsT.put(gri2, sessionCtxT);
    		
    		domainsT.put(domainId, sessionsT);
			/*Document tvsdoc = TVSTable.buildTVSTable (domainId, gri, notBefore, notOnOrAfter,
					actionId, resourceId, resourceSource, resourceTarget, 
					subjectId, subjectRole, subjectContext);
			*/
    		//Document tvsdoc = TVSTable.buildTVSTable (domainsT);
			//String tvsfile =  TVS.getTVSTableFile ();
			//TVSTable tb = new TVSTable(tvsdoc);
		
    		System.out.println("\nSlect TVSTable operation: \n" +
    				"1 - addEntryTVStable (GRI, DomainId, sessionCtx) \n" +
    				"2 - deleteEntryTVStable (DomainId, GRI)\n" +
    				"3 - purgeTVSTable (domainId, expireTime)\n"); 
   	   		int op = HelpersReadWrite.readStdinInt();			
	   		switch(op) {
	   		// add/delete/purge
	   		case 1: {
	    		//gri3 = "667bee4c78bfc754055bb23cb8713515ae5c3ebc";
				//gri1 = "3fafac1843cb72e75446d6781d39e06c5b613071"; 
				//boolean added = TVSTable.addEntryTVSTable(domainId, gri3, sessionCtxT);
				TVS.setEntryTVSTable(domainId, gri1, sessionCtxT);
	    		System.out.println("\nAdded TVS entry for domainId = " + domainId + 
						"; SessionId/GRI = " + gri1 + "\n");
	   			return;}
	   		case 2: {
				//boolean deleted = TVSTable.deleteEntryTVSTable(domainId, gri1);
				// (decision ? "Permit" : "Deny")
				TVS.deleteEntryTVSTable(domainId, gri1);
	    		System.out.println("\nDeleted TVS entry for domainId = " + domainId + 
						"; SessionId/GRI = " + gri1 + "\n");
	   			return;}
	   		case 3: {
	   			TVSTable.purgeTVSTable(null, 0);
	    		System.out.println("\nTVSTable purged for domainId = " + domainId); 
	   			return;}
	   		}
    		String tablefile = TVS.getTVSTableFile ();
   			Document tokendoc = readFileToDOM(tablefile);
   			HelpersXMLsecurity.printDOMdoc(tokendoc);
   			return;}   			
   		case 10: {
   			//"10 - Programming TVS via WS/XML message: MessageSetTVS (GRI, ResourceID, (TokenValue | TokenKey)?, NotBefore?, NotOnOrAfter?)\n" +  
   			return;}   			
   		}
   		System.out.println("OK");
   		System.exit(0);
   	   	} catch (Exception e) {
   	   		e.printStackTrace();
   	   		System.exit(1);
   	   		}

    }

	public static String generateTokenKeySimple(String gri) throws Exception {

        //byte[] buf=new byte[64];
        //SecureRandom rand = new SecureRandom();

		//byte[] buf = new byte[20];
        
        //byte[] gribytes = gri.getBytes("UTF8");
        byte[] gribytes = gri.getBytes();
        
        String grihex =  new String(Hex.encode(gribytes));

        System.out.println("gri length=" + gribytes.length + "  gri = " + gri);
        //for (int i=0; i<gribytes.length; i++)
        //    id.append(Character.forDigit(gribytes[i] & 15, 16));
		
		//byte[] tokenKey = gribytes;
        //String keyBase = id.toString();
        String keyBase = grihex;
        
        tokenKey = keyBase;
        System.out.println("tokenkey = " + tokenKey);
        
		return gri; //tokenKey;
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
        encryptionFile.toString());
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

	public static void writeToFile (String docstring, String filename) throws IOException {

		byte[] docbytes = docstring.getBytes();
		
		File File = new File(filename);
	    FileOutputStream f = new FileOutputStream(File);
	    f.write(docbytes);
	    f.close();
	    
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

	// Read File as string
	public static String readFileToString(String fileName) throws IOException {
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
		//System.out.println("Key encryption key stored in " + kekFile.toString());

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
