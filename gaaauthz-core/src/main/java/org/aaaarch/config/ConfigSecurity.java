/*
 * Created on Feb 2, 2005
 *
 */
package org.aaaarch.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

import org.aaaarch.xmltooling.HelpersXMLsecurity;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;


/**
 * @author demch
 * Configuration methods use "configId" to refer to the specific profile:
 *    nrp, ph-nsp, grid (GAAA-NRP, GAAA-NSP, GAAA-GRID)
 *    
 * The configuration Id/profile defines the following parameters:
 *  * key set and keystore name and access creds
 *  * policy directory
 *  * attributes Id sets   
 * 
 * TODO: decide on Ticket authority - who issues the AuthzTicket?
 * tickauth = "tickauth:pep" or "tickauth:pdp" 
 * TODO: Move configuration to config file
 * In the process - 1) NRP domains configuration
 *                  2) TVS token validity time 
 *                  3) PEP-PDP config?
 * 
 */
public class ConfigSecurity {
	
	//Local directories configuration
	public static final String LOCAL_DIR_ROOT = "";

	// Configuration directory
	public static final String LOCAL_DIR_SECURITYCONFIG = LOCAL_DIR_ROOT + "data/config/";	
	
	//
	static String configfile = ConfigSecurity.LOCAL_DIR_SECURITYCONFIG + "gaaapi-nrp-config001.xml";

	// General GAAA-AuthZ configuration profiles
	//public static final String SECURITYCONFIG_CNL2 = "cnl02"; // TODO: Historical, to be removed
	public static final String SECURITYCONFIG_DEFAULT = "gaaa-nrp"; // TODO: Move to default config "gaaapi-pep-pdp"
	public static final String SECURITYCONFIG_NRP = "nrp";
	public static final String SECURITYCONFIG_GRID_INTEROP = "grid";
	public static final String SECURITYCONFIG_PH_NSP = "ph-nsp";
	
	// Providers
	public static final String PROVIDER_GAAA_AUTHN_HARMONY_AAI = "gaaa:authn:provider:harmony-aai";
	public static final String PROVIDER_GAAA_AUTHZ_HARMONY_AAI = "gaaa:authz:provider:harmony-aai";

	//public static final String SECURITYCONFIG = ConfigSecurity.SECURITYCONFIG_NRP;
	public static final String TRUSTDOMAIN_CURRENT = ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP;

	
	// KEYSTOREs configuration
	public static final String LOCAL_DIR_KEYSTORE = LOCAL_DIR_ROOT + "etc/security/keystore/";
	//public static final String LOCAL_DIR_KEYSTORE_CNLSEC = LOCAL_DIR_KEYSTORE + "cnlsec/"; //TODO: Remove CNLSEC
	public static final String LOCAL_DIR_KEYSTORE_NRPSEC = LOCAL_DIR_KEYSTORE + "nrpsec/"; //
	////
	public static final String LOCAL_DIR_KEYSTORE_TRUSTED = LOCAL_DIR_KEYSTORE + "trusted/";	
	public static final String LOCAL_DIR_KEYSTORE_TRUSTED_NRP = LOCAL_DIR_KEYSTORE + "nrpsec/trusted/";	
	public static final String LOCAL_DIR_SYMKEYSTORE = LOCAL_DIR_KEYSTORE + "xmlsec/symkeystore/";	
	public static final String LOCAL_DIR_SYMKEYSTORE_NRP = LOCAL_DIR_KEYSTORE + "nrpsec/symkeystore/";	
	public static final String LOCAL_DIR_KEYSTORE_IBC = LOCAL_DIR_KEYSTORE + "ibc/";	

	// Policy directory
	//public static final String LOCAL_DIR_POLICY = LOCAL_DIR_ROOT + "data/policy/" + SECURITYCONFIG + "/";
	public static final String LOCAL_DIR_POLICY = LOCAL_DIR_ROOT + "data/policy/";
	
	// Working and temporal directories
	public static final String LOCAL_DIR_SCHEMAS = LOCAL_DIR_ROOT + "data/schemas/";
	public static final String LOCAL_DIR_AAADATA_TMP = LOCAL_DIR_ROOT + "_aaadata/tmp/";
    public static final String LOCAL_DIR_AAADATA_CACHE = LOCAL_DIR_ROOT + "_aaadata/cache/";
	public static final String LOCAL_DIR_AAADATA_CACHE_AZTICKETS = LOCAL_DIR_AAADATA_CACHE + "aztickets/";
	public static final String CACHE_SESSIONS_TVS_TABLE = LOCAL_DIR_AAADATA_CACHE + "sessions/" + "tvs-table-simple.xml";

	////
	public static String getDomainLocal() throws Exception {
		String domainId = "";
		Element root = getConfigDocElement ();
		Element domains =  (Element) root.getElementsByTagName("Domains").item(0);
		
		////
		NodeList domainlist = domains.getElementsByTagName("Domain");
		int checklocal = 0;
		for (int i = 0; i < domainlist.getLength(); i++) {
	    	//HashMap<String, Vector<Comparable>> sessionsT = new HashMap<String, Vector<Comparable>> ();
	    	//System.out.println("\nDomainsContext: got element i = " + i);
	    	Element entry = (Element) domainlist.item(i);
	    	if ((entry.hasAttribute("domaintype") && (entry.getAttribute("domaintype").toString().equals("local")))) {
	    		 domainId = entry.getAttribute("domainId");
	    		 checklocal++;
	        } 
	    // TODO: do we need to throw exception if no local domain configured	
	    if (checklocal > 1) {
	    	throw new MalformedConfigFileException ("Malformed Config file: Two local domains indicated");
	    }
		}
		return domainId;
	}

	// Read PEP configuration data from the config file
	public static HashMap getPEPConfigData() throws Exception {
		
		HashMap<String, String> devconfigmap = new HashMap();
		Element root = getConfigDocElement ();
		Element configdata =  (Element) root.getElementsByTagName("ConfigurationData").item(0);
		
		////
		NodeList devicelist = configdata.getElementsByTagName("DeviceConfig");
		for (int i = 0; i < devicelist.getLength(); i++) {
	    	//HashMap<String, Vector<Comparable>> sessionsT = new HashMap<String, Vector<Comparable>> ();
	    	//System.out.println("\nDomainsContext: got element i = " + i);
	    	Element device = (Element) devicelist.item(i);
	    	if ((device.hasAttribute("devicetype") && 
	    			(device.getAttribute("devicetype").toString().equals("PEP")))) {
	    		NodeList paramlist = device.getElementsByTagName("ConfigParam");
	    		for (int j = 0; j < paramlist.getLength(); j++) {
	    	    	Element entry = (Element) paramlist.item(j);
	    	    	devconfigmap.put(entry.getAttribute("name").toString(), 
	    	    			entry.getTextContent());
	    	    	}
	    		}
	        } 
		return devconfigmap;
		}

	// Read TVS configuration data
	public static HashMap getTVSConfigData() throws Exception {
		HashMap<String, String> devconfigmap = new HashMap();
		Element root = getConfigDocElement ();
		Element configdata =  (Element) root.getElementsByTagName("ConfigurationData").item(0);
		
		////
		NodeList devicelist = configdata.getElementsByTagName("DeviceConfig");
		for (int i = 0; i < devicelist.getLength(); i++) {
	    	//HashMap<String, Vector<Comparable>> sessionsT = new HashMap<String, Vector<Comparable>> ();
	    	//System.out.println("\nDomainsContext: got element i = " + i);
	    	Element device = (Element) devicelist.item(i);
	    	if ((device.hasAttribute("devicetype") && 
	    			(device.getAttribute("devicetype").toString().equals("TVS")))) {
	    		NodeList paramlist = device.getElementsByTagName("ConfigParam");
	    		for (int j = 0; j < paramlist.getLength(); j++) {
	    	    	Element entry = (Element) paramlist.item(j);
	    	    	devconfigmap.put(entry.getAttribute("name").toString(), 
	    	    			entry.getTextContent());
	    	    	}
	    		}
	        } 
		return devconfigmap;
	}
	
	public static List getServers (String configId) throws Exception {
	   	List confsrv = new ArrayList();

	   	//AuthZ infrastructure servers 
		String aaaServer = "http://146.50.22.64:8080/AAA/server";
		String authnServer = "http://146.50.22.64:8080/AAA/server";
		String attrServer = "http://146.50.22.64:8080/AAA/server";
		String policyServer = "http://146.50.22.64:8080/AAA/server";
		// 

	    confsrv.add(aaaServer);
	    confsrv.add(authnServer);
	    confsrv.add(attrServer);
	    confsrv.add(policyServer);

		return confsrv;
	}
	public static List getSites (String configId) throws Exception {
	   	List<String> confsrv = new ArrayList<String>();

	   	//AuthZ infrastructure servers 
		String site1 = "http://146.50.22.64:8080/AAA/server";
		String site2 = "http://146.50.22.64:8080/AAA/server";
		String site3 = "http://146.50.22.64:8080/AAA/server";
		String site4 = "http://146.50.22.64:8080/AAA/server";
		// 

	    confsrv.add(site1);
	    confsrv.add(site2);
	    confsrv.add(site3);
	    confsrv.add(site3);

		return confsrv;
	}

	public static String getURLaaa (String configId) throws Exception {

	   	List servers = getServers(configId);
	   	/// get aaaServer as the first element
	   	String aaaServer = servers.get(0).toString();

		return aaaServer;
	}
	public static String getLocalDir (String configId) throws Exception {

	   	//AuthZ infrastructure servers 
		String localdir = LOCAL_DIR_ROOT;
		// 
		return localdir;
	}
	public static String getTicketAuthority (String configId, String trustdomain) throws Exception {

		// AuthzTicket authority
	    String tickauthpep = ConfigTrustDomains.TICKETAUTHORITY_PEP;		
		String tickauthpdp = ConfigTrustDomains.TICKETAUTHORITY_PDP;		
		String tickauth = tickauthpdp;

		if (configId == getSecurityConfigId()) {
			if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP){
				tickauth = tickauthpep;
			} if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PDP){
				tickauth = tickauthpdp;
			} if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP_PDP){
				tickauth = tickauthpdp;
			}
		} 
		return tickauth;
	}
	
	//TODO: pre-configured security - change 
	public static String getAuthnKeyId (String configId, String provider) throws Exception {

		// AuthnKey ID
		String keyid = "keypassAuthnDES";

		if (configId == getSecurityConfigId()) {
			// "gaaa:authn:provider:harmony-aai"
			if (provider.equals(PROVIDER_GAAA_AUTHN_HARMONY_AAI)){
				return keyid;
		}}
		return keyid;
	}
	
	public static List getConfigPolicy (String configId) throws Exception {
	   	List<String> confpolicy = new ArrayList<String>();

	   	//AuthZ policy location and prefix (opt)
	    String policyDir = ConfigSecurity.LOCAL_DIR_POLICY + configId + "/";
	    // String policyPrefix = ConstantsNS.AAA_POLICY_PREFIX;
	   	// Policy Authority - not used
		// 

	    confpolicy.add(policyDir);
	    //confpolicy.add(policyPrefix);

		return confpolicy;
	}
	  public static String getSecurityConfigId () throws Exception {
			   	String confsec;
			   	confsec = ConfigSecurity.SECURITYCONFIG_DEFAULT;

				return confsec;
			}
			
			// Default sec-domain = project domain
			// It is read from the local config file
			public static String getSecurityDomain () throws Exception {
			   	String secdomain;
			   	
			   	secdomain = getSecurityDomainDefault();

				return secdomain;
			}
			public static String getSecurityDomainDefault () throws Exception {
			   	String secdomain;
			   	
			   	//secdomain = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_DEFAULT;
			   	secdomain = ConfigSecurity.getDomainLocal();

				return secdomain;
			}

			/// 
			private static Element getConfigDocElement () throws Exception {
				Document configdoc = HelpersXMLsecurity.readFileToDOM(configfile);
				Element root = (Element) configdoc.getElementsByTagName("Configuration").item(0);
				return root;
			}
			}
