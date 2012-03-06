package org.aaaarch.config;

import java.util.ArrayList;
import java.util.List;

public class KeyStoreConfig {

	//TODO: 
	public static List getConfigKeys (String configId) throws Exception {
	   	List<String> confsec = new ArrayList<String>();
	
	if (configId.equals("gaaa-nrp")) {	   	
	   	//All the parameters for the keystore
	    String keystoreType = "JKS";
	    String keystoreFile = ConfigSecurity.LOCAL_DIR_ROOT + "etc/security/keystore/nrpsec/keystore01phsec.jks";
	    String keystorePass = "ph_security";
	    String privateKeyAlias = "gaaa_tk";
	    String privateKeyPass = "trust:gaaatk";
	    String certificateAlias = "gaaa_tk";
	    //  
		confsec.add(keystoreType); // (0)
		confsec.add(keystoreFile); // (1)
		confsec.add(keystorePass); // (2)
		confsec.add(privateKeyAlias); // (3)
		confsec.add(privateKeyPass); // (4)
		confsec.add(certificateAlias); // (5)					
	} else {
		if (configId.equals("gaaa-nc6")) {
		    String keystoreType = "JKS";
		    String keystoreFile = ConfigSecurity.LOCAL_DIR_ROOT + 
		    	"etc/security/keystore/unicore6/keystore06unicore.jks";
		    String keystorePass ="uc_security";
		    String privateKeyAlias = "mykey";
		    String privateKeyPass = "asdfasdf";
		    String certificateAlias = "mykey";

		    //String issuerAlias = "mykey";
		    //String issuerJKSPath = "etc/security/keystore/unicore6/store1.jks";
		    //char[] issuerJKSPass = "asdfasdf".toCharArray();
		    //
		    //String subjectAlias = "mykey";
		    //String subjectJKSPath = "etc/security/keystore/unicore6/store2.jks";
		    //char[] subjectJKSPass = "asdfasdf".toCharArray();

		    //  
			confsec.add(keystoreType);
			confsec.add(keystoreFile);
			confsec.add(keystorePass);
			confsec.add(privateKeyAlias);
			confsec.add(privateKeyPass);
			confsec.add(certificateAlias);								
		} else {
	    String keystoreType = "JKS";
	    String keystoreFile = ConfigSecurity.LOCAL_DIR_ROOT + "etc/security/keystore/xmlsec/keystore1xmlsec.jks";
	    String keystorePass = "xmlsecurity";
	    String privateKeyAlias = "cnl01";
	    String privateKeyPass = "xmlsecurity";
	    String certificateAlias = "cnl01";
	    //  
		confsec.add(keystoreType);
		confsec.add(keystoreFile);
		confsec.add(keystorePass);
		confsec.add(privateKeyAlias);
		confsec.add(privateKeyPass);
		confsec.add(certificateAlias);		
		}
	}
		return confsec;
	}

	////
	public static List getConfigKeysPEP (String configId) throws Exception {
	   	List<String> confsec = new ArrayList<String>();
	   	
		if (configId == ConfigSecurity.getSecurityConfigId()) {
	
			String keystoreType = "JKS";
		    String keystoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE_NRPSEC + "keystore01phsec.jks";
		    String keystorePass = "ph_security";
		    //PDP and PEP keys/credentials 
		    String pepprivKalias = "gaaa_pep";
		    String pepprivKpass = "trust:pep";
		    String pepCertAlias = "gaaa_pep";
		    
		   	//Trusted and local keys/credentials 
		    String trustedstoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE_NRPSEC + "trusted/keystore01phtrusted.jks";
		    String trustedstorePass = "ph_trusted";
		    String trustedAuthority = "gaaa-trust.xml";
	
		    // trusted sites or authorities
			// AuthzTicket authority
	    String tickauthpep = "tickauth:pep";		
		String tickauthpdp = "tickauth:pdp";		
		String ticketAuthority = tickauthpep;
	
		// adding to the list
		confsec.add(keystoreType); //0
		confsec.add(keystoreFile); //1
		confsec.add(keystorePass); //2
		confsec.add(pepprivKalias); //3
		confsec.add(pepprivKpass); //4
		confsec.add(pepCertAlias); //5					
		confsec.add(trustedstoreFile);	// 6
		confsec.add(trustedstorePass);	// 7
		//
		confsec.add(trustedAuthority);       	// 8
		confsec.add(ticketAuthority);       	// 9
	
	return confsec;
	} else { 
	confsec = null;
	
	return confsec;}
	}

	public static List getConfigKeysPDP (String configId) throws Exception {
	   	List<String> confsec = new ArrayList<String>();
	   	
		if (configId == ConfigSecurity.getSecurityConfigId()) {
	
			String keystoreType = "JKS";
		    String keystoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE_NRPSEC + "keystore01phsec.jks";
		    String keystorePass = "ph_security";
		    //PDP and PEP keys/credentials 
		    String pdpprivKalias = "gaaa_pdp";
		    String pdpprivKpass = "trust:pdp";
		    String pdpCertAlias = "gaaa_pdp";
		    
		   	//Trusted and local keys/credentials 
		    String trustedstoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE_NRPSEC + "trusted/keystore01phtrusted.jks";
		    String trustedstorePass = "ph_trusted";
		    String trustedAuthority = "gaaa-trust.xml";
	
		    // trusted sites or authorities
			// AuthzTicket authority
	    String tickauthpep = "tickauth:pep";		
		String tickauthpdp = "tickauth:pdp";		
		String ticketAuthority = tickauthpep;
	
		// adding to the list
		confsec.add(keystoreType); //0
		confsec.add(keystoreFile); //1
		confsec.add(keystorePass); //2
		confsec.add(pdpprivKalias); //3
		confsec.add(pdpprivKpass); //4
		confsec.add(pdpCertAlias); //5					
		confsec.add(trustedstoreFile);	// 6
		confsec.add(trustedstorePass);	// 7
		//
		confsec.add(trustedAuthority);       	// 8
		confsec.add(ticketAuthority);       	// 9
	
	return confsec;
	} else { 
	confsec = null;
	
	return confsec;}
	}

	// Provides key set from default configuration "gaaa-tk" where PEP and PDP co-located 
	public static List getConfigKeysDefault (String configId) throws Exception {
	   	List<String> confsec = new ArrayList<String>();
	
		if (configId == ConfigSecurity.getSecurityConfigId()) {
	
			String keystoreType = "JKS";
		    String keystoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE_NRPSEC + "keystore01phsec.jks";
		    String keystorePass = "ph_security";
		    String privateKeyAlias = "gaaa_tk";
		    String privateKeyPass = "trust:gaaatk";
		    String certificateAlias = "gaaa_tk";
		    
		   	//Trusted and local keys/credentials 
		   	// - Certs are selfsigned
		    String trustedstoreFile = ConfigSecurity.LOCAL_DIR_KEYSTORE_NRPSEC + "trusted/keystore01phtrusted.jks";
		    String trustedstorePass = "ph_trusted";
		    String trustedAuthority = "gaaa-trust.xml";
	
		    // AuthzTicket authority
		    String tickauthpep = "tickauth:pep";		
			String tickauthpdp = "tickauth:pdp";		
			String ticketAuthority = tickauthpep;
	
			// adding to the list
			confsec.add(keystoreType); //0
			confsec.add(keystoreFile); //1
			confsec.add(keystorePass); //2
			confsec.add(privateKeyAlias); //3
			confsec.add(privateKeyPass); //4
			confsec.add(certificateAlias); //5					
			confsec.add(trustedstoreFile);	// 6
			confsec.add(trustedstorePass);	// 7
			//
			confsec.add(trustedAuthority);       	// 8
			confsec.add(ticketAuthority);       	// 9
		
		return confsec;
		} else { 
		confsec = null;
		
		return confsec;}
	}

	public static List getConfigKeysUC6 (String configId) throws Exception {
	   	List<String> confsec = new ArrayList<String>();
	
		if (configId == "gaaa-uc6") {
	
			String issuerKStype = "JKS";
		    String issuerJKSPath = ConfigSecurity.LOCAL_DIR_KEYSTORE + "unicore6/store1.jks";
		    String issuerJKSPass = "asdfasdf";
		    String issuerAlias = "mykey";
		    String issuerPrivKeyPass = "asdfasdf"; //??
		    String issuerCertAlias = "mykey"; //??

			String subjectKStype = "JKS";
		    String subjectJKSPath = ConfigSecurity.LOCAL_DIR_KEYSTORE + "unicore6/store2.jks";
		    String subjectJKSPass = "asdfasdf";
		    String subjectAlias = "mykey";
		    String subjectPrivKeyPass = "asdfasdf"; //??
		    String subjectCertAlias = "mykey"; //??
	
			// adding to the list
			confsec.add(issuerKStype); //0
			confsec.add(issuerJKSPath); //1
			confsec.add(issuerJKSPass); //2
			confsec.add(issuerAlias); //3
			confsec.add(issuerPrivKeyPass); //4
			confsec.add(issuerCertAlias); //5
			////
			confsec.add(subjectKStype);	// 6
			confsec.add(subjectJKSPath);	// 7
			confsec.add(subjectJKSPass);       	// 8
			confsec.add(subjectAlias);       	// 9
			confsec.add(subjectPrivKeyPass); //10
			confsec.add(subjectCertAlias); //11					
		
		return confsec;
		} else { 
		confsec = null;
		
		return confsec;}
	}
}
