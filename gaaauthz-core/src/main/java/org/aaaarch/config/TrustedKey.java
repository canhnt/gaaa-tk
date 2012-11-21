/*
 * Created on Feb 6, 2005
 *
 */
package org.aaaarch.config;

import java.util.Collection;
import java.util.HashSet;

/**
 * @author demch
 * This class will manage (access to) trusted repository in a form of 
 * JKS (keystore5cnltrusted.jks) or 
 * cnl-trust.xml file that contains all trusted public keys/Certs in the form of ds:KeyInfo 
 */
public class TrustedKey {
	
	public static void addTrustedKey (Collection newTrustedKey) {
		// Add new trusted key
	}

	public static Collection getTrustedKey (String trustanchor) {
	    HashSet trustedKeys = new HashSet(); 
		// Find trusted key in the trusted repository
	    
		return trustedKeys;
	}

}
