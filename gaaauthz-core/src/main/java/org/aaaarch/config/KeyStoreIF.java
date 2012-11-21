/*
 * Created on Feb 6, 2005
 *
 */
package org.aaaarch.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.aaaarch.config.ConfigSecurity;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * @author demch
 *
 */
public class KeyStoreIF {
	
	//static String configId; 
	private static String configId;
	//configId = ConfigSecurity.getSecurityConfigId();
	
	public static SecretKey GenerateAndStoreKeyEncryptionKey(String jceAlgorithmName, String kekfname)
    throws Exception {

    //String kekpath = "data/keystore/cnlsec/symkeystore/" + kekfname;
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

    public static SecretKey GenerateDataEncryptionKey(String jceAlgorithmName) throws Exception {

    //String jceAlgorithmName = "AES";
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(jceAlgorithmName);
    keyGenerator.init(128);
    return keyGenerator.generateKey();
}

public static PrivateKey getPrivKey (List keyconf) throws Exception {
	
	// List keyconf:
	// 	0 - keystoreType, 1 - keystoreFile, 2 - keystorePass,
	// 	3 - trustedstoreFile, 4 - trustedstorePass, 
	// 	3 - privKalias, 4 - privKpass, 5 - certificateAlias, 

	//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
	    String keystoreType = (String) keyconf.get(0);
	    String keystoreFile = (String) keyconf.get(1);
	    String keystorePass = (String) keyconf.get(2);
	    String privateKeyAlias = (String) keyconf.get(3);
	    String privateKeyPass = (String) keyconf.get(4);
	
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

public static PublicKey getPublicKey (List keyconf) throws Exception {
	
	// List keyconf:
	// 	0 - keystoreType, 1 - keystoreFile, 2 - keystorePass,
	// 	3 - trustedstoreFile, 4 - trustedstorePass, 
	// 	3 - privKalias, 4 - privKpass, 5 - certificateAlias, 

		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
	    String keystoreType = (String) keyconf.get(0);
	    String keystoreFile = (String) keyconf.get(1);
	    String keystorePass = (String) keyconf.get(2);
	    String privKeyAlias = (String) keyconf.get(3);
	    String privKeyPass = (String) keyconf.get(4);
	    String certificateAlias = (String) keyconf.get(5);
	
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

public static X509Certificate getCert (List keyconf) throws Exception {

// List keyconf:
// 	0 - keystoreType, 1 - keystoreFile, 2 - keystorePass,
// 	3 - trustedstoreFile, 4 - trustedstorePass, 
// 	5 - pepprivKalias, 6 - pepprivKpass, 7 - peppubKalias, 8 - pdppubKalias
//  9 - trustedAuth

	//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
    String keystoreType = (String) keyconf.get(0);
    String keystoreFile = (String) keyconf.get(1);
    String keystorePass = (String) keyconf.get(2);
    String certificateAlias = (String) keyconf.get(7);

    // Retrieving key information
    KeyStore ks = KeyStore.getInstance(keystoreType);
    FileInputStream fis = new FileInputStream(keystoreFile);
    //load the keystore
    ks.load(fis, keystorePass.toCharArray());
    //get the private key for signing.
     X509Certificate cert =
        (X509Certificate) ks.getCertificate(certificateAlias);

     //System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
    return cert;
}

public static PrivateKey getSigningKey (String trustdomain) throws Exception {

	List keyconf = null; // 
	configId = ConfigSecurity.getSecurityConfigId();
	
	// TRUSTDOMAIN_PEP = "urn:cnl:trust:pep"; // basic
	// TRUSTDOMAIN_PDP = "urn:cnl:trust:pdp";
	// TRUSTDOMAIN_PEP_PDP = "urn:cnl:trust:pdp-pep";
	if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP) {
		keyconf = KeyStoreConfig.getConfigKeysPEP(configId);
	} if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PDP) {
		keyconf = KeyStoreConfig.getConfigKeysPDP(configId);		
	} if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP_PDP) {
		// PEP and PDP under one trust admin/domain
		keyconf = KeyStoreConfig.getConfigKeysDefault(configId);		
	}

	// List keyconf:
	// 	0 - keystoreType, 1 - keystoreFile, 2 - keystorePass,
	// 	3 - privKalias, 4 - privKpass, 
	// 	5 - certificateAlias, 6 - trustedstoreFile, 7 - trustedstorePass, 
	//  8 - trustedAuthority, 9 - ticketAuthority
	// Trusted key: for PEP domain - PDP pubkey, for PDP domain - PEP pubkey 
	// TODO: check TRUSTDOMAIN_PEP_PDP configuration
	
	    String keystoreType = (String) keyconf.get(0);
	    String keystoreFile = (String) keyconf.get(1);
	    String keystorePass = (String) keyconf.get(2);
	    String privKalias = (String) keyconf.get(3);
	    String privKpass = (String) keyconf.get(4);
	    String certificateAlias = (String) keyconf.get(5);
	    String trustedstoreFile = (String) keyconf.get(6);
	    String trustedstorePass = (String) keyconf.get(7);
	    String trustedAuthority = (String) keyconf.get(8);
	    String ticketAuthority = (String) keyconf.get(9);
	
	    // Retrieving key information
	    KeyStore ks = KeyStore.getInstance(keystoreType);
	    FileInputStream fis = new FileInputStream(keystoreFile);
	    //load the keystore
	    ks.load(fis, keystorePass.toCharArray());
	    //get the private key for signing.
	    //get the private key for signing.
	    PrivateKey privateKey = (PrivateKey) ks.getKey(privKalias, privKpass.toCharArray());
	    //System.out.print("\n###Private key: \n" + privateKey.toString() + "\n");
         
	    return privateKey;
	}

public static PublicKey getTrustedKey (String trustdomain) throws Exception {

	List keyconf = null; // 
	configId = ConfigSecurity.getSecurityConfigId(); //"gaaa-nrp";
	
	// TRUSTDOMAIN_PEP = "urn:cnl:trust:pep";
	// TRUSTDOMAIN_PDP = "urn:cnl:trust:pdp";
	// TRUSTDOMAIN_PDP_PEP = "urn:cnl:trust:pep-pdp";
	if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP) {
		keyconf = KeyStoreConfig.getConfigKeysPEP(configId);
	} if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PDP) {
		keyconf = KeyStoreConfig.getConfigKeysPDP(configId);		
	} if (trustdomain == ConfigTrustDomains.TRUSTDOMAIN_AUTHZ_PEP_PDP) {
		// PEP and PDP under one trust admin/domain
		keyconf = KeyStoreConfig.getConfigKeysDefault(configId);		
	}

	// List keyconf:
	// 	0 - keystoreType, 1 - keystoreFile, 2 - keystorePass,
	// 	3 - privKalias, 4 - privKpass, 
	// 	5 - certificateAlias, 6 - trustedstoreFile, 7 - trustedstorePass, 
	//  8 - trustedAuthority, 9 - ticketAuthority
	// Trusted key: for PEP domain - PDP pubkey, for PDP domain - PEP pubkey 
	// TODO: check TRUSTDOMAIN_PEP_PDP configuration
	
	    String keystoreType = (String) keyconf.get(0);
	    String keystoreFile = (String) keyconf.get(1);
	    String keystorePass = (String) keyconf.get(2);
	    String privKalias = (String) keyconf.get(3);
	    String privKpass = (String) keyconf.get(4);
	    String certificateAlias = (String) keyconf.get(5);
	    String trustedstoreFile = (String) keyconf.get(6);
	    String trustedstorePass = (String) keyconf.get(7);
	    String trustedAuthority = (String) keyconf.get(8);
	    String ticketAuthority = (String) keyconf.get(9);
	
	    // Retrieving key information
	    KeyStore ks = KeyStore.getInstance(keystoreType);
	    //FileInputStream fis = new FileInputStream(trustedstoreFile);
	    FileInputStream fis = new FileInputStream(keystoreFile); //debug

	    //load the keystore
	    //ks.load(fis, trustedstorePass.toCharArray());
	    ks.load(fis, keystorePass.toCharArray()); //debug

	    //get the private key for signing.
         //X509Certificate cert = (X509Certificate) ks.getCertificate(trustedpubKalias);
         X509Certificate cert = (X509Certificate) ks.getCertificate(certificateAlias); //debug

         System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
         
	    PublicKey trustedKey = (PublicKey) cert.getPublicKey();
	    //System.out.print("\n###Public key: \n" + trustedKey.toString() + "\n");
	    return trustedKey;
	}

	public static void printKeyStoreInfo(String configId) throws Exception {
		List checkconfsec = new ArrayList();

		checkconfsec = KeyStoreConfig.getConfigKeys(configId);

		String keystoreType = (String) checkconfsec.get(0);
		String keystoreFile = (String) checkconfsec.get(1);
		String keystorePass = (String) checkconfsec.get(2);
		String privateKeyAlias = (String) checkconfsec.get(3);
		String privateKeyPass = (String) checkconfsec.get(4);
		String certificateAlias = (String) checkconfsec.get(5);
		//

		System.out.print("\n###Echo Key information\n" + "keystoreType="
			+ keystoreType + "\n" + "keystoreFile=" + keystoreFile + "\n"
			+ "keystorePass=" + keystorePass + "\n" + "privateKeyAlias="
			+ privateKeyAlias + "\n" + "privateKeyPass=" + privateKeyPass
			+ "\n" + "certificateAlias=" + certificateAlias + "\n\n");
	}

}
