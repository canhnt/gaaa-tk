/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.tvs.key;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 
 * @date: Mar 17, 2011
 * 
 */

/**
 * The generic interface KeyManager: 
 * providing keys using for token generation and token validation.
 */
public interface KeyManager {
	
//	/**
//	 * Return the decrypted session key in the KEYBLOB of the specific issuer.
//	 * 
//	 * @param issuer
//	 * @param keyBlob
//	 * @return
//	 */
//	public byte[] decryptSessionKey(String issuer, byte[] keyBLOB);
	
	/**
	 * Generate a session symmetric key for a specific issuer.
	 *  
	 * @param issuer
	 * @param nonce
	 * @return
	 */
	public byte[] generateSesionKey(String issuer, byte[] nonce);
	
//	/**
//	 * Generate the KEYBLOB storing the session key.
//	 * 
//	 * @param issuer
//	 * @param nonce The random input from the issuer
//	 * @return
//	 */
//	public byte[] createKeyBLOB(String issuer, byte[] sessionKey);
}
