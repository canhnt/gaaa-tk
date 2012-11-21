/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.tvs.key.impl;

import org.aaaarch.crypto.HMACProcessorException;
import org.aaaarch.crypto.HMACprocessor;
import org.aaaarch.tvs.key.KeyManager;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 
 * @date: Mar 17, 2011
 * 
 */

/**
 * The default trivial KeyManager, return the session key of a issuer based on its issuer's name.
 * 
 * TokeyKey = HMAC(issuer | nonce, SHARING_SEED)
 * 
 * KEYBLOB is unencrypted, storing the same value as the tokenkey.
 *  
 */
public class DefaultKeyManager implements KeyManager {

	protected final static byte[] STATIC_SHARING_SEED = new byte[] {0x12, 0x34, 0x56, 0x78, (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef};
//	/* (non-Javadoc)
//	 * @see org.aaaarch.tvs.key.KeyManager#getTokenKey(java.lang.String, byte[])
//	 */
//	@Override
//	public byte[] decryptSessionKey(String issuer, byte[] keyBLOB) {
//		return keyBLOB;
//	}
//
//	@Override
//	public byte[] createKeyBLOB(String issuer, byte[] sessionKey) {
//
//		return sessionKey;
//	}

	public byte[] generateSesionKey(String issuer, byte[] nonce) {
		byte[] sessionKey = null;
		try {
			sessionKey = HMACprocessor.computeHMAC(issuer + nonce.toString(), STATIC_SHARING_SEED, null);
		} catch (HMACProcessorException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return sessionKey;
	}
	
}
