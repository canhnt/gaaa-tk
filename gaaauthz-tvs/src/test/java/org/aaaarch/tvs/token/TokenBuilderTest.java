/**
 * @author CanhNT
 *  
 * Created on March 17, 2011
 * SNE at UvA
 */
package org.aaaarch.tvs.token;

import org.junit.Test;
import java.util.Date;

import org.aaaarch.tvs.TVSConstants;
import org.aaaarch.tvs.key.KeyManager;
import org.aaaarch.tvs.key.impl.DefaultKeyManager;
import org.aaaarch.tvs.token.AuthzTokenException;
import org.aaaarch.tvs.token.TokenBuilder;
import org.aaaarch.tvs.token.TokenValidator;


public class TokenBuilderTest {

	private static final int VALIDITY_PERIOD = 60 * 60 * 1000;
	
	private static final String GEYSERS_GRI = "fedcba9876543210";
	
	private static final String GEYSERS_ISSUER = "http://geysers.eu";

	private static final String SNE_GRI = "0123456789abcdef";
	private static final String SNE_ISSUER = "http://sne.uva.nl";

	public TokenBuilderTest() {
	}

	@Test
	public void doTest() {
		System.out.println("Test to create token org.aaaarch.tvs.token.TokenBuilder");
		
		KeyManager keyManager = new DefaultKeyManager();
		
		Date now = new Date();
		Date expired = new Date(now.getTime() + VALIDITY_PERIOD);
		
		byte[] tokenKeySNE = keyManager.generateSesionKey(SNE_ISSUER, SNE_GRI.getBytes());		
		
		TokenBuilder tbSNE = new TokenBuilder(tokenKeySNE, now, expired);
		String accessToken = tbSNE.createAccessToken(SNE_ISSUER, SNE_GRI);
		System.out.println("Access Token of SNE Issuer: " + accessToken);
		
		String pilotToken1 = tbSNE.createPilotToken(TVSConstants.PILOT_TOKEN_TYPE_1, SNE_ISSUER, SNE_GRI, null);
		System.out.println("Pilot Token 1 of SNE Issuer: " + pilotToken1);

		byte[] tokenKeyGeysers = keyManager.generateSesionKey(SNE_ISSUER, SNE_GRI.getBytes());
		TokenBuilder tbGeysers = new TokenBuilder(tokenKeyGeysers, now, expired);
		
		String pilotToken2 = tbGeysers.createPilotToken(TVSConstants.PILOT_TOKEN_TYPE_2, GEYSERS_ISSUER, GEYSERS_GRI, pilotToken1);
		System.out.println("Pilot Token 2 of GEYSSERS Issuer: " + pilotToken2);
		
		TokenValidator validatorSNE = new TokenValidator(tokenKeySNE);
		TokenValidator validatorGeysers = new TokenValidator(tokenKeyGeysers);
		
		try {
			System.out.println("Validating access token: " + validatorSNE.validate(TokenBuilder.deserialize(accessToken)));
		} catch (AuthzTokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try {
			System.out.println("Validating pilot token 1: " + validatorSNE.validate(TokenBuilder.deserialize(pilotToken1)));
		} catch (AuthzTokenException e) {
			// TODO Auto-generated catch block
			System.err.println(e.getMessage());
		}
		
		try {
			System.out.println("Validating pilot token 2: " + validatorGeysers.validate(TokenBuilder.deserialize(pilotToken2)));
		} catch (AuthzTokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
