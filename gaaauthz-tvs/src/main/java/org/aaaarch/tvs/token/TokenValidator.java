/**
 * 
 */
package org.aaaarch.tvs.token;

import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.aaaarch.tvs.utils.HelpersHexConverter;

/**
 * @author CanhNT
 * @Date 2011.03.04
 * 
 *
 */
public class TokenValidator {

	byte[] _issuerTokenKey;
	
	public TokenValidator(byte[] issuerTokenKey) {
		_issuerTokenKey = Arrays.copyOf(issuerTokenKey, issuerTokenKey.length);
	}
	
	/**
	 * Validate the TokenValue in the authzToken object.
	 * Formula: 
	 * 		TokenValue = HMAC(domainId | sessionId | tokenId, tokenKey)
	 * 		
	 * @param authzToken
	 * @return
	 * @throws AuthzTokenException 
	 */
	public boolean validate(AuthzTokenType authzToken) throws AuthzTokenException {
		
		if (authzToken.getTokentype().equals(TokenConstants.PILOT_TOKEN_TYPE1))
			throw new AuthzTokenException("Pilot-token type1 cannot validate tokenvalue");
		
		return validateLifetime(authzToken) &&
			   validateTokenValue(authzToken);		
	}

	private boolean validateLifetime(AuthzTokenType authzToken) {
		ConditionsType conditions = authzToken.getConditions();
		XMLGregorianCalendar notBefore = conditions.getNotBefore();
		XMLGregorianCalendar notOnOrAfter = conditions.getNotOnOrAfter();
		
		// create current date object
		GregorianCalendar c = new GregorianCalendar();
		c.setTime(new Date());
		try {
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
			if (notBefore.compare(now) == DatatypeConstants.GREATER)
				return false;
			
			if (notOnOrAfter.compare(now) != DatatypeConstants.GREATER)
				return false;
			
			return true;
		} catch (DatatypeConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private boolean validateTokenValue(AuthzTokenType authzToken) throws AuthzTokenException {
				
		String tokenValue = authzToken.getTokenValue();
		if (tokenValue == null || tokenValue.isEmpty())
			throw new AuthzTokenException("The authzToken not contain TokenValue for validation:" + TokenBuilder.serialize(authzToken));
		
		String tokenId = HelpersHexConverter.byteArrayToHex(authzToken.getTokenID()).toString();		
		String sessionId = authzToken.getSessionID();		
		String domainId = authzToken.getIssuer();
		
		String generatedValue = TokenBuilder.generateTokenValue(domainId, sessionId, tokenId, _issuerTokenKey);
		
		return tokenValue.trim().equalsIgnoreCase(generatedValue.trim());
	}
}
