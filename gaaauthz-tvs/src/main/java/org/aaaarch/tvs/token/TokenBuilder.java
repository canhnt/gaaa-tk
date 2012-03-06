/**
 * 
 */
package org.aaaarch.tvs.token;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.aaaarch.crypto.HMACProcessorException;
import org.aaaarch.crypto.HMACprocessor;
import org.aaaarch.tvs.IDgenerator;
import org.aaaarch.tvs.TVSConstants;
import org.aaaarch.tvs.utils.HelpersHexConverter;

/**
 * @author CanhNT
 * 
 */
public class TokenBuilder {
	/**
	 * Default token lifetime (millisecond) is 1 hour
	 */
	private static final long DEFAULT_TOKEN_LIFETIME = 1 * 60 * 60 * 1000;
	
	public static final String TOKEN_PILOT_TYPE_0 = "pilot-type0";
	public static final String TOKEN_PILOT_TYPE_1 = "pilot-type1";
	public static final String TOKEN_PILOT_TYPE_2 = "pilot-type2";
	public static final String TOKEN_PILOT_TYPE_3 = "pilot-type3";
	public static final String TOKEN_PILOT_TYPE_4 = "pilot-type4";

	
//	private static final String TOKEN_PILOT = "token-pilot";

//	private static final String TVS_ISSUSER_SUFFIX = "/aaa/TVS";

//	private String 	_issuerDomain;

	Date 			_notBefore;
	Date 			_notOnOrAfter;
	
	byte[] 			_tokenKey;
	
	ObjectFactory 	_tokenObjFactory;

	public TokenBuilder(/*String issuerDomain,*/byte[] tokenKey, Date notBefore, Date notOnOrAfter) {
		
		if (tokenKey == null || tokenKey.length == 0)
			throw new IllegalArgumentException("The tokenKey argument must not be null or empty.");
		
		_tokenKey = Arrays.copyOf(tokenKey, tokenKey.length);
		
		if (notBefore == null || notOnOrAfter == null) {
			setDefaultValidTime();
		} else {
			_notBefore = notBefore;
			_notOnOrAfter = notOnOrAfter;
		}
		
//		_issuerDomain = issuerDomain;
		
		//create the factory object
		_tokenObjFactory = new ObjectFactory();
	}

	// Creates access token
	public String createAccessToken(String domainId, String sessionId){

		if (_tokenObjFactory == null)
			throw new NullPointerException("Token object factory failed to initialize");
		
//		String issuer = getIssuerId(domainId);

		// a random generated tokenId
		byte[] tokenId = IDgenerator.generateID().getBytes();
		
		String tokenValue;
		try {
			String tokenIdHexValue = HelpersHexConverter.byteArrayToHex(tokenId).toString();
			
			tokenValue = generateTokenValue(domainId, sessionId, tokenIdHexValue, _tokenKey);
		} catch (Exception e) {
			System.err.println("Cannot generate tokenValue from sessionId");
			e.printStackTrace();
			return null;
		}		
		
//		Document tokendoc = XMLTokenType.generateTokenXML(sessionId, tokenValue, issuer, _notBefore, _notOnOrAfter);
//		String tokenxml = HelpersXMLsecurity.convertDOMToString(tokendoc);
		
		AuthzTokenType accessToken = _tokenObjFactory.createAuthzTokenType();
		accessToken.setTokentype(TokenConstants.ACCESS_TOKEN);
		
		//set condition
		ConditionsType conditions = createConditions(_tokenObjFactory, _notBefore, _notOnOrAfter);				
		accessToken.setConditions(conditions);
		
		// set attributes
		accessToken.setIssuer(domainId);
		accessToken.setSessionID(sessionId);
		
		accessToken.setTokenID(tokenId);				
		
		accessToken.setTokenValue(tokenValue);
		
		return serialize(accessToken);
	}

	private static ConditionsType createConditions(ObjectFactory tof, Date notBefore, Date notOnOrAfter) {
		
		ConditionsType conditions = tof.createConditionsType();
		try {
			conditions.setNotBefore(createXMLGregorianCalendar(notBefore));
			conditions.setNotOnOrAfter(createXMLGregorianCalendar(notOnOrAfter));
		} catch (DatatypeConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
		return conditions;
	}

	/**
	 * Serialize the authz-token into XML string
	 * 
	 * @param authzToken
	 * @return
	 * @throws JAXBException 
	 */
	public static String serialize(AuthzTokenType authzToken) {		
		try {
			JAXBContext context = JAXBContext.newInstance(AuthzTokenType.class);
			Marshaller marshaller = context.createMarshaller();
			
			ByteArrayOutputStream buffer = new ByteArrayOutputStream ();				
			
			JAXBElement<AuthzTokenType> jaxbObj = (new ObjectFactory()).createAuthzToken(authzToken);
			
			marshaller.marshal(jaxbObj, buffer);
			
			return buffer.toString();
		} catch (JAXBException e) {
			System.err.println("Error serialize authztoken object to XML string");
			e.printStackTrace();
			return null;
		}		
	}

	private static XMLGregorianCalendar createXMLGregorianCalendar(Date date)
			throws DatatypeConfigurationException {
		GregorianCalendar c = new GregorianCalendar();
		c.setTime(date);		
		return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
	}

	/**
	 * Assign the default lifetime for the current creating token
	 * 
	 * @throws Exception
	 */
	private void setDefaultValidTime(){
		_notBefore = new Date(); // now
		try {
			_notOnOrAfter = new Date(_notBefore.getTime() + DEFAULT_TOKEN_LIFETIME);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/*
	 * Pilot token can be of the following types defined by the optional "type"
	 * attribute 
	 *  - type 0 (default) - access token (doesn't contain context element) 
	 *  - type 1 - simple pilot token: contains only GRI (and optionally
	 * 	  Conditions?) 
	 *  - type 2 - source authentication token: TokenValue is created
	 * 		as crypto (GRI, domainId, tokenId), where crypto is using HMAC or PKI
	 * 		digisign current implmentation: HMAC (omainId + "/_" + GRI) 
	 *  - type 3 - extends the Type2 with a Domains element that allows to collect domains
	 * 		security context information (in the Domains/Domain element) when passing
	 * 		multiple domains during the reservation process. Such information may
	 * 		includes the previous token and the domain’s trust anchor or public key.
	 * 
	 * TODO: revise type3 implementation. type 4 - type 2 token with collected
	 * all previous tokens of type 2, 3 in the token context element. Can be
	 * used at the deployment stage. 
	 * 
	 * TODO: revise type4 implementation.
	 * 
	 * Tokens of type 0 and 1 may not contain "type" attribute but they can be
	 * distinguished by presence of the TokenValue element
	 * 
	 * @ domainId vs domain: - domainId is a full name/string for the domain
	 * identification e.g. domainId = "http://tesbed.ist-phosphorus.eu/harmony"
	 * - domain = resource-domain e.g. domain = "harmony"
	 * 
	 * @ tokenCtx = (previous XML token) || (previous AuthzTicket) TODO:
	 * currently supported only tokenCtx = tokenPrevious
	 */
	// ptokentype = {1, 2 , 3, 4}

	public String createPilotToken(int ptokentype, String domainId, String sessionId, String tokenCtxPrevious){

		if (ptokentype == TVSConstants.ACCESS_TOKEN_TYPE)
			throw new IllegalArgumentException("This method only supports creating pilot token");
		
		if (domainId == null)
			throw new IllegalArgumentException("DomainId argument must not be null");

		String tokenXML = null;
		
//		String issuer = getIssuerId(domainId);

		try {
			switch (ptokentype) {
			case TVSConstants.PILOT_TOKEN_TYPE_1:
				tokenXML = createPilotTokenType1(domainId, sessionId);
				break;

			case TVSConstants.PILOT_TOKEN_TYPE_2:
				tokenXML = createPilotTokenType2(domainId, sessionId);
				break;

			case TVSConstants.PILOT_TOKEN_TYPE_3:
//				tokenXML = createPilotTokenType3(domainId, sessionId, tokenCtxPrevious);
//				break;
				throw new UnsupportedOperationException("Not support this token type:" + TokenConstants.PILOT_TOKEN_TYPE3);
				

			case TVSConstants.PILOT_TOKEN_TYPE_4:
				throw new UnsupportedOperationException("TokenBuilder: this token type = " + ptokentype + " is not known");

			default:
				throw new UnsupportedOperationException("TokenBuilder: this token type = " + ptokentype + " is not known");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return tokenXML;
	}

	private String createPilotTokenType3(String domainId, String sessionId,
			String previousToken) {
		String tokentype = TOKEN_PILOT_TYPE_3;
		
		byte[] tokenId = IDgenerator.generateID().getBytes();
		String tokenIdHex = HelpersHexConverter.byteArrayToHex(tokenId).toString();
		
		String tokenValue = generateTokenValue(domainId, sessionId, tokenIdHex, _tokenKey);

		AuthzTokenType pilotToken = _tokenObjFactory.createAuthzTokenType();
		pilotToken.setTokentype(TokenConstants.PILOT_TOKEN_TYPE3);

		//set condition if exist
		if (_notBefore != null && _notOnOrAfter != null) {
			ConditionsType conditions = createConditions(_tokenObjFactory, _notBefore, _notOnOrAfter);				
			pilotToken.setConditions(conditions);			
		}
		
		// set attributes
		pilotToken.setIssuer(domainId);
		pilotToken.setSessionID(sessionId);
		
		pilotToken.setTokenValue(tokenValue);
		
		pilotToken.setTokenID(tokenId);
		
		// create Domains element from the token of the previous domain 
		DomainsType domains = _tokenObjFactory.createDomainsType();
		DomainType domain = createDomainType(previousToken);
		domains.getDomain().add(domain);
		
		pilotToken.setDomains(domains);
		
		return serialize(pilotToken);	
	}

	/**
	 * Create DomainType object containing the the token of a domain.
	 * 
	 * @param previousToken
	 * @return
	 */
	private DomainType createDomainType(String token) {
		AuthzTokenType authzToken = deserialize(token);
		
		String domainId = authzToken.getIssuer();
		
		DomainType domain = _tokenObjFactory.createDomainType();
		domain.setAuthzToken(authzToken);
		domain.setDomainId(domainId);
		
		// set the keyInfo 
		KeyInfoType keyInfo = _tokenObjFactory.createKeyInfoType();
		//...
		// need implement?
		
		domain.getKeyInfo().add(keyInfo);
		return domain;
	}

	/**
	 * Deserialize the authz-token string to the AuthzToken object
	 * 
	 * @param token
	 * @return
	 */
	public static AuthzTokenType deserialize(String token) {
		try {
			JAXBContext context = JAXBContext.newInstance(AuthzTokenType.class);
			Unmarshaller unmarshaller = context.createUnmarshaller();
			
			InputStream is = new ByteArrayInputStream(token.getBytes());
			
			JAXBElement<AuthzTokenType> jaxbObj = (JAXBElement<AuthzTokenType>) unmarshaller.unmarshal(is);
			AuthzTokenType authzToken = jaxbObj.getValue();
			
			return authzToken;
		} catch (JAXBException e) {
			System.err.println("Error to deserialize from XML string to authztoken object");
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Create a pilot token type 1, containing only the sessionId (GRI) and the issuer.
	 * The Conditions is optional.
	 * 
	 * @param sessionId
	 * @param issuer
	 * @return
	 */
	private String createPilotTokenType1(String domainId, String sessionId) {
		if (_tokenObjFactory == null)
			throw new NullPointerException("Token object factory failed to initialize");

		AuthzTokenType pilotToken = _tokenObjFactory.createAuthzTokenType();
		pilotToken.setTokentype(TokenConstants.PILOT_TOKEN_TYPE1);
		
		//set condition if exist
		if (_notBefore != null && _notOnOrAfter != null) {
			ConditionsType conditions = createConditions(_tokenObjFactory, _notBefore, _notOnOrAfter);				
			pilotToken.setConditions(conditions);			
		}
		
		// set attributes
		pilotToken.setIssuer(domainId);
		pilotToken.setSessionID(sessionId);
		
		// a random tokenId
		pilotToken.setTokenID(IDgenerator.generateID().getBytes());
		
		return serialize(pilotToken);		
	}

//	private String createPilotTokenType3(String sessionId, String domainId,
//			String issuer, String tokenCtxPrevious)
//	throws Exception {
//
//		String tokentype = XMLTokenType.TOKEN_PILOT_TYPE_3;
//		issuer = issuer + "/" + TOKEN_PILOT;
//
//		String tokenId = IDgenerator.generateID().toString();
//		
//		String tokenValue = generateTokenValue(sessionId, domainId, tokenId);
//
//		// REF: domainsCtx(domainId, (String domainId, Document token, String
//		// KeyInfo))
//		HashMap<String, Vector<Object>> domainCtx = new HashMap<String, Vector<Object>>();
//		Vector<Object> vdomain = new Vector<Object>();
//
//		if (tokenCtxPrevious != null) {
//			XMLTokenType tokobj = new XMLTokenType(tokenCtxPrevious);
//			System.out.println("Token from the previous domain = "
//					+ tokenCtxPrevious);
//
//			String tokenDomainPrevious = tokobj.getTokenDomain();
//			String keyinfo = TokenKey.getTokenPublic(tokenDomainPrevious);
//
//			vdomain.add(tokenDomainPrevious);
//			vdomain.add(keyinfo);
//			vdomain.add(tokobj);
//
//			domainCtx.put(tokenDomainPrevious, vdomain);
//		} else {
//			domainCtx = null;
//		}
//		//
//		Document tokdoc = XMLTokenType.generateTokenXML(sessionId, tokenValue,
//				issuer, _notBefore, _notOnOrAfter, tokenId, tokentype, domainCtx);
//
//		String xmlToken = HelpersXMLsecurity.convertDOMToString(tokdoc);
//
//		return xmlToken;
//	}

//	private String createPilotTokenType2(String domainId, String sessionId,
//			String issuer) throws Exception {
//
//		// HashMap domainCtx = new HashMap();
//		String tokentype = XMLTokenType.TOKEN_PILOT_TYPE_2; // authentication
//		// token
//		issuer = issuer + "/" + TOKEN_PILOT;
//
//		String tokenId = IDgenerator.generateID().toString();
//
//		String tokenValue = generateTokenValue(sessionId, domainId, tokenId);
//
//		Document tokdoc = XMLTokenType.generateTokenXML(sessionId, tokenValue,
//										issuer, _notBefore, _notOnOrAfter, tokenId, tokentype, null);
//
//		return HelpersXMLsecurity.convertDOMToString(tokdoc);
//	}

	
	
	/**
	 * Create pilot token type 2: containing sessionId, issuer, token value and domainId.
	 * @param issuer2 
	 */
	private String createPilotTokenType2(String domainId, String sessionId) {
		if (_tokenObjFactory == null)
			throw new NullPointerException("Token object factory failed to initialize");

		// a random tokenId
		byte[] tokenId = IDgenerator.generateID().getBytes();
		
		String tokenValue;
		try {
			String tokenIdHex = HelpersHexConverter.byteArrayToHex(tokenId).toString();
			tokenValue = generateTokenValue(domainId, sessionId, tokenIdHex, _tokenKey);				
		} catch (Exception e) {
			System.err.println("Cannot generate tokenValue from sessionId");
			e.printStackTrace();
			return null;
		}
		
		AuthzTokenType pilotToken = _tokenObjFactory.createAuthzTokenType();
		pilotToken.setTokentype(TokenConstants.PILOT_TOKEN_TYPE2);

		//set condition if exist
		if (_notBefore != null && _notOnOrAfter != null) {
			ConditionsType conditions = createConditions(_tokenObjFactory, _notBefore, _notOnOrAfter);				
			pilotToken.setConditions(conditions);			
		}
		
		// set attributes
		pilotToken.setIssuer(domainId);
		pilotToken.setSessionID(sessionId);
		
		pilotToken.setTokenValue(tokenValue);
		
		pilotToken.setTokenID(tokenId);
		
		return serialize(pilotToken);		

	}
	
	public static String generateTokenValue(String domainId, String sessionId, String tokenId, byte[] tokenKey){

		if (domainId == null || sessionId == null || tokenId == null || tokenKey == null)
			throw new IllegalArgumentException("Every arguments must be not null");
		
		String hashedValue = domainId + "/" + sessionId + "/" + tokenId;
		
		byte[] tokenValue;
		try {
			tokenValue = HMACprocessor.computeHMAC(hashedValue, tokenKey, null);
		} catch (HMACProcessorException e) {
			e.printStackTrace();
			return null;
		}
				
		return HelpersHexConverter.byteArrayToHex(tokenValue).toString();
	}
	

//	private String createPilotTokenType1(String sessionId, Object object, String issuer) throws Exception {
//
//		Document doctok = XMLTokenType.generateTokenXML(sessionId, null,
//				issuer, null, null);
//
//		return HelpersXMLsecurity.convertDOMToString(doctok);
//	}

//	/**
//	 * Generate the Token Value from the sessionId & the token crypto-key
//	 * 
//	 * @param sessionId
//	 * @param tokenKey
//	 * @return
//	 * @throws Exception
//	 */
//	private static byte[] generateTokenValue(String sessionId, byte[] tokenKey)
//	throws Exception {
//
//		byte[] token;
//
//		if (tokenKey == null) {
//			tokenKey = TokenKey.generateTokenKey(sessionId);
//		}
//
//		token = HMACprocessor.computeHMAC(sessionId, tokenKey, null);
//
//		return token;
//	}

//	/**
//	 * Convert the DomainId to IssuerId
//	 * Formula: 
//	 * 			IssuerId = DomainId + TVS_ISSUSER_SUFFIX;
//	 */
//	private String getIssuerId(String domainId) {
//
//		if (domainId != null)
//			return domainId + TVS_ISSUSER_SUFFIX;
//		else
//			return _issuerDomain + TVS_ISSUSER_SUFFIX;
//	}
//	
//	/**
//	 * Convert the IssuerId to DomainId. 
//	 * If the issuerId does not have proper suffix, then the domainId is the same as issuerId.
//	 * 
//	 * Formula: 
//	 * 			IssuerId = DomainId + TVS_ISSUSER_SUFFIX;
//	 */
//	private String getDomainId(String issuerId) {
//		
//		String domainId;
//		
//		if (issuerId.endsWith(TVS_ISSUSER_SUFFIX)) {
//			domainId = issuerId.substring(0, issuerId.lastIndexOf(TVS_ISSUSER_SUFFIX));
//		}
//		else 
//			domainId = issuerId;
//		
//		return domainId;
//		
//	}
}
