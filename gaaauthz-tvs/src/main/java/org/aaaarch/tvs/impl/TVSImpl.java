/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.tvs.impl;

import java.util.Date;

import org.aaaarch.tvs.GRIgenerator;
import org.aaaarch.tvs.Action;
import org.aaaarch.tvs.AuthorizationContext;
import org.aaaarch.tvs.ContextTable;
import org.aaaarch.tvs.Resource;
import org.aaaarch.tvs.Subject;
import org.aaaarch.tvs.TVS;
import org.aaaarch.tvs.TVSException;
import org.aaaarch.tvs.key.KeyManager;
import org.aaaarch.tvs.key.impl.DefaultKeyManager;
import org.aaaarch.tvs.token.AuthzTokenType;
import org.aaaarch.tvs.token.TokenBuilder;
import org.aaaarch.tvs.token.TokenValidator;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.2
 * @date 2011.04.20
 */
public class TVSImpl implements TVS {
	
	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TVSImpl.class);
	
	protected MultiDomainContextTables	_domainCtxTables;
	
	public TVSImpl() {
		_domainCtxTables = new MultiDomainContextTables();
	}
	
	public String addContext(String domainId, Subject subject, Resource resource, Action action, Date notBefore, Date notOnOrAfter) throws TVSException {
		//subject, resource, action, notBefore, notOnOrAfter
		AuthorizationContextImpl authzCtx = new AuthorizationContextImpl();
		authzCtx.initialize();
		authzCtx.addSubject(subject);
		authzCtx.addResource(resource);
		authzCtx.addAction(action);				
		authzCtx.setNotBefore(notBefore);
		authzCtx.setNotOnOrAfter(notOnOrAfter);
		
		return addContext(domainId, authzCtx);		
	}
	
	/**
	 * Add the context to the session table with default lifetime.
	 * 
	 * @param domainId
	 * @param subject
	 * @param resource
	 * @param action
	 * @return
	 * @throws TVSException 
	 */
	public String addContext(String domainId, Subject subject, Resource resource, Action action) throws TVSException {
		return addContext(domainId, subject, resource, action, null, null);
	}
	
	public String addContext(String domainId, AuthorizationContext authzCtx) throws TVSException {
		String sessionId = generateSessionId(); // generate here
		
		if (!isSessionIdValid(domainId, sessionId))
			throw new TVSException("Generating a new sessionId in the domain \"" + domainId + "\" failed");
		
		_domainCtxTables.put(domainId, sessionId, authzCtx);
		
		return sessionId;
	}
	
	private String generateSessionId() throws TVSException {
		
		// Generate a new sessionId 
		String sessionId;
		try {
			sessionId = GRIgenerator.generateGRI(20).toString();
			return sessionId;
		} catch (Exception e) {
			String msg = "Failed to generate sessionId";
			log.error(msg);
			throw new TVSException(msg, e);			
		}
	}

	/**
	 * Check if the sessionId is duplicated with an existing sessionId
	 * @param domainId
	 * @param sessionId
	 * @return false if the domainId not existed or the sessionId is duplicated 
	 */
	private boolean isSessionIdValid(String domainId, String sessionId) {
		ContextTable ctxTable = _domainCtxTables.getContextTable(domainId);
		
		if (ctxTable == null) {
			System.err.println("No domainId \"" + domainId + "\" existed");
			return false;
		}
		
		if (ctxTable.get(sessionId) != null) {
			System.err.println("SessionId \"" + sessionId + "\" for the domain \"" + domainId +"\"  existed");
			return false;
		}
		
		return true;
	}

	/**
	 * Delete all contexts of a domain
	 * 
	 * @param domainId
	 */
	public ContextTable deleteContext(String domainId) {
		return _domainCtxTables.removeContextTable(domainId);
	}
	
	/**
	 * Delete a context specified by the sessionId of a domain
	 * 
	 * @param domainId
	 * @param sessionId
	 * @return the removed context. Null if it's not existing in the context table
	 */
	public AuthorizationContext deleteContext(String domainId, String sessionId) {
		ContextTable currentCtxTable = _domainCtxTables.getContextTable(domainId);
		
		if (currentCtxTable == null)
			return null;
		
		return currentCtxTable.remove(sessionId);	
	}
	
	public AuthorizationContext getContext(String domainId, String sessionId) {
		ContextTable currentCtxTable = _domainCtxTables.getContextTable(domainId);
		
		if (currentCtxTable == null)
			return null;
		
		return currentCtxTable.get(sessionId);
	}
	
	
	/**
	 * Validating the authz-token and verify against the authz-context storing in the TVS
	 * 
	 * Algorithm:
	 *  - Validate token
	 *  - Get authz-context from the domainId & sessionId of the authz-token
	 *  - Comparing returned authz-context to the authz-request <Subject, Resource, Action>
	 *  
	 * @param authzToken The proprietary GAAA-TK XML token in string format
	 * @param subject
	 * @param resource
	 * @param action
	 * @return
	 * @throws Exception
	 */
	public boolean validateAuthzRequestByToken(String authzTokenXML, Subject subject, Resource resource, Action action) throws Exception {
		
		/** 		 
		 * 2011.03.04 - remove temporary the validation token due to bugs inside 
		 * org.aaaarch.gaaapi.TokenBuilder, TokenKey & XMLTokenType
		 */
//		// Validate the token authenticity
//		TokenValidator tokenValidator = new TokenValidator();
//		if (!tokenValidator.validateXMLToken(authzToken)) {
//			System.out.println("\nTVS: Validating AuthzRequest against XMLToken: Token not valid");
//			return false;
//		}
//		/*End of comment*/
		
		// Token validation
		AuthzTokenType authzToken = TokenBuilder.deserialize(authzTokenXML);
		
		KeyManager keyManager = new DefaultKeyManager();
		byte[] tokenKey = keyManager.generateSesionKey(authzToken.getIssuer(), authzToken.getSessionID().getBytes());
				
		TokenValidator tokenValidator = new TokenValidator(tokenKey);
		
		if (!tokenValidator.validate(authzToken)){
			log.debug("TVS: the authorization token is invalid.");
			return false;
		}
		
		// Get the domainId & sessionId from the token
		String domainId = authzToken.getIssuer();
		String sessionId = authzToken.getSessionID();
					
		// Get the authz-context from cache
		AuthorizationContext authzCtx = getContext(domainId, sessionId);
		
		if (authzCtx == null) {
			log.debug("\nTVS: Validating AuthzRequestByToken: There is no stored context for this session\nAccess will be denied");
			return false;
		}
		
		//validating the authz-context against the authz-request
		if (authzCtx.validate(subject, resource, action))
			return true;
		
		return false;		
	}

	@Override
	public String requestToken(String domainId, String sessionId) {
		// TODO Auto-generated method stub
		return null;
	}	

	
	
}
