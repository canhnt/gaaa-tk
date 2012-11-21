/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.tvs;

import java.util.Date;

import org.aaaarch.tvs.impl.AuthorizationContextImpl;
import org.aaaarch.tvs.token.TokenValidator;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * 
 * @version 0.2
 * @date: Apr 20, 2011
 *  - Modify addContext methods: the sessionId will be generated and returned from TVS side, not by client side
 *  - Add interface method requestToken() to allow TVS returns a token refering to cached context 
 * 
 * @version 0.1
 * @date: Mar 04, 2011
 *  - Initial version
 */
public interface TVS {

	public String addContext(String domainId, Subject subject, Resource resource, Action action, Date notBefore, Date notOnOrAfter) throws TVSException;
	
	/**
	 * Add the context to the session table with default lifetime.
	 * 
	 * @param domainId
	 * @param subject
	 * @param resource
	 * @param action
	 * @return the generated sessionId which refers to the cached context
	 */
	public String addContext(String domainId, Subject subject, Resource resource, Action action) throws TVSException;
	
	public String addContext(String domainId, AuthorizationContext authzCtx) throws TVSException;
		
	/**
	 * Delete all contexts of a domain
	 * 
	 * @param domainId
	 */
	public ContextTable deleteContext(String domainId);
	/**
	 * Delete a context specified by the sessionId of a domain
	 * 
	 * @param domainId
	 * @param sessionId
	 * @return the removed context. Null if it's not existing in the context table
	 */
	public AuthorizationContext deleteContext(String domainId, String sessionId);
	
	public AuthorizationContext getContext(String domainId, String sessionId);
	
	
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
	public boolean validateAuthzRequestByToken(String authzToken, Subject subject, Resource resource, Action action) throws Exception;
	
	/**
	 * Request an authz-token for the cached context in the TVS
	 * 
	 * @param domainId The domain identifier of sessions
	 * @param sessionId the returned sessionId from the addContext method
	 * @return The serialized token in string format
	 */
	public String requestToken(String domainId, String sessionId);
}
