/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.policy;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.1
 * @date: Mar 15, 2011
 * 
 */

/**
 * Looking policy from the XACML request to the policy reference identifier
 */
public interface PolicyResolver {
	/**
	 * Return the policy reference identifier which is used by a PolicyFinderModule to load policy
	 * 
	 * @param xamlcRequest
	 * @return
	 * @throws PolicyException 
	 */
	public String lookup(RequestType xamlcRequest) throws PolicyException;
}
