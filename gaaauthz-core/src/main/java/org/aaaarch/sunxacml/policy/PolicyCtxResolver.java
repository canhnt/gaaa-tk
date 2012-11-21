/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.sunxacml.policy;

import org.aaaarch.policy.PolicyException;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.finder.PolicyFinder;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.1
 * @date: Mar 15, 2011
 * 
 */

/**
 * Looking up policy object from external source for a given evaluation context
 */
public interface PolicyCtxResolver {
	/**
	 * Return the policy object loaded from external source based on the context attributes
	 * 
	 * @param xamlcRequest
	 * @return
	 * @throws PolicyException 
	 */
	AbstractPolicy lookup(EvaluationCtx context) throws PolicyException;
	
	void init(PolicyFinder finder);
}
