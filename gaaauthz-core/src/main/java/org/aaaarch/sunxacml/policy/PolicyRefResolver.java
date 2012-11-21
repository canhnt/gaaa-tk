/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.sunxacml.policy;

import java.net.URI;

import org.aaaarch.policy.PolicyException;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.PolicyMetaData;
import com.sun.xacml.VersionConstraints;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.1
 * @date: Mar 16, 2011
 * 
 */

/**
 * Looking up policy object from external source for a given evaluation context
 */
public interface PolicyRefResolver {
	
	/**
	 * Return the policy object loaded from external source based on the context attributes
	 * 
	 * @param idReference
	 * @param type
	 * @param constraints
	 * @param parentMetaData
	 * @return
	 * @throws PolicyException
	 */
	AbstractPolicy lookup(URI idReference, int type,
            VersionConstraints constraints,
            PolicyMetaData parentMetaData) throws PolicyException;
}
