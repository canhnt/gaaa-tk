/**
 * System and Network Engineering Group
 * University of Amsterdam
 *
 */
package org.aaaarch.sunxacml.policy;

import java.net.URI;

import org.aaaarch.policy.PolicyException;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.PolicyMetaData;
import com.sun.xacml.VersionConstraints;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Mar 16, 2012
 */
public class FilePolicyRefResolver implements PolicyRefResolver {

	/* (non-Javadoc)
	 * @see org.aaaarch.sunxacml.PolicyRefResolver#lookup(java.net.URI, int, com.sun.xacml.VersionConstraints, com.sun.xacml.PolicyMetaData)
	 */
	public AbstractPolicy lookup(URI idReference, int type,
			VersionConstraints constraints, PolicyMetaData parentMetaData)
			throws PolicyException {
		// TODO Auto-generated method stub
		return null;
	}

}
