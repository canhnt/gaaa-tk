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
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.PolicyFinderResult;
import com.sun.xacml.support.finder.PolicyCollection;

/**
 * Dynamic loaded referenced policy from external resource 
 * 
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Mar 15, 2012
 */
public class DynamicRefPolicyFinderModule extends PolicyFinderModule{
	private PolicyCollection policies;
	
	private PolicyFinder finder;
		
	private PolicyRefResolver policyResolver;
	
	public DynamicRefPolicyFinderModule(PolicyRefResolver resolver) {
		this.policyResolver = resolver;
		this.policies = new PolicyCollection();
	}
	
	@Override
	public void init(PolicyFinder finder) {
		this.finder = finder;
		
	}
	
	@Override
    public PolicyFinderResult findPolicy(URI idReference, int type,
            VersionConstraints constraints,
            PolicyMetaData parentMetaData) {
        
		AbstractPolicy policy = policies.getPolicy(idReference.toString(), 
				type, constraints);
		
		if (policy == null) {
			AbstractPolicy loadedPolicy;
			try {
				loadedPolicy = policyResolver.lookup(idReference, type, constraints, parentMetaData);
				policies.addPolicy(loadedPolicy);
				
				policy = policies.getPolicy(idReference.toString(), 
						type, constraints);
			} catch (PolicyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
		}
    	return new PolicyFinderResult(policy);
    }
	
    @Override
    public boolean isIdReferenceSupported() {
		return true;
	}
}
