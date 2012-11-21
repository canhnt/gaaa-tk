/**
 * System and Network Engineering Group
 * University of Amsterdam
 *
 */
package org.aaaarch.sunxacml.policy;

import org.aaaarch.policy.PolicyException;
import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.PolicyFinderResult;
import com.sun.xacml.support.finder.PolicyCollection;
import com.sun.xacml.support.finder.TopLevelPolicyException;

/**
 * Dynamic loaded policy from external resource and provide to PDP
 * 
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Mar 15, 2012
 */
public class DynamicPolicyFinderModule extends PolicyFinderModule{
	private PolicyCollection policies;
	
	private PolicyFinder finder;
		
	private PolicyCtxResolver policyResolver;
	
	public DynamicPolicyFinderModule(PolicyCtxResolver resolver) {
		this.policyResolver = resolver;
		this.policies = new PolicyCollection();
	}
	
	@Override
	public void init(PolicyFinder finder) {
		this.finder = finder;
		policyResolver.init(finder);
		
	}
	
	@Override
    public PolicyFinderResult findPolicy(EvaluationCtx context) {
        AbstractPolicy lookupPolicy = null;
        
		try {
			lookupPolicy = policies.getPolicy(context);
		
			// no matched policy found in the current policy collection, loading new one
			if (lookupPolicy == null) {
				try {
					AbstractPolicy loadedPolicy = policyResolver.lookup(context);
					policies.addPolicy(loadedPolicy);
					lookupPolicy = policies.getPolicy(context);
				} catch (PolicyException e) {
					e.printStackTrace();
				}
			}
		} catch (TopLevelPolicyException e) {
			e.printStackTrace();
		}		
		
    	return new PolicyFinderResult(lookupPolicy);
    }
	
    @Override
	public boolean isRequestSupported() {
		return true;
	}
}
