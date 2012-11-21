package org.aaaarch.sunxacml;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.aaaarch.sunxacml.policy.DynamicPolicyFinderModule;
import org.aaaarch.sunxacml.policy.PolicyCtxResolver;
import org.aaaarch.sunxacml.policy.SubjectRoleFilePolicyCtxResolver;

import com.sun.xacml.PDPConfig;
import com.sun.xacml.UnknownIdentifierException;
import com.sun.xacml.combine.PermitOverridesPolicyAlg;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.AttributeFinderModule;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.ResourceFinder;
import com.sun.xacml.finder.impl.CurrentEnvModule;
import com.sun.xacml.finder.impl.SelectorModule;
import com.sun.xacml.support.finder.StaticPolicyFinderModule;
import com.sun.xacml.support.finder.StaticRefPolicyFinderModule;

public class SunXACMLPDPAdapterBuilder {

	/**
	 * Create a SunXACML PDP adapter with policy resolution based on
	 * subject-role
	 * 
	 * @param policyDir
	 * @param log
	 * @return
	 */
	public static SunXACMLPDPAdapter createSubjectRolebasedAdapter(String policyDir,
			org.slf4j.Logger log) {

		PDPConfig config = createPDPConfigSubjectRolebased(policyDir, log);

		SunXACMLPDPAdapter adapter = new SunXACMLPDPAdapter(config);
		return adapter;
	}

	/**
	 * Create a SunXACML PDP adapter with two static loaded policies: by
	 * contexts and by references.
	 * 
	 * @param refPolicyList
	 *            Set of referenced policies
	 * @param policyList
	 *            Set of context policies
	 * @return
	 */
	public static SunXACMLPDPAdapter createAdapter(List<String> refPolicyList,
			List<String> policyList) {

		StaticPolicyFinderModule staticModule;
		try {
			staticModule = new StaticPolicyFinderModule(
					PermitOverridesPolicyAlg.algId, policyList);

			StaticRefPolicyFinderModule staticRefModule = new StaticRefPolicyFinderModule(
					refPolicyList);

			Set<PolicyFinderModule> policyModules = new HashSet<PolicyFinderModule>();
			policyModules.add(staticModule);
			policyModules.add(staticRefModule);

			PDPConfig config = createPDPConfig(policyModules);

			SunXACMLPDPAdapter adapter = new SunXACMLPDPAdapter(config);
			return adapter;
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnknownIdentifierException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Create a PDPConfig object used for file-based policy resolution based on
	 * subject-role (SubjectRoleFilePolicyCtxResolver)
	 * 
	 * @param policyDir
	 * @param log
	 * @return
	 */
	private static PDPConfig createPDPConfigSubjectRolebased(String policyDir, org.slf4j.Logger log) {
		PolicyCtxResolver policyCtxResolver = new SubjectRoleFilePolicyCtxResolver(
				log, policyDir);

		Set<PolicyFinderModule> policyModules = new HashSet<PolicyFinderModule>();
		policyModules.add(new DynamicPolicyFinderModule(policyCtxResolver));

		return createPDPConfig(policyModules);
	}

	/**
	 * Create a basic PDPConfig object from a set of PolicyFinderModule
	 * 
	 * @param policyModules
	 * @return
	 */
	private static PDPConfig createPDPConfig(
			Set<PolicyFinderModule> policyModules) {
		AttributeFinder attributeFinder = new AttributeFinder();

		List<AttributeFinderModule> attrModules = new ArrayList<AttributeFinderModule>();
		attrModules.add(new CurrentEnvModule());
		attrModules.add(new SelectorModule());
		attributeFinder.setModules(attrModules);

		PolicyFinder policyFinder = new PolicyFinder();
		policyFinder.setModules(policyModules);

		ResourceFinder resourceFinder = new ResourceFinder();

		return new PDPConfig(attributeFinder, policyFinder, resourceFinder);
	}
}
