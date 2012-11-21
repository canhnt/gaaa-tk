package org.aaaarch.sunxacml.policy;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.aaaarch.policy.PolicyException;
import org.aaaarch.sunxacml.util.PolicyUtil;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.attr.AttributeValue;
import com.sun.xacml.attr.BagAttribute;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.cond.EvaluationResult;
import com.sun.xacml.finder.PolicyFinder;

/**
 * Load policy from files based on subject-role attribute in the evaluation context
 * 
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Mar 16, 2012
 */
public class SubjectRoleFilePolicyCtxResolver implements PolicyCtxResolver  {
		
	private PolicyFinder finder;
	
	private org.slf4j.Logger log;
	
	private String policyDir;

	public SubjectRoleFilePolicyCtxResolver(org.slf4j.Logger log, String policyDir){
		this.log = log;
		this.policyDir = policyDir;
	}

	
	private String getSubjectRole(EvaluationCtx context) throws RuntimeException{
		try {
			EvaluationResult result = context.getSubjectAttribute(new URI("http://www.w3.org/2001/XMLSchema#string"),
					new URI("http://authz-interop.org/AAA/xacml/subject/subject-role"), 
					new URI("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"));
			
			AttributeValue attrValue = result.getAttributeValue();
			if (attrValue.isBag()) {
				BagAttribute bag = (BagAttribute)attrValue;
				if (bag.size() > 0) {
					StringAttribute value = (StringAttribute) (bag.iterator().next());
					return value.getValue();
				}
			}
		} catch (URISyntaxException ue) {
			log.warn("Error finding subject-role attribute", ue);
		}
		throw new RuntimeException("Subject-role attribute not found");
	}

	public AbstractPolicy lookup(EvaluationCtx context) throws PolicyException {
		String subjectRole = getSubjectRole(context);
		String str = buildPolicyFilePath(subjectRole);
		
		log.info("Loading policy file: {}", str);

		return PolicyUtil.loadPolicy(finder, log, str);
	}

	private String buildPolicyFilePath(String subjectRole) {
		
		return this.policyDir + "/" + subjectRole + "-policy.xml";
	}

	public void init(PolicyFinder finder) {
		this.finder = finder;	
	}
	
	
}
