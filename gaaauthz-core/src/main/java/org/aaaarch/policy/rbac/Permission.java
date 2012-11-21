/**
 * 
 */
package org.aaaarch.policy.rbac;

import java.util.Map;

/**
 * @author Canh Ngo <email:t.c.ngo@uva.nl>
 *
 */
public class Permission {
	
	private String policyId;

	private Map<String, String> subjectAttrs;
	
	private Map<String, String> resourceAttrs;
	
	private Map<String, String> actionAttrs;
	
		
	public String getPolicyId() {
		return policyId;
	}
	
	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}
		
	public void setSubject(Map<String, String> attrs) {
		this.subjectAttrs = attrs;
	}
	
	public void setResource(Map<String, String> attrs) {
		this.resourceAttrs = attrs;
	}
	
	public void setAction(Map<String, String> attrs) {
		this.actionAttrs = attrs;
	}
}
