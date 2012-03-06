/**
 * 
 */
package org.aaaarch.tvs;

import java.util.Date;

import org.aaaarch.tvs.impl.ActionImpl;
import org.aaaarch.tvs.impl.AuthorizationContextImpl;
import org.aaaarch.tvs.impl.ResourceImpl;
import org.aaaarch.tvs.impl.SubjectImpl;
import org.aaaarch.tvs.impl.TVSImpl;

/**
 * @author CanhNT
 *
 */
public class testTVS {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		TVSImpl tvs = new TVSImpl();
		
		String domainId = "http://nextwork.geysers.eu/ncp";
		String sessionId = null;//GRIgenerator.generateGRI(20).toString(); 
		
		String subjectId = "VIO112@sap.geysers.eu/sml"; 
		String subjectRole = "VIO-IT"; 
//		String keyinfo = "keyinfo011"; // String keyinfo = TokenKey.getTokenPublic(domainId, gri)
		
		String actionId = "create-path"; 
		
		String resourceId = "http://nextwork.geysers.eu/ncp/networklink/1234"; 
		
		Subject subject = new SubjectImpl(subjectId, subjectRole);		
		Resource resource = new ResourceImpl(resourceId);
		Action action = new ActionImpl(actionId);
		
		Date now = new Date();
				
		sessionId = tvs.addContext(domainId, subject, resource, action, now, new Date(now.getTime() + 1 * 60 * 60 * 1000));	// 1 hour lifetime
		
		// retrieve context
		AuthorizationContext authzCtx2 = tvs.getContext(domainId, sessionId);
		if (authzCtx2 !=null) {
			if (authzCtx2.validate(subject, resource, action))
				System.out.println("The authz request has a matching context in the session table");
		}
		else {
			System.err.println("no authz-ctx found");
		}
	}

}
