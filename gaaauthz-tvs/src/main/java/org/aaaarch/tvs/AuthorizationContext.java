/**
 * 
 */
package org.aaaarch.tvs;

import java.util.List;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */

/**
 * This interface describe the context of an authorization session in the Token Validation Service (TVS).
 * An authorization context should have following information
 * - Subject that authorized
 * - Resource that authorized
 * - Action that authorized
 * - Obligations
 * - Environment: time validity, etc.
 * 
 */
public interface AuthorizationContext {
	
	/**
	 * Return true if the context parameter is the subset of the current context
	 * 
	 * @param targetCtx Context to be checked
	 * @return
	 */
	public boolean validate(Subject subject, Resource resource, Action action);
	
	public boolean validate(List<Subject> subjects, List<Resource> resources, List<Action> actions);
	
}
