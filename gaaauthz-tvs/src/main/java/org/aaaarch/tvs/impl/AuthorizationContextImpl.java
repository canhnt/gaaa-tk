/**
 * 
 */
package org.aaaarch.tvs.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.aaaarch.tvs.Action;
import org.aaaarch.tvs.AuthorizationContext;
import org.aaaarch.tvs.Resource;
import org.aaaarch.tvs.Subject;
import org.aaaarch.tvs.TVSConstants;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 * 
 * @version $Revision 0.2 
 * $Date: 2011/12/18
 */
public class AuthorizationContextImpl implements AuthorizationContext {
	
	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthorizationContextImpl.class);
	
	private List<Subject> 	subjects;
	
	private List<Resource>	resources;
	
	private List<Action>	actions;
	
	private Date			notBefore;
	
	private Date			notOnOrAfter;
	
//	/**
//	 * Create the authorization context
//	 *  
//	 * @param subjects
//	 * @param resources
//	 * @param actions
//	 * @param notBefore if this parameter is null, the default is the current datetime
//	 * @param notOnOrAfter if this parameter is null, the default is the date the notBefore value plus the TVSConstants.VALID_TIME_DEFAULT
//	 */
//	public AuthorizationContextImpl(List<Subject> subjects, List<Resource> resources, List<Action> actions, Date notBefore, Date notOnOrAfter) {
//		
//		if (subjects == null)
//			throw new IllegalArgumentException("Argument subjects must not be null");
//
//		if (resources == null)
//			throw new IllegalArgumentException("Argument resources must not be null");
//		
//		if (actions == null)
//			throw new IllegalArgumentException("Argument actions must not be null");
//			
//		subjects = new ArrayList<Subject>(subjects);
//		Collections.copy(subjects, subjects);
//		
//		resources = new ArrayList<Resource>(resources);
//		Collections.copy(resources, resources);
//
//		actions = new ArrayList<Action>(actions);
//		Collections.copy(actions, actions);
//		
//		// initialize the valid time period
//		if (notBefore == null) 
//			notBefore = new Date();
//		else
//			this.notBefore = notBefore;
//		
//		if (notOnOrAfter != null)
//			this.notOnOrAfter = notOnOrAfter;
//		else {
//			notOnOrAfter = new Date(notBefore.getTime() + TVSConstants.DEFAULT_CTX_LIFETIME);
//		}
//	}
	
	public AuthorizationContextImpl() {
		
	}
	public AuthorizationContextImpl(AuthorizationContextImpl authzCtx) {
		throw new UnsupportedOperationException();
	}

	public void initialize() {
		this.subjects = new ArrayList<Subject>();
		this.resources = new ArrayList<Resource>();
		this.actions = new ArrayList<Action>();
	}
	
//	public AuthorizationContextImpl(Subject subject, Resource resource, Action action, Date notBefore, Date notOnOrAfter) {
//		this(Collections.nCopies(1, subject), 
//			 Collections.nCopies(1, resource), 
//			 Collections.nCopies(1, action), 
//			 notBefore, notOnOrAfter);
//	}
	
	public boolean validate(Subject subject, Resource resource, Action action) {
		
		return validate(Collections.nCopies(1, subject), Collections.nCopies(1, resource), Collections.nCopies(1, action));
	}
	
	
	/**
	 * Validate the authz-request against the authz-context
	 * Target context is included when all target's subjects, resources, actions 
	 * are subsets of the context's
	 */
	public boolean validate(List<Subject> subjects, List<Resource> resources, List<Action> actions) throws IllegalArgumentException {
	
		
		if (subjects == null || subjects.size() == 0)
			throw new IllegalArgumentException("Invalid subject value");
		
		if (resources == null || resources.size() == 0)
			throw new IllegalArgumentException("Invalid resource value");
		
		if (actions == null || actions.size() == 0)
			throw new IllegalArgumentException("Invalid action value");
	
		// Check if the context's lifetime is still valid
		if (isTimeValid() == false) {
			log.debug("Validating authz-context: lifetime not valid: from " + notBefore + " to " + notOnOrAfter);
			return false;
		}
		
		// verify subjects existence
		for(Subject subject: subjects) {
			if (findSubject(subject) == false) {
				log.debug("Validating authz-context: subject not match: " + subject.toString());
				return false;
			}
				
		}
		
		// verify resources existence
		for (Resource resource: resources) {
			if (findResource(resource) == false) {
				log.debug("Validating authz-context: resource not match: " + resource.toString());
				return false;
			}
				
		}
		
		// verify actions existence
		for (Action action: actions) {
			if (findAction(action) == false) {
				log.debug("Validating authz-context: action not match: " + action.toString());
				return false;
			}
				
		}
		
		return true;
	}
	
	private boolean isTimeValid() {
		
		// if all time conditions are null, default is true
		if (notBefore == null && notOnOrAfter == null)
			return true;
		
		Date now = new Date();
		
		if (notBefore != null && now.before(notBefore)) 
			return false;
		
		if (notOnOrAfter != null && (now.after(notOnOrAfter) || now.equals(notOnOrAfter)))
			return false;
		
		return true;
	}

	/**
	 * Return true if the action target is existing in the action list
	 *  
	 * @param target
	 * @return
	 */
	private boolean findAction(Action target) {
		
		for(Action action: actions) {
			if (action.match(target))
				return true;
		}		
		return false;
	}

	/**
	 * Return true if the resource target is existing in the resource list
	 * 
	 * @param target
	 * @return
	 */
	private boolean findResource(Resource target) {
		for(Resource resource: resources) {
			if (resource.match(target))
				return true;
		}
		
		return false;
	}

	/**
	 * Return true if the subject target is existing in the subject list
	 * 
	 * @param target
	 * @return
	 */
	private boolean findSubject(Subject target) {
		for(Subject subject: subjects) {
			if (subject.match(target))
				return true;
		}
		
		return false;
	}

	public List<Subject> getSubjects() {
		return this.subjects;			
	}
	
	public void addSubject(Subject subject) {
		this.subjects.add(subject);
	}
	
	public List<Resource> getResources() {
		return this.resources;
	}
	
	public void addResource(Resource resource) {
		this.resources.add(resource);
	}
	
	public List<Action> getActions() {
		return this.actions;
	}
	
	public void addAction(Action action) {
		this.actions.add(action);
	}

	public Date getNotBefore() {
		return this.notBefore;
	}
	
	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}
	
	public Date getNotOnOrAfter() {
		return this.notOnOrAfter;
	}
	
	public void setNotOnOrAfter(Date notOnOrAfter) {
		this.notOnOrAfter = notOnOrAfter;
	}
}
