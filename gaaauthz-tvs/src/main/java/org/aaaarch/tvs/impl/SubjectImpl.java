/**
 * 
 */
package org.aaaarch.tvs.impl;

import org.aaaarch.tvs.Subject;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */

/**
 * @deprecated as of 2011/12/18, replaced by {@link #GenericSubjectImpl}
 */
@Deprecated	
public class SubjectImpl implements Subject {

	private String	_subjectId;
	
	private String	_subjectRole;
	
	
	public SubjectImpl(String subjectId, String subjectRole) {
		_subjectId = subjectId;
		_subjectRole = subjectRole;
	}
	
	/* (non-Javadoc)
	 * @see org.aaaarch.tvs.Subject#equal(org.aaaarch.tvs.Subject)
	 */
	public boolean match(Subject value) {
		if (!(value instanceof SubjectImpl))
			throw new IllegalArgumentException("Cannot compare two different subject implementations");
		
		SubjectImpl targetSubject = (SubjectImpl)value;
		
		// This implementation only compares subject-Id and subject-role
		if (_subjectId.equalsIgnoreCase(targetSubject._subjectId) &&
			_subjectRole.equalsIgnoreCase(targetSubject._subjectRole))
			return true;
		
		return false;
	}
	
	@Override
	public String toString() {
		return "SubjectID = " + _subjectId + ";Role=" + _subjectRole;
		
	}

}
