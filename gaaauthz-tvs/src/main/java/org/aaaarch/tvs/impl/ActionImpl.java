/**
 * 
 */
package org.aaaarch.tvs.impl;

import org.aaaarch.tvs.Action;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */

/**
 * @deprecated as of 2011/12/18, replaced by {@link #GenericActionImpl}
 */
@Deprecated
public class ActionImpl implements Action {

	private String	_actionId;
	
	public ActionImpl(String actionId) {
		_actionId = actionId;
	}
	
	/* (non-Javadoc)
	 * @see org.aaaarch.tvs.Action#equal(org.aaaarch.tvs.Action)
	 */
	public boolean match(Action value) {
		if (!(value instanceof ActionImpl))
			throw new IllegalArgumentException("Cannot compare two different resource implementations");
		
		ActionImpl targetAction = (ActionImpl)value;
		
		if (_actionId.equalsIgnoreCase(targetAction._actionId))
			return true;
		
		return false;
	}

}
