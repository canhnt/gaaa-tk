/**
 * 
 */
package org.aaaarch.tvs.impl;

import org.aaaarch.tvs.Resource;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */
/**
 * @deprecated as of 2011/12/18, replaced by {@link #GenericResourceImpl}
 */
@Deprecated
public class ResourceImpl implements Resource {

	private String	_resourceId;
	
	public ResourceImpl(String resourceId) {
		_resourceId = resourceId;
	}
	
	/* (non-Javadoc)
	 * @see org.aaaarch.tvs.Resource#equal(org.aaaarch.tvs.Resource)
	 */
	public boolean match(Resource value) {
		if (!(value instanceof ResourceImpl))
			throw new IllegalArgumentException("Cannot compare two different resource implementations");
		
		ResourceImpl targetResource = (ResourceImpl)value;
		
		if (_resourceId.equalsIgnoreCase(targetResource._resourceId))
			return true;
		
		return false;
	}

	@Override
	public String toString() {
		return "ResourceID = " + _resourceId;
		
	}
}
