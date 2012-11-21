package org.aaaarch.tvs.impl;

import java.util.Map;

import org.aaaarch.tvs.Resource;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Dec 6, 2011
 * 
 */
public class GenericResourceImpl implements Resource {

	private GenericAuthzObject object;
	
	public GenericResourceImpl(Map<String, String> attributes) {
		object = new GenericAuthzObject(attributes);
	}
	@Override
	public boolean match(Resource value) {
		if (!(value instanceof GenericResourceImpl))
			throw new IllegalArgumentException("Cannot compare two different Resource implementations");
		
		GenericResourceImpl target = (GenericResourceImpl)value; 
		
		return object.match(target.object);
	}

}
