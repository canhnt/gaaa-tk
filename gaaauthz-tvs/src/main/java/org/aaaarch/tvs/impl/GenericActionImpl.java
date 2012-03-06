package org.aaaarch.tvs.impl;

import java.util.Map;

import org.aaaarch.tvs.Action;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Dec 6, 2011
 * 
 */
public class GenericActionImpl implements Action {

	private GenericAuthzObject object;
	
	public GenericActionImpl(Map<String, String> attributes) {
		object = new GenericAuthzObject(attributes);
	}
	@Override
	public boolean match(Action value) {
		if (!(value instanceof GenericActionImpl))
			throw new IllegalArgumentException("Cannot compare two different Action implementations");
		
		GenericActionImpl target = (GenericActionImpl)value; 
		
		return object.match(target.object);
	}

}