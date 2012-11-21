package org.aaaarch.tvs.impl;

import java.util.HashMap;
import java.util.Map;

import org.aaaarch.tvs.Matchable;

/**
 * Implement of authorization object (Subject, Resource or Action).
 * 
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Dec 18, 2011
 */
class GenericAuthzObject implements Matchable<GenericAuthzObject>{

	private HashMap<String, String> attributes;
	
	public GenericAuthzObject(Map<String, String> attributes) {
		this.attributes = new HashMap<String, String>(attributes); 
	}

	@Override
	public boolean match(GenericAuthzObject object) {
		if (!(object instanceof GenericAuthzObject))
			throw new IllegalArgumentException("Cannot matching two different instance implementations");
		
		GenericAuthzObject target = (GenericAuthzObject)object;
		for (String key:target.attributes.keySet()) {
			if (!attributes.containsKey(key))
				return false;
			if (!attributes.get(key).equalsIgnoreCase(target.attributes.get(key)))
				return false;
		}
		
		return true;
	}

}
