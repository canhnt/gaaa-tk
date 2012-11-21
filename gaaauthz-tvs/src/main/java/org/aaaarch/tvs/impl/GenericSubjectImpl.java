package org.aaaarch.tvs.impl;

import java.util.HashMap;

import org.aaaarch.tvs.Subject;
/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Dec 6, 2011
 * 
 */
public class GenericSubjectImpl implements Subject {

	private GenericAuthzObject object;
	
	public GenericSubjectImpl(HashMap<String, String> attributes) {
		object = new GenericAuthzObject(attributes);
	}
	
	public boolean match(Subject value) {
		if (!(value instanceof GenericSubjectImpl))
			throw new IllegalArgumentException("Cannot compare two different Subject implementations");
		
		GenericSubjectImpl target = (GenericSubjectImpl)value; 
		
		return object.match(target.object);
	}

}
