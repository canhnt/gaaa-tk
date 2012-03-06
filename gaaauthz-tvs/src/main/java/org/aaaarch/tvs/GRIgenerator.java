package org.aaaarch.tvs;

import org.aaaarch.tvs.IDgenerator;

public class GRIgenerator {

	public static String generateGRI(int nbytes) throws Exception {

		String gri = IDgenerator.generateID(nbytes).toString();
        
		return gri;
	}

	//griprefix - typically "domainId" but can be any string
	public static String generateGRI(int nbytes, String griprefix) throws Exception {
		String gri = IDgenerator.generateID(nbytes).toString();
		if (! ((griprefix == null) || (griprefix.equals("")))) {
			gri = (griprefix + "_").concat(gri);
		}
		return gri;
	}
	
	public static String getGRIvalue(String gri) throws Exception {

		String grihex = gri;
		
		char[] grichars = gri.toCharArray();
		int index1 = gri.indexOf("_");
	    StringBuffer buf = new StringBuffer(gri.getBytes().length);

        //TODO: this is not working
		
		return grihex;
	}
}
