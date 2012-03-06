/**
 * @author:
 * Thierry DENYS
 * Created: in 2008
 * Last update: july, 31th 2008
 */

package org.aaaarch.gaaapi.test.exist;

import java.io.File;

public class FilesResolver {

	public static  String[] find(String path) {
		File directory = new File(path);
		if(!directory.exists())	{
			System.out.println("The directory " + path + " doesn't exist");
		}
		else {
			if(!directory.isDirectory()) {
				return null;
			}
			else {
				File[] subFiles = directory.listFiles();
				String files[] = new String[subFiles.length];
				for(int i=0 ; i<subFiles.length; i++){
					files[i] = subFiles[i].getName();
				}
				return files;
			}
		}
		return null;
	}
	
	public static void main(String args[]){	
		String path="D:\\deveclipse\\aaauthreach\\external\\xacml2.0-conformance-test2005\\truc";
		String tab[] = find(path);
		for (int i=0;i<tab.length;i++){
			System.out.println(tab[i]);
		}
	}
}