/*
 * August 2007
 */
package org.aaaarch.gaaapi.test.saml;

import org.w3c.dom.*; 
import javax.xml.transform.*; 
import javax.xml.transform.dom.*; 
import javax.xml.transform.stream.*; 
import java.io.*; 

public class CreateDOM{
	
	public CreateDOM(){
	}
	
	/* Transform and save the document in the file*/
	public static void transformerXml(Document document, String file) {
        try {
            // DOM Source
            Source source = new DOMSource(document);
    
            // File Output
            File fileOutput = new File(file);
            Result result = new StreamResult(file);
    
            // Transformer config
            TransformerFactory builder= TransformerFactory.newInstance();
            Transformer transformer = builder.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "ISO-8859-1");
            
            // Transformation
            transformer.transform(source, result);
        }catch(Exception e){
        	e.printStackTrace();	
        }
    }
}   