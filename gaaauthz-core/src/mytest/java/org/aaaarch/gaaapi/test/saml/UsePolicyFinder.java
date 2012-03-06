package org.aaaarch.gaaapi.test.saml;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.Iterator;

import com.sun.xacml.Indenter;
import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.finder.PolicyFinder;
//import com.sun.xacml.finder.impl.FilePolicyModule;
import com.sun.xacml.support.finder.FilePolicyModule;


public class UsePolicyFinder {
	
	/* List Directory (XML files only)*/
	public static String[] ListXMLDirectory(File directory){
		 String[] listFile;
		 listFile=directory.list();

		 int nbXMLFiles = 0;
		 for(int i=0 ; i < listFile.length ; i++){
			 if(listFile[i].endsWith(".xml") == true){
				 nbXMLFiles ++;
				 } 
		 }

		 String[] listFileFinal = new String [nbXMLFiles];
		 for(int i=0 ; i < listFileFinal.length ; i++){
			 if(listFile[i].endsWith(".xml") == true){
				 listFileFinal[i] = "XACMLTests/PolicyRepository/"+listFile[i];
			 }
		 }
		 
		 
		 return listFileFinal;
	}


	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
		      System.out.println("Usage: <request>");
		      System.exit(1);
		}
		 
		// Get the XML request file in argument
		String requestFile = null;
		requestFile = args[0];
	
		 String[] policiesFile = new String[100];
		 File directory = new File("XACMLTests/PolicyRepository/");
		 policiesFile = ListXMLDirectory(directory);
		  // Create a PolicyFinderModule and initialize it
		  // Use the sample FilePolicyModule
		 FilePolicyModule filePolicyModule = new FilePolicyModule();
			 for(int i=0; i<policiesFile.length; i++){
			      filePolicyModule.addPolicy(policiesFile[i]);
			 }
		      
			  
		  // Set up the PolicyFinder that this PDP will use
		  PolicyFinder policyFinder = new PolicyFinder();
		  Set policyModules = new HashSet();
		  policyModules.add(filePolicyModule);
		  policyFinder.setModules(policyModules);
		  
		
		  // Create the PDP
		  PDP pdp = new PDP(new PDPConfig(null, policyFinder, null));
		  
		  //  Get the request send by the PEP
		  RequestCtx request =
		      RequestCtx.getInstance(new FileInputStream(requestFile));
		  
		  // Evaluate the request. Generate the response.
		  ResponseCtx response = pdp.evaluate(request);
		  
		  // Display the output on std out
		  response.encode(System.out, new Indenter());
	}
}
