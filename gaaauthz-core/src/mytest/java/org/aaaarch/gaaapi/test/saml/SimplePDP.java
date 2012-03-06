package org.aaaarch.gaaapi.test.saml;
/*
 * @(#)SimplePDP.java
 *
 * Copyright 2003-2004 Sun Microsystems, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistribution of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 * 
 *   2. Redistribution in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * Neither the name of Sun Microsystems, Inc. or the names of contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * This software is provided "AS IS," without a warranty of any kind. ALL
 * EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
 * ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
 * AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
 * AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
 * DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
 * REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
 * INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
 * OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
 * EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *
 * You acknowledge that this software is not designed or intended for use in
 * the design, construction, operation or maintenance of any nuclear facility.
 */


import org.aaaarch.gaaapi.test.mysql.InitMySQLDB;
import com.sun.xacml.ConfigurationStore;
import com.sun.xacml.Indenter;
import com.sun.xacml.ParsingException;
import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.cond.FunctionFactory;
import com.sun.xacml.cond.FunctionFactoryProxy;
import com.sun.xacml.cond.StandardFunctionFactory;
import com.sun.xacml.cond.TimeInRangeFunction;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.impl.CurrentEnvModule;
//import com.sun.xacml.finder.impl.FilePolicyModule;
import com.sun.xacml.finder.impl.SelectorModule;
import com.sun.xacml.support.finder.FilePolicyModule;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import java.sql.Connection;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aaaarch.gaaapi.test.exist.InitExistDB;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import org.aaaarch.gaaapi.test.saml.CreateDOM;
import org.aaaarch.utils.HelpersReadWrite;

import org.xml.sax.InputSource;

import java.io.StringReader;


/**
 * This is a simple, command-line driven XACML PDP. It acts both as an example
 * of how to write a full-featured PDP and as a sample program that lets you
 * evaluate requests against policies. See the comments for the main() method
 * for correct usage.
 *
 * @since 1.1
 * @author seth proctor
 */
public class SimplePDP
{
    // this is the actual PDP object we'll use for evaluation
    private PDP pdp = null;
    
    /**
     * Default constructor. This creates a <code>SimplePDP</code> with a
     * <code>PDP</code> based on the configuration defined by the runtime
     * property com.sun.xcaml.PDPConfigFile.
     */
    public SimplePDP() throws Exception {
        // load the configuration
        ConfigurationStore store = new ConfigurationStore();

        // use the default factories from the configuration
        store.useDefaultFactories();

        // get the PDP configuration's and setup the PDP
        pdp = new PDP(store.getDefaultPDPConfig());
    }

    /**
     * Constructor that takes an array of filenames, each of which
     * contains an XACML policy, and sets up a <code>PDP</code> with access
     * to these policies only. The <code>PDP</code> is configured
     * programatically to have only a few specific modules.
     *
     * @param policyFiles an arry of filenames that specify policies
     */
    public SimplePDP(String[] policyFiles) throws Exception {
        // Create a PolicyFinderModule and initialize it...in this case,
        // we're using the sample FilePolicyModule that is pre-configured
        // with a set of policies from the filesystem
        FilePolicyModule filePolicyModule = new FilePolicyModule();
        
        for (int i = 0; i < policyFiles.length; i++)
            filePolicyModule.addPolicy(policyFiles[i]);

        // next, setup the PolicyFinder that this PDP will use
        PolicyFinder policyFinder = new PolicyFinder();
        Set policyModules = new HashSet();
        policyModules.add(filePolicyModule);
        policyFinder.setModules(policyModules);

        // now setup attribute finder modules for the current date/time and
        // AttributeSelectors (selectors are optional, but this project does
        // support a basic implementation)
        CurrentEnvModule envAttributeModule = new CurrentEnvModule();
        SelectorModule selectorAttributeModule = new SelectorModule();

        // Setup the AttributeFinder just like we setup the PolicyFinder. Note
        // that unlike with the policy finder, the order matters here. See the
        // the javadocs for more details.
        AttributeFinder attributeFinder = new AttributeFinder();
        List attributeModules = new ArrayList();
        attributeModules.add(envAttributeModule);
        attributeModules.add(selectorAttributeModule);
        attributeFinder.setModules(attributeModules);

        // Try to load the time-in-range function, which is used by several
        // of the examples...see the documentation for this function to
        // understand why it's provided here instead of in the standard
        // code base.
        FunctionFactoryProxy proxy =
            StandardFunctionFactory.getNewFactoryProxy();
        FunctionFactory factory = proxy.getConditionFactory();
        factory.addFunction(new TimeInRangeFunction());
        FunctionFactory.setDefaultFactory(proxy);

        // finally, initialize our pdp
        pdp = new PDP(new PDPConfig(attributeFinder, policyFinder, null));
    }

    /**
     * Evaluates the given request and returns the Response that the PDP
     * will hand back to the PEP.
     *
     * @param requestFile the name of a file that contains a Request
     *
     * @return the result of the evaluation
     *
     * @throws IOException if there is a problem accessing the file
     * @throws ParsingException if the Request is invalid
     */
    public ResponseCtx evaluate(String requestFile)
        throws IOException, ParsingException
    {
        // setup the request based on the file
        RequestCtx request =
            RequestCtx.getInstance(new FileInputStream(requestFile));

        // evaluate the request
        return pdp.evaluate(request);
    }
    
    /*	
     * **********        NEW       *************
     */
    
    // For One request evaluation of one policy 
    public SimplePDP(String policyFiles) throws Exception {
        // Create a PolicyFinderModule and initialize it...in this case,
        // we're using the sample FilePolicyModule that is pre-configured
        // with a set of policies from the filesystem
        FilePolicyModule filePolicyModule = new FilePolicyModule();
        filePolicyModule.addPolicy(policyFiles);
        
        // next, setup the PolicyFinder that this PDP will use
        PolicyFinder policyFinder = new PolicyFinder();
        Set policyModules = new HashSet();
        policyModules.add(filePolicyModule);
        policyFinder.setModules(policyModules);

        // now setup attribute finder modules for the current date/time and
        // AttributeSelectors (selectors are optional, but this project does
        // support a basic implementation)
        CurrentEnvModule envAttributeModule = new CurrentEnvModule();
        SelectorModule selectorAttributeModule = new SelectorModule();

        // Setup the AttributeFinder just like we setup the PolicyFinder. Note
        // that unlike with the policy finder, the order matters here. See the
        // the javadocs for more details.
        AttributeFinder attributeFinder = new AttributeFinder();
        List attributeModules = new ArrayList();
        attributeModules.add(envAttributeModule);
        attributeModules.add(selectorAttributeModule);
        attributeFinder.setModules(attributeModules);

        // Try to load the time-in-range function, which is used by several
        // of the examples...see the documentation for this function to
        // understand why it's provided here instead of in the standard
        // code base.
        FunctionFactoryProxy proxy =
            StandardFunctionFactory.getNewFactoryProxy();
        FunctionFactory factory = proxy.getConditionFactory();
        factory.addFunction(new TimeInRangeFunction());
        FunctionFactory.setDefaultFactory(proxy);

        // finally, initialize our pdp
        pdp = new PDP(new PDPConfig(attributeFinder, policyFinder, null));
    }
    
    /* List Directory (XML files only)*/
    /* type is equal to Policy.xml or Response
     * It depends if you want the policy Files or the response Files*/
	public static String[] listXMLDirectory(File directory,String type){
		 String[] listFile;
		 listFile = directory.list();
	
		 int nbXMLFiles = 0;
		 for(int i=0 ; i < listFile.length ; i++){
			 if(type.equals("Policy.xml") && listFile[i].endsWith(type) == true)
					 nbXMLFiles ++;
			
			 if(type.equals("Response") && listFile[i].startsWith(type) == true)
					 nbXMLFiles ++;
			
		 }
		 
		 String[] listFileFinal = new String[nbXMLFiles];
		 int incr = 0;
		 for(int i=0 ; i < listFile.length ; i++){
			 if(type.equals("Policy.xml") && listFile[i].endsWith("Policy.xml") == true){
					 listFileFinal[incr] = directory.getPath()+"/"+listFile[i];
					 incr ++;
				
			 }
			 if(type.equals("Response") && listFile[i].startsWith("Response") == true){
					 listFileFinal[incr] = directory.getPath()+"/"+listFile[i];
					 incr ++;
			 }
		 }
		 
		 return listFileFinal;
	}
    
	// Print Decision for each policy in function of the request
	public static void printDecisions(String requestFile, String[] policyFiles, String tmpDir) throws Exception{
		SimplePDP simplePDP = null;

	    for (int i = 0; i < policyFiles.length; i++){
	        simplePDP = new SimplePDP(policyFiles[i]);
	        
	        // evaluate the request
	        ResponseCtx response = simplePDP.evaluate(requestFile);
	        Set results = new HashSet();
	        results = response.getResults();
	        
	        /*
	        * Error/Warning with XACML files :
	        *  - AttributeFinder (Almost all)
	        *  - AttributeDesignator
	        *  - PolicyFinder
	        *  - AttributeSelector
	        */
		    Iterator it = results.iterator();
		    System.out.print("Policy : "+policyFiles[i]+ " - Decision : ");
		        while (it.hasNext()) {
		            Result result = (Result)(it.next());
		            
		            int numberDecision = result.getDecision();
		            
		            if(numberDecision == result.DECISION_DENY)
		            	System.out.println("DENY");
		            
		            if(numberDecision == result.DECISION_INDETERMINATE)
		            	System.out.println("INDETERMINATE");
		            
		            if(numberDecision == result.DECISION_NOT_APPLICABLE)
		            	System.out.println("NOT_APPLICABLE");
		            
		            if(numberDecision == result.DECISION_PERMIT){
		            	System.out.println("PERMIT");
		            	
		            	/* Save the request and the good policies 
		            	 */
		            	OutputStream output = new FileOutputStream(tmpDir+"Response"+policyFiles[i].substring(policyFiles[i].length()-16, policyFiles[i].length()-10)+".xml");
		            	response.encode(output, new Indenter());
		            	
		            	/* Create XML document instance */ 
		        		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		        		
		        		// SAML Assertion and XML Signature part need to be namespace aware
		        		dbf.setNamespaceAware(true);		
		        		DocumentBuilder db = dbf.newDocumentBuilder();
		        		
		        		// Open the policy document
		        		File policy = new File(policyFiles[i]);
		                Document documentXACMLPolicy = db.parse(policy);
		                
		                /* Transform and Save the policy Files*/ 
		            	CreateDOM createDOM = new CreateDOM();
		        		createDOM.transformerXml(documentXACMLPolicy, tmpDir+policyFiles[i].substring(policyFiles[i].length()-16, policyFiles[i].length()));
		             }     
		        }
	    }
	}
	
	// Write XML policy Files in a directory
	public static void writePolicyFiles(String[] policyFileName, String[] policyFiles, String dir) throws Exception{
	
		for(int i=0; i<policyFileName.length; i++){
		DocumentBuilder parser = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		Document document = parser.parse(new InputSource(new StringReader(policyFiles[i])));
		
		/* This file is in the package utils*/
		/* Error if you use the saveDOM function but not with transformerXml*/ 
		CreateDOM createDOM = new CreateDOM();
		createDOM.transformerXml(document, dir+policyFileName[i]);
		}
	}

	// Delete all files of the path directory
	static public boolean deleteFilesDirectory(File path) { 
        boolean result = true; 
        
        if(path.exists()) { 
                File[] files = path.listFiles(); 
                for(int i=0; i<files.length; i++) { 

                	if(files[i].isDirectory()) { 
                        result = deleteFilesDirectory(files[i]); 
	                } 
	                else { 
	                	result = files[i].delete(); 
	                } 
                    
                    if(result == false)	
                    	System.out.println("Error to dell tmp files : "+ files[i]);  	
                } 
        }   
        return result; 
	} 
	
	
	/*
	 * Main 
	 * One Argument : XML request file 
	 */
    public static void main(String [] args) throws Exception {
        if (args.length < 1) {
            System.out.println("<request>");
            System.exit(1);
        }
        
        // Main information
		String directoryName ="external/xacml-conformance-test/";
		String dirTmp = "_aaadata/tmp/database/";
		String dirXacmlData = "_aaadata/tmp/xacmldata/";
		String collectionName = "XACMLRepository";
		
        // Get the Request
        String requestFile = null;
        requestFile = args[0];
        String[] policyFiles = null;
        
        try{
        	System.out.println("*** Parse all policies and get Decision for the request ***");
    		System.out.println("Select one method :\n" +
    				"1 - ConformanceTests Directory\n" +
    				"2 - Normal Request to the eXist Database (Collection : XACMLRepository)\n"+
    				"3 - SOAP Request to the eXist database (Collection : XACMLRepository)\n"+
    				"4 - Query to the MySQL Database\n");
    		int s = HelpersReadWrite.readStdinInt();
    		switch(s) {
    		
			case 1: {
	            // Get all policies in the directory File (only Policy.xml files)
	            File directory = new File(directoryName);
	    		policyFiles = listXMLDirectory(directory,"Policy.xml");
	    		
	    		/* Print Decisions and save the good requets and "Permit" Policy
	    		 * in the XACML directory*/
	    		printDecisions(requestFile,policyFiles,dirXacmlData);
	    		
				return;
				}
			
			case 2: {
				// 0 -> Connection to the database
				InitExistDB existDB = new InitExistDB();
				existDB.connectionExist(existDB.getDBConnection()+"/"+collectionName,"admin","");
				
				// 1 ->Policy File Name
				policyFiles = existDB.getPoliciesFile();
				
				// 2 -> get the data policy Files in the database
				String[] policyFilesData = existDB.getPoliciesData(collectionName,policyFiles);
				
				// 3 -> Write the policy Files in a tmp directory with the data and the name
				writePolicyFiles(policyFiles,policyFilesData,dirTmp);
			
					// 4 -> Add the tmp dir before the policyFiles (name)
					for(int i=0; i<policyFiles.length; i++){
						policyFiles[i] = dirTmp+policyFiles[i];
					}
				
				// 5 -> call the function and print decision for each policy file
				// Save the good request and policy in the Xacml Data directory
				printDecisions(requestFile,policyFiles,dirXacmlData);
				
				// 6 -> Delete all files of the tmp database directory
				deleteFilesDirectory(new File(dirTmp));
				
				// 7 -> Disconnect to the database
				existDB.disconnectExist();
			
				return;
				}
			case 3: {
				InitExistDB existDB = new InitExistDB();
				
				policyFiles = existDB.getPoliciesFile();
				
				/* SOAP Request*/
				String[] policyFilesData = existDB.getPoliciesDataSOAP(collectionName, policyFiles);
				writePolicyFiles(policyFiles,policyFilesData,dirTmp);
			
					// Add the tmp dir before the policyFiles (name)
					for(int i=0; i<policyFiles.length; i++){
						policyFiles[i] = dirTmp+policyFiles[i];
					}
				
				printDecisions(requestFile,policyFiles, dirXacmlData);
				deleteFilesDirectory(new File(dirTmp));
				
				return;
				}
			
			case 4:{
				InitMySQLDB mysqlDB = new InitMySQLDB();
				Connection conn = mysqlDB.MySQLConnection(mysqlDB.getDatabaseName(), "root", "");
				
				/* Get policy of the database and save it in a directory*/
				String queryGetpolicy = "SELECT policyname,content FROM "+mysqlDB.getTableName();
				ResultSet resultset = mysqlDB.SQLResult(queryGetpolicy, conn);
				
				String queryNbPolicy ="SELECT COUNT(*) FROM "+mysqlDB.getTableName();
				ResultSet resultNbPolicy = mysqlDB.SQLResult(queryNbPolicy, conn);
				int nbPolicy = 0;	
					while(resultNbPolicy.next()) {
						nbPolicy = resultNbPolicy.getInt(1);
					}
					
					policyFiles = new String[nbPolicy];
					int i = 0;
					while(resultset.next()) {
						/* Save these files (Name + Value)*/
					    String[] policyFilesData = new String[1];
					    String[] policyFilesName = new String[1];
					    
					    policyFilesName[0] = resultset.getString(1);
					    policyFilesData[0] = resultset.getString(2);
					    
					    writePolicyFiles(policyFilesName, policyFilesData,dirTmp);
					    policyFiles[i] = dirTmp+policyFilesName[0];
					    i++;
					}
					
				printDecisions(requestFile,policyFiles, dirXacmlData);
				deleteFilesDirectory(new File(dirTmp));
				}
    		}
		}catch (Exception e) {
				e.printStackTrace();
				System.exit(1);
		}
    }
}