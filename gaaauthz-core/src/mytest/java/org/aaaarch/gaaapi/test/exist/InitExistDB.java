/**
 * @authors:
 * Thierry DENYS
 * Sylvain RAYNAL
 * Created: in 2007
 * Last update: july, 31th 2008
 */
package org.aaaarch.gaaapi.test.exist;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

import org.aaaarch.utils.HelpersReadWrite;
import org.exist.soap.Query;
import org.exist.soap.QueryService;
import org.exist.soap.QueryServiceLocator;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xmldb.api.DatabaseManager;
import org.xmldb.api.base.Collection;
import org.xmldb.api.base.Database;
import org.xmldb.api.base.Resource;
import org.xmldb.api.base.ResourceIterator;
import org.xmldb.api.base.ResourceSet;
import org.xmldb.api.base.XMLDBException;
import org.xmldb.api.modules.CollectionManagementService;
import org.xmldb.api.modules.XMLResource;
import org.xmldb.api.modules.XPathQueryService;



public class InitExistDB {
	//private static Logger log = Logger.getLogger(InsertRepositoryDB.class);
	
	public static Collection root;

	// Information to connection data
	public static String dbDriver = ConfigExist.DB_EXIST_DRIVER;
	public static String dbConnection = ConfigExist.DB_EXIST_CONNECTION;
	public static String dirExist = ConfigExist.DB_EXIST_DIR;
	public static String dbLogin = ConfigExist.DB_EXIST_LOGIN_ADMIN;
	public static String dbPassword = ConfigExist.DB_EXIST_PASSWD_ADMIN;	
	public static String collectionShortXACML = "XACMLRepository";
	public static String collectionShortAAA = "AAASessionsRepository";
	public static String fileSeparator="/";
	public static String policiesNameFile[] = {
		"IIA001Policy.xml","IIA002Policy.xml","IIA003Policy.xml", 
		"IIB001Policy.xml","IIB002Policy.xml","IIB003Policy.xml",
		"IIC001Policy.xml","IIC002Policy.xml",
		"IID001Policy.xml","IID002Policy.xml",
		"IIE001Policy.xml","IIE002Policy.xml",
		"IIIA001Policy.xml","IIIC001Policy.xml","IIIF006Policy.xml"};
	public static String schemas[] = {
		"cs-xacml-schema-context-01.xsd","cs-xacml-schema-policy-01.xsd"};
	public InitExistDB(){
	}
	
    public String[] getPoliciesFile(){
    	return policiesNameFile;
    }
    /* get all policies in a String[]*/
    public static String[] getPoliciesData(String collectionName, String[] policiesNameFile) 
    	throws Exception{

    	String[] policiesCollection = new String[policiesNameFile.length];
    	System.out.println("\nInitExistDB.getPoliciesData: policiesNameFile.length = " + policiesNameFile.length);
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	
    	/* query Request */
    	for(int i=0; i<policiesNameFile.length;i++ ){
    	String query = "for $policies in doc('/db"+fileSeparator+collectionName+fileSeparator+policiesNameFile[i]+"') return $policies";
    	
    	ResourceSet resultQuery = service.query(query);
    	
	       ResourceIterator resourceIterator = resultQuery.getIterator();
           while (resourceIterator.hasMoreResources()) {
               Resource resource = resourceIterator.nextResource();
               policiesCollection[i] = (String) resource.getContent();
          }
    	}
        return policiesCollection;
    }
    // Return the dbConnection
    public String getDBConnection(){
    	return dbConnection;
    }
    
	/* Database Connection*/
	public void connectionExist(String dbConnection, String login, String password) throws Exception{
		Class<?> cl = Class.forName(dbDriver);            
		Database database = (Database)cl.newInstance();
		String createdatabase = "true";
		String dbFileName = dirExist+"";
		database.setProperty("create-database", createdatabase);
        database.setProperty("configuration", dbFileName);
        database.setProperty("encoding","ISO-8859-1");
        DatabaseManager.registerDatabase(database);
        System.out.println("Connection to the database : "+dbConnection);
		root = DatabaseManager.getCollection(dbConnection,login,password);
	}
	
	/* Database Disconnect*/
    public void disconnectExist() throws PBoxXMLDBRepositoryException {
        if (root != null) {
            try {
                root.close();
                System.out.println("Disconnect to the database");
                root = null;
            } catch (XMLDBException e) {
                System.err.println("Cannot disconect from the Database" + e.errorCode + " " + e.getMessage());
                throw new PBoxXMLDBRepositoryException(e);
            }
        }
    }

	/* Create Collection*/
	public void createExistCollection(String collectionName){
		try{
			CollectionManagementService mgtService = (CollectionManagementService) root.getService("CollectionManagementService", "1.0");
			mgtService.createCollection(collectionName);
			System.out.println("Collection "+collectionName+" created in the database");
		}
		catch (Exception e) {
            System.err.println("Cannot create collection"  + collectionName + e);
        }
	}
	
	 /* Drop collection */
    public void dropExistCollection(String collectionName) throws PBoxXMLDBRepositoryException {
        try {
        	CollectionManagementService mgtService = (CollectionManagementService) root.getService("CollectionManagementService", "1.0");
        	mgtService.removeCollection(collectionName);
        	System.out.println("Collection "+collectionName+" droped from the database");
        }
        catch (Exception e) {
        	System.err.println("Cannot Drop the Collection " + collectionName + ", it doesn't exist");
            throw new PBoxXMLDBRepositoryException(e);
        } 
    }
	
	/* Add node (XML file) in the collection*/
    public void addDOMNodeCollection(Node node, String resourceName, String collectionName) throws PBoxXMLDBRepositoryException, Exception {
        try {
        	
        	System.out.println("*** Add XML Resource ("+resourceName+") in Collection");
            XMLResource xmlResource = (XMLResource) root.createResource(resourceName, XMLResource.RESOURCE_TYPE);   
            xmlResource.setContentAsDOM(node);
          
            root.storeResource(xmlResource);
            xmlResource.getId();
        } catch (XMLDBException e) {
            throw new PBoxXMLDBRepositoryException(e);
        }
    }
    
 	
	/* Read file and returns DOM document*/
    public static Document readFileToDOM(String filename) throws Exception {
	  /*  // start xml document processing part
	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    //XML Signature needs to be namespace aware
	    dbf.setNamespaceAware(true);

	    DocumentBuilder db = dbf.newDocumentBuilder();
	    // reading document
	    Document doc = db.parse(filename);
	    
	    return doc;*/
        // start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		//org.w3c.dom.Document docnew = db.newDocument();

		// reading document
		System.out.print("file to read " + filename + "\n");
		org.w3c.dom.Document doc = db.parse(filename);
		

		return doc;
	}	
   
    /*Request repository using PolicyId without namespace and return Policy*/
    public String getPolicyFromPolicyId(String collectionName, String PolicyId, InitExistDB exist) throws Exception {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
    	String Policy=null;
    	Set<Object> policiesCollection = new HashSet<Object>();
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	/* query Request */
    	String query = "for $col in collection('/db/" + collectionName + "/') where some $r in $col//Policy satisfies $r[@PolicyId=\""+PolicyId+"\"]return $col";
    	System.out.println("request: "+ query);
    	ResourceSet resultQuery = service.query(query);
	    ResourceIterator resourceIterator = resultQuery.getIterator();
        while (resourceIterator.hasMoreResources()) {
        	Resource resource = resourceIterator.nextResource();
        	policiesCollection.add(resource.getContent());
        	Policy = (String) resource.getContent();
          }
    	exist.disconnectExist();
    	return Policy;
    }
    
    /*Request repository using PolicyId with namespace and return Policy*/
    public String getPolicyFromPolicyId(String collectionName, String PolicyId, String NameSpace, InitExistDB exist) throws Exception
    {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
    	String Policy=null;
    	Set<Object> policiesCollection = new HashSet<Object>();
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	/* query Request */
    	String query = "declare namespace ns = \""+ NameSpace+"\"; for $col in collection('/db/" + collectionName + "/') where some $r in $col//ns:Policy satisfies $r[@PolicyId=\""+PolicyId+"\"]return $col";
    	System.out.println("request: "+ query);
    	ResourceSet resultQuery = service.query(query);
	       ResourceIterator resourceIterator = resultQuery.getIterator();
           while (resourceIterator.hasMoreResources()) {
               Resource resource = resourceIterator.nextResource();
               policiesCollection.add(resource.getContent());
               Policy = (String) resource.getContent();
          }
    	exist.disconnectExist();
    	return Policy;
    }
    
    /*Request repository using Resource without namespace and return Policy*/
    public String getPolicyFromResource(String collectionName, String Resource, InitExistDB exist) throws Exception
    {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
    	String Policy=null;
    	Set<Object> policiesCollection = new HashSet<Object>();
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	/* query Request */
    	String query = "for $col in collection('/db/" + collectionName + "/') where some $r in $col//Target/Resources/Resource/ResourceMatch/AttributeValue satisfies $r = \""+Resource+"\" return $col";
    	System.out.println("request: "+ query);
    	ResourceSet resultQuery = service.query(query);
	       ResourceIterator resourceIterator = resultQuery.getIterator();
           while (resourceIterator.hasMoreResources()) {
               Resource resource = resourceIterator.nextResource();
               policiesCollection.add(resource.getContent());
               Policy = (String) resource.getContent();
          }
    	exist.disconnectExist();
    	return Policy;
    }
    
    /*Request repository using Resource with namespace and return Policy*/
    public String getPolicyFromResource(String collectionName, String Resource, String NameSpace, InitExistDB exist) throws Exception
    {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
    	String Policy=null;
    	Set<Object> policiesCollection = new HashSet<Object>();
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	/* query Request */
    	String query = "declare namespace ns = \"" + NameSpace + "\"; for $col in collection('/db/" + collectionName + "/') where some $r in $col//ns:Target/ns:Resources/ns:Resource/ns:ResourceMatch/ns:AttributeValue satisfies $r = \""+Resource+"\" return $col";
    	System.out.println("request: "+ query);
    	ResourceSet resultQuery = service.query(query);
	       ResourceIterator resourceIterator = resultQuery.getIterator();
           while (resourceIterator.hasMoreResources()) {
               Resource resource = resourceIterator.nextResource();
               policiesCollection.add(resource.getContent());
               Policy = (String) resource.getContent();
          }
    	exist.disconnectExist();
    	return Policy;
    }
    
    /*Get Sessions Context using domainId and gri*/
    public String getSessionsContext(String domainId, String gri, InitExistDB exist) throws Exception {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
    	String SessionCtx=null;
    	Set<Object> policiesCollection = new HashSet<Object>();
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	/* query Request */
    	String query = "for $col in collection('/db/" + collectionShortAAA + "/" + domainId + "/') where some $r in $col/SessionContext satisfies $r[@SessionId=\""+gri+"\"]return $col";
    	System.out.println("request: "+ query);
    	ResourceSet resultQuery = service.query(query);
	    ResourceIterator resourceIterator = resultQuery.getIterator();
        while (resourceIterator.hasMoreResources()) {
        	Resource resource = resourceIterator.nextResource();
        	policiesCollection.add(resource.getContent());
        	SessionCtx = (String) resource.getContent();
          }
    	exist.disconnectExist();
    	return SessionCtx;
    }
    
    /*Get Sessions Context using gri*/
    public String getSessionsContext(String gri, InitExistDB exist) throws Exception {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
    	String SessionCtx=null;
    	Set<Object> policiesCollection = new HashSet<Object>();
    	XPathQueryService service = (XPathQueryService) root.getService("XPathQueryService", "1.0");
    	/* query Request */
    	String query = "for $col in collection('/db/" + collectionShortAAA + "/') where some $r in $col//SessionContext satisfies $r[@SessionId=\""+gri+"\"]return $col";
    	System.out.println("request: "+ query);
    	ResourceSet resultQuery = service.query(query);
	    ResourceIterator resourceIterator = resultQuery.getIterator();
        while (resourceIterator.hasMoreResources()) {
        	Resource resource = resourceIterator.nextResource();
        	policiesCollection.add(resource.getContent());
        	SessionCtx = (String) resource.getContent();
          }
    	exist.disconnectExist();
    	return SessionCtx;
    }
    
    /* SOAP request to the database in order to get all policies*/
    public static String[] getPoliciesDataSOAP(String collectionName, String policiesNameFile[]) throws Exception{
    	
    	/*Connection with user : guest and password : guest*/
    	QueryService service = new QueryServiceLocator();
        Query query = service.getQuery();
        String session = query.connect("guest", "guest");
        String[] policiesCollection = new String[policiesNameFile.length];
    	
        /* Get all policies in the database and the collectionName*/
        for(int i= 0;i<policiesNameFile.length; i++){
		String data = query.getResource(session, 
			"/db/"+collectionName+"/"+policiesNameFile[i],true, false);
		policiesCollection[i] = data;
        }
        query.disconnect(session); 
		
		return policiesCollection;
    }
    
    public static void createCollection(String collection, InitExistDB exist) throws Exception
    {

		exist.connectionExist(dbConnection,dbLogin,dbPassword);
		exist.createExistCollection(collection);
		exist.disconnectExist();
		System.out.println("Collection " + collection + "Created");
    }
    
    public static void dropCollection(String collection, InitExistDB exist) throws Exception
    {
    	exist.connectionExist(dbConnection,dbLogin,dbPassword);
		exist.dropExistCollection(collection);
		exist.disconnectExist();
    }
    
    public static void insertPolicies(String collection, String files[], String path, InitExistDB exist) throws Exception
    {
    	exist.connectionExist(collection,dbLogin,dbPassword);
		/* Add policies in the database*/
    	if (files==null){
    		File directory = new File(path);
    		Document doc = readFileToDOM(path);
    		exist.addDOMNodeCollection(doc.getFirstChild(), directory.getName(),collection);
    	}
    	else {
    		for(int i=0; i<files.length;i++ ){
    		Document doc = readFileToDOM(path+files[i]);
    		exist.addDOMNodeCollection(doc.getFirstChild(), files[i],collection);
    		}
    		
    	}
    }
    
    
    public void insertAAAtickets(String collection, Node ticket, String gri, InitExistDB exist) throws Exception
    {
    	exist.connectionExist(dbConnection+fileSeparator+collection,dbLogin,dbPassword);
		/* Add ticket in the database*/
    		exist.addDOMNodeCollection(ticket, gri,collection);
    }
  
   
	/* Main*/
	public static void main(String args[]){	
	
		try{
		InitExistDB exist = new InitExistDB();
		
		
		System.out.println("eXist Policy Repository \n" + "***\n"+
		   		"0 - Create collections\n"+
		   		"1 - Drop collections \n"+
		   		"2 - Insert XACMLPolicies into repository\n"+
		   		"3 - Query Policies collection using PolicyId\n"+
		   		"4 - Query Policies collection using Resource\n"+
		   		"5 - exit\n\n"+
		   		"6 - insert XACMLPolicies Conformance test\n" +
		   		"7 - Query Session context using Gri and domainId"+
				"");
		   	   	int s = HelpersReadWrite.readStdinInt();			
		   		switch(s) {
		   		
		   		//Create collections
		   		case 0: {
		   			createCollection(collectionShortXACML, exist);
		   			createCollection(collectionShortAAA, exist);
		   			createCollection(collectionShortAAA+"/violaReservations", exist);
		 			createCollection(collectionShortAAA+"/i2catReservations", exist);
		 			createCollection(collectionShortAAA+"/uclpReservations", exist);
		 			createCollection(collectionShortAAA+"/oscarsReservations", exist);
		 			createCollection(collectionShortAAA+"/drackReservations", exist);
		 			createCollection(collectionShortAAA+"/uvaReservations", exist);
					return;}
		   		
		   		//Drop collections
		   		case 1: {
		   			dropCollection(collectionShortXACML, exist);
		   			dropCollection(collectionShortAAA+"/violaReservations", exist);
		   			dropCollection(collectionShortAAA+"/i2catReservations", exist);
		   			dropCollection(collectionShortAAA+"/uclpReservations", exist);
		   			dropCollection(collectionShortAAA+"/oscarsReservations", exist);
		   			dropCollection(collectionShortAAA+"/drackReservations", exist);
		   			dropCollection(collectionShortAAA+"/uvaReservations", exist);
		   			dropCollection(collectionShortAAA, exist);
					return;}
		   		
		   		//insert XACMLPolicies
		   		case 2: {
		   			String collectionName = dbConnection+fileSeparator+collectionShortXACML;
		   			/*InputStreamReader isr = new InputStreamReader( System.in );
		   			BufferedReader stdin = new BufferedReader( isr );
		   			System.out.println("Path:");
		   			String path = stdin.readLine();*/
		   			String path="C:\\Documents and Settings\\Thierry\\Bureau\\test\\viola-policy-harmony-demo041.xml";
		   			//String path="D:\\deveclipse\\aaauthreach\\policies\\";
		   			String files[] = FilesResolver.find(path);
		   			insertPolicies(collectionName, files, path, exist);
		   			return;}
		   		
		   		//Get XACMLPolicies using PolicyId
		   		case 3: {
		   			InputStreamReader isr = new InputStreamReader( System.in );
		   			BufferedReader stdin = new BufferedReader( isr );
		   			System.out.println("PolicyId:");
		   			String PolicyId = stdin.readLine();
		   			String NameSpace="urn:oasis:names:tc:xacml:2.0:policy:schema:os";
		   			String results = exist.getPolicyFromPolicyId(collectionShortXACML, PolicyId, NameSpace, exist);
		   			if (results == null) {
		   				System.out.println("No results, trying without namespace");
		   				results = exist.getPolicyFromPolicyId(collectionShortXACML, PolicyId, exist);
		   			}
		   			System.out.println(results);
					return;}
		   		
		   		//Get XACMLPolicies using Resource
		   		case 4: {
		   			InputStreamReader isr = new InputStreamReader( System.in );
		   			BufferedReader stdin = new BufferedReader( isr );
		   			System.out.println("Resource:");
		   			String Resource = stdin.readLine();
		   			String NameSpace="urn:oasis:names:tc:xacml:2.0:policy:schema:os";
		   			String results = exist.getPolicyFromResource(collectionShortXACML, Resource, NameSpace, exist);
		   			if (results == null) {
		   				System.out.println("No results, trying without namespace");
		   				results = exist.getPolicyFromResource(collectionShortXACML, Resource, exist);
		   			}
		   			System.out.println(results);
					return;}
		   		
		   		case 5: {
		   			return;}

		   		//insert XACMLPolicies Conformance test
		   		case 6: {
		   			String collectionName = dbConnection+fileSeparator+collectionShortXACML;
		   			String	XACML_DIR_CONF_TEST = "D:/deveclipse/aaauthreach/external/xacml2.0-conformance-test2005/";
		   			String policiesNameFile[] = {
		   					"IIA001Policy.xml","IIA002Policy.xml","IIA003Policy.xml", 
		   					"IIB001Policy.xml","IIB002Policy.xml","IIB003Policy.xml",
		   					"IIC001Policy.xml","IIC002Policy.xml",
		   					"IID001Policy.xml","IID002Policy.xml",
		   					"IIE001Policy.xml","IIE002Policy.xml",
		   					"IIIA001Policy.xml","IIIC001Policy.xml","IIIF006Policy.xml"};
		   			
		   			String schemas[] = {
		   					"access_control-xacml-2.0-context-schema-os.xsd","access_control-xacml-2.0-policy-schema-os.xsd"};
		   			InitExistDB.insertPolicies(collectionName, policiesNameFile, XACML_DIR_CONF_TEST, exist);
		   			InitExistDB.insertPolicies(collectionName, schemas, XACML_DIR_CONF_TEST, exist);
		   			return;}

		   		case 7:
		   			InputStreamReader isr = new InputStreamReader( System.in );
		   			BufferedReader stdin = new BufferedReader( isr );
		   			System.out.println("domainId:");
		   			String domainId = stdin.readLine();
		   			domainId = domainId + "Reservations";
		   			System.out.println("gri:");
		   			String gri = stdin.readLine();
		   			String result = null;
		   			if (domainId.length()==0)
		   			{
		   				result = exist.getSessionsContext(gri, exist);
		   			}
		   			else
		   			{
		   				result = exist.getSessionsContext(domainId, gri, exist);
		   			}
		   			System.out.println(result);
		   			return;}
		
		
		//SOAP Part
		//String [] policiesData = getPoliciesDataSOAP(collectionShortName,policiesNameFile);
		   		exist.disconnectExist();
		} catch (Exception e) {
            e.printStackTrace();
		}
	}
}
