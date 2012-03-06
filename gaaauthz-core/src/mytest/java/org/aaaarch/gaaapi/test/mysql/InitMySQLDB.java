/**
 * @author:
 * Thierry DENYS
 * Created: in 2007 by Sylvain Raynal
 * Last update: july, 18th 2008
 */


package org.aaaarch.gaaapi.test.mysql;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.utils.HelpersReadWrite;
import org.xml.sax.SAXException;



public class InitMySQLDB {
	
	protected static String databaseName = "XACMLRepository";
	protected static String login = "root";
	protected static String password = "toor";
	protected static String tableName = "policy";
	
	public InitMySQLDB(){
		
	}
	
	public String getDatabaseName(){
		return databaseName;
	}
	
	public String getTableName(){
		return tableName;
	}
	
	/* Connection to the MySQL database*/
	public static Connection MySQLConnection(String database, String login, String password) throws Exception{
		Class.forName("com.mysql.jdbc.Driver").newInstance();
		Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/"+database,login,password);
		System.out.println("Connection to the MySQL Database : "+database);
		return conn;
	}
	
	/* SQL Query*/
	public static void SQLQuery(String query, Connection conn) throws SQLException{
		PreparedStatement ps = conn.prepareStatement(query);
	    ps.execute();
	}
	
	/* Get Result to a SQL Query*/
	public static ResultSet SQLResult(String query, Connection conn) throws SQLException{
		ResultSet results = null;

		try {
			Statement stmt = conn.createStatement();
			results = stmt.executeQuery(query);
		}
		catch(Exception e){
			e.printStackTrace();
		}
		return results;
	}
		
	public static String GetPolicyId(String filename) throws ParserConfigurationException, SAXException, IOException
	{
		String PolicyId=null;
        // start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

		// reading document
		org.w3c.dom.Document doc = db.parse(filename);
		
		if (doc.getDocumentElement().getTagName()=="Policy")
			PolicyId=doc.getDocumentElement().getAttribute("PolicyId");

		
		return PolicyId;
	}
	
	public static int GetNbPolicyFromPolicySet(String filename) throws ParserConfigurationException, SAXException, IOException
	{
        // start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

		// reading document
		org.w3c.dom.Document doc = db.parse(filename);

			
		return doc.getDocumentElement().getChildNodes().getLength();
	}
	
	public static String GetPolicyIdFromPolicySet(String filename, int NumPolicy) throws ParserConfigurationException, SAXException, IOException
	{
        // start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

		// reading document
		org.w3c.dom.Document doc = db.parse(filename);
		System.out.println(doc.getDocumentElement());
		System.out.println("coucou");
		return doc.getDocumentElement().getElementsByTagName("Policy").item(NumPolicy).getAttributes().getNamedItem("PolicyId").getNodeValue(); 
	}
	
	public static String extractPolicyFromPolicyId(String PolicyId, Connection conn) throws SQLException
	{
		String Policy=null;
		String queryPolicy = "SELECT content from policy where PolicyId='"+PolicyId+"';";
		
		ResultSet results;
		Statement stmt = conn.createStatement();
		results=stmt.executeQuery(queryPolicy);
		while (results.next()) { 
            //System.out.println(results.getString("content" )); 
            Policy=results.getString("content");
 
          }
		return Policy;
	}
	
	
	public static String extractPolicyFromPolicyNameFile(String PolicyNameFile, Connection conn) throws SQLException
	{
		String Policy=null;
		String queryPolicy = "SELECT content from policy where PolicyNameFile=\""+PolicyNameFile+"\";";
		System.out.println(queryPolicy);
		ResultSet results;
		Statement stmt = conn.createStatement();
		results=stmt.executeQuery(queryPolicy);
		while (results.next()) { 
            //System.out.println(results.getString("content" )); 
            Policy=results.getString("content");
 
          }
		return Policy;
	}
	
	public static void dropTable(String TableName, Connection conn) throws Exception
	{
		/* Drop the old Table*/
		String queryDropTable = "DROP TABLE "+TableName;
		SQLQuery(queryDropTable, conn);
	}
	
	public static void createTable(String TableName, Connection conn) throws Exception
	{
		String queryCreateTable = "CREATE TABLE "+TableName+"("+
		"id MEDIUMINT NOT NULL AUTO_INCREMENT,"+
		"PolicyNameFile VARCHAR(150) NOT NULL,"+
		"PolicyId text,"+
		"content text,"+
		"PRIMARY KEY  (id)"+ 
		")";
		SQLQuery(queryCreateTable, conn);
	}
	
	public static void insertPolicy(String TableName, String dirPolicy, String[] policyName, Connection conn) throws SQLException, ParserConfigurationException, SAXException, IOException
	{
			String queryInsertPolicy=null;
			for(int i=0; i<policyName.length; i++){
				if (GetPolicyId(dirPolicy+policyName[i])!=null)
				{
   				queryInsertPolicy = "INSERT INTO "+TableName+ "(PolicyNameFile,PolicyId,content)"+
   				" VALUES ('"+policyName[i]+"','"+GetPolicyId(dirPolicy+policyName[i])+"',LOAD_FILE('"+dirPolicy+policyName[i]+"')"+
   				")";
				}
				else
				{
					int nb_policy = GetNbPolicyFromPolicySet(dirPolicy+policyName[i]);
					System.out.println(nb_policy);
					/*for(int j=0;j<nb_policy+1;j++)
					{
						GetPolicyIdFromPolicySet(dirPolicy+policyName[i],j);
					}*/
				}
   				System.out.println(queryInsertPolicy);
   				SQLQuery(queryInsertPolicy, conn);
   			}
	}
	
	public static void main(String[] args) throws Exception{

		/* Connection*/
		Connection conn = MySQLConnection(databaseName,login, password);
		
		System.out.println("Mysql Policy Repository \n" + "***\n"+
   		"0 - Create table policy\n"+
   		"1 - Drop table policy\n"+
   		"2 - Insert elements into policy Table\n"+
   		"3 - Query policy Table using PolicyId\n"+
   		"4 - Query policy Table using PolicyNameFile\n"+
   		"5 - exit\n"+
		"");
   	   	int s = HelpersReadWrite.readStdinInt();			
   		switch(s) {
   		// Simple ticket sample fixed
   		case 0: {
   			createTable(tableName, conn);
   			System.out.println("Table created");
			return;}
   		case 1: {
				dropTable(tableName, conn);
				System.out.println("Table Droped");
				return;}
   		case 2: {
   			String dirPolicy = "D:/deveclipse/aaauthreach/external/xacml2.0-conformance-test2005/";
   			String policyName[] = {
   				"IIA001Policy.xml","IIA002Policy.xml","IIA003Policy.xml", 
   				"IIB001Policy.xml","IIB002Policy.xml","IIB003Policy.xml",
   				"IIC001Policy.xml","IIC002Policy.xml",
   				"IID001Policy.xml","IID002Policy.xml",
   				"IIE001Policy.xml","IIE002Policy.xml",
   				"IIIA001Policy.xml","IIIC001Policy.xml","IIIF006Policy.xml"};
			String schemas[] = {
   						"access_control-xacml-2.0-context-schema-os.xsd","access_control-xacml-2.0-policy-schema-os.xsd"};
			insertPolicy(tableName, dirPolicy, policyName, conn);
			insertPolicy(tableName, dirPolicy, schemas, conn);   
   				return;}
   		case 3: {
   			InputStreamReader isr = new InputStreamReader( System.in );
   			BufferedReader stdin = new BufferedReader( isr );
   			System.out.println("PolicyId:");
   			String PolicyId = stdin.readLine();
   			String result = extractPolicyFromPolicyId(PolicyId, conn);
			System.out.println(result);
			return;}
   		case 4: {
   			InputStreamReader isr = new InputStreamReader( System.in );
   			BufferedReader stdin = new BufferedReader( isr );
   			System.out.println("PolicyNameFile:");
   			String PolicyNameFile = stdin.readLine();
   			String result = extractPolicyFromPolicyNameFile(PolicyNameFile, conn);
			System.out.println(result);
			return;}
   		case 5: {
   			return;}
		}
	}
}
