/*
 * Created on May 19, 2008
 * 
 * @author demch
 * 
 */
package org.aaaarch.gaaapi.test.xacml;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

import com.sun.xacml.test.TestDriver;

import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.gaaapi.IDgenerator;
import org.aaaarch.gaaapi.ticktok.CachedAuthzTicket;
import org.opensaml.SAMLAttribute;
import org.aaaarch.utils.HelpersDateTime;
import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;
import org.apache.regexp.RE;
import org.apache.regexp.RESyntaxException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.w3c.dom.Node;

/**
 * @author demch
 *
 */
public class TestXACMLConformProfileNRP {
	
	protected SAMLNameIdentifier nameId = null;
	protected static ArrayList confirmationMethods = new ArrayList();
	protected static Element confirmationData = null;
	protected static KeyInfo keyInfo = null;
	
	public static final String DELIM_URN = ":";
	public final static String DELIM = " ";
	public static final String CSV_PATTERN =
		"\"([^\"\\\\]*(\\\\.[^\"\\\\]*)*)\",?|([^,]+),?|,";
	
	public static void printDOMdoc(org.w3c.dom.Document doc) throws Exception {
		// print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
	}
	public static void printDOMdoc(org.w3c.dom.Node element) throws Exception {
		//print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(element, f);
		f.close();
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
	}
	
	public static void saveDOMdoc(org.w3c.dom.Document doc, String filename)
	throws Exception {
		//save file from DOM doc
		FileOutputStream f = new FileOutputStream(filename);
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		//System.out.println("Wrote echo DOM doc to " + filename);
	}
	///////////////////////////////////////////////////
	// Generate policy of external access table in CSV format
	// Read CSV file as a String and build arrays rollist[], actlist[], accesstab[][]
	public static Collection parseCSVstring(String prefix, String pollist) throws IOException, RESyntaxException {

		//String[] polset = new String[npolis];
		ArrayList polset = new ArrayList();
		ArrayList testlist = new ArrayList();
			String line;
			String[][] table = new String[10][10];
			int npolis = 0;
			int ntests = 0;
			// Construct a new Regular Expression parser.
			RE csv = new RE(CSV_PATTERN);

			//BufferedReader is = new BufferedReader(new InputStreamReader(System.in));
			BufferedReader is = new BufferedReader(new StringReader(pollist));
		
			// For each line...
			int j = 0;
			while ((line = is.readLine()) != null) {
				//System.out.println("line = \"" + line + "\"");
				int i = 0;
				// For each field
				for (int fieldNum = 0, offset = 0; csv.match(line, offset); fieldNum++) 
				{

					// Print the field (0=null, 1=quoted, 3=unquoted).
					//int n = csv.getParenCount()-1;//if table with capture row/col
					int n = csv.getParenCount()-1;
					if (n==0)	// null field
						{System.out.println("field[" + fieldNum + "] = \"\" is empty");} 
					else
						{
							table [j][i] = csv.getParen(n);
							//System.out.println("field[" + fieldNum + "] = \"" + csv.getParen(n) + "\"");
							if (j == 0 ) { npolis = i; };
							i++;
							} 

					// Skip what already matched.
					offset += csv.getParen(0).length();
				}
				ntests = j; j++;
			}

		int val = 0;
		String nn = null;
		System.out.println("Policies list contains " + npolis + " policies:"); 
		for (int k = 0; k <= npolis; k++) {
			nn = table [0][k];
			val = Integer.parseInt(nn);
			if (val<10) {nn = "00" + nn;} else {
				if (val<100) {nn = "0" + nn;}
			}
			polset.add(prefix + nn);
			//System.out.println(polset.get(k)); 
			}

		System.out.println("Tests list contains " + ntests + " tests:"); 
		String mm = null;
		for (int k = 0; k < ntests; k++) { 
			mm = table [k + 1][0];		
			testlist.add(mm);
			System.out.println( testlist.get(k)); 
			}
		return polset;
	}
	
	/* 
	 <tests>
	<test name = "IIA011" errorExpected = "false" expereimental="true">
	<policyReference ref="IIA005Policy.xml">IIA005Policy.xml</policyReference>
	<!-- <policySetReference ref="IIA005Policy.xml">IIA005Policy.xml</policySetReference> -->
	</test>
	</tests>
	 * 
	 */
	public static void makeTestSetFile(ArrayList names, String filename)
	throws Exception {
        // start xml document part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        // reading document
        org.w3c.dom.Document doc = db.newDocument();

        // root element is "tests"
        Element root = doc.createElement("tests");
        //root.setAttribute("testsID", testsid);
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("\n"));

        for (Iterator i=names.iterator(); i.hasNext();){
        	String testn = (String) i.next();
        Element test = doc.createElement("test");

        test.setAttribute("name", testn);
        test.setAttribute("errorExpected", "false");
        test.setAttribute("expereimental", "true");
        root.appendChild(test);
        root.appendChild(doc.createTextNode("\n"));
        /// Validity attributes
        Element polref = doc.createElement("policyReference");
        polref.setAttribute("ref", testn);
        polref.appendChild(doc.createTextNode(testn + "Policy.xml"));
        test.appendChild(polref);

        }
        // end of document creation part
		//save file from DOM doc
		FileOutputStream f = new FileOutputStream(filename);
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		System.out.println("Wrote TestSet to " + filename + "\n" + HelpersXMLsecurity.convertDOMToString(doc));
	}
	
	public static void main(String[] args) throws Exception 
	{
		org.apache.xml.security.Init.init();
		
		//Receive parameters for the keystore
		//String keyalias = "cnl01";
		//List checkconfsec = new ArrayList();
		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
		
		Properties pdpconf = null;
		//System.setProperties(pdpconf);
        // Changed in ConfigurationStore from
		//String configFile = System.getProperty(PDP_CONFIG_PROPERTY);
    	// to
		//String configFile = "data/config/xacml1.2-config00.xml";
		
		//pdpconf.setProperty("com.sun.xacml.PDPConfigFile", "fpol");//??
		
		try {   	
			System.out.println("\nRun XACML conformance tests");
			System.out.println("Select Conformance test group and next enter test policy number in \"000\" format:\n" +
					"(Mandatory-to-Implement Functionality - II{A,B,C,D,E}000Policy.xml, where 000 - number,\n" +
					"Optional, but Normative Functionality Tests - III(A,C,F,G)000Policy.xml\n" +
					"1 - IIA. Attribute References (001-021), \n" +
					"2 - IIB. Target Matching (001-053), \n" +
					"3 - IIC. Function Evaluation (001-232), \n" +
					"4 - IID. Combining Algorithms (001-030)");
			String diroftest = "data/policy/xacml-conformance-test/";
			int s = HelpersReadWrite.readStdinInt();			
			switch(s) {
			case 1: {
				System.out.println("\nInput list of test numbers separated by coma:");
				String polcsv = HelpersReadWrite.readInString();			
				System.out.println("I read this line: " + polcsv); 
				ArrayList polset = (ArrayList) parseCSVstring("IIA", polcsv);
				//ArrayList pollist = new ArrayList();
				//pollist.add("IIA001");
				//pollist.add("IIA002");
				//pollist.add("IIA003");
				//String testsetfile = "testset00.xml";
				String testsetfile = "testset01.xml";
		        makeTestSetFile(polset, testsetfile);
				TestDriver testDriver = new TestDriver(testsetfile);
		        testDriver.runTests(diroftest);
				return;}
			case 2: {
				String polcsv = HelpersReadWrite.readInString();			
				System.out.println("I read this line: " + polcsv); 
				ArrayList polset = (ArrayList) parseCSVstring("IIB", polcsv);
				String testsetfile = "testset01.xml";
		        makeTestSetFile(polset, testsetfile);
				TestDriver testDriver = new TestDriver(testsetfile);
		        testDriver.runTests(diroftest);
				return;}
			case 3: {
				String polcsv = HelpersReadWrite.readInString();			
				System.out.println("I read this line: " + polcsv); 
				ArrayList polset = (ArrayList) parseCSVstring("IIC", polcsv);
				String testsetfile = "testset01.xml";
		        makeTestSetFile(polset, testsetfile);
				TestDriver testDriver = new TestDriver(testsetfile);
		        testDriver.runTests(diroftest);
				return;}
			case 4: {
				String polcsv = HelpersReadWrite.readInString();			
				System.out.println("I read this line: " + polcsv); 
				ArrayList polset = (ArrayList) parseCSVstring("IID", polcsv);
				String testsetfile = "testset01.xml";
		        makeTestSetFile(polset, testsetfile);
				TestDriver testDriver = new TestDriver(testsetfile);
		        testDriver.runTests(diroftest);
				return;}
			} 
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
	
}
