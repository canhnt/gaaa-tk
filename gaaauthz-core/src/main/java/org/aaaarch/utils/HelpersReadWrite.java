/*
 * Created on May 3, 2004
 *
 * AIRG at UvA, Collaboratory.nl Project
 */
package org.aaaarch.utils;
import java.io.*;
import java.util.ArrayList;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

/**
 * @author Yuri Demchenko
 *
 * AIRG at UvA, Collaboratory.nl Project 
 */
public class HelpersReadWrite {

	//////////// Input/Output helpers ////////////////////	
	// Write String to File
	 
	public static void writerFile(String text, String fileName) throws IOException {
		PrintWriter out =
			new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
		out.print(text);
		out.close();
	}
	
	public static void writeToFile (String docstring, String filename) throws IOException {

		byte[] docbytes = docstring.getBytes();
		
		File File = new File(filename);
	    FileOutputStream f = new FileOutputStream(File);
	    f.write(docbytes);
	    f.close();
	    
	}

	public static void write (String fileName, Document doc) throws IOException {
		//TODO: to use another stream writer, not PrintWriter
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, bos);
		String docstr = bos.toString();
		bos.close();

		PrintWriter out =
			new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
		out.print(docstr);
		out.close();
	}

	public static void writeOutputStream (String fileName, ByteArrayOutputStream bos) throws IOException {
		//TODO: to use another stream writer, not PrintWriter
		String docstr = bos.toString();
		bos.close();

		PrintWriter out =
			new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
		out.print(docstr);
		out.close();
	}

	public static org.w3c.dom.Document readFileToDOM (String filename) throws Exception {
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

	
	////////////////////////////////	
	// Read File as string

	public static String readFileToString(String fileName) throws IOException {
		StringBuffer sb = new StringBuffer();
		BufferedReader in = new BufferedReader(new FileReader(fileName));
		String s;
		while ((s = in.readLine()) != null) {
			sb.append(s);
			sb.append("\n");
		}
		in.close();
		return sb.toString();
	}
	////////////////////////////////	
	// Replace oldstr with newstr in instring 

	public static String subst(String oldStr, 
			String newStr, String inString) {

			int start = inString.indexOf(oldStr);
			if (start == -1) {
				return inString;
			}
			StringBuffer sb = new StringBuffer();
			sb.append(inString.substring(0, start));
			sb.append(newStr);
			sb.append(inString.substring(start+oldStr.length()));
			return sb.toString();
		}
	////////////////////////////////	
	// Input roles list
	
	public static ArrayList readIn (int n) {
	
	ArrayList lines = new ArrayList();

	for (int i = 0; i < n; i++) {
		
	String line = null;
	int val = 0;
		try {
				BufferedReader is = new BufferedReader(
								   new InputStreamReader(System.in));
			line = is.readLine();
			//val = Integer.parseInt(line);
		} 
	//catch (NumberFormatException ex) 
	//{System.err.println("Not a valid number: " + line);} 
	catch (IOException e) 
	{
	System.err.println("Unexpected IO ERROR: " + e);
	}
		  lines.add(line);
		  //System.out.println("I read this line: " + line);
	}
	return lines;
	}	

	////////////////////////////////	
	// Input String
	
	public static String readInString () {
	
	String line = null;
		try {
				BufferedReader is = new BufferedReader(
								   new InputStreamReader(System.in));
			line = is.readLine();
			//val = Integer.parseInt(line);
		} 
	catch (IOException e) 
	{
	System.err.println("Unexpected IO ERROR: " + e);
	}
	//System.out.println("I read this line: " + line);
	return line;
	}	
	
	////////////////////////////////	
	// Input menu number (integer)

	public static int readStdinInt (){
		String line = null;
		int val = 0;
		try {
			BufferedReader is = new BufferedReader(
				new InputStreamReader(System.in));
				line = is.readLine();
				val = Integer.parseInt(line);
			} 
		catch (NumberFormatException ex) 
		{
		System.err.println("Not a valid number: " + line);
		} 
		catch (IOException e) 
		{
		System.err.println("Unexpected IO ERROR: " + e);
		}
		//System.out.println("I read this number: " + val);
		return val;
	}
	// TODO: adopt
	public void save(String filename, Document doc) {
		//finalizeRootElement(node);
		//NodeSerXml.internalAdjustPrefix(node.domNode, true);
		//node.adjustPrefix();

		internalSave(
		 new javax.xml.transform.stream.StreamResult(new java.io.File(filename)), doc);
	}
	public void save(java.io.OutputStream ostream, org.w3c.dom.Node node) {

		internalSave(
				new javax.xml.transform.stream.StreamResult(ostream),
				node.getOwnerDocument()
				);
	}
	// TODO: adopt
	protected static void internalSave(javax.xml.transform.Result result, org.w3c.dom.Document doc) {
		try {
			javax.xml.transform.Source source
					= new javax.xml.transform.dom.DOMSource(doc);
			javax.xml.transform.Transformer transformer
					= javax.xml.transform.TransformerFactory.newInstance().newTransformer();
			transformer.transform(source, result);
		} catch (javax.xml.transform.TransformerConfigurationException e) {
			throw new XmlException(e);
		} catch (javax.xml.transform.TransformerException e) {
			throw new XmlException(e);
		}
	}
}
