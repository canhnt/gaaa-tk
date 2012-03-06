/*
 * Created on Nov 29, 2004
 *
 */
package org.aaaarch.gaaapi.test.xacml;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URI;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.logging.Logger;

import com.sun.xacml.ConfigurationStore;
import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.attr.AttributeFactory;
import com.sun.xacml.attr.AttributeValue;
import com.sun.xacml.attr.DateTimeAttribute;
import com.sun.xacml.ctx.Attribute;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Subject;
import com.sun.xacml.finder.PolicyFinder;

import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.config.ConfigTrustDomains;
import org.aaaarch.config.ConstantsNS;
import org.aaaarch.gaaapi.IDgenerator;
import org.aaaarch.gaaapi.ResourceHelper;
import org.aaaarch.gaaapi.impl.pdp.XACMLPDPsimple;
import org.aaaarch.gaaapi.ticktok.CachedAuthzTicket;
import org.aaaarch.policy.SimplePolicyFinderModule;
import org.aaaarch.policy.utils.XACMLPolicyMaker;
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
public class TestXACMLPDP {

    // using std java Logger 
	// TODO: warning logging based on events and exceptions
    // private static final Logger logger = Logger.getLogger(TestXACMLPDP.class.getName());

	protected SAMLNameIdentifier nameId = null;
	protected static ArrayList confirmationMethods = new ArrayList();
	protected static Element confirmationData = null;
	protected static KeyInfo keyInfo = null;

    // Test program data
	//static ArrayList subjset = new ArrayList();
	
	////Sun XACML init module
	// the pdp we use to do all evaluations
    private static PDP pdp;
    // Policy module that manage policies
    private static SimplePolicyFinderModule policyModule;
    
    // Requests components
    private static Set subjects = null;
    //private static Set attributes;
    private static Set resource;
    private static Set action;
    private static Set environment;

	/////
	public static final String DELIM_URN = ":";
	public final static String DELIM = " ";
	public static final String CSV_PATTERN =
		"\"([^\"\\\\]*(\\\\.[^\"\\\\]*)*)\",?|([^,]+),?|,";
	/*
	public static final String XACML_NS = "urn:oasis:names:tc:xacml:1.0:";
	public static final String XACML_CONTEXT_NS = "urn:oasis:names:tc:xacml:1.0:context:";
	public static final String XACML_SUBJECT_NS = "urn:oasis:names:tc:xacml:1.0:subject:";
	public static final String XACML_RESOURCE_NS = "urn:oasis:names:tc:xacml:1.0:resource:";
	public static final String XACML_ACTION_NS = "urn:oasis:names:tc:xacml:1.0:action:";
	public static final String XACML_ENVIRONMENT_NS = "urn:oasis:names:tc:xacml:1.0:environment:";

	public final static String SAML_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    public final static String SAMLP_NS = "urn:oasis:names:tc:SAML:1.0:protocol";
	public static final String SAML_ACTION_NS = "urn:oasis:names:tc:SAML:1.0:action";

	
	// Namespace identifiers
	public static final String CNL_ISSUER = "CNL2AttributeIssuer";
	public static final String CNL_NS = "urn:cnl";
	public static final String CNL_SUBJECT_NS = "cnl:subject";
	public static final String CNL_SUBJECT_ATTRIBUTE_NS = "cnl:subject:attributes";
	public static final String CNL_RESOURCE_NS = "cnl:resource";
	public static final String CNL_ACTION_NS = "cnl:action";
	
	public  static final String CNL_SUBJECT_SUBJECT_ID = "subject-id";
	public  static final String CNL_SUBJECT_TOKEN = "token";
	public  static final String CNL_SUBJECT_JOBID = "job-id";
	public  static final String CNL_SUBJECT_ROLE = "role";
	public  static final String CNL_RESOURCE_RESOURCE_ID = "resource-id";
	public  static final String CNL_ACTION_ACTION_ID = "action-id";
	public  static final String CNL_ENVIRONMENT = "environment";
	public static final String AAA_NS = "AAA:";
	*/
    private static void configurePDP() throws Exception {
        // load the configuration
        ConfigurationStore cs = new ConfigurationStore();
        policyModule = new SimplePolicyFinderModule();

        // use the default factories from the configuration
        cs.useDefaultFactories();

        // get the PDP configuration's policy finder modules...
        PDPConfig config = cs.getDefaultPDPConfig();
        PolicyFinder finder = config.getPolicyFinder();
        Set policyModules = finder.getModules();
        
        // add the module used in this PDP request
        policyModules.add(policyModule);
        finder.setModules(policyModules);

        // finally, setup the PDP
        pdp = new PDP(config);
    }

    //public static ResponseCtx requestPDP(String policyID, RequestCtx request) {
    public static String requestPDP(RequestCtx request, String policyref) 
    throws IOException {
        ResponseCtx response = null;
        //policyModule = new SimplePolicyFinderModule();
        //
		ByteArrayOutputStream ousin = new ByteArrayOutputStream();
		request.encode(ousin);
		System.out.println("\nPDP Request (requestPDP): \n" + ousin);
        
        //
        try {
            
            // re-set the module to use this instant policy or policies set
        	// from *.xacml.test.BasicTest
            policyModule.setPolicies(policyref);
            /*
            {
                Iterator it = policies.iterator();
                Set set = new HashSet();

                while (it.hasNext()) 
                	set.add((String)(it.next()));

                policyModule.setPolicies(set);
            }
            */
            // re-set references for multiple policies
            //policyModule.setPolicyRefs(policyRefs, testPrefix);
            //policyModule.setPolicySetRefs(policySetRefs, testPrefix);
            System.out.println("\nTracking echo (requestPDP): bijna pdp.evaluate(request)");
            // actually do the evaluation
            response = pdp.evaluate(request);
    		System.out.println("\nPDP Response: " + ((response==null)? "null" : "not null"));

            // load the reponse that we expectd to get
            //ResponseCtx expectedResponse = ResponseCtx.getInstance(new FileInputStream("responseID"));
           // see if the actual result matches the expected result
           //boolean equiv = TestUtil.areEquivalent(response, expectedResponse);
                
        } catch (Exception e) {
            // any errors happen as exceptions, and may be successes if we're
            // supposed to fail and we haven't reached the failure point yet
                System.out.println("UNEXPECTED PDP EXCEPTION: " + e.getMessage());
        }
        // convert to String
		//output 
		ByteArrayOutputStream ous = new ByteArrayOutputStream();
		response.encode(ous);
		//System.out.println("\nPDP Response (requestPDP): \n" + ous);
		//
		String respstr = ous.toString();
		ous.close();

        return respstr;
    }
 

    
    //What's needed for XACML Request: 
    //SunXACML RequestCtx(Set subjects, Set resource, Set action, Set environment)
	//public static void generateXACMLRequest() throws Exception {
	public static String generateXACMLRequest(HashMap subjmap, String resctx, String actctx, String envctx) 
	throws Exception {
		// Subject attributes
		subjects = new HashSet();
		
		/// Subject with subjmap and iterator
		HashSet attributes = new HashSet();
		String issuer = ConfigTrustDomains.AAA_ATTRIBUTE_ISSUER;
		DateTimeAttribute issueInstant = new DateTimeAttribute();
		URI attrdtype = new URI("http://www.w3.org/2001/XMLSchema#string");
		//URI attrvaluri = new URI(subjectid);
        for (Iterator i=subjmap.keySet().iterator(); i.hasNext();){
        	String key = i.next().toString();
        	String entry = subjmap.get(key).toString();
        	
        //Subject attributes
		//Attribute(URI id, String issuer, DateTimeAttribute issueInstant, AttributeValue value)
		//String attributeId = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
		//URI attributeId = new URI(XACML_SUBJECT_NS + CNL_SUBJECT_SUBJECT_ID);
		URI attrId = new URI(ConstantsNS.XACML_SUBJECT + DELIM_URN + key);
		
		// Attributes set
		AttributeFactory attrf = AttributeFactory.getInstance();
		AttributeValue attrval = attrf.createValue(attrdtype, entry);
		//AttributeValue attrval = new AttributeValue (attrvaluri);
		Attribute attr = new Attribute (attrId, issuer, issueInstant, attrval);
		attributes.add(attr);
        }
		Subject subj = new Subject (attributes);
		subjects.add(subj);

		
		// Resource Attributes
		AttributeFactory attrf = AttributeFactory.getInstance();
		//AttributeValue attrval = new AttributeValue (attrvaluri);
		//URI attrId = new URI(XACML_RESOURCE_NS + CNL_RESOURCE_RESOURCE_ID);
		Attribute attr = new Attribute (
				new URI(ConstantsNS.XACML_RESOURCE + DELIM_URN + ConstantsNS.RESOURCE_RESOURCE_ID), issuer, issueInstant, 
				attrf.createValue(new URI("http://www.w3.org/2001/XMLSchema#anyURI"), resctx));
	
		//resource = new HashSet();
		resource = new HashSet();
		resource.add(attr);
		
		// Action Attributes
		Attribute attr3 = new Attribute (
				new URI(ConstantsNS.XACML_ACTION + DELIM_URN + ConstantsNS.ACTION_ACTION_ID), issuer, issueInstant, 
				attrf.createValue(attrdtype, actctx));

		action = new HashSet();
		action.add(attr3);

		// Environment Attributes
		Attribute attr4 = new Attribute (
				new URI(ConstantsNS.XACML_ENVIRONMENT + DELIM_URN + ConstantsNS.ENVIRONMENT), issuer, issueInstant, 
				attrf.createValue(attrdtype, envctx));

		environment = new HashSet();
		environment.add(attr4);
		
		RequestCtx reqctx = new RequestCtx (subjects, resource, action, environment);
		ByteArrayOutputStream ous = new ByteArrayOutputStream();
		reqctx.encode(ous);
		System.out.println("\nSun XACML RequestCtx: \n" + ous);
		//
		String docstr = ous.toString();
		ous.close();
		//PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(testfile)));
		//out.print(docstr);
		//out.close();
		return docstr;
		
	}
	
	// 
	public static Date dateformat (String dateTime) throws ParseException {
        SimpleDateFormat formatter = null;
        //String dateTime = "2002-02-02T22:22:22Z";
        //String dateTime = "2002-02-02";
        int dot = dateTime.indexOf('.');
        int col = dateTime.indexOf(':');
        if (col > 0) {
        if (dot > 0) {
            formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        }
        else {
            formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        }} else{
            formatter = new SimpleDateFormat("yyyy-MM-dd");
        }
        //formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        Date dt = formatter.parse(dateTime);
		return dt;
	}
	
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
	public static Collection parseCSVlines(String prefix, String stringlist) throws IOException, RESyntaxException {

		//String[] polset = new String[npolis];
		ArrayList itemset = new ArrayList();
		ArrayList lineset = new ArrayList();
			String line;
			String[][] table = new String[10][10];
			int nitems = 0;
			int nlines = 0;
			// Construct a new Regular Expression parser.
			RE csv = new RE(CSV_PATTERN);

			//BufferedReader is = new BufferedReader(new InputStreamReader(System.in));
			BufferedReader is = new BufferedReader(new StringReader(stringlist));
		
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
							if (j == 0 ) { nitems = i; };
							i++;
							} 

					// Skip what already matched.
					offset += csv.getParen(0).length();
				}
				nlines = j; j++;
			}

		int val = 0;
		String nn = null;
		System.out.println("Policies list contains " + nitems + " policies:"); 
		for (int k = 0; k <= nitems; k++) {
			nn = table [0][k];
			val = Integer.parseInt(nn);
			if (val<10) {nn = "00" + nn;} else {
				if (val<100) {nn = "0" + nn;}
			}
			itemset.add(prefix + nn);
			//System.out.println(polset.get(k)); 
			}

		System.out.println("Tests list contains " + nlines + " tests:"); 
		String mm = null;
		for (int k = 0; k < nlines; k++) { 
			mm = table [k + 1][0];		
			lineset.add(mm);
			System.out.println( lineset.get(k) ); 
			}
		return itemset;
	}
	
	////////////////////////////////	
	// Write String to File
	 
	public static void write(String fileName, String text) throws IOException {
		PrintWriter out =
			new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
		out.print(text);
		out.close();
	}
	
	public static void main(String[] args) throws Exception 
	{
		//org.apache.xml.security.Init.init();
		
		//Receive parameters for the keystore
		//String keyalias = "cnl01";
		//String reqfile = "_aaadata/tmp/requestsunxacml-test00.xml";
		//String polfile = "data/policy/examples/CNL2policyXACML00.xml";

		//List checkconfsec = new ArrayList();
		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);

		// Subject attributes 
		ArrayList subjset = new ArrayList();
        String subjectid = "WHO740@users.collaboratory.nl";
        String confdata = "SeDFGVHYTY83ZXxEdsweOP8Iok";
        String subjctx = "demo001";
        String role = "analyst";
        subjset.add(subjectid);
        subjset.add(confdata);
        subjset.add(subjctx);
        subjset.add(role);
        
        // Preferable subjmap
        HashMap subjmap = new HashMap();
        subjmap.put(ConstantsNS.SUBJECT_SUBJECT_ID, subjectid);
        subjmap.put(ConstantsNS.SUBJECT_CONFDATA, confdata);
        subjmap.put(ConstantsNS.SUBJECT_CONTEXT, subjctx);
        subjmap.put(ConstantsNS.SUBJECT_ROLE, role);

        //other Request components/attributes
        String resctx = "http://resources.collaboratory.nl/Phillips_XPS1";
        String actctx = "ControlExperiment";
        String envctx = "OnSchedule";    
		
		Properties pdpconf = null;
		//System.setProperties(pdpconf);
        ////TODO: IMPORTANT 
		//Changed in ConfigurationStore from
		//String configFile = System.getProperty(PDP_CONFIG_PROPERTY);
    	// to
		//String configFile = "data/config/xacml1.2-config00.xml";
		
		//pdpconf.setProperty("com.sun.xacml.PDPConfigFile", "fpol");//??
		
		try {   	
			System.out.println("\nRun XACML PDP test with SunXACML");
			System.out.println(
					"1 - Create XACML Request message, \n" +
					"2 - XACMLPolicyMaker using external access table in CSV format;\n" +
					"3 - XACMLPolicyMaker create interactively XACML Policy, \n" +
					"4 - Run simple PDP test (fixed policy and request), \n" +
					"5 - Run PDP test against created in (2) policy for entered actions and roles," +
					"");
			String diroftest = "data/policy/xacml-conformance-test/";
			String dirpolcnl = "data/policy/";
			int s = HelpersReadWrite.readStdinInt();			
			switch(s) {
			case 1: {
				String reqfile = "_aaadata/tmp/requestsunxacml-test00.xml";
				String testreq = generateXACMLRequest(subjmap, resctx, actctx, envctx);
				write(reqfile, testreq);
				System.out.println("Wrote XACMLRequest to " + reqfile);
				//RequestCtx request = RequestCtx. getInstance( new ByteArrayInputStream(testreq.getBytes()) );
				return;}
			case 2: {
				String polext = "accesstab-01csv.txt";
				String polfile = "data/policy/examples/CNL2policyXACML00.xml";
				String restype = "http://resources.collaboratory.nl/Phillips_XPS1";
				ArrayList parsobjs = XACMLPolicyMaker.parseAccessTable(polext); 
				String[] rolarray = (String[]) parsobjs.get(0);
				String[] actarray = (String[]) parsobjs.get(1);
				String[][] accesstab = (String[][]) parsobjs.get(2);
				String policyId = "CNL2-XPS1-test"; /*to be entered interactively*/
				System.out.println( "Creating policy for " + restype ); 
				String policy = XACMLPolicyMaker.createSimplePolicy(policyId, restype, rolarray, actarray, accesstab);
				write(polfile, policy);
				System.out.println("Wrote policy file to " + polfile);
				return;}
			case 3: {
				String polfile = "data/policy/examples/CNL2policyXACML01.xml";
				String policy = XACMLPolicyMaker.interactiveGenerateXACMLPolicy();
				write(polfile, policy);
				System.out.println("Wrote XACMLPolicy to " + polfile);
				return;}
			case 4: {
				//reqfile = "requestsunxacml00.xml";
				//polfile = "data/policy/CNL3policyXACML00.xml";
				String polfile = "data/policy/examples/CNL2policyXACML00.xml";
				String reqfile = "_aaadata/tmp/requestsunxacml-test00.xml";
				// testing policyset from compliance test
				polfile = "external/xacml1.1-conformance-test2003/IID005Policy.xml";
				reqfile = "external/xacml1.1-conformance-test2003/IID005Request.xml";

				//
				polfile = "external/xacml1.1-conformance-test2003/IID005Policy.xml";
				reqfile = "external/xacml1.1-conformance-test2003/IID005Request.xml";

				//this is a fix - real above policy and request from above are simply moved 
				// to the test directory
				//reqfile = "external/xacml-conformance-test/IIA033Request.xml";
				//polfile = "external/xacml-conformance-test/IIA033Policy.xml";
				//configurePDP();
		        RequestCtx request = RequestCtx.getInstance(new FileInputStream(reqfile));
	 			String response = requestPDP(request, polfile);
	 			System.out.println("\nPDP Response: \n" + response);
				return;}
			case 5: {
				String polcsv = HelpersReadWrite.readInString();			
				System.out.println("I read this line: " + polcsv); 
				String reqfile = "_aaadata/tmp/requestsunxacml-test00.xml";
		        RequestCtx request = RequestCtx.getInstance(new FileInputStream(reqfile));
				String polfile = "data/policy/examples/CNL2policyXACML00.xml";

				//configurePDP();
	 			//String response = requestPDP(polfile, request);
	 			String response = XACMLPDPsimple.requestPDP(request, polfile);
	 			System.out.println("\nPDP Response: \n" + response);
				return;}
			case 6: {
				//String resid = "urn:oasis:names:tc:xacml:1.0:function:string-equal";
				String resid = "http://testbed.ist-phosphorus.eu/subdomain/resource-type/nsp/a/b/c";			
				//String resURL = "testbed.ist-phosphorus.eu/subdomain/resource-type/nsp/a/b/c";			
				HashMap resmap = ResourceHelper.parseResourceURI(resid);
	 			System.out.println("\nPDP Response: \n" + resmap.get("resource-domain") + "/" + resmap.get("resource-subdomain"));
				
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
