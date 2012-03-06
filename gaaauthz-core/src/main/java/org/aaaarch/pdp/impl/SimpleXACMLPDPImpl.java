package org.aaaarch.pdp.impl;

import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import org.aaaarch.pdp.PDPConstants;
import org.aaaarch.pdp.XACMLPDP;
import org.aaaarch.policy.AbstractPolicyFinderModule;
import org.aaaarch.policy.PolicyException;
import org.aaaarch.policy.impl.FilePolicyFinderModule;
import org.aaaarch.utils.SunXACMLHelper;
import org.aaaarch.utils.XMLHelper;

import com.sun.xacml.ConfigurationStore;
import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.finder.PolicyFinder;

public class SimpleXACMLPDPImpl implements XACMLPDP {
	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SimpleXACMLPDPImpl.class);
	
	public static final String PDP_CONFIG_FILE = "PDP_CONFIG_FILE";
	
	protected static final String DEFAULT_CONFIGURATION_PROPERTIES = "XACMLPDP.properties";
//	protected static final String DEFAULT_CONFIGURATION_PROPERTIES = "D:/workspace/gaaauthz-bundles/gaaauthz-core/src/main/java/org/aaaarch/pdp/impl/XACMLPDP.properties";
   
	// hard-codes constants
	public static final String POLICY_FINDER_MODULE_CLASS_VALUE = "org.aaaarch.policy.impl.FilePolicyFinderModule";
	public static final String PDP_CONFIG_FILE_VALUE = "src/main/resources/config/XACMLPDPConfig.xml";
	
	
    private RequestType	_currentRequest;
	
    private PDP _pdp;
    
    private AbstractPolicyFinderModule _policyFinderModule;
    
	protected Properties _configProps;
	
	protected static Properties _defaultConfigProps;
	
	static {
		try {			
//			InputStream is = SimpleXACMLPDPImpl.class.getResourceAsStream(DEFAULT_CONFIGURATION_PROPERTIES);
//			InputStream is = new FileInputStream(new File(DEFAULT_CONFIGURATION_PROPERTIES));			
			
//			if (is == null)
//				throw new IOException("Cannot read default configuration file");
			
//			_defaultConfigProps = new Properties();
//			_defaultConfigProps.load(is);
			
			// use the hard-codes for default configuration
			_defaultConfigProps = new Properties();
			_defaultConfigProps.put(PDPConstants.POLICY_FINDER_MODULE_CLASS, POLICY_FINDER_MODULE_CLASS_VALUE);
			_defaultConfigProps.put(FilePolicyFinderModule.POLICY_FINDER_MODULE_POLICY_PATH, POLICY_FINDER_MODULE_CLASS_VALUE);
			_defaultConfigProps.put(PDP_CONFIG_FILE, PDP_CONFIG_FILE_VALUE);
			
//		}catch(IOException e) {
//			System.err.println("Could not load default XACMLPDP.properties configuration file.");
//			e.printStackTrace();
//			_defaultConfigProps = null;
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public SimpleXACMLPDPImpl() {
		this(_defaultConfigProps);
	}
	
    public SimpleXACMLPDPImpl(Properties configProps) {
    	try {
    		_configProps = configProps;
    		
            loadPolicyFinderModule();

			configurePDP();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

	private void configurePDP() throws Exception {
        
		// Set System property com.sun.xacml.PDPConfigFile
		log.info("Loading PDP configuration at " + _configProps.getProperty(PDP_CONFIG_FILE));
		
		java.util.Properties p = System.getProperties();
		p.setProperty(ConfigurationStore.PDP_CONFIG_PROPERTY, _configProps.getProperty(PDP_CONFIG_FILE));
		System.setProperties(p);
		
		// load the configuration
        ConfigurationStore cs = new ConfigurationStore();
        
        // use the default factories from the configuration
        cs.useDefaultFactories();

        // get the PDP configuration's policy finder modules...
        PDPConfig config = cs.getDefaultPDPConfig();
        PolicyFinder finder = config.getPolicyFinder();
        Set policyModules = finder.getModules();
        
        // add the module used in this PDP request
        policyModules.add(_policyFinderModule);
        finder.setModules(policyModules);

        // finally, setup the PDP
        _pdp = new PDP(config);
    }

	public static Properties getDefaultConfiguration() {
		return _defaultConfigProps;
	}
	/**
	 * Loading the PolicyFinderModule class setting from the configuration file
	 * 
	 * @throws PolicyException
	 */
    private void loadPolicyFinderModule() throws PolicyException{
	
    	Properties propsPolicyFinderModule = getPolicyFinderModuleProps(_configProps);
		_policyFinderModule = new FilePolicyFinderModule(propsPolicyFinderModule);
//		System.out.println("Using FilePolicyFinder module");
    	
//    	try {
        	// load the class name
//        	String policyFinderModuleClassName = _configProps.getProperty(PDPConstants.POLICY_FINDER_MODULE_CLASS);
//        	
//        	ClassLoader classLoader = ClassLoader.getSystemClassLoader();
//        	
//        	@SuppressWarnings("unchecked")
//			Class<AbstractPolicyFinderModule> policyFinderClass = (Class<AbstractPolicyFinderModule>) classLoader.loadClass(policyFinderModuleClassName);
        	
//        	try {
//				Constructor<AbstractPolicyFinderModule> policyFinderClassConstructor = policyFinderClass.getConstructor(Properties.class);
//				
//				Properties propsPolicyFinderModule = getPolicyFinderModuleProps(_configProps);
//				
//				_policyFinderModule = policyFinderClassConstructor.newInstance(propsPolicyFinderModule);
//			} catch (SecurityException e) {
//				e.printStackTrace();
//				throw new PolicyException("Error loading POLICY_FINDER_MODULE=" + policyFinderModuleClassName, e);
//			} catch (NoSuchMethodException e) {				
//				e.printStackTrace();
//				throw new PolicyException("Error loading POLICY_FINDER_MODULE=" + policyFinderModuleClassName, e);
//			} 
//			catch (IllegalArgumentException e) {				
//				e.printStackTrace();
//				throw new PolicyException("Error loading POLICY_FINDER_MODULE=" + policyFinderModuleClassName, e);
//			} catch (InvocationTargetException e) {
//				e.printStackTrace();
//				throw new PolicyException("Error loading POLICY_FINDER_MODULE=" + policyFinderModuleClassName, e);
//			}
			
//		} catch (InstantiationException e) {			
//			e.printStackTrace();
//			throw new PolicyException(e);
//		} catch (IllegalAccessException e) {			
//			e.printStackTrace();
//			throw new PolicyException(e);
//		} catch (ClassNotFoundException e) {			
//			e.printStackTrace();
//			throw new PolicyException(e);
//		}    	
	}

	
//	public ResponseCtx evaluate(RequestCtx request) {
//       throw new UnsupportedOperationException("This evaluation method is not supported");
//	}

	public ResponseCtx evaluate(RequestType request) {
		_currentRequest = request;
		
		log.info("SimpleXACMLPDPImpl: On receive authz-request from PDP Proxy to PDP:\n" + 
				XMLHelper.marshalDOMElement(SunXACMLHelper.marshall(request)));
		
		try {			
			// load referenced policies based on request 
			_policyFinderModule.loadPolicies(request);
			
			return _pdp.evaluate(request);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Return the properties for the policy finder module with their key prefixes is POLICY_FINDER_MODULE_PREFIX
	 * 
	 * @param pdpProps
	 * @return
	 */
	protected Properties getPolicyFinderModuleProps(Properties pdpProps) {
		Properties propsPFM = new Properties();
		
		Set keys = pdpProps.keySet();
		for (Iterator it = keys.iterator(); it.hasNext();) {
			String key = (String)it.next();
			if (key.startsWith(PDPConstants.POLICY_FINDER_MODULE_PREFIX)) {
				propsPFM.put(key, pdpProps.get(key));
			}
		}
		return propsPFM;
		
	}

}
