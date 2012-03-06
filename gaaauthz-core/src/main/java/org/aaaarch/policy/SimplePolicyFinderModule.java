package org.aaaarch.policy;

import java.io.FileInputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.MatchResult;
import com.sun.xacml.Policy;
import com.sun.xacml.PolicyReference;
import com.sun.xacml.PolicySet;
import com.sun.xacml.ctx.Status;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.PolicyFinderResult;

/* This module returns XACML policies set to XACML PDP
 * Policies are stored as separate XML files in a designed directory
 * (e.g. data/policy/{profile})
 * TODO: general clean and polciy sets management
 */

public class SimplePolicyFinderModule  extends PolicyFinderModule
{

    // the finder that owns this module
    private PolicyFinder finder = null;

    // the policies used by PDP to evaluate a Request
    // (defined by request attributes or loaded from the default storage)
    private Set<AbstractPolicy> policies = null;

    // a map of URIs to policies for the reference-based policies we're
    // currently providing, and the current namespace prefix
    private Map policyRefs = null;
    private String policyRefPrefix;

    // a map of URIs to policies for the reference-based policy sets we're
    // currently providing, and the current namespace prefix
    private Map policySetRefs = null;
    private String policySetRefPrefix;
    
    /**
     * Default constructor.
     */
    public SimplePolicyFinderModule() {
        policies = new HashSet();
    }

    /**
     * Initializes this module with the given finder.
     *
     * @param finder the <code>PolicyFinder</code> that owns this module
     */
    public void init(PolicyFinder finder) {
        this.finder = finder;
    }

    /**
     * Always returns true, since request-based retrieval is supported.
     *
     * @return true
     */
    public boolean isRequestSupported() {
        return true;
    }

    /**
     * Always returns true, since reference-based retrieval is supported.
     *
     * @return true
     */
    public boolean isIdReferenceSupported() {
        return true;
    }

    /**
     * Load (single) policy file to policies set used by PDP 
     *
     * @param policyFile a file containing a policy or policy set
     *
     * @throws Exception if the policy cannot be loaded
     */
    public void setPolicies(String policyFile) throws Exception {
        policies.clear();

        AbstractPolicy policy = loadPolicy(policyFile, finder);
        if (policy == null)
            throw new Exception("failed to load policy");

        policies.add(policy);
    }

    /**
     * Load set of policy files to policies set used by PDP 
     *
     * @param policyFiles <code>String</code>s specifying files that contain
     *                    policies or policy sets
     *
     * @throws Exception if the any of the policies cannot be loaded
     */
    public void setPolicies(Set policyFiles) throws Exception {
        Iterator it = policyFiles.iterator();
        
        policies.clear();

        while (it.hasNext()) {
            AbstractPolicy policy = loadPolicy((String)(it.next()), finder);
            if (policy == null)
                throw new Exception("failed to load policy");

            policies.add(policy);
        }
    }

    /**
     * Sets the policy reference mapping used for policies.
     *
     * @param policyRefs the reference mapping
     * @param prefix the prefix for these references
     */
    public void setPolicyRefs(Map policyRefs, String prefix) {
        this.policyRefs = policyRefs;
        policyRefPrefix = prefix;
    }

    /**
     * Sets the policy reference mapping used for policy sets.
     *
     * @param policySetRefs the reference mapping
     * @param prefix the prefix for these references
     */
    public void setPolicySetRefs(Map policySetRefs, String prefix) {
        this.policySetRefs = policySetRefs;
        policySetRefPrefix = prefix;
    }

    /**
     * Finds the applicable policy (if there is one) for the given context.
     *
     * @param context the evaluation context
     *
     * @return an applicable policy, if one exists, or an error
     */
    public PolicyFinderResult findPolicy(EvaluationCtx context) {
        AbstractPolicy selectedPolicy = null;
        Iterator it = policies.iterator();

        // iterate through all the policies we currently have loaded
        while (it.hasNext()) {
            AbstractPolicy policy = (AbstractPolicy)(it.next());
            MatchResult match = policy.match(context);
            int result = match.getResult();

            // if target matching was indeterminate, then return the error
            if (result == MatchResult.INDETERMINATE)
                return new PolicyFinderResult(match.getStatus());

            // see if the target matched
            if (result == MatchResult.MATCH) {
                // see if we previously found another match
                if (selectedPolicy != null) {
                    // we found a match before, so this is an error
                    ArrayList<String> code = new ArrayList<String>();
                    code.add(Status.STATUS_PROCESSING_ERROR);
                    Status status = new Status(code, "too many applicable "
                                               + "top-level policies");
                    return new PolicyFinderResult(status);
                }

                // this is the first match we've found, so remember it
                selectedPolicy = policy;
            }
        }

        // return the single applicable policy (if there was one)
        return new PolicyFinderResult(selectedPolicy);
    }

    /**
     * Private helper that tries to load the given file-based policy, and
     * returns null if any error occurs.
     */
    private AbstractPolicy loadPolicy(String filename, PolicyFinder finder) {
        try {
            // create the factory
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setIgnoringComments(true);
            factory.setNamespaceAware(true);
            factory.setValidating(false);
            
            // create a builder based on the factory & try to load the policy
            DocumentBuilder db = factory.newDocumentBuilder();
            Document doc = db.parse(new FileInputStream(filename));
            
            // handle the policy, if it's a known type
            Element root = doc.getDocumentElement();
            String name = root.getLocalName();
            
            if (name.equals("Policy")) {
                return Policy.getInstance(root);
            } else if (name.equals("PolicySet")) {
                return PolicySet.getInstance(root, finder);
            }
        } catch (Exception e) {}

        // a default fall-through in the case of an error
        return null;
    }

}
