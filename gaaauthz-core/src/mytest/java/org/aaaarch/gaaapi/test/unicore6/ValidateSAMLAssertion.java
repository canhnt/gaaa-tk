import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.xmlbeans.XmlException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import eu.unicore.saml.SAMLParseException;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;

public class ValidateSAMLAssertion extends TestCase
{

  private static final Logger log = LoggerFactory.getLogger(ValidateSAMLAssertion.class);

  public void testValidation() throws XmlException, IOException, SAMLParseException, KeyStoreException, NoSuchAlgorithmException, CertificateException
  {
    String issuerAlias = "mykey";
    String issuerJKSPath = "/tmp/store1.jks";
    char[] issuerJKSPass = "asdfasdf".toCharArray();

    String subjectAlias = "mykey";
    String subjectJKSPath = "/tmp/store2.jks";
    char[] subjectJKSPass = "asdfasdf".toCharArray();

    KeyStore issuerJKS = KeyStore.getInstance(KeyStore.getDefaultType());
    issuerJKS.load(new FileInputStream(new File(issuerJKSPath)), issuerJKSPass);

    String issuerDN = "null";
    X509Certificate issuerX509 = null;

    Certificate issuerCert = issuerJKS.getCertificate(issuerAlias);
    if (issuerCert instanceof X509Certificate)
    {
      issuerX509 = (X509Certificate) issuerCert;
      issuerDN = issuerX509.getSubjectDN().getName();
      log.info("Issuer DN: " + issuerDN);
    }

    KeyStore subjectJKS = KeyStore.getInstance(KeyStore.getDefaultType());
    subjectJKS.load(new FileInputStream(new File(subjectJKSPath)), subjectJKSPass);
    Certificate subjectCert = subjectJKS.getCertificate(subjectAlias);
    //    log.info("Server cert: " + subjectCert);
    String subjectDN = "null";
    if (subjectCert instanceof X509Certificate)
    {
      X509Certificate subjectX509 = (X509Certificate) subjectCert;
      subjectDN = subjectX509.getSubjectDN().getName();
      log.info("Subject DN: " + subjectDN);
    }

    InputStream is = new FileInputStream(new File("/tmp/assertion.saml"));

    AssertionDocument ad = AssertionDocument.Factory.parse(is);
    TrustDelegation td = new TrustDelegation(ad);
    List<TrustDelegation> tds = new ArrayList<TrustDelegation>();
    tds.add(td);

    ETDApi engine = UnicoreSecurityFactory.getETDEngine();
    X509Certificate[] subjectCerts = new X509Certificate[1];
    subjectCerts[0] = (X509Certificate) subjectCert;

    X509Certificate[] issuerCerts = new X509Certificate[1];
    issuerCerts[0] = (X509Certificate) issuerCert;

//    ValidationResult vr = engine.isTrustDelegated(tds, subjectCerts, issuerCerts);
    ValidationResult vr = engine.isTrustDelegated(tds, subjectDN, issuerDN);
//    ValidationResult vr = engine.validateTD(td, (X509Certificate) issuerCert, issuerCerts, subjectCerts);
//    ValidationResult vr = engine.validateTD(td, issuerDN, issuerDN, subjectDN);

    if (vr.isValid())
    {
      log.info("Delegation is valid");
    }
    else
    {
      log.error("Delegation is invalid: " + vr.getInvalidResaon());
    }
  }
}
