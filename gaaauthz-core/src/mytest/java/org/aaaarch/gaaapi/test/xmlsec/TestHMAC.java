////========================================================
//
// Java Example Code from http://JavaFAQ.nu 
// please come back later when you need more code examples 
// 
// If you have not found an example which you need, please drop us a couple of words 
// and we will try to do the best for you 
// The link to leave your order is below :-)  
// http://javafaq.nu/index.php?name=Contact 
// 
// Wednesday, August 08, 2007 (00:36:28) CET 
//
// ========================================================

// hmac -  simple use of the Java Cryptography Extension (JCE). <br />// If you are going to compile it please Copy All (<b>ctrl+A</b>, then <b>ctrl+C</b>) and paste (<b>ctrl+V</b>) to your Java editor[code]

package org.aaaarch.gaaapi.test.xmlsec;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.awt.Toolkit;
import java.awt.datatransfer.*;

/**
 * hmac - a little utility to compute HMACs on data;
 * the data and key may be obtained from files, from
 * the command line, or from the clipboard.  Note that
 * this little program is really only suitable for
 * files of very modest length, because it attempts
 * to load the entire file into a byte array.
 * <p>
 * This utility accepts command-line options, and 
 * prints HMAC values in hex.
 * <p>
 * For more information 
 */

public class TestHMAC {
  private File keyFile;
  private String keyString;
  private byte [] keyBytes;

  private File dataFile;
  private String dataString;
  private byte [] dataBytes;
  
  protected Clipboard clip;
  protected boolean verbose = false;
  protected boolean noHex = false;

  protected boolean reverse = false;

  protected String alg = DEFAULT_ALG;

  public static final int MIN_LENGTH = 8;
  public static final int BUF_LENGTH = 256;
  public static final String DEFAULT_ALG = "HMacMD5";

  /**
   * Send a message to the user, with an exception.
   */
  public static final void message(String s, Exception e) {
    System.err.println("hmac: " + s);
    if (e != null) {
      System.err.println("\texception was: " + e);
      e.printStackTrace(System.err);
    }
  }

  /**
   * Send a message to the user, no exception.
   */
  public static final void message(String s) {
    message(s,null);
  }

  /**
   * Return true if the input argument character is
   * a digit, a space, or A-F.
   */
  public static final boolean isHexStringChar(char c) {
    return (Character.isDigit(c) ||
            Character.isWhitespace(c) || 
	    (("0123456789abcdefABCDEF".indexOf(c)) >= 0));
  }

  /**
   * Return true if the argument string seems to be a
   * Hex data string, like "a0 13 2f ".  Whitespace is
   * ignored.
   */
  public static final boolean isHex(String sampleData) {
    for(int i = 0; i < sampleData.length(); i++) {
      if (!isHexStringChar(sampleData.charAt(i))) return false;
    }
    return true;
  }

  /**
   * Return true if the argument byte array seems to be a
   * Hex data string, like "a0 13 2f ".  Only check as far
   * as a supplied length; if it seems to be hex for that
   * many (ascii) bytes, then return true.
   */
  public static final boolean isHex(byte [] sampleData, int len) {
    for(int i = 0; i < len; i++) {
      if (!isHexStringChar((char)(sampleData[i]))) return false;
    }
    return true;
  }

  static final String hexDigitChars = "0123456789abcdef";

  /**
   * Convert a hex string into an array of bytes.
   * The hex string can be all digits, or 1-octet
   * groups separated by blanks, or any mix thereof.
   * 
   * @param str String to be converted
   */
  public static final byte [] hexToByteArray(String str, boolean rev) {
    StringBuffer acc = new StringBuffer(str.length() + 1);
    int cx, rp, ff, val; 
    char [] s = new char[str.length()];
    str.toLowerCase().getChars(0, str.length(), s, 0);
    for(cx = str.length() - 1, ff = 0; cx >= 0; cx--) {
      if (hexDigitChars.indexOf(s[cx]) >= 0) {
	acc.append(s[cx]);
	ff++;
      }
      else {
	if ((ff % 2) > 0) acc.append('0');
	ff = 0;
      }
    }
    if ((ff % 2) > 0) acc.append('0');
    //System.out.println("Intermediate SB value is '" + acc.toString() + "'");

    byte [] ret = new byte[acc.length() / 2];
    for(cx = 0, rp = ret.length - 1; cx < acc.length(); cx++, rp--) {
      val = hexDigitChars.indexOf(acc.charAt(cx));
      cx++;
      val += 16 * hexDigitChars.indexOf(acc.charAt(cx));
      ret[rp] = (byte)val;
    }
    if (rev) {
      byte tmp;
      int fx, bx;
      for(fx = 0, bx = ret.length - 1; fx < (ret.length / 2); fx++, bx--) {
	tmp = ret[bx];
	ret[bx] = ret[fx];
	ret[fx] = tmp;
      }
    }
    return ret;
  }

  /**
   * Convert a byte array to a hex string of the format
   * "1f 30 b7".
   */
  public static final String byteArrayToHex(byte [] a) {
    int hn, ln, cx;
    StringBuffer buf = new StringBuffer(a.length * 2);
    for(cx = 0; cx < a.length; cx++) {
      hn = ((int)(a[cx]) & 0x00ff) / 16;
      ln = ((int)(a[cx]) & 0x000f);
      buf.append(hexDigitChars.charAt(hn));
      buf.append(hexDigitChars.charAt(ln));
      buf.append(' ');
    }
    return buf.toString();
  }
 

  /**
   * Accept a file name, and read that file as a string or
   * as raw data (read first N bytes to check it out).
   * If the file can't be read, then return null.  If
   * we can't read at least minValidLength bytes, then
   * we declare that the file is invalid and return null.
   * All the real work is done in readDataStream.
   *
   * @see readDataStream
   */
  public byte [] readDataFile(File f, int minValidLength) {
    InputStream fr = null;
    byte [] buf = null;
    int cc;
    try {
      if (f.getName().equals("-")) {
	fr = System.in;
      }
      else {
	fr = new FileInputStream(f);
      }
    }
    catch (IOException ie) {
      message("Could not read file " + f, ie);
      return null;
    }
    if (verbose) message("Reading file data from " + f);
    return readDataStream(fr, minValidLength);
  }

  public byte[] readDataStream(InputStream is, int minValidLength) {
    int cc;
    byte [] buf = new byte[BUF_LENGTH];
    is = new BufferedInputStream(is);
    try {
      cc = is.read(buf, 0, minValidLength);
      if (cc < minValidLength) return null;
    }
    catch (IOException ie) {
      message("Could not read initial data", ie);
      try { is.close(); } catch (Exception e) { }
      return null;
    }
    
    boolean ishex = (noHex)?(false):(isHex(buf, cc));

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(buf, 0, cc);
    while (cc > 0) {
      try {
	cc = is.read(buf);
	if (cc > 0) baos.write(buf, 0, cc);
      }
      catch (IOException ie) {
	message("Error read stream data", ie);
	try { is.close(); } catch (Exception e) { }
	return null;
      }
    }

    try { is.close(); } catch (IOException ie2) { }
    
    byte [] result;
    result = baos.toByteArray();
    if (verbose) message("Read " + result.length + " bytes");
    if (ishex) {
      result = hexToByteArray(new String(result), reverse);
    }

    return result;
  }

  
  /**
   * Read hex data from the clipboard and process it into
   * a byte array.
   */
  public byte [] readDataClipboard() {
    byte [] result = null;

    try {
      if (clip == null) {
	clip = Toolkit.getDefaultToolkit().getSystemClipboard();
      }
      Transferable contents;
      contents = clip.getContents(null);
      if (contents != null) {
	StringReader sr;
	sr = (StringReader)(contents.getTransferData(DataFlavor.plainTextFlavor));
	StringBuffer sb = new StringBuffer();
	char [] buf = new char[BUF_LENGTH];
	int cc;
	do {
	  cc = sr.read(buf, 0, BUF_LENGTH);
	  if (cc > 0) sb.append(buf, 0, cc);
	} while(cc > 0);
	String s = sb.toString();
	if (verbose) message("Got clipboard data: " + s);

	result = s.getBytes();      
	boolean ishex = (noHex)?(false):(isHex(result, 16));
	if (ishex) {
	  result = hexToByteArray(s, reverse);
	}
      }
    }
    catch (Exception te) {
      message("Transfer clipboard problem", te);
    }
    return result;
  }


  String [] usageLines = {
    "java hmac [options]",
    "",
    "where options are the following:",
    "\t-k keydata        key data as a hex string",
    "\t-kc               get key data as hex string from the clipboard",
    "\t-kf file          get key data from specified file",
    "\t-d data           data to hash as a hex string",
    "\t-dc               get data to hash as hex string from the clipboard",
    "\t-df file          get data to hash from specified file",
    "\t-a alg		 use specified HMAC algorithm, {HMacMD5, HMacSHA1}",
    "\t                    (default is HMacMD5)",                  
    "\t-r		 interpret hex strings in reverse",
    "\t                    (as strings rather than numbers)",
    "\t-B                treat ALL files as binary data",
    "\t-v                print verbose messages",
    "",
    "If a file name is given as '-' then read standard input.  If no -d",
    "options are given, then we read standard input.",
    "",
    "Options are interpreted in the order given, including -r and -B;",
    "use them with care.",
    "",
    "For files and standard input, the program will inspect",
    "the data and decide whether it seems to",
    "be binary data or hex data, unless -B is given.",
    "",
    "Here are some example command lines:",
    "     java hmac -kc -df capture1",
    "     java hmac -k 1f031b78a0993d42 -df - -a HMacSHA1 <myfile.dat",
    "",
    "For more information, contact Neal Ziring.",
  };
    
  protected void usage() {
    for(int i = 0; i < usageLines.length; i++) {
      System.out.println(usageLines[i]);
    }
  }

  /**
   * Process the command line options for this hmac
   * object.  The command-line syntax is do*****ented in
   * the usage array; run the program with no command-line
   * arguments, and it will print the usage message.
   */
  protected void processCommandLine(String [] args) {
    int i;
    String data = null;

    if (args.length == 0) { 
      usage();
      System.exit(0);
    }

    try {
      for(i = 0; i < args.length; i++) {
	if (args[i].equalsIgnoreCase("-k")) {
	  data = args[++i];
	  if (isHex(data.getBytes(),4)) {
	    if (verbose) message("Treating key bytes as hex.");
	    keyBytes = hexToByteArray(data, reverse);
	  }
	  else {
	    if (verbose) message("Treating key bytes as ASCII.");
	    keyBytes = data.getBytes();
	  }
	}
	else if (args[i].equalsIgnoreCase("-kc")) {
	  keyBytes = readDataClipboard();
	  if (keyBytes == null) {
	    message("Clipboard is empty.  No key data.");
	    System.exit(0);
	  }
	}
	else if (args[i].equalsIgnoreCase("-kf")) {
	  keyFile = new File(args[++i]);
	  keyBytes = readDataFile(keyFile, MIN_LENGTH);
	  if (keyBytes == null) {
	    message("No key bytes available.");
	    System.exit(0);
	  }
	}
	else if (args[i].equalsIgnoreCase("-d")) {
	  data = args[++i];
	  if (isHex(data.getBytes(),4)) {
	    if (verbose) message("Treating data bytes as hex.");
	    dataBytes = hexToByteArray(data, reverse);
	  }
	  else {
	    if (verbose) message("Treating data bytes as ASCII.");
	    dataBytes = data.getBytes();
	  }
	}
	else if (args[i].equalsIgnoreCase("-dc")) {
	  dataBytes = readDataClipboard();
	  if (dataBytes == null) {
	    message("Clipboard is empty.  No data available to hash.");
	    System.exit(0);
	  }
	}
	else if (args[i].equalsIgnoreCase("-df")) {
	  dataFile = new File(args[++i]);
	  dataBytes = readDataFile(dataFile, MIN_LENGTH);
	  if (dataBytes == null) {
	    message("No data bytes available from file");
	    System.exit(0);
	  }
	}
	else if (args[i].equalsIgnoreCase("-a")) {
	  alg = args[++i];
	  if (verbose) message("Set algorithm to " + alg);
	}
	else if (args[i].equalsIgnoreCase("-B")) {
	  noHex = true;
	}
	else if (args[i].equalsIgnoreCase("-v")) {
	  verbose = true;
	}
	else if (args[i].equalsIgnoreCase("-r")) {
	  reverse = true;
	  if (verbose) message("Hex strings will be interpreted in reverse");
	}
	else {
	  message("Bad option: " + args[i]);
	  usage();
	  System.exit(0);
	}
      }
    }
    catch (Exception e) {
      message("Problem processing options", e);
      usage();
      System.exit(0);
    }
  }

  /**
   * compute the MAC from the member arrays
   * keyBytes and the dataBytes.  Return the MAC.
   */
  public byte[] computeMac() {
    Mac hm = null;
    byte [] result = null;

    if (verbose) {
      message("Key data: " + byteArrayToHex(keyBytes));
      message("Hash data: " + byteArrayToHex(dataBytes));
      message("Algorithm: " + alg);
    }

    try {
      hm = Mac.getInstance(alg);

      Key k1 = new SecretKeySpec(keyBytes, 0, keyBytes.length, alg);
      hm.init(k1);
      result = hm.doFinal(dataBytes);
    }
    catch (Exception e) {
      message("Bad algorithm or crypto library problem", e);
    }
    return result;
  }

  public static void main(String args[]) {
    TestHMAC h1 = new TestHMAC();

    try {
      Provider sp = new com.sun.crypto.provider.SunJCE();
      Security.addProvider(sp);
    }
    catch (Exception e) {
      message("Problem loading crypto provider", e);
      System.exit(0);
    }

    h1.processCommandLine(args);
    byte [] hmac = h1.computeMac();
    
    message("Result: " + byteArrayToHex(hmac));
    System.exit(0);
  }
}
