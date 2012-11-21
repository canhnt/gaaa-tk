package org.aaaarch.util;

public class HelpersHexConverter {

	  static final String hexDigitChars = "0123456789abcdef";
	
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
	   * Return true if the input argument character is
	   * a digit, a space, or A-F.
	   */
	  public static final boolean isHexStringChar(char c) {
	    return (Character.isDigit(c) ||
	            Character.isWhitespace(c) || 
		    (("0123456789abcdefABCDEF".indexOf(c)) >= 0));
	  }

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
	  public static final String byteArrayToHexSpace(byte [] a) {
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
	   * Convert a byte array to a hex string of the format
	   * "1f30b7".
	   */
	  public static final String byteArrayToHex(byte [] a) {
	    int hn, ln, cx;
	    StringBuffer buf = new StringBuffer(a.length * 2);
	    for(cx = 0; cx < a.length; cx++) {
	      hn = ((int)(a[cx]) & 0x00ff) / 16;
	      ln = ((int)(a[cx]) & 0x000f);
	      buf.append(hexDigitChars.charAt(hn));
	      buf.append(hexDigitChars.charAt(ln));
	    }
	    return buf.toString();
	  }
}
