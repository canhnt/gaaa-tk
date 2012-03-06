/**
 * XmlException.java
 *
 */


package org.aaaarch.utils;


public class XmlException extends RuntimeException {
	protected java.lang.Exception	innerException;
	protected String				message;

	public XmlException(String text) {
		innerException = null;
		message = text;
	}

	public XmlException(java.lang.Exception other) {
		innerException = other;
		message = other.getMessage();
	}

	public String getMessage() {
		return message;
	}

	public java.lang.Exception getInnerException() {
		return innerException;
	}
}
