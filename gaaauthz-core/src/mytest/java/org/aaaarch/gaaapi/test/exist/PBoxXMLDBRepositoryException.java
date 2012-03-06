/* This source has been formatted by an unregistered SourceFormatX */

/* If you want to remove this info, please register this shareware */

/* Please visit http://www.textrush.com to get more information    */

/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */
package org.aaaarch.gaaapi.test.exist;


/**
 *
 * @author ferraro
 */
import java.io.PrintStream;
import java.io.PrintWriter;

public class PBoxXMLDBRepositoryException extends PBoxException {
    protected Throwable cause;
    private int type = -1;
    public static int CONNECTION_FAILURE = 0;
    public static int COLLECTION_NOT_FOUND = 1;
    public PBoxXMLDBRepositoryException() {}

    public PBoxXMLDBRepositoryException(String message) {
        super(message);
    }

    public PBoxXMLDBRepositoryException(String message, int _type) {
        super(message);
        type = _type;
    }
    
    public PBoxXMLDBRepositoryException(Throwable cause) {
        super();
        this.cause = cause;
    }
    
    public PBoxXMLDBRepositoryException(Throwable cause, int _type) {
        this(cause);
        type = _type;
    }

    public int getType() {
        return type;
    }

    public void printStackTrace() {
        printStackTrace(System.err);
    }

    public void printStackTrace(PrintStream s) {
        super.printStackTrace(s);
        if (this.cause != null) {
            s.print("Caused by: ");
            this.cause.printStackTrace(s);
        }
    }

    public void printStackTrace(PrintWriter s) {
        super.printStackTrace(s);
        if (this.cause != null) {
            s.print("Caused by: ");
            this.cause.printStackTrace(s);
        }
    }

    public Throwable getCause() {
        return cause;
    }
}
