/* This source has been formatted by an unregistered SourceFormatX */

/* If you want to remove this info, please register this shareware */

/* Please visit http://www.textrush.com to get more information    */

/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */
package org.aaaarch.gaaapi.test.exist;


import java.io.PrintStream;
import java.io.PrintWriter;


/**
 * A PRException is the base class for all Policy Repository related
 * Exceptions.
 */
public class PBoxException extends Exception {
    protected Throwable cause;
    private int type = -1;
    public static int XMLREP_XPATH_EMPTY = 0;
    public static int XMLREP_NOT_AVAILABLE_RESOURCE = 1;
    public PBoxException() {}

    public PBoxException(String message) {
        super(message);
    }

    public PBoxException(String message, int _type) {
        super(message);
        type = _type;
    }

    public PBoxException(Throwable cause) {
        super();
        this.cause = cause;
    }

    public PBoxException(String message, Throwable cause) {
        super(message);
        this.cause = cause;
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
