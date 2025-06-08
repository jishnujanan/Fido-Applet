/** 
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.javacard.fido;

import javacard.framework.*;

/**
 * Applet class
 * 
 * @author <user>
 */

public class FidoApplet extends Applet {

    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FidoApplet(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected FidoApplet(byte[] bArray, short bOffset, byte bLength) {
        register(bArray,((short)(bOffset + 1)), bArray[bOffset]);
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
        //Insert your code here
    }
    
    @Override
    public boolean select() {
    	return true;
    }
}
