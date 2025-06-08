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

class FidoApplet extends Applet {

	// CLA (Class Byte) Definitions
	private static final byte CLA_PROPRIETARY = (byte) 0x80; // CLA for proprietary commands (logical channel 0, proprietary class)
	private static final byte CLA_STANDARD    = (byte) 0x00; // CLA for standard ISO/IEC 7816 commands (e.g., SELECT)

	// INS (Instruction Byte) Definitions
	private static final byte INS_SELECT      = (byte) 0xA4; // Standard INS for selecting files or applets (ISO/IEC 7816-4)
	private static final byte INS_STORE_PIN   = (byte) 0x20; // INS for storing a PIN during personalisation phase
	private static final byte INS_VERIFY      = (byte) 0x21; // INS for verifying a user PIN (User State)
	private static final byte INS_REGISTER    = (byte) 0x22; // INS for registering a new user or entity
	private static final byte INS_LOGIN       = (byte) 0x23; // INS for logging in an existing user
	private static final byte INS_CHANGE_PIN  = (byte) 0x24; // INS for changing an existing user's PIN
	private static final byte INS_DISABLE     = (byte) 0x25; // INS for disabling a user or feature

	// Card State Definitions
	private static final byte STATE_INACTIVE    = (byte) 0x22; // Card state: inactive or uninitialized
	private static final byte STATE_ACTIVE      = (byte) 0x33; // Card state: active and operational
	private static final byte STATE_UNWORKABLE  = (byte) 0x44; // Card state: error or blocked, no operations allowed

	// Current card state variable (initialized to STATE_INACTIVE by default)
	private byte CARD_STATE 					= STATE_INACTIVE;


	/**
	 * Installs this applet.
	 * 
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new FidoApplet(bArray, bOffset, bLength);
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected FidoApplet(byte[] bArray, short bOffset, byte bLength) {
		register(bArray, ((short) (bOffset + 1)), bArray[bOffset]);
	}

	/**
	 * Processes an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu the incoming APDU
	 */
	@Override
	public void process(APDU apdu) {
		
		byte[] apduBuffer = apdu.getBuffer();
		byte ins = apduBuffer[ISO7816.OFFSET_INS];
		// Insert your code here
		if (CARD_STATE == STATE_INACTIVE) {
			if(ins == INS_SELECT){
				selectProcessing(apdu);
			} else if(ins == INS_STORE_PIN){
				storePinProcessing(apdu);
			} else{
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} else if (CARD_STATE == STATE_ACTIVE) {
			if (ins == INS_VERIFY) {
		        verifyProcessing(apdu);
		    } else if (ins == INS_REGISTER) {
		        registerProcessing(apdu);
		    } else if (ins == INS_LOGIN) {
		        loginProcessing(apdu);
		    } else if (ins == INS_CHANGE_PIN) {
		        changePinProcessing(apdu);
		    } else if (ins == INS_DISABLE) {
		        disableProcessing(apdu);
		    } else {
		        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		    }
		} else if (CARD_STATE == STATE_UNWORKABLE) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		} else {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}

	}

	private void disableProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	private void changePinProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	private void loginProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	private void registerProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	private void verifyProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	private void storePinProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	private void selectProcessing(APDU apdu) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean select() {
		return true;
	}
	
}
