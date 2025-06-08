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
	private byte CARD_STATE				 		= STATE_INACTIVE;

	private OwnerPIN ownerPIN 					= null;
	private static final byte PIN_TRY_LIMIT		= (byte) 0x0F;
	private static final byte MAX_PIN_SIZE		= (byte) 0x0F;
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
		
		ownerPIN = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		
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
		try {
			byte[] apduBuffer = apdu.getBuffer();
			
			//We should call setIncomingAndReceive as data is present in all the commands.
			short bytesLeft = (short)(apduBuffer[ISO7816.OFFSET_LC]&(short)0x00FF);
			short bytesReceived = apdu.setIncomingAndReceive();
			if(bytesLeft > (short)0 )
			{
				bytesLeft -= bytesReceived;
				bytesReceived = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA+bytesReceived));
			}
			
			byte ins = apduBuffer[ISO7816.OFFSET_INS];
			// Insert your code here
			if (CARD_STATE == STATE_INACTIVE) {
				if(ins == INS_SELECT){
					select();
				} else if(ins == INS_STORE_PIN){
					storePinProcessing(apdu);
				} else{
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				}
			} else if (CARD_STATE == STATE_ACTIVE) {
				if(ins == INS_SELECT){
					select();
				} else if (ins == INS_VERIFY) {
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
		}catch(ISOException e)
		{
			ISOException.throwIt(e.getReason());
		}
		catch(Exception e)
		{
			ISOException.throwIt((short)0x6800);
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
		
		byte[] apduBuffer = apdu.getBuffer();
		
		byte cla = apduBuffer[ISO7816.OFFSET_CLA];
		
		if(cla!=CLA_PROPRIETARY)
		{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		//Validate the PIN format.
		if(apduBuffer[ISO7816.OFFSET_LC] < (byte)0x06
				||apduBuffer[ISO7816.OFFSET_LC] > (byte)0x0E)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte dataStartOffset = ISO7816.OFFSET_CDATA;
		
		byte pinLength = apduBuffer[(short)(dataStartOffset+1)];
		
		if(apduBuffer[dataStartOffset] != (byte)0x01
				||pinLength < (byte)0x04
				||pinLength > (byte)0x0C)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		byte iter = 0;
		byte pinOffset = (byte) (dataStartOffset+2);
		while(iter<pinLength)
		{
			if((byte)(apduBuffer[(byte)(iter+pinOffset)]&0xF0) != (byte)0x30
					||(byte)(apduBuffer[(byte)(iter+pinOffset)]&0x0F) > (byte)0x09)
			{
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				break;
			}
			iter++;
		}
		
		JCSystem.beginTransaction();
		
		ownerPIN.update(apduBuffer, pinOffset, pinLength);
		CARD_STATE = STATE_ACTIVE;
		
		JCSystem.commitTransaction();
	}

	@Override
	public boolean select() {
		return true;
	}
	
}
