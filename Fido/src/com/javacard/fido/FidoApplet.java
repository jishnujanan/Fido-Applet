/** 
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.javacard.fido;

import javacard.framework.*;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;

/**
 * Applet class
 * 
 * @author <user>
 */

class FidoApplet extends Applet {
	// CLA (Class Byte) Definitions
	// CLA for proprietary commands (logical channel 0, proprietary class)
	private static final byte CLA_PROPRIETARY = (byte) 0x80;

	// INS (Instruction Byte) Definitions
	// Standard INS for selecting files or applets (ISO/IEC 7816-4)
	private static final byte INS_SELECT = (byte) 0xA4;

	// INS for storing a PIN during personalisation phase
	private static final byte INS_STORE_PIN = (byte) 0x20;

	// INS for verifying a user PIN (User State)
	private static final byte INS_VERIFY = (byte) 0x21;

	// INS for registering a new user or entity
	private static final byte INS_REGISTER = (byte) 0x22;

	// INS for logging in an existing user
	private static final byte INS_LOGIN = (byte) 0x23;

	// INS for changing an existing user's PIN
	private static final byte INS_CHANGE_PIN = (byte) 0x24;

	// INS for disabling a user or feature
	private static final byte INS_DISABLE = (byte) 0x25;

	// Card State Definitions
	// Card state: inactive or uninitialized
	private static final byte STATE_INACTIVE = (byte) 0x22;

	// Card state: active and operational
	private static final byte STATE_ACTIVE = (byte) 0x33;

	// Card state: error or blocked, no operations allowed
	private static final byte STATE_UNWORKABLE = (byte) 0x44;

	// Current card state variable (initialized to STATE_INACTIVE by default)
	private byte CARD_STATE = STATE_INACTIVE;


	// Tag for Credential ID
	private static final short TAG_CREDENTIAL_ID 		= (short)0x4349;
	
	// Size of Credential ID
	private static final byte SIZEOF_CREDENTIAL_ID 		= (byte)0x04;
	
	// Tag for Public Key
	private static final short TAG_PUBLIC_KEY			= (short)0x4B59;
	
	// Size of Public Key
	private static final byte SIZEOF_PUBLIC_KEY			= (byte)0x41;
	
	// Tag for Key Details
	private static final short TAG_KEY_DETAILS	 		= (short)0xEC10;
	
	// Size of Key Details
	private static final byte SIZEOF_KEY_DETAILS	 	= (byte)0x01;
	
	// Tag for Signature (the actual digital signature bytes) 'SG"
	private static final short TAG_SIGNATURE 			= (short)0x5347;

	// Tag for Signature Algorithm (e.g., RSA, ECDSA) 'SA'
	private static final short TAG_SIGNATURE_ALGORITHM 	= (short)0x5341; 
	
	// Size of Signature Algorithm (e.g., RSA, ECDSA) 'SA'
	private static final byte	 SIZEOF_SIGNATURE_ALGORITHM 	= (byte)0x01; 

	// Tag for Challenge (random nonce used for anti-replay) 'CH'
	private static final short TAG_CHALLENGE 			= (short)0x4348; 

	// Size of Challenge (random nonce used for anti-replay) 'CH'
	private static final byte SIZEOF_CHALLENGE 			= (byte)0x08; 
	
	// PIN and Credential Handling

	// OwnerPIN object for managing user PIN
	private OwnerPIN ownerPIN = null;

	// Maximum number of allowed PIN attempts
	private static final byte PIN_TRY_LIMIT = (byte) 0x0F;

	// Maximum allowed PIN size
	private static final byte MAX_PIN_SIZE = (byte) 0x0F;

	// Stores all credential IDs
	private byte[] credentialId = null;

	// Total allocated space for credential IDs (supports 100 credentials)
	private static short sizeOfcredentialIdArray = (short) (4 * 100);

	// Points to the top of the credential ID stack (next free index)
	private byte credentialIdReferenceTop = (byte) 0;

	// Transient array for computation (scratch space)
	private byte[] transientArrayForComputation = null;

	// Index to generate new credential
	private static final byte INDEX_GEN_CRED = (byte) 0;
	
	// Index to generate new credential
	private static final byte INDEX_SIGNATURE = (byte)(INDEX_GEN_CRED + SIZEOF_CREDENTIAL_ID);

	// Key Management

	// Random number generator for secure operations
	private static RandomData randomData = null;

	// KeyPair used for ECC key generation
	private static KeyPair keyPair = null;

	// Array of private keys for storing multiple credentials
	private PrivateKey[] privateKeys = null;

	private static Signature signature = null;
	// APDU Case Definitions

	// APDU Case 1: No data in, no data out
	private static final byte CASE1 = (byte) 0x01;

	// APDU Case 2: No data in, data out
	private static final byte CASE2 = (byte) 0x02;

	// APDU Case 3: Data in, no data out
	private static final byte CASE3 = (byte) 0x03;

	// APDU Case 4: Data in, data out
	private static final byte CASE4 = (byte) 0x04;

	//Tags
	
	
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
		
		// Initialize the OwnerPIN with the defined try limit and maximum PIN size
		ownerPIN = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

		// Allocate memory for storing credential IDs
		credentialId = new byte[sizeOfcredentialIdArray];

		// Initialize the random number generator using true random number generator (TRNG)
		randomData = RandomData.getInstance(RandomData.ALG_TRNG);

		// Create a transient byte array for computation, cleared on card reset
		transientArrayForComputation = JCSystem.makeTransientByteArray((short)(100), JCSystem.CLEAR_ON_RESET);

		// Initialize an EC key pair with a 256-bit key size over a prime field
		keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

		// Create an array to hold private keys, one per credential (4 bytes per credential)
		privateKeys = new PrivateKey[(short)(sizeOfcredentialIdArray >> 2)];
		
		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		
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
		
		//Login is a CASE4 command.
		//The data should be in following format
		//TAG_CREDENTIAL_ID(2byte) : LENGTH(1 byte) : VALUE(4bytes)
		//TAG_CHALLENGE(2byte) : LENGTH(1 byte) : VALUE(8bytes)
		
		receiveAndSend(apdu, CASE4);
		
		if(!ownerPIN.isValidated())
		{
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		byte[] apduBuffer = apdu.getBuffer();
		short dataStartOffset = (short)ISO7816.OFFSET_CDATA;
		short credentialIdOffset = (short)0;
		short challengeOffset = (short)0;
		
		if(Util.getShort(apduBuffer, dataStartOffset) == TAG_CREDENTIAL_ID)
		{
			dataStartOffset += (short)2;
			if(apduBuffer[dataStartOffset] == SIZEOF_CREDENTIAL_ID)
			{
				dataStartOffset++;
				credentialIdOffset = dataStartOffset;
				dataStartOffset += SIZEOF_CREDENTIAL_ID;
				if(Util.getShort(apduBuffer, dataStartOffset) == TAG_CHALLENGE)
				{
					dataStartOffset += (short)2;
					if(apduBuffer[dataStartOffset] == SIZEOF_CHALLENGE)
					{
						dataStartOffset++;
						challengeOffset = dataStartOffset;
					}
					else
					{
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					}
				}
				else
				{
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
			}
			else
			{
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		}
		else
		{
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		//Data is correct
		//Find the corresponding key index.
		short privateKeyOffset = (short)0;
		short totalCredentialIdSize = (short) (credentialIdReferenceTop*4);
		while(privateKeyOffset<totalCredentialIdSize)
		{
			if(Util.arrayCompare(apduBuffer, credentialIdOffset, credentialId, privateKeyOffset, SIZEOF_CREDENTIAL_ID) == (byte)0)
			{
				break;
			}
			privateKeyOffset+=SIZEOF_CREDENTIAL_ID;
		}
		privateKeyOffset = (short)(privateKeyOffset/4);
		
		PrivateKey privateKey = privateKeys[privateKeyOffset];
		
		signature.init(privateKey, Signature.MODE_SIGN);
		
		short signatureLength = signature.sign(apduBuffer, challengeOffset, SIZEOF_CHALLENGE, transientArrayForComputation, INDEX_SIGNATURE);
		short outdataOffset = (short)0;
		
		Util.setShort(apduBuffer, outdataOffset, TAG_CREDENTIAL_ID);
		outdataOffset+=(short)2;
		apduBuffer[outdataOffset] = SIZEOF_CREDENTIAL_ID;
		outdataOffset++;
		outdataOffset = Util.arrayCopyNonAtomic(apduBuffer, credentialIdOffset, apduBuffer, outdataOffset, SIZEOF_CREDENTIAL_ID);
		
		Util.setShort(apduBuffer, outdataOffset, TAG_SIGNATURE);
		outdataOffset+=(short)2;
		apduBuffer[outdataOffset] = (byte) signatureLength;
		outdataOffset++;
		outdataOffset = Util.arrayCopyNonAtomic(transientArrayForComputation, INDEX_SIGNATURE, apduBuffer, outdataOffset, signatureLength);
		
		Util.setShort(apduBuffer, outdataOffset, TAG_SIGNATURE_ALGORITHM);
		outdataOffset+=(short)2;
		apduBuffer[outdataOffset] = SIZEOF_SIGNATURE_ALGORITHM;
		outdataOffset++;
		apduBuffer[outdataOffset] = Signature.ALG_ECDSA_SHA_256;
		outdataOffset++;
		
		apdu.setOutgoingLength(outdataOffset);
		apdu.sendBytes((short)0, outdataOffset);
	}

	private void registerProcessing(APDU apdu) {
		
		//Multiple registration should be blocked by the Authentication Server.
		
		receiveAndSend(apdu, CASE2);
		
		if(!ownerPIN.isValidated())
		{
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		
		byte[] apduBuffer = apdu.getBuffer();
		short credentialRefTop = credentialIdReferenceTop;
		byte cla = apduBuffer[ISO7816.OFFSET_CLA];
		
		if(cla!=CLA_PROPRIETARY)
		{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if(credentialRefTop == (byte)(sizeOfcredentialIdArray/4))
		{
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
		
		//Generate a credential ID [4 bytes]
		randomData.nextBytes(transientArrayForComputation, INDEX_GEN_CRED, SIZEOF_CREDENTIAL_ID);
		//Check the credential ID generated is duplicate or not.
		short iter = (short)0;
		while(iter<(short)(credentialIdReferenceTop*4))
		{
			if(Util.arrayCompare(transientArrayForComputation, INDEX_GEN_CRED, credentialId, iter, SIZEOF_CREDENTIAL_ID) == 0)
			{
				randomData.nextBytes(transientArrayForComputation, INDEX_GEN_CRED, SIZEOF_CREDENTIAL_ID);
				iter=0;
			}
			else
			{
				iter+=4;
			}
		}

		JCSystem.beginTransaction();
		
		//Credential is copied to persistent array
		Util.arrayCopy(transientArrayForComputation, INDEX_GEN_CRED, credentialId, credentialIdReferenceTop, SIZEOF_CREDENTIAL_ID);

		//Generation of Key Pair
		keyPair.genKeyPair();
		
		privateKeys[credentialIdReferenceTop] = keyPair.getPrivate();
		
		//Credential Reference Top is incremented by 1 to store the next credential ID
		credentialIdReferenceTop++;

		JCSystem.commitTransaction();
		
		//Send back the Public Key and Credential ID
		short outData = (short)0;
		
		//TLV Coding for Credential ID
		Util.setShort(apduBuffer, outData, TAG_CREDENTIAL_ID);
		outData+=(short)2;
		apduBuffer[outData] = SIZEOF_CREDENTIAL_ID;
		outData++;
		Util.arrayCopyNonAtomic(transientArrayForComputation, INDEX_GEN_CRED, apduBuffer, outData, SIZEOF_CREDENTIAL_ID);
		outData+=(short)SIZEOF_CREDENTIAL_ID;
		
		//TLV Coding for Public Key Value
		Util.setShort(apduBuffer, outData, TAG_PUBLIC_KEY);
		outData+=(short)2;
		apduBuffer[outData] = SIZEOF_PUBLIC_KEY;
		outData++;
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		publicKey.getW(apduBuffer, outData);
		outData+=SIZEOF_PUBLIC_KEY;
		
		//TLV Coding for Key Details
		// EC over P-256
		Util.setShort(apduBuffer, outData, TAG_KEY_DETAILS);
		outData+=(short)2;
		apduBuffer[outData] = SIZEOF_KEY_DETAILS;
		outData+=SIZEOF_KEY_DETAILS;
		apduBuffer[outData] = KeyPair.ALG_EC_FP;
		outData++;
		apdu.setOutgoingLength(outData);
		apdu.sendBytes((short)0, outData);
	}

	private void verifyProcessing(APDU apdu) {
		
		receiveAndSend(apdu, CASE3);
		
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
		
		if(ownerPIN.getTriesRemaining() <= (byte)0x00)
		{
			ISOException.throwIt(ISO7816.SW_AUTHENTICATION_METHOD_BLOCKED);
		}
		
		boolean validatedPin = ownerPIN.check(apduBuffer, pinOffset, pinLength);
		if(validatedPin == false)
		{
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	private void storePinProcessing(APDU apdu) {
		
		receiveAndSend(apdu, CASE3);
		
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

	private void receiveAndSend(APDU apdu,byte commandCase)
	{
		short ne ;
		switch(commandCase)
		{
		case CASE2:
			ne = apdu.setOutgoing();
			if(ne == (short)0)
			{
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			break;
		case CASE3:
		case CASE4:
			byte[] apduBuffer = apdu.getBuffer();
			//We should call setIncomingAndReceive as data is present in all the commands.
			short bytesLeft = (short)(apduBuffer[ISO7816.OFFSET_LC]&(short)0x00FF);
			short bytesReceived = apdu.setIncomingAndReceive();
			if(bytesLeft > (short)0 )
			{
				bytesLeft -= bytesReceived;
				bytesReceived = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA+bytesReceived));
			}
			
			if(commandCase == CASE4)
			{
				ne = apdu.setOutgoing();
				if(ne == (short)0)
				{
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			}
			else
			{
				ne = apdu.setOutgoing();
				if(ne > (short)0)
				{
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}
	
	@Override
	public boolean select() {
		return true;
	}
	
}
