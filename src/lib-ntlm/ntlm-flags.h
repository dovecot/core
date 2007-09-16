/*
 * NTLM message flags.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#ifndef NTLM_FLAGS_H
#define NTLM_FLAGS_H

/*
 * Indicates that Unicode strings are supported for use in security
 * buffer data. 
 */
#define NTLMSSP_NEGOTIATE_UNICODE 0x00000001 

/*
 * Indicates that OEM strings are supported for use in security buffer data.
 */
#define NTLMSSP_NEGOTIATE_OEM 0x00000002 

/*
 * Requests that the server's authentication realm be included in the
 * Type 2 message. 
 */
#define NTLMSSP_REQUEST_TARGET 0x00000004 

/*
 * Specifies that authenticated communication between the client and server
 * should carry a digital signature (message integrity). 
 */
#define NTLMSSP_NEGOTIATE_SIGN 0x00000010 

/*
 * Specifies that authenticated communication between the client and server
 * should be encrypted (message confidentiality).
 */
#define NTLMSSP_NEGOTIATE_SEAL 0x00000020 

/*
 * Indicates that datagram authentication is being used. 
 */
#define NTLMSSP_NEGOTIATE_DATAGRAM 0x00000040 

/*
 * Indicates that the LAN Manager session key should be
 * used for signing and sealing authenticated communications.
 */
#define NTLMSSP_NEGOTIATE_LM_KEY 0x00000080 

/*
 * Indicates that NTLM authentication is being used. 
 */
#define NTLMSSP_NEGOTIATE_NTLM 0x00000200 

/*
 * Sent by the client in the Type 1 message to indicate that the name of the
 * domain in which the client workstation has membership is included in the
 * message. This is used by the server to determine whether the client is
 * eligible for local authentication. 
 */
#define NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED 0x00001000 

/*
 * Sent by the client in the Type 1 message to indicate that the client
 * workstation's name is included in the message. This is used by the server
 * to determine whether the client is eligible for local authentication.
 */
#define NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED 0x00002000 

/*
 * Sent by the server to indicate that the server and client are on the same
 * machine. Implies that the client may use the established local credentials
 * for authentication instead of calculating a response to the challenge.
 */
#define NTLMSSP_NEGOTIATE_LOCAL_CALL 0x00004000 

/*
 * Indicates that authenticated communication between the client and server
 * should be signed with a "dummy" signature. 
 */
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN 0x00008000 

/*
 * Sent by the server in the Type 2 message to indicate that the target
 * authentication realm is a domain.
 */
#define NTLMSSP_TARGET_TYPE_DOMAIN 0x00010000 

/*
 * Sent by the server in the Type 2 message to indicate that the target
 * authentication realm is a server. 
 */
#define NTLMSSP_TARGET_TYPE_SERVER 0x00020000 

/*
 * Sent by the server in the Type 2 message to indicate that the target
 * authentication realm is a share. Presumably, this is for share-level
 * authentication. Usage is unclear. 
 */
#define NTLMSSP_TARGET_TYPE_SHARE 0x00040000 

/*
 * Indicates that the NTLM2 signing and sealing scheme should be used for
 * protecting authenticated communications. Note that this refers to a
 * particular session security scheme, and is not related to the use of
 * NTLMv2 authentication.
 */ 
#define NTLMSSP_NEGOTIATE_NTLM2 0x00080000 

/*
 * Sent by the server in the Type 2 message to indicate that it is including
 * a Target Information block in the message. The Target Information block
 * is used in the calculation of the NTLMv2 response.
 */
#define NTLMSSP_NEGOTIATE_TARGET_INFO 0x00800000 

/*
 * Indicates that 128-bit encryption is supported. 
 */
#define NTLMSSP_NEGOTIATE_128 0x20000000 

/*
 * Indicates that the client will provide an encrypted master session key in
 * the "Session Key" field of the Type 3 message. This is used in signing and
 * sealing, and is RC4-encrypted using the previous session key as the
 * encryption key.
 */
#define NTLMSSP_NEGOTIATE_KEY_EXCHANGE 0x40000000 

/*
 * Indicates that 56-bit encryption is supported.
 */
#define NTLMSSP_NEGOTIATE_56 0x80000000 

#endif
