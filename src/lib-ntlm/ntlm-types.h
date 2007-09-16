/*
 * NTLM data structures.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#ifndef NTLM_TYPES_H
#define NTLM_TYPES_H

#define NTLMSSP_MAGIC			0x005053534d4c544eULL

#define	NTLMSSP_MSG_TYPE1		1
#define	NTLMSSP_MSG_TYPE2		2
#define	NTLMSSP_MSG_TYPE3		3

#define NTLMSSP_DES_KEY_LENGTH		7

#define NTLMSSP_CHALLENGE_SIZE		8

#define LM_HASH_SIZE			16
#define LM_RESPONSE_SIZE		24

#define NTLMSSP_HASH_SIZE		16
#define NTLMSSP_RESPONSE_SIZE		24

#define NTLMSSP_V2_HASH_SIZE		16
#define NTLMSSP_V2_RESPONSE_SIZE	16


typedef uint16_t ucs2le_t;

struct ntlmssp_buffer {
	uint16_t length;	/* length of the buffer */
	uint16_t space;		/* space allocated space for buffer */
	uint32_t offset;	/* data offset from the start of the message */
};

typedef struct ntlmssp_buffer ntlmssp_buffer_t;


/*
 * 
 */
struct ntlmssp_message {
	uint64_t magic;			/* NTLMSSP\0 */
	uint32_t type;			/* Should be 1 */
};

/*
 * Type 1 message, client sends it to start NTLM authentication sequence.
 */
struct ntlmssp_request {
	uint64_t magic;			/* NTLMSSP\0 */
	uint32_t type;			/* Should be 1 */
	uint32_t flags;			/* Flags */
	ntlmssp_buffer_t domain;	/* Domain name (optional) */
	ntlmssp_buffer_t workstation;	/* Workstation name (optional) */
	/* Start of the data block */
};

/*
 * The Type 2 message is sent by the server to the client in response to
 * the client's Type 1 message. It serves to complete the negotiation of
 * options with the client, and also provides a challenge to the client.
 */
struct ntlmssp_challenge {
	uint64_t magic;			/* NTLMSSP\0 */
	uint32_t type;			/* Should be 2 */
	ntlmssp_buffer_t target_name;	/* Name of authentication target */
	uint32_t flags;			/* Flags */
	uint8_t challenge[NTLMSSP_CHALLENGE_SIZE];	/* Server challenge */
	uint32_t context[2];		/* Local authentication context handle */
	ntlmssp_buffer_t target_info;	/* Target information block (for NTLMv2) */
	/* Start of the data block */
};

/*
 * The Type 3 message is the final step in authentication. This message
 * contains the client's responses to the Type 2 challenge, which demonstrate
 * that the client has knowledge of the account password without sending the
 * password directly. The Type 3 message also indicates the domain and username
 * of the authenticating account, as well as the client workstation name.
 */
struct ntlmssp_response {
	uint64_t magic;			/* NTLMSSP\0 */
	uint32_t type;			/* Should be 3 */
	ntlmssp_buffer_t lm_response;	/* LM/LMv2 recponse */
	ntlmssp_buffer_t ntlm_response;	/* NTLM/NTLMv2 recponse */
	ntlmssp_buffer_t domain;	/* Domain name */
	ntlmssp_buffer_t user;		/* User name */
	ntlmssp_buffer_t workstation;	/* Workstation name */
	ntlmssp_buffer_t session_key;	/* Session key (optional */
	uint32_t flags;			/* Flags (optional) */
	/* Start of the data block */
};

/*
 * NTLMv2 Target Information Block item.
 */
struct ntlmssp_v2_target_info {
	uint16_t type;			/* Data type (see below) */
	uint16_t length;		/* Length of content field */
	/* Content (always in ucs2-le) */
};

/*
 * NTLMv2 Target Information Block item data type.
 */
enum {
	NTPLMSSP_V2_TARGET_END = 0,	/* End of list  */
	NTPLMSSP_V2_TARGET_SERVER,	/* NetBIOS server name */ 
	NTPLMSSP_V2_TARGET_DOMAIN,	/* NT Domain NetBIOS name */
	NTPLMSSP_V2_TARGET_FQDN,	/* Fully qualified host name */
	NTPLMSSP_V2_TARGET_DNS		/* DNS domain name */
};

/*
 * NTLMv2 Authentication data blob.
 */
struct ntlmssp_v2_blob {
	uint32_t magic;			/* Should be 0x01010000 */
	uint32_t reserved;		/* Always 0 */
	uint64_t timestamp;		/* Timestamp */
	uint32_t unknown;		/* Unknown something */
	/* Target Information Block */
};

#endif
