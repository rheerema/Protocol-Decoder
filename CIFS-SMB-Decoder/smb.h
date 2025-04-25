//-----------------------------------------------------------------------
//   Copyright (c) <2005> by Tizor Systems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   File: smb.h
// 
//   Component: SMB protocol processing
//
//-----------------------------------------------------------------------
#ifndef _SMB_H
#define _SMB_H

#include <netmon/netmon_types.h>
#include "smbDebug.hh"

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

// Debug Modes (mutually exclusive)
//
// show a dump of every SMB request and response
//#define SMB_DEBUG_MODE_1

// show successful SMB responses, summary with UID, PID, MID
//#define SMB_DEBUG_MODE_2     O B S O L E T E

// Session Data debug
//#define SMB_DEBUG_MODE_3


#define NBNS_PORT    137    // NetBIOS Name Service
#define NBDGRAM_PORT 138    // NetBIOS Datagram
#define SMB_PORT1    445    // Raw SMB over TCP/IP
#define SMB_PORT2    139    // NetBIOS Session

#define SMB_SERVER_TO_CLIENT_445 1
#define SMB_CLIENT_TO_SERVER_445 2
#define SMB_SERVER_TO_CLIENT_139 3
#define SMB_CLIENT_TO_SERVER_139 4

#define SMB_COM_CREATE_DIRECTORY                0x00
#define SMB_COM_DELETE_DIRECTORY                0x01
#define SMB_COM_OPEN                            0x02
#define SMB_COM_CREATE                          0x03
#define SMB_COM_CLOSE                           0x04
#define SMB_COM_FLUSH                           0x05
#define SMB_COM_DELETE                          0x06
#define SMB_COM_RENAME                          0x07
#define SMB_COM_QUERY_INFORMATION               0x08
#define SMB_COM_SET_INFORMATION                 0x09
#define SMB_COM_READ                            0x0A
#define SMB_COM_WRITE                           0x0B
#define SMB_COM_LOCK_BYTE_RANGE                 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE               0x0D
#define SMB_COM_CREATE_TEMPORARY                0x0E
#define SMB_COM_CREATE_NEW                      0x0F
#define SMB_COM_CHECK_DIRECTORY                 0x10
#define SMB_COM_PROCESS_EXIT                    0x11
#define SMB_COM_SEEK                            0x12
#define SMB_COM_LOCK_AND_READ                   0x13
#define SMB_COM_WRITE_AND_UNLOCK                0x14
#define SMB_COM_READ_RAW                        0x1A
#define SMB_COM_READ_MPX                        0x1B
#define SMB_COM_READ_MPX_SECONDARY              0x1C
#define SMB_COM_WRITE_RAW                       0x1D
#define SMB_COM_WRITE_MPX                       0x1E
#define SMB_COM_WRITE_MPX_SECONDARY             0x1F
#define SMB_COM_WRITE_COMPLETE                  0x20
#define SMB_COM_QUERY_SERVER                    0x21
#define SMB_COM_SET_INFORMATION2                0x22
#define SMB_COM_QUERY_INFORMATION2              0x23
#define SMB_COM_LOCKING_ANDX                    0x24
#define SMB_COM_TRANSACTION                     0x25
#define SMB_COM_TRANSACTION_SECONDARY           0x26
#define SMB_COM_IOCTL                           0x27
#define SMB_COM_IOCTL_SECONDARY                 0x28
#define SMB_COM_COPY                            0x29
#define SMB_COM_MOVE                            0x2A
#define SMB_COM_ECHO                            0x2B
#define SMB_COM_WRITE_AND_CLOSE                 0x2C
#define SMB_COM_OPEN_ANDX                       0x2D
#define SMB_COM_READ_ANDX                       0x2E
#define SMB_COM_WRITE_ANDX                      0x2F
#define SMB_COM_NEW_FILE_SIZE                   0x30
#define SMB_COM_CLOSE_AND_TREE_DISC             0x31
#define SMB_COM_TRANSACTION2                    0x32
#define SMB_COM_TRANSACTION2_SECONDARY          0x33
#define SMB_COM_FIND_CLOSE2                     0x34
#define SMB_COM_FIND_NOTIFY_CLOSE               0x35
/* Used by Xenix/Unix           0x60-0x6E */
#define SMB_COM_TREE_CONNECT                    0x70
#define SMB_COM_TREE_DISCONNECT                 0x71
#define SMB_COM_NEGOTIATE                       0x72
#define SMB_COM_SESSION_SETUP_ANDX              0x73
#define SMB_COM_LOGOFF_ANDX                     0x74
#define SMB_COM_TREE_CONNECT_ANDX               0x75
#define SMB_COM_QUERY_INFORMATION_DISK          0x80
#define SMB_COM_SEARCH                          0x81
#define SMB_COM_FIND                            0x82
#define SMB_COM_FIND_UNIQUE                     0x83
#define SMB_COM_FIND_CLOSE                      0x84
#define SMB_COM_NT_TRANSACT                     0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY           0xA1
#define SMB_COM_NT_CREATE_ANDX                  0xA2
#define SMB_COM_NT_CANCEL                       0xA4
#define SMB_COM_NT_RENAME                       0xA5
#define SMB_COM_OPEN_PRINT_FILE                 0xC0
#define SMB_COM_WRITE_PRINT_FILE                0xC1
#define SMB_COM_CLOSE_PRINT_FILE                0xC2
#define SMB_COM_GET_PRINT_QUEUE                 0xC3
#define SMB_COM_READ_BULK                       0xD8
#define SMB_COM_WRITE_BULK                      0xD9
#define SMB_COM_WRITE_BULK_DATA                 0xDA

#define SMB_COM_NULL_COMMAND                    0xFF  // Tizor-defined


// Status Codes
#define NT_STATUS_SUCCESS                 0x00000000


//======================================================================
// Packet Header Structure Definitions
//======================================================================

//----------------------------------------------------------------------
// NetBIOS and SMB Headers
//----------------------------------------------------------------------
// port 139
typedef struct NBHeader {
tz_uint8  type;
tz_uint8  flags;
tz_uint16 length;
} NBHeader;

// port 445
typedef struct NBHeaderRaw {
tz_uint8  reserved;
tz_uint8  length[3];          // network order (big endian)
} __attribute__((packed)) NBHeaderRaw;

typedef struct SmbHeader {
tz_uint32 protocol; // 0xFF SMB
tz_uint8  command;
union {
  struct {
  tz_uint8  errorClass;
  tz_uint8  reserved;
  tz_uint16 errorCode;
  } DosErr;
  tz_uint32 NTstatus;
} status;
tz_uint8  flags;
tz_uint16 flags2;
tz_uint8  reserved2[12];
tz_uint16 treeId;
tz_uint16 processId;
tz_uint16 userId;
tz_uint16 multiplexId;
} __attribute__((packed)) SmbHeader;

#define SMB_FLAGS2_UNICODE  0x8000

// Negotiate capabilities
#define NEG_CAP_RAW_MODE          (1 << 0)
#define NEG_CAP_MPX_MODE          (1 << 1)
#define NEG_CAP_UNICODE           (1 << 2)
#define NEG_CAP_LARGE_FILES       (1 << 3)
#define NEG_CAP_NT_SMBS           (1 << 4)
#define NEG_CAP_RPC_REMOTE_APIS   (1 << 5)
#define NEG_CAP_STATUS32          (1 << 6)
#define NEG_CAP_LEVEL_II_OPLOCKS  (1 << 7)
#define NEG_CAP_LOCK_AND_READ     (1 << 8)
#define NEG_CAP_NT_FIND           (1 << 9)
#define NEG_CAP_DFS               (1 << 12)
#define NEG_CAP_INFOLVL_PASSTHRU  (1 << 13)
#define NEG_CAP_LARGE_READX       (1 << 14)
#define NEG_CAP_LARGE_WRITEX      (1 << 15)
#define NEG_CAP_UNIX              (1 << 23)
#define NEG_CAP_RESERVED          (1 << 25)
#define NEG_CAP_BULK_XFER         (1 << 29)
#define NEG_CAP_COMPRESSED_DATA   (1 << 30)
#define NEG_CAP_EXTENDED_SEC      (1 << 31)

//----------------------------------------------------------------------
// Negotiate
//----------------------------------------------------------------------
typedef struct SmbNegotiateRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // count of data bytes
struct {
  tz_uint8 bufferFormat;    // 0x2 -- dialect
  tz_uint8 dialectName[];   // ASCII null-terminated string
} Dialects[];
} __attribute__((packed)) SmbNegotiateRequest;

typedef struct SmbNegotiateNTLM012Response {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 dialectIndex;     // index of selected dialect
tz_uint8  securityMode;
tz_uint16 maxMpxCnt;        // Max pending outstanding requests
tz_uint16 maxNumVcs;        // Max number of VCs between client and server
tz_uint32 maxBufferSize;    // Max transmit buffer size
tz_uint32 maxRawSize;       // Max raw buffer size
tz_uint32 sessionKey;       // unique to this session
tz_uint32 capabilities;     // server capabilities
tz_uint32 systemTimeLow;    // server system time (UTC)
tz_uint32 systemTimeHigh;   // server system time (UTC)
tz_uint16 serverTimeZone;   // minutes from UTC
tz_int8   encryptKeyLength;
tz_uint16 byteCount;
tz_uint8  encryptKey[];     // present if no CAP_EXTENDED_SECURITY
tz_uint8  oemDomainName[];  // present if no CAP_EXTENDED_SECURITY
tz_uint8  guid[16];         // globally unique identifier (if CAP_EXTENDED_SECURITY)
tz_uint8  SecurityBlob[TZX_512_STRING]; // the security blob
} __attribute__((packed)) SmbNegotiateNTLM012Response;

//----------------------------------------------------------------------
// Session Setup Andx
//----------------------------------------------------------------------
typedef struct SmbSsnSetupAndxPreNTLM012Request {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // 
tz_uint8  reserved;         // count of data bytes
tz_uint16 andxOffset;       // Offset to next command in this SMB packet
tz_uint16 maxBuffer;        // maximum client buffer size
tz_uint16 maxMpxCnt;        // Maximum pending multiplexed requests
tz_uint16 vcNum;            // vc number
tz_uint32 sessionKey;       // unique session token identifying this session
tz_uint16 ansiPasswordLength;    // length of ANSI password
tz_uint32 reserved2;        // not used
tz_uint16 byteCount;        // count of data bytes
tz_uint8  AccountPassword[]; // Account Password
tz_uint8  AccountName[];     // Account Name (unicode)
tz_uint8  PrimaryDomain[];   // Client's Primary Domain (unicode)
tz_uint8  NativeOS[];        // Client's Native OS (unicode)
tz_uint8  NativeLanMan[];    // Client's Native LAN Manager type (unicode)
} __attribute__((packed)) SmbSsnSetupAndxPreNTLM012Request;

typedef struct SmbSsnSetupAndxPreNTLM012Response {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // 
tz_uint8  reserved;         // count of data bytes
tz_uint16 andxOffset;       // Offset to next command in this SMB packet
tz_uint16 action;           // req mode b0 == Guest
tz_uint16 byteCount;        // count of data bytes
tz_uint8  NativeOS[];       // Client's Native OS (unicode)
tz_uint8  NativeLanMan[];   // Client's Native LAN Manager type (unicode)
tz_uint8  PrimaryDomain[];  // Client's Primary Domain (unicode)
} __attribute__((packed)) SmbSssSetupAndxPreNTLM012Response;


typedef struct SmbSsnSetupAndxNTLM012ExtSecRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved;         // count of data bytes
tz_uint16 andxOffset;       // Offset to next command in this SMB packet
tz_uint16 maxBuffer;        // maximum client buffer size
tz_uint16 maxMpxCnt;        // Maximum pending multiplexed requests
tz_uint16 vcNum;            // vc number
tz_uint32 sessionKey;       // unique session token identifying this session
tz_uint16 SecurityBlobLength; // length of security blob
tz_uint32 reserved2;        // not used
tz_uint32 capabilities;     // Client capabilities
tz_uint16 byteCount;        // count of data bytes
tz_uint8  SecurityBlob[TZX_512_STRING]; // the security blob
} __attribute__((packed)) SmbSsnSetupAndxNTLM012ExtSecRequest;

typedef struct SmbSsnSetupAndxNTLM012ExtSecResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // 
tz_uint8  reserved;         // count of data bytes
tz_uint16 andxOffset;       // Offset to next command in this SMB packet
tz_uint16 action;           // req mode b0 == Guest
tz_uint16 securityBlobLen;  //
tz_uint16 byteCount;        // count of data bytes
tz_uint8  SecurityBlob[TZX_512_STRING]; // the security blob
tz_uint8  NativeOS[];       // Client's Native OS (unicode)
tz_uint8  NativeLanMan[];   // Client's Native LAN Manager type (unicode)
tz_uint8  PrimaryDomain[];  // Client's Primary Domain (unicode)
} __attribute__((packed)) SmbSsnSetupAndxNTLM012ExtSecResponse;

// NTLM security
#define SMB_NTLMSSP_UNKNOWN    0X00000000    // fabricated value
#define SMB_NTLMSSP_NEGOTIATE  0x00000001    // protocol value
#define SMB_NTLMSSP_CHALLENGE  0x00000002    // protocol value
#define SMB_NTLMSSP_AUTH       0x00000003    // protocol value

// Kerberos security
#define SMB_KRB5_UNKNOWN       0x00000000
#define SMB_KRB5_AUTH          0x00000001

// Session Setup Security Authorization Modes
#define SMB_AUTHMODE_NOEXTSEC       0x00000001
#define SMB_AUTHMODE_EXTSEC         0x00000002
//#define SMB_AUTHMODE_EXTSEC_NTLMSSP 0x00000003
//#define SMB_AUTHMODE_EXTSEC_KRB5    0x00000004

// SPNEGO ASN.1 types
#define SMB_SPNEGO_NEGINIT_APP_CONSTRUCT     0x60
#define SMB_SPNEGO_TAG_OID                   0x06
#define SMB_SPNEGO_CONSTRUCTED_SEQ           0x30
#define SMB_SPNEGO_NEGINIT_ELEMENT_MECHTYPES 0xa0

#define SMB_SPNEGO_NEGINIT_TOKEN_IDENTIFIER  0xa0
#define SMB_SPNEGO_NEGTARG_TOKEN_IDENTIFIER  0xa1

// SPNEGO Parse return codes
#define SMB_SPNEGO_ERROR            0x00000000
#define SMB_SPNEGO_NEG_TOKEN_INIT   0x00000001
#define SMB_SPNEGO_NEG_TOKEN_TARG   0x00000002

// ASN.1 Length encoding tokens
#define LEN_XTND  0x80  // indefinite or log form
#define LEN_MASK  0x7f  // bits 7 thru 1

// The expected OIDS.  Order here matches the expected OID list,
// oidList[], which is found in smb.cc
// WARNING: Correspondence between the two must be maintained
typedef enum
{
  OID_SPNEGO,
  OID_MS_KRB5,
  OID_MS_KRB5_LGCY,
  OID_NTLMSSP,
  OID_UNKNOWN,
} OidType;

typedef struct mechOID
{
  OidType    oidType;
  tz_uint32  totalLen;  // Identifier, Length and OID bytes
  tz_uint32  oidLen;    // OID bytes themselves
  tz_int8   *stg;
} mechOID;

// NTLM blob format
// (all offsets are from the first byte of the magic signature)
typedef struct SmbNtlmSsp {
tz_uint64 ntlmMagic;        // magic signature sequence (big endian)
tz_uint32 ntlmSspType;      // Negotiate, Challenge, Auth
tz_uint16 lmRspLen;         // LM Response
tz_uint16 lmRspMaxLen;      // 
tz_uint32 lmRspOffset;      // 
tz_uint16 ntlmRspLen;       // NTLM Response
tz_uint16 ntlmRspMaxLen;    // 
tz_uint32 ntlmRspOffset;    // 
tz_uint16 domainLen;        // Domain Name
tz_uint16 domainMaxLen;     // 
tz_uint32 domainOffset;     // 
tz_uint16 userLen;          // User Name
tz_uint16 userMaxLen;       // 
tz_uint32 userOffset;       // 
tz_uint16 hostLen;          // Host Name
tz_uint16 hostMaxLen;       // 
tz_uint32 hostOffset;       // 
} __attribute__((packed)) SmbNtlmSsp;

typedef struct SmbSsnSetupAndxNTLM012NoExtSecRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // 
tz_uint8  reserved;         // count of data bytes
tz_uint16 andxOffset;       // Offset to next command in this SMB packet
tz_uint16 maxBuf;           //
tz_uint16 maxMpxCount;      //
tz_uint16 vcNum;            //
tz_uint32 sessionKey;       //
tz_uint16 ansiPasswdLen;    //
tz_uint16 unicodePasswdLen; //
tz_uint32 reserved2;        //
tz_uint32 capabilities;     //
tz_uint16 byteCnt;          //
tz_int8   ansiPasswd[TZX_512_STRING]; //
tz_int8   unicodePasswd[];  //
tz_int8   account[];        //
tz_int8   priDomain[];      //
tz_int8   NativeOS[];       // Client's Native OS
tz_int8   NativeLanMan[];   // Client's Native LAN Manager type
} __attribute__((packed)) SmbSsnSetupAndxNTLM012NoExtSecRequest;

typedef struct SmbSsnSetupAndxNTLM012NoExtSecResponse {
tz_uint8  wordCount;        // count of parameter words (3)
tz_uint8  andxCommand;      // 
tz_uint8  reserved;         // count of data bytes
tz_uint16 andxOffset;       // Offset to next command in this SMB packet
tz_uint16 action;           // req mode b0 == Guest
tz_uint16 byteCount;        // count of data bytes
tz_uint8  NativeOS[TZX_512_STRING]; // Client's Native OS (unicode)
tz_uint8  NativeLanMan[];   // Client's Native LAN Manager type (unicode)
tz_uint8  PrimaryDomain[];  // Client's Primary Domain (unicode)
} __attribute__((packed)) SmbSsnSetupAndxNTLM012NoExtSecResponse;

//----------------------------------------------------------------------
// Create
//     Taken from Draft-leach-cifs-v1-spec-02, it's not in CIFS 1.0
//----------------------------------------------------------------------
typedef struct SmbCreateRequest{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 fileAttrib;       //
tz_uint32 createTime;       //
tz_uint16 byteCount;        //
tz_uint8  bufferFormat;     //
tz_int8   filename[TZX_512_STRING]; // file to create
} __attribute__((packed)) SmbCreateRequest;

typedef struct SmbCreateResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 fid;              // file ID assigned
tz_uint16 byteCount;        //
} __attribute__((packed)) SmbCreateResponse;

//----------------------------------------------------------------------
// NT Create Andx
//----------------------------------------------------------------------
typedef struct SmbNTCreateAndXRequest {
tz_uint8  wordCount;                // count of parameter words
tz_uint8  andxCommand;              // andx command
tz_uint8  reserved1;                // count of data bytes
tz_uint16 andxOffset;               // andx offset
tz_uint8  reserved2;                // 
tz_uint16 filenameLength;           // filename length
tz_uint32 createFlags;              // create flags
tz_uint32 rootFid;                  // 
tz_uint32 accessMask;               //
tz_uint64 allocationSize;           // 
tz_uint32 fileAttributes;           //
tz_uint32 shareAccess;              //
tz_uint32 disposition;              //
tz_uint32 createOptions;            //
tz_uint32 impersonations;           //
tz_uint8  securityFlags;            //
tz_uint16 byteCount;                // 
tz_uint8  reserved3;                // not part of filename (Ethereal)
tz_int8   filename[TZX_512_STRING]; // file to open or create
} __attribute__((packed)) SmbNTCreateAndXRequest;

#define SMB_NT_CREATE_ANDX_CREATE_ACT_OPEN      1
#define SMB_NT_CREATE_ANDX_CREATE_ACT_CREATE    2
#define SMB_NT_CREATE_ANDX_CREATE_ACT_TRUNCATE  3

typedef struct SmbNTCreateAndXResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // next chained command
tz_uint8  reserved1;        // count of data bytes
tz_uint16 andxOffset;       // next command offset
tz_uint8  oplockLvl;        // oplock level granted
tz_uint16 fid;              // file ID assigned
tz_uint32 createAction;     // create action taken
tz_uint64 createTime;       //
tz_uint64 lastAccessTime;   //
tz_uint64 lastWriteTime;    //
tz_uint64 changeTime;       //
tz_uint32 fileAttributes;   //
tz_uint64 allocSize;        //
tz_uint64 endOfFileOffset;  // actual file size
tz_uint16 fileType;         // 
tz_uint16 deviceState;      // 
tz_uint8  isDirectory;      // bool
tz_uint16 byteCount;        // set to 0
} __attribute__((packed)) SmbNTCreateAndXResponse;

//----------------------------------------------------------------------
// Read 
//     Taken from Draft-leach-cifs-v1-spec-02, it's not in CIFS 1.0
//----------------------------------------------------------------------
typedef struct SmbReadRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 fid;              // file ID assigned
tz_uint16 count;            // bytes to be written
tz_uint32 offset;           // offset in file to begin write
tz_uint16 remaining;        // reserved (obsolescent requests)
tz_uint16 byteCount;        // data bytes
} __attribute__((packed)) SmbReadRequest;

typedef struct SmbReadResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 count;            // bytes which were written
tz_uint16 reserved[4];      // must be 0
tz_uint16 byteCount;        // count of data bytes, 0
tz_uint8  bufferFormat;     //
tz_uint16 dataLength;       // no. data bytes
} __attribute__((packed)) SmbReadResponse;

//----------------------------------------------------------------------
// Read Andx
//----------------------------------------------------------------------
typedef struct SmbReadAndxRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved1;        // must be 0
tz_uint16 andxOffset;       // andx offset
tz_uint16 fid;              // file ID assigned
tz_uint32 offset;           // offset in file to begin read
tz_uint16 maxCount;         // max no. bytes to return
tz_uint16 minCount;         // reserved (obsolescent requests)
tz_uint32 maxCountHigh;     // high 16-bits maxCount if CAP_LARGE_READX
tz_uint16 remaining;        // reserved (obsolescent requests)
tz_uint32 offsetHigh;       // upper 32-bits of offset if wordCount==12
tz_uint16 byteCount;        // count of data bytes, 0
} __attribute__((packed)) SmbReadAndxRequest;


typedef struct SmbReadAndxResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved1;        // must be 0
tz_uint16 andxOffset;       // andx offset
tz_uint16 remaining;        // reserved (obsolescent requests)
tz_uint16 dataCompactMode;  // 
tz_uint16 reserved2;        // must be 0
tz_uint16 dataLength;       // no. data bytes
tz_uint16 dataOffset;       // from header start
tz_uint32 dataLengthHigh;   // high 16-bits of number if CAP_LARGE_READX
tz_uint16 reserved3[3];     // must be 0
tz_uint16 byteCount;        // data bytes, ignore if CAP_LARGE_READX
} __attribute__((packed)) SmbReadAndXResponse;

//----------------------------------------------------------------------
// Write
//----------------------------------------------------------------------
typedef struct SmbWriteRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 fid;              // file ID assigned
tz_uint16 count;            // bytes to be written
tz_uint32 offset;           // offset in file to begin write
tz_uint16 remaining;        // reserved (obsolescent requests)
tz_uint16 byteCount;        // data bytes
tz_uint8  bufferFormat;     //
tz_uint16 dataLength;       //
tz_uint8  data[];           // data to write
} __attribute__((packed)) SmbWriteRequest;

typedef struct SmbWriteResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 count;            // bytes which were written
tz_uint16 byteCount;        // data bytes
} __attribute__((packed)) SmbWriteResponse;

//----------------------------------------------------------------------
// Write Andx
//----------------------------------------------------------------------
typedef struct SmbWriteAndxRequest {
tz_uint8  wordCount;        // count of parameter words (12 or 14)
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved1;        // must be 0
tz_uint16 andxOffset;       // andx offset
tz_uint16 fid;              // file ID assigned
tz_uint32 offset;           // offset in file to begin read
tz_uint32 reserved2;        // must be 0
tz_uint16 writeMode;        // 0 - write through
tz_uint16 remaining;        // reserved (obsolescent requests)
tz_uint16 dataLengthHigh;   // high 16-bits of number
tz_uint16 dataLength;       // no. data bytes
tz_uint16 dataOffset;       // from header start
tz_uint32 offsetHigh;       // upper 32-bits of offset if wordCount==14
tz_uint16 byteCount;        // data bytes, ignore if CAP_LARGE_WRITEX
tz_uint8  pad;              // pad to uint16 or uint32
tz_uint8  data[];           // data to write
} __attribute__((packed)) SmbWriteAndxRequest;

typedef struct SmbWriteAndxResponse {
tz_uint8  wordCount;        // count of parameter words = 6
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved1;        // must be 0
tz_uint16 andxOffset;       // andx offset
tz_uint16 count;             // no. bytes written
tz_uint16 remaining;        // reserved
tz_uint32 reserved2;        //
tz_uint16 byteCount;        // data bytes = 0
} __attribute__((packed)) SmbWriteAndxResponse;

//----------------------------------------------------------------------
// Open Andx
//     Considered obsolete yet it's still used.  See 
//     Draft-leach-cifs-v1-spec-02, this is NOT in the CIFS 1.0 spec.
//----------------------------------------------------------------------
typedef struct SmbOpenAndxRequest{
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved1;        // must be 0
tz_uint16 andxOffset;       // andx offset
tz_uint16 flags;            // 
tz_uint16 access;           // 
tz_uint16 searchAttrib;     //
tz_uint16 fileAttrib;       //
tz_uint32 createTime;       //
tz_uint16 openFunct;        //
tz_uint32 allocSize;        //
tz_uint64 reserved2;        //
tz_uint16 byteCount;        //
tz_uint8  bufferFormat;     //
tz_int8   filename[TZX_512_STRING]; // file to open
} __attribute__((packed)) SmbOpenAndxRequest;

typedef struct SmbOpenAndxResponse{
tz_uint8  wordCount;        // count of parameter words
tz_uint8  andxCommand;      // SMB command
tz_uint8  reserved1;        // must be 0
tz_uint16 andxOffset;       // andx offset
tz_uint16 fid;              // file ID assigned
tz_uint16 fileAttrib;       //
tz_uint32 lastWriteTime;    //
tz_uint32 fileSize;         //
tz_uint16 access;           //
tz_uint16 fileType;         // disk file or directory (0)
tz_uint16 ipcState;         // 
tz_uint16 action;           //
tz_uint32 serverFid;        //
tz_uint16 reserved2;        //
tz_uint16 byteCount;        //
} __attribute__((packed)) SmbOpenAndxResponse;

//----------------------------------------------------------------------
// Locking Andx
//----------------------------------------------------------------------

//----------------------------------------------------------------------
// Tree Connect Andx
//----------------------------------------------------------------------
typedef struct SmbTreeConnectAndxRequest {
tz_uint8  wordCount;               // count of parameter words = 4
tz_uint8  andxCommand;             // SMB command
tz_uint8  reserved1;               // must be 0
tz_uint16 andxOffset;              // andx offset
tz_uint16 flags;                   // Additional information:
                                   // bit 0 - Disconnect TID
tz_uint16 passwordLen;              // length of password[]
tz_uint16 byteCount;               //  
tz_int8   password[TZX_512_STRING];//  
tz_int8   path[];                  // servername and sharename
tz_int8   service[];               // service name
} __attribute__((packed)) SmbTreeConnectAndxRequest;

typedef struct SmbTreeConnectAndxResponse {
tz_uint8  wordCount;               // count of parameter words
tz_uint8  andxCommand;             // 
tz_uint8  reserved;                // count of data bytes
tz_uint16 andxOffset;              // Offset to next command in this SMB packet
tz_uint16 optionalSupport;         //
tz_uint16 byteCount;               //     
tz_int8   service[TZX_512_STRING]; //
tz_int8   nativeFS[];              //
} __attribute__((packed)) SmbTreeConnectAndxResponse;

//----------------------------------------------------------------------
// Tree Disconnect
//----------------------------------------------------------------------
typedef struct SmbTreeDisconnectRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // count of data bytes
} __attribute__((packed)) SmbTreeDisconnectRequest;

typedef struct SmbTreeDisconnectResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // count of data bytes
} __attribute__((packed)) SmbTreeDisconnectResponse;


//----------------------------------------------------------------------
// Logoff Andx
//----------------------------------------------------------------------

//----------------------------------------------------------------------
// Open
//     Considered obsolete yet it's still used.  See 
//     Draft-leach-cifs-v1-spec-02, this is NOT in the CIFS 1.0 spec.
//----------------------------------------------------------------------
typedef struct SmbOpenRequest{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 access;           // 
tz_uint16 searchAttrib;     //
tz_uint16 byteCount;        //     
tz_uint8  bufferFmt;        //
tz_int8   filename[TZX_512_STRING];
} __attribute__((packed)) SmbOpenRequest;

typedef struct SmbOpenResponse{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 fid;              // 
tz_uint16 fileAttrib;       //
tz_uint32 lastWrite;        //
tz_uint32 fileSize;         //
tz_uint16 grantedAccess;    //
tz_uint16 byteCount;        //
} __attribute__((packed)) SmbOpenResponse;

#define SMB_OPEN_FILE_ATTRIB_IS_DIR     0x00000010

//----------------------------------------------------------------------
// Close
//----------------------------------------------------------------------
typedef struct SmbCloseRequest{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 fid;              // file ID assigned
tz_uint64 lastWriteTime;    //
tz_uint16 byteCount;        // set to 0
} __attribute__((packed)) SmbCloseRequest;

typedef struct SmbCloseResponse{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // set to 0
} __attribute__((packed)) SmbCloseResponse;

//----------------------------------------------------------------------
// Transaction2
//----------------------------------------------------------------------

// -- Subcommand Codes--
//
// Create file with extended attributes
#define TRANS2_OPEN2                   0x00
 //Begin search for files
#define TRANS2_FIND_FIRST2             0x01
// Resume search for files
#define TRANS2_FIND_NEXT2              0x02
 //Get file system information
#define TRANS2_QUERY_FS_INFORMATION    0x03
// Reserved (TRANS_SET_FS_INFORMATION?)
                                    // 0x04
// Get information about a named file or directory
#define TRANS2_QUERY_PATH_INFORMATION  0x05
// Set information about a named file or directory
#define TRANS2_SET_PATH_INFORMATION    0x06 
// Get information about a handle
#define TRANS2_QUERY_FILE_INFORMATION  0x07
// Set information by handle
#define TRANS2_SET_FILE_INFORMATION    0x08
// Not implemented by NT server
#define TRANS2_FSCTL                   0x09
// Not implemented by NT server
#define TRANS2_IOCTL2                  0x0A
// Not implemented by NT server
#define TRANS2_FIND_NOTIFY_FIRST       0x0B
// Not implemented by NT server
#define TRANS2_FIND_NOTIFY_NEXT        0x0C
// Create directory with extended attributes
#define TRANS2_CREATE_DIRECTORY        0x0D
// Session setup with extended security information
#define TRANS2_SESSION_SETUP           0x0E

// Get a DFS referral
#define TRANS2_GET_DFS_REFERRAL         0x10
// Report a DFS knowledge inconsistency
#define TRANS2_REPORT_DFS_INCONSISTENCY 0x11

typedef struct SmbTransaction2Request {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 totalParmCount;   // total parameter bytes being sent
tz_uint16 totalDataCount;   // total data bytes being sent
tz_uint16 maxParmCount;     // max parameter bytes to return
tz_uint16 maxDataCount;     // max data bytes to return
tz_uint8  maxSetupCount;    // max setup words to return
tz_uint8  reserved;
tz_uint16 flags;            // Additional information:
                            // bit 0 - Disconnect TID
tz_uint32 timeout;
tz_uint16 reserved2;
tz_uint16 parameterCount;   // Parameter bytes sent this buffer
tz_uint16 parameterOffset;  // Offset from SMB header start to Parms
tz_uint16 dataCount;        // Data bytes sent this buffer
tz_uint16 dataOffset;       // Offset (from header start) to data
tz_uint8  setupCount;       // Count of setup words
tz_uint8  reserved3;        // Reserved (pad above to word boundary)
tz_uint16 setup;            // Subcommand
tz_uint16 byteCount;
tz_uint8  parmDataArea[];   // Size depends on subcommand
} __attribute__((packed)) SmbTransaction2Request;

// Set File Info Parameters
typedef struct SmbTrans2SetFileInfoParms {
tz_uint16 fid;
tz_uint16 infoLevel;
tz_uint16 reserved;
} __attribute__((packed)) SmbTrans2SetFileInfoParms;

// Query Path Info Parameters
typedef struct SmbTrans2QueryPathInfo {
tz_uint16 infoLevel;
tz_uint32 reserved;
tz_int8   fileDirName[TZX_512_STRING];
} __attribute__((packed)) SmbTrans2QueryPathInfo;

// Query FS Info
typedef struct SmbTrans2QueryFSInfo {
tz_uint16 infoLevel;
} __attribute__((packed)) SmbTrans2QueryFSInfo;

// Find First2
typedef struct SmbTrans2QueryFindFirst2 {
tz_uint16 searchAttrib;
tz_uint16 searchCount;
tz_uint16 flags;
tz_uint16 infoLevel;
tz_uint32 searchStorageType;
tz_int8   filename[TZX_512_STRING];
tz_int8   data[];
} __attribute__((packed)) SmbTrans2QueryFindFirst2;

// Get DFS Referral
typedef struct SmbTrans2QueryGetDfsReferral {
tz_uint16 maxReferralLevel;
tz_int8   filename[TZX_512_STRING];
} __attribute__((packed)) SmbTrans2QueryGetDfsReferral;

typedef struct SmbTransaction2Response {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 totalParmCount;   // total parameter bytes being sent
tz_uint16 totalDataCount;   // total data bytes being sent
tz_uint16 reserved;
tz_uint16 parameterCount;   // Parameter bytes sent this buffer
tz_uint16 parameterOffset;  // Offset from SMB header start to Parms
tz_uint16 parameterDispl;   // Displacement of parameter bytes
tz_uint16 dataCount;        // Data bytes sent this buffer
tz_uint16 dataOffset;       // Offset (from header start) to data
tz_uint16 dataDispl;        // Displacement of data bytes
tz_uint8  setupCount;        // Count of setup words
tz_uint8  reserved2;
tz_uint16 setup;            // Subcommand
tz_uint8  parmDataArea[];   // Size depends on subcommand
} __attribute__((packed)) SmbTransaction2Response;

//----------------------------------------------------------------------
// Transaction
//----------------------------------------------------------------------

// Function codes
#define TRANS_FUNCT_SET_NAMED_PIPE_HND_STATE  0x01 
#define TRANS_FUNCT_NAMED_PIPE_DCERPCCMD      0x26
#define TRANS_FUNCT_WAIT_NAMED_PIPE           0x53
#define TRANS_FUNCT_CALL_NAMED_PIPE           0x54

typedef struct SmbPipeProtocol {
tz_uint16 function;
tz_uint16 fid;
tz_uint8  data[];
} __attribute__((packed)) SmbPipeProtocol;

typedef struct SmbDceRpc {
tz_uint8  verMaj;            // version major
tz_uint8  verMin;            // version minor
tz_uint8  pktType;           // packet type
tz_uint8  flags;             // flags
tz_uint8  dataRep[4];        // data representation
tz_uint16 fragLen;           // fragment length, inc header + tail
tz_uint16 authLen;           // quthentication length
tz_uint32 callId;            // call identifier
tz_uint32 allocHint;         // allocation hint
tz_uint16 contextId;         // presentation context identifier
tz_uint8  parm[2];           // req: u16 opnum
                             // rsp: u8 cancelCnt u8 reserved
} __attribute__((packed)) SmbDceRpc;

// MS SPOOLSS Subsystem
//
#define SPOOLSS_ENUM_PRINTERS             0x00
#define SPOOLSS_OPEN_PRINTER              0x01
#define SPOOLSS_SET_JOB                   0x02
#define SPOOLSS_GET_JOB                   0x03
#define SPOOLSS_ENUM_JOBS                 0x04
#define SPOOLSS_ADD_PRINTER               0x05
#define SPOOLSS_DELETE_PRINTER            0x06
#define SPOOLSS_SET_PRINTER               0x07
#define SPOOLSS_GET_PRINTER               0x08
#define SPOOLSS_ADD_PRINTER_DRIVER        0x09
#define SPOOLSS_ENUM_PRINTER_DRIVERS      0x0a
#define SPOOLSS_GET_PRINTER_DRIVER_DIR    0x0c
#define SPOOLSS_DELETE_PRINTER_DRIVER     0x0d
#define SPOOLSS_ADD_PRINT_PROCESSOR       0x0e
#define SPOOLSS_ENUM_PRINT_PROCESSORS     0x0f
#define SPOOLSS_GET_PRINT_PROCESSOR_DIR   0x10
#define SPOOLSS_START_DOC_PRINTER         0x11
#define SPOOLSS_START_PAGE_PRINTER        0x12
#define SPOOLSS_WRITE_PRINTER             0x13
#define SPOOLSS_END_PAGEP_RINTER          0x14
#define SPOOLSS_ABORT_PRINTER             0x15
#define SPOOLSS_END_DOC_PRINTER           0x17
#define SPOOLSS_ADD_JOB                   0x18
#define SPOOLSS_SCHEDULE_JOB              0x19
#define SPOOLSS_GET_PRINTER_DATA          0x1a
#define SPOOLSS_SET_PRINTER_DATA          0x1b
#define SPOOLSS_CLOSE_PRINTER             0x1d
#define SPOOLSS_ADD_FORM                  0x1e
#define SPOOLSS_DELETE_FORM               0x1f
#define SPOOLSS_GET_FORM                  0x20
#define SPOOLSS_SET_FORM                  0x21
#define SPOOLSS_ENUM_FORMS                0x22
#define SPOOLSS_ENUM_PORTS                0x23
#define SPOOLSS_ENUM_MONITORS             0x24
#define SPOOLSS_ENUM_PRINT_PROCDATATYPES  0x33
#define SPOOLSS_RESET_PRINTER             0x34
#define SPOOLSS_GET_PRINTER_DRIVER2       0x35
#define SPOOLSS_FCPN                      0x38
#define SPOOLSS_REPLY_OPEN_PRINTER        0x3a
#define SPOOLSS_ROUTER_REPLY_PRINTER      0x3b
#define SPOOLSS_REPLY_CLOSE_PRINTER       0x3c
#define SPOOLSS_RFFPCNEX                  0x41
#define SPOOLSS_RRPCN                     0x42
#define SPOOLSS_RFNPCNEX                  0x43
#define SPOOLSS_OPEN_PRINTER_EX           0x45
#define SPOOLSS_ADD_PRINTER_EX            0X46
#define SPOOLSS_ENUM_PRINTER_DATA         0x48
#define SPOOLSS_DELETE_PRINTER_DATA       0x49
#define SPOOLSS_SET_PRINTER_DATA_EX       0x4d
#define SPOOLSS_GET_PRINTER_DATA_EX       0x4e
#define SPOOLSS_ENUM_PRINTER_DATA_EX      0x4f
#define SPOOLSS_ENUM_PRINTER_KEY          0x50
#define SPOOLSS_DELETE_PRINTER_DATA_EX    0x51
#define SPOOLSS_DELETE_PRINTER_KEY        0x52
#define SPOOLSS_DELETE_PRINTER_DRIVER_EX  0x54
#define SPOOLSS_ADD_PRINTER_DRIVER_EX     0x59

typedef struct SmbTransactionRequest {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 totalParmCount;   // total parameter bytes being sent
tz_uint16 totalDataCount;   // total data bytes being sent
tz_uint16 maxParmCount;     // max parameter bytes to return
tz_uint16 maxDataCount;     // max data bytes to return
tz_uint8  maxSetupCount;    // max setup words to return
tz_uint8  reserved;
tz_uint16 flags;            // 
tz_uint32 timeout;
tz_uint16 reserved2;
tz_uint16 parameterCount;   // Parameter bytes sent this buffer
tz_uint16 parameterOffset;  // Offset from SMB header start to Parms
tz_uint16 dataCount;        // Data bytes sent this buffer
tz_uint16 dataOffset;       // Offset (from header start) to data
tz_uint8  setupCount;       // Count of setup words
tz_uint8  reserved3;
tz_uint16 function;         // transaction function code
tz_uint16 fid;
tz_uint8  data[];           // DCE RPC
} __attribute__((packed)) SmbTransactionRequest;

typedef struct SmbTransactionResponse {
tz_uint8  wordCount;        // count of parameter words
tz_uint16 totalParmCount;   // total parameter bytes being sent
tz_uint16 totalDataCount;   // total data bytes being sent
tz_uint16 reserved;
tz_uint16 parameterCount;   // Parameter bytes sent this buffer
tz_uint16 parameterOffset;  // Offset from SMB header start to Parms
tz_uint16 parameterDisp;    // parameter displacement
tz_uint16 dataCount;        // Data bytes sent this buffer
tz_uint16 dataOffset;       // Offset (from header start) to data
tz_uint16 dataDisp;         // data displacement
tz_uint8  setupCount;       // Count of setup words
tz_uint8  reserved1;
tz_uint16 byteCount;
tz_uint8  padding;
tz_uint8  data[];           // DCE RPC
} __attribute__((packed)) SmbTransactionResponse;

//----------------------------------------------------------------------
// Delete
//----------------------------------------------------------------------
typedef struct SmbDeleteRequest{
tz_uint8  wordCount;                // count of parameter words
tz_uint16 searchAttrib;             //
tz_uint16 byteCount;                //
tz_uint8 bufferFormat;              // 0x04
tz_int8  filename[TZX_512_STRING];  //
} __attribute__((packed)) SmbDeleteRequest;

typedef struct SmbDeleteResponse{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // set to 0
} __attribute__((packed)) SmbDeleteResponse;

//----------------------------------------------------------------------
// Delete Directory
//----------------------------------------------------------------------

typedef struct SmbDeleteDirRequest{
tz_uint8  wordCount;                // count of parameter words
tz_uint16 byteCount;                //
tz_uint8  bufferFormat;             // 0x04
tz_int8   dirname[TZX_512_STRING];  // directory to be deleted
} __attribute__((packed)) SmbDeleteDirRequest;

typedef struct SmbDeleteDirResponse{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // count of data bytes
} __attribute__((packed)) SmbDeleteDirResponse;

//----------------------------------------------------------------------
// Rename
//----------------------------------------------------------------------
typedef struct SmbRenameRequest{
tz_uint8  wordCount;                // count of parameter words
tz_uint16 searchAttrib;             //
tz_uint16 byteCount;                //
tz_uint8 bufferFormat1;             // 0x04
tz_int8  oldFilename[TZX_512_STRING];
tz_uint8 bufferFormat2;             // 0x04
tz_int8  newFilename[];
} __attribute__((packed)) SmbRenameRequest;

typedef struct SmbRenameResponse{
tz_uint8  wordCount;        // count of parameter words
tz_uint16 byteCount;        // count of data bytes
} __attribute__((packed)) SmbRenameResponse;


//
// Layer Manager Configuration for LMCFG_SMB
//
typedef struct PipeStgData
{
    struct PipeStgData *next;
    tz_uint32           server;
    tz_uint8            nullServer;
    tz_int8            *pipeName;
    tz_uint8            nullPipe;
    tz_int8            *interface;
    tz_uint32           application;
} PipeStgData;

typedef struct LmCfgSmb
{
  // Each LM Config storage begins with a change sequence number
  tz_uint32 chgSeqNum;
  
  // Current list of pipe strings
  tz_uint32 pipeStgListChgSeqNum;
  PipeStgData *pipeStgList;

  // Operational modes
  bool fileshareIsEnabled;
  bool tdsNamedPipeIsEnabled;

} LmCfgSmb;


//======================================================================
// SMB Error Codes
//======================================================================
//
// don't forget to update smbUtilError2String() !
//
#define SMB_ERROR_NONE                    0x00000000

#define SMB_ERROR_NO_SESSION              0x000000ff
#define SMB_ERROR_NO_SMB_INFO_DESCR       0x00000100
#define SMB_ERROR_NO_UID_DESCR            0x00000101
#define SMB_ERROR_UID_CREATE              0x00000102
#define SMB_ERROR_NO_PID_MID_DESCR        0x00000103
#define SMB_ERROR_PID_MID_CREATE          0x00000104
#define SMB_ERROR_NO_FID_DESCR            0x00000105
#define SMB_ERROR_FID_CREATE              0x00000106
#define SMB_ERROR_NO_TID_DESCR            0x00000107
#define SMB_ERROR_TID_CREATE              0x00000108

//======================================================================
// SMB Logging Macros
//======================================================================

// SMB Error Log - uses lc_log_debug to show function, file, line
// to help debug anomolous events
//
#define SmbErrLog(level, format, ...)                                      \
    do {                                                                   \
        lc_log_internal(__FUNCTION__, __FILE__, __LINE__,                  \
          LCO_SOURCE_INFO, 0, level, format, ## __VA_ARGS__);              \
    } while(0)

// SMB Monitor Log - when enabled by the "mon" debug command this sends
// interesting SMB decoder operational output to syslog as LOG_NOTICE
// events
//
#define SmbMonLog(format, ...)                                             \
    do {                                                                   \
        if( SmbDebug::monIsEnabled )                                       \
        {                                                                  \
            lc_log_internal(__FUNCTION__, __FILE__, __LINE__,              \
                      0, 0, LOG_NOTICE, format, ## __VA_ARGS__);           \
        }                                                                  \
    } while(0)


// SMB Debug Log - used for displaying packets
//
#define SmbDbgLog(mode, level, format, ...)                                \
    if(    level >= smbDebugLevel                                          \
        && mode == smbDebugMode  )                                         \
    {                                                                      \
        do {                                                               \
            lc_log_internal(__FUNCTION__, __FILE__, __LINE__,              \
                           0, 0, level, format, ## __VA_ARGS__);           \
        } while(0);                                                        \
    }

// SMB Decode Log - writes packet decode info to ./decode_log.txt
//
#ifdef SMB_DECODE_LOG
#define SmbDcdLog(ssnEntry, format, ...)                                   \
    this->smbUtilDecodeLog( ssnEntry, format, ## __VA_ARGS__);
#else
#define SmbDcdLog(ssnEntry, format, ...)
#endif

class ContentScanner;

//======================================================================
// SmbInfo - session protocol data
//======================================================================

// SessionEntry context (client and server contests per TID)
typedef struct SmbSsnSeCtxt
{
    SessionDetail *sessionDetail;
    tz_uint64        id;

} SmbSsnSeCtxt;

typedef struct SmbTdsEncaps
{
    // SMB session variables
    struct SmbInfo *smbInfo;
    SessionDetail  *smbSsnDetail;
    tz_uint64       smbId;

    // TDS session variables
    TdsInfo        *tdsInfo;
    SessionDetail  *tdsSsnDetail;
    tz_uint64       tdsId;

} SmbTdsEncaps;

// PID:MID list element
typedef struct SmbSsnPidMid
{
    tz_uint16     pid;
    tz_uint16     mid;
    SmbSsnPidMid *next;

    // Payload    
    tz_int8     filename[TZX_512_STRING]; // NtCreateAndx
    tz_int8     filename2[TZX_512_STRING];// Rename (new name)
    tz_uint16   fid;                      // Close

    tz_uint16   trans2SubCmd;             // Trans2
    tz_uint16   trans2DataCountRspTot;    // Trans2, running total of rsp
    tz_uint16   trans2Parm;               // Trans2, subcmd-specific
    tz_uint16   trans2Data;               // Trans2, subcmd-specific

    // Lifetime monitoring
    tz_watch_t *age;

} SmbSsnPidMid;

// File ID Mode
typedef enum
{
  FID_MODE_FILESHARE,                     // File share
  FID_MODE_NMD_PIPE_SPOOLSS,              // Named Pipe, print monitoring
  FID_MODE_NMD_PIPE_SQL,                  // Named Pipe, SQL Server encaps

} FidMode;

// File ID list element
typedef struct SmbSsnFid
{
    tz_uint16   fid;
    SmbSsnFid  *next;
    tz_uint16   tid;                       // Tree ID for this FID
    bool        isEventSource;             // (to generate events)
    bool        isDirectory;               // "filename" is a directory
    FidMode     mode;                      // operational mode
    SmbTdsEncaps    tdsEncaps;             // TDS Named Pipes
    ContentScanner *clientCs;              // Content Scanner objects
    ContentScanner *serverCs;
    tz_int8     filename[TZX_512_STRING];
} SmbSsnFid;

// TID list element
typedef struct SmbSsnTid
{
    tz_uint16   tid;
    SmbSsnTid  *next;
    bool        isEventSource;             // (to generate events)

    // SessionEntry contexts
    bool         ctxtIsEmpty;
    SmbSsnSeCtxt seCtxt;

    tz_int8     servername[TZX_64_STRING];  // server (from TreeConnectAndx)
    tz_int8     sharename[TZX_64_STRING];   // which share on that server
} SmbSsnTid;

// A user's state on a particular transport session
// (a list element).
typedef struct SmbSsnUid
{
    tz_uint16   uid;
    SmbSsnUid * next;
    bool        authIsCompleted;

    // FID list
    SmbSsnFid *fidList;

    // PID:MID list
    SmbSsnPidMid *pidMidList;

    // TID list
    SmbSsnTid *tidList;

    // File Info Tree, a collection of files which EncEngFmt performs
    // filtering on
    void *fileInfoTree;

} SmbSsnUid;

// Session Stats
typedef struct ThisSsnStats
{
    // Current descriptor allocation stats
    tz_uint32 currUidCount;
    tz_uint32 currPidMidCount;
    tz_uint32 currTidCount;
    tz_uint32 currFidCount;

    // Maximum allocations seen
    tz_uint32 maxUidCount;
    tz_uint32 maxPidMidCount;
    tz_uint32 maxTidCount;
    tz_uint32 maxFidCount;
    tz_uint64 maxPidMidLife;  // tz_watch ticks
} ThisSsnStats;

// Fragmentation management
#define SMB_FRAG_BLOCK_LEN (2048)

typedef struct FragState
{
  bool       isActive; // fragmentation mode
  tz_uint32  len;      // end of valid data
  tz_int8   *data;     // reassembly buffer
  tz_uint32  dataSz;   // current reassembly buffer size

} FragState;

// Large SMB commands can span multiple frames.  State information is
// stored here
typedef struct LargeCmdState
{
    bool      isActive;
    tz_uint32 tcpSegOffset;  // from the byte after the last of the TCP
                             // header to the first of the NetBIOS header
    tz_uint32 totExpected;   // from NetBIOS header length
    tz_uint32 totReceived;   // so far
    tz_uint32 totRemaining;  // remaining in current command
    tz_uint32 remainInPkt;   // bytes still unparsed in this packet

    FragState fs;            // fragmentation tracking

    tz_uint8  smbCommand;    // the SMB command in-progress
    SmbTdsEncaps   *tdsEncaps; // named pipes
    ContentScanner *cs;        // Content Scanner object
    tz_uint16 csUid;
    tz_uint16 csPid;
    tz_uint16 csMid;
    tz_uint16 csTid;
    
} LargeCmdState;


//----------------------------------------------------------------------
//  SmbInfo structure itself
//----------------------------------------------------------------------
// SMB Info for this session which represents one user.  The protocol
// generate many UIDs for this user.  Most are ephemeral, some are
// long lasting.  All the active UIDs are related to this one user.

typedef struct SmbInfo
{
  //tz_uint32  dir;

  // List of UIDs on this transport session
  SmbSsnUid *uidList;
  tz_uint32  uidListCnt;

#if 0
  // Unknown Fid and Tid are persistent descriptors for dealing with an
  // unknown UID encountered when jumping into an existing session
  SmbSsnFid ssnFidUnknown;
  SmbSsnTid ssnTidUnknown;
#endif

  // For SessionSetup/TreeConnect Andx pairs, the UID for the request pair
  // is different than that of the response.  We remember the req UID here
  tz_uint16 treeConnectReqUid;

  // Running counts over the lifetime of this user's session
  tz_uint64  filesDirsAccessed;

  // Session ID number (for debugging)
  tz_uint16 sessionIdNum;

  // Session Stats
  ThisSsnStats thisSsnStats;

  // Capabilities (from NEGOTIATE response)
  tz_uint32 capabilities;

  // Maximum multiplexed client requests in flight at a given time
  tz_uint16 srvMaxMpxCount;
  tz_uint16 cliMaxMpxCount;

  // Authentication state variables
  tz_uint32 ntlmSspState;                   // type of most recent client req
  tz_uint32 krb5State;
  tz_uint32 authMode;                       // authentication mode in progress
  tz_uint32 authFailCnt;                    // STATUS_LOGON_FAILURE counts
                                            // in one session
  // Encoding engine dimension lists
  DimValListEntry  *contDimValListEntry;
  DimValListEntry  *operDimValListEntry;
  DimValListEntry  *sizeDimValListEntry;     // size.bytes
  DimValListEntry  *respDimValListEntry;     // response.status
  DimValListEntry  *respDataDimValListEntry; // response.data
  DimValListEntry  *cmdDataDimValListEntry;  // command.data

  // Large SMB Command State descriptors.  We keep two of these to handle,
  // for example, a premature response received while a write request is
  // in progress.
  LargeCmdState reqLcs;
  LargeCmdState rspLcs;

  // SESSION dimension related
  tz_int8    serverUser[TZX_512_STRING];    // name of the user on the server
  tz_int8    hostUser[TZX_512_STRING];      // name of the user on the host
  tz_uint32  clientPid;                     // PID of the client process 
                                            // making the connection
  tz_int8    serverVersion[TZX_512_STRING]; // What version of server is this 
  tz_int8    serverInfo[TZX_512_STRING];    // <server>\<share>
  tz_int8    domainName[TZX_64_STRING];     // from SessionSetupAndx

} SmbInfo;


class smbEncEngFormatter;

//======================================================================
// CIFS/SMB Decode Class
//======================================================================

class SmbDecode
{

  friend class SmbDebug;

public:

  // -- Public Functions --

  SmbInfo *CreateProtocolData( SessionEntry *sessionEntry );

  void DeleteProtocolData( SessionEntry *sessionEntry );
  void SendAppLogoutEvent( SessionEntry *sessionEntry,
                           SmbSsnTid *ssnTid );

  // ctor
  SmbDecode(NetMonDriver *nmd, EncodingEngine *ee, TDSDecode *tds);

  // dtor
  virtual ~SmbDecode();

  // Process login or data packets
  tz_uint32 smbProcess( SessionEntry *sessionEntry,
                        const u_char *data, 
                        tz_uint32     length,
                        tz_uint32     tcpHole );

  void smbDecodeCommand( SessionEntry *sessionEntry,
                         const u_char *data, 
                         tz_uint32     length,
                         tz_uint32     tcpHole );

  // Status counter manipulators
  void ClearDecodeStats( void );
  void SumDecodeStats( void *context );
  void currUidCountInc( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      ++smbInfo->thisSsnStats.currUidCount;
      if(smbInfo->thisSsnStats.maxUidCount < smbInfo->thisSsnStats.currUidCount)
      {
          smbInfo->thisSsnStats.maxUidCount = smbInfo->thisSsnStats.currUidCount;
      }
  }
  void currUidCountDec( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      --smbInfo->thisSsnStats.currUidCount;
  }
  void currPidMidCountInc( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      ++smbInfo->thisSsnStats.currPidMidCount;
      if( smbInfo->thisSsnStats.maxPidMidCount < smbInfo->thisSsnStats.currPidMidCount)
      {
          smbInfo->thisSsnStats.maxPidMidCount = smbInfo->thisSsnStats.currPidMidCount;
      }
  }
  void currPidMidCountDec( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      --smbInfo->thisSsnStats.currPidMidCount;
  }
  void currTidCountInc( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      ++smbInfo->thisSsnStats.currTidCount;
      if( smbInfo->thisSsnStats.maxTidCount < smbInfo->thisSsnStats.currTidCount)
      {
          smbInfo->thisSsnStats.maxTidCount = smbInfo->thisSsnStats.currTidCount;
      }
  }
  void currTidCountDec( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      --smbInfo->thisSsnStats.currTidCount;
  }
  void currFidCountInc( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      ++smbInfo->thisSsnStats.currFidCount;
      if( smbInfo->thisSsnStats.maxFidCount < smbInfo->thisSsnStats.currFidCount)
      {
          smbInfo->thisSsnStats.maxFidCount = smbInfo->thisSsnStats.currFidCount;
      }
  }
  void currFidCountDec( SessionEntry *sessionEntry )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      --smbInfo->thisSsnStats.currFidCount;
  }

  void CsEnab( void *context);
  void smbUtilEvtFilterMode( bool isOn );
  bool smbUtilEvtFilterModeIsEnab( void );
  void smbUtilGetPidMidConfig( tz_uint64 *var );
  void smbUtilSetPidMidConfig( tz_uint64 *var );
  static tz_int8 *smbUtilDebugGenerateDump( void );

  // -- Public Data --

  NetMonDriver   *netMonDriver;
  EncodingEngine *encodingEngine;
  TDSDecode      *tdsDecode;

  // Content Scanner Pattern Matchers
  PatternManager *rspDataPatMgr;
  PatternManager *cmdDataPatMgr;

  // packet counters
  tz_uint32 smbClientPkts;
  tz_uint32 smbServerPkts;

private:

  // -- Private Functions --

  static void smbUtilErrorDisplayStats( void );
  char     *smbUtilCmd2String( tz_uint8 cmd );
  char     *smbUtilTcpContinString( void );
  char     *smbUtilBlankString( void );
  char     *smbUtilError2String( tz_uint32 error );
  void      smbUtilErrorUpdateStats( tz_uint32 error );
  void      smbUtilDisplaySmbInfo( SessionEntry *sessionEntry );
  char     *smbUtilTrans2_2String( tz_uint32 subcmd );
  char     *smbUtilNtlmssp2String( tz_uint32 code );
  char     *smbUtilSpoolss2String( tz_uint32 code );
  char     *smbUtilNtStatus2String( tz_uint32 code );
  tz_int8  *smbUtilUnicodeToAscii(tz_int8 *offset, tz_uint32 inLen,
                                                   tz_int8 *name);
  void      smbUtilFreeVector(DimValListEntry *vector);
  tz_uint32 smbUtilAsnDerGetLength( tz_uint8 *data, tz_uint32 *len, 
                                    tz_uint32 *bytes );
  tz_uint32 smbUtilAsnDerCheckOid( tz_uint8 *data, OidType oid, 
                                   tz_uint32 *bytes );
  bool      smbUtilIsEventSource( tz_int8 *filename );
  bool      smbUtilIsHiddenShare( tz_int8 *share );
  void      smbUtilCSPrintResults( ContentScanner  *cs, 
                                   DimValListEntry *curEntry );

  void smbUtilDecodeLog( SessionEntry *sessionEntry,
                         const char * format, ...);

  void smbCsSaveUidPidMidTid( LargeCmdState *lcs, 
                              tz_uint16 uid, tz_uint16 pid,
                              tz_uint16 mid, tz_uint16 tid );

  tz_uint32 smbCsFindSsnDescrs( SessionEntry   *sessionEntry,
                                 LargeCmdState  *lcs, 
                                 SmbSsnUid     **ssnUid,
                                 SmbSsnPidMid  **ssnPidMid,
                                 SmbSsnFid     **ssnFid,
                                 SmbSsnTid     **ssnTid );

  void smbServerCsSendEvent( SessionEntry  *sessionEntry,
                             SmbSsnUid     *ssnUid,
                             SmbSsnFid     *ssnFid );

  void smbClientCsSendEvent( SessionEntry  *sessionEntry,
                             SmbSsnUid     *ssnUid,
                             SmbSsnFid     *ssnFid );

  void smbCmdDump( tz_uint8      cmd, 
                   tz_uint32     dir,
                   const u_char *data, 
                   tz_uint32     length);

  void smbPktDump( const u_char *data, 
                   tz_uint32     length);

  bool smbIsLogonPacket( tz_uint8 command );

  void smbPrintCmd( char *pCmdStg );

  // LM Config
  void smbLmCfgProcess( LmCfgSmb * lmCfg );

  // TDS encapsulation
  void smbTdsEncapsClientReq( SessionEntry *sessionEntry,
                              SmbTdsEncaps *tdsEncaps,
                              tz_uint8     *data,
                              tz_uint32     length );

  void smbTdsEncapsServerRsp( SessionEntry *sessionEntry,
                              SmbTdsEncaps *tdsEncaps,
                              tz_uint8     *data,
                              tz_uint32     length );

  bool smbTdsEncapsFidIsNP( SessionEntry *sessionEntry,
                            tz_int8      *fidName );

  void smbTdsEncapsLogout( SessionEntry *sessionEntry,
                           SmbTdsEncaps *tdsEncaps );

  // TCP Continuation
  void handleTcpContInProgress( SessionEntry  *sessionEntry,
                                tz_uint8      *data,
                                tz_uint32      length,
                                LargeCmdState *lcs );

  void handleTcpContComplete( SessionEntry  *sessionEntry,
                              tz_uint8      *data,
                              tz_uint32      length,
                              LargeCmdState *lcs );

  // Fragmentation
  void handleFragBegin( SessionEntry *sessionEntry,
                        const u_char *data,
                        tz_uint32     length );

  void handleFragCont( SessionEntry *sessionEntry,
                       const u_char *data, 
                       tz_uint32     length );

  // SMB Command Handlers
  tz_uint32 smbProcessLogonPacket( SessionEntry *sessionEntry,
                                   tz_uint8      command,
                                   const u_char *data,
                                   tz_uint32     length,
                                   tz_uint32     tcpHole );

  tz_uint32 smbProcessDataPacket( SessionEntry  *sessionEntry,
                                   tz_uint8      command,
                                  const u_char  *data,
                                  tz_uint32      length,
                                  tz_uint32      tcpHole );

  void smbHandleNegotiate( SessionEntry *sessionEntry,
                           const u_char *data,
                           tz_uint32     length );

  void smbHandleSessionSetupAndx( SessionEntry *sessionEntry,
                                  const u_char *data,
                                  tz_uint32 length );

  void smbHandleLogoffAndx( SessionEntry *sessionEntry,
                            const u_char *data,
                            tz_uint32 length );

  void smbHandleTreeConnectAndx( SessionEntry *sessionEntry,
                              const u_char *data,
                              tz_uint32 length );

  void smbHandleTreeDisconnect( SessionEntry *sessionEntry,
                                const u_char *data,
                                tz_uint32 length );

  void smbHandleCreate( SessionEntry *sessionEntry,
                        const u_char *data,
                        tz_uint32 length );

  void smbHandleNtCreateAndx( SessionEntry *sessionEntry,
                              const u_char *data,
                              tz_uint32 length );
  void smbHandleOpen( SessionEntry *sessionEntry,
                      const u_char *data,
                      tz_uint32 length );
  void smbHandleOpenAndx( SessionEntry *sessionEntry,
                          const u_char *data,
                          tz_uint32 length );
  void smbHandleRead( SessionEntry *sessionEntry,
                      const u_char *data,
                      tz_uint32 length );
  void smbHandleReadAndx( SessionEntry *sessionEntry,
                          const u_char *data,
                          tz_uint32 length );
  void smbHandleClose( SessionEntry *sessionEntry,
                       const u_char *data,
                       tz_uint32 length );

  void smbHandleDelete( SessionEntry *sessionEntry,
                        const u_char *data,
                        tz_uint32 length );

  void smbHandleWrite( SessionEntry *sessionEntry,
                       const u_char *data,
                       tz_uint32 length );

  void smbHandleWriteAndx( SessionEntry *sessionEntry,
                           const u_char *data,
                           tz_uint32 length );

  void smbHandleTransaction( SessionEntry *sessionEntry,
                             const u_char *data,
                             tz_uint32 length );

  void smbHandleTransaction2( SessionEntry *sessionEntry,
                              const u_char *data,
                              tz_uint32 length );

  void smbHandleDeleteDirectory( SessionEntry *sessionEntry,
                                 const u_char *data,
                                 tz_uint32 length );

  void smbHandleRename( SessionEntry *sessionEntry,
                        const u_char *data,
                        tz_uint32 length );

  void smbHandleDefaultCommand( SessionEntry *sessionEntry,
                                const u_char *data,
                                tz_uint32 length );

  void smbAuthNoExtSec( SessionEntry *sessionEntry,
                        SmbHeader    *smbHeader,
                        void         *hdr );

  void smbAuthExtSec( SessionEntry *sessionEntry,
                      SmbHeader    *smbHeader,
                      void         *hdr );

  tz_uint32 smbAuthParseSpnego( tz_uint8 *data, OidType &oidType );

  tz_uint32 SmbSsnFindSsnDescrs( SessionEntry   *sessionEntry,
                                 SmbHeader      *smbHeader,
                                 SmbSsnUid     **ssnUid,
                                 SmbSsnPidMid  **ssnPidMid,
                                 SmbSsnFid     **ssnFid,
                                 SmbSsnTid     **ssnTid );

  tz_uint32 SmbSsnFindSsnDescrsUid( SessionEntry   *sessionEntry,
                                    tz_uint16       uid,
                                    SmbHeader      *smbHeader,
                                    SmbSsnUid     **ssnUid,
                                    SmbSsnPidMid  **ssnPidMid,
                                    SmbSsnFid     **ssnFid,
                                    SmbSsnTid     **ssnTid );

  //
  // session data management
  //

  SmbInfo *SmbSsnDataInit( SessionEntry *sessionEntry );

  void SmbSsnDataDeInit(SessionEntry *sessionEntry);

  SmbSsnUid *SmbSsnDataFindByUid( SessionEntry *sessionEntry, 
                                  tz_uint16     uid );

  SmbSsnFid *SmbSsnDataFindByFid( SmbSsnUid *ssnUid, 
                                  tz_uint16 fid );

  tz_uint32 SmbSsnDataAddPidMid( SmbSsnUid      *ssnUid, 
                                 tz_uint16       pid,
                                 tz_uint16       mid,
                                 SmbSsnPidMid  **ssnPidMid );

  SmbSsnPidMid *SmbSsnDataFindByPidMid( SessionEntry   *sessionEntry,
                                        SmbSsnUid      *ssnUid, 
                                        tz_uint16       pid,
                                        tz_uint16       mid );

  SmbSsnPidMid *SmbSsnDataFindAgedPidMid( SessionEntry *sessionEntry,
                                          SmbSsnUid    *ssnUid );

  SmbSsnTid *SmbSsnDataFindByTid( SmbSsnUid *ssnUid, 
                                  tz_uint16 tid );

  tz_uint32 SmbSsnCreateSsnPidMid( SessionEntry   *sessionEntry,
                                   SmbHeader      *smbHeader,
                                   SmbSsnPidMid  **ssnPidMid );

  tz_uint32 SmbSsnDataAddUid( SessionEntry *sessionEntry, 
                              tz_uint16    uid );

  tz_uint32 SmbSsnDataRemoveUid(SessionEntry *sessionEntry, 
                                tz_uint16    uid);

  tz_uint32 SmbSsnDataAddFid( SessionEntry   *sessionEntry,
                              SmbSsnUid      *ssnUid,
                              tz_uint16       fid );

  tz_uint32 SmbSsnDataRemoveFid(  SessionEntry   *sessionEntry,
                                  SmbSsnUid      *ssnUid,
                                  tz_uint16       fid );

  tz_uint32 SmbSsnDataRemovePidMid( SessionEntry *sessionEntry,
                                    SmbSsnUid    *ssnUid, 
                                    tz_uint16     pid,
                                    tz_uint16     mid );

  tz_uint32 SmbSsnDataAddTid( SessionEntry   *sessionEntry,
                              SmbSsnUid      *ssnUid,
                              tz_uint16       tid );

  tz_uint32 SmbSsnDataRemoveTid( SessionEntry  *sessionEntry,
                                 SmbSsnUid     *ssnUid, 
                                 tz_uint16      tid );



  // -- Private Data --

  // String for formatting commands
  tz_int8   currCmdStg[TZX_512_STRING];

  // STATUS_LOGON_FAILURE count for consecutive but different sessions
  tz_uint32 authFailCnt;

  // Encoding Engine Formatter
  smbEncEngFormatter *encEngFmt;

  // SMB Logger level, nominally LOG_NOTICE
  tz_uint32 smbDebugLevel;

  // SMB debug mode, selects output
  tz_uint32 smbDebugMode;

  // Login Required flag.
  // TRUE - In this mode we must see the authentication of the UID in
  //        order to montior any traffic on it
  // FALSE - This is "session jump-in" mode.  We log traffic on all UIDs
  //         and show the user as UNKNOWN_USER if we haven't seen login
  tz_uint32 smbLoginIsRequired;

  // Processed Packet ID number (for debugging )
  tz_uint32 processedPktNum;

  // Session ID number (for debugging )
  tz_uint16 sessionIdNum;

  // Layer Manager Config variables
  LmCfgSmb myLmCfg;

  // PID/MID Age Timeout
  tz_uint64 pidMidAgeTimeout;

  // PID/MID Per Session Limit
  tz_uint32 pidMidPerSsnLimit;

  // Andx Command State is used for processing chained commands
  struct AndxCmdState
  {
      // andxCmd is from the request header.  0xff is end of chain
      tz_uint8  cmd;
      // chainCnt keeps track of processing iterations
      tz_uint8  chainCnt;
      // andxOffset is from the request header.
      tz_uint16 offset;
  } andxCmdState;

  // smbUtilDecodeLog file
  FILE *dlFile;

  // Statistics counters
  struct DecodeStats
  {
      // Gaps seen
      tz_uint32 tcpHole;

      // Unimplemented commands
      tz_uint32 unimplCmdCount;

      // Count of non-SMB frames (synchronization failed)
      tz_uint32 notSyncCount;

      // Synchronization succeeded
      tz_uint32 reSyncSuccess;

      // Possible NetBIOS Session Service packets
      tz_uint32 possibNbssCount;

      // Descriptor error stats
      tz_uint32 noSession;
      tz_uint32 noSmbInfoDescr;
      tz_uint32 noUidDescr;
      tz_uint32 uidCreateError;
      tz_uint32 noPidMidDescr;
      tz_uint32 pidMidCreateError;
      tz_uint32 pidMidAgedDescr;
      tz_uint32 noFidDescr;
      tz_uint32 fidCreateError;
      tz_uint32 noTidDescr;
      tz_uint32 tidCreateError;
      tz_uint32 failedRemove;
      tz_uint32 miscError;

      // Former Session Stats (sessions which have come and gone)
      tz_uint32 oldSsnMaxUidCount;
      tz_uint32 oldSsnMaxPidMidCount;
      tz_uint32 oldSsnMaxTidCount;
      tz_uint32 oldSsnMaxFidCount;
      tz_uint64 oldSsnMaxPidMidLife;

  } decodeStats;

};


#endif /* _SMB_H */
