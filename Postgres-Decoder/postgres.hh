//-----------------------------------------------------------------------
//   Copyright (c) <2009> by Netezza Corporation
//   All Rights Reserved.
//   Licensed Material - Property of Netezza Corporation.
//
//   File: postgres.hh
// 
//   Component: PostgreSQL Frontend/Backend message protocol
//
//-----------------------------------------------------------------------

#ifndef __POSTGRES_HH__
#define __POSTGRES_HH__

#include <netmon/sessionBuffer.hh>

#ifndef PACKED
#define PACKED __attribute__ ((packed))
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

//-----------------------------------------------------------------------
// Message Headers
//-----------------------------------------------------------------------

// NZ Versions
#define CP_VERSION_1     1   // startup packet
#define CP_VERSION_2     2   // handshake - (msg[len(4bytes), opcode(2bytes), payload(0-1024)])
#define CP_VERSION_3     3   // handshake - (msg[len(4bytes), opcode(2bytes), payload(0-1024)]) Suppotrs SSL

// NZ Handshake Opcodes
typedef enum
{
    HSV2_INVALID_OPCODE = 0,
    HSV2_CLIENT_BEGIN,
    HSV2_DB,
    HSV2_USER,
    HSV2_OPTIONS,
    HSV2_TTY,
    HSV2_REMOTE_PID,
    HSV2_PRIOR_PID,
    HSV2_CLIENT_TYPE,    // nzload,...
    HSV2_PROTOCOL,
    HSV2_HOSTCASE,       // 10

    HSV2_SSL_NEGOTIATE,  // 11
    HSV2_SSL_CONNECT,

    HSV2_CLIENT_DONE = 1000,
    HSV2_SERVER_BEGIN,
    HSV2_PWD,
    HSV2_SERVER_DONE = 2000
} nz_hs_v2opcode_t;

// NZ Client Types
typedef enum
{
    CLIENT_TYPE_LIBPQ = 1,
    CLIENT_TYPE_ODBC,
    CLIENT_TYPE_JDBC,
    CLIENT_TYPE_CLI,
    CLIENT_TYPE_NZLOAD,
    CLIENT_TYPE_NZBACKUP,
    CLIENT_TYPE_NZRESTORE
} nz_client_type_codes;



// Authentication requests sent by the backend.
// (Note: if change here, update Auth2String())

#define AUTH_REQ_OK         0   /* User is authenticated  */
#define AUTH_REQ_KRB4       1   /* Kerberos V4 */
#define AUTH_REQ_KRB5       2   /* Kerberos V5 */
#define AUTH_REQ_PASSWORD   3   /* Password */
#define AUTH_REQ_CRYPT      4   /* Encrypted password */
#define AUTH_REQ_MD5        5   /* Encrypted password using MD5 */

//----------------------------------------------------------------------
// NZ Messages 
//   - format on the wire is Little Endian (allegedly)
//   - this was chosen because the majority of their clients and their
//     host machine are Intel hardware
//----------------------------------------------------------------------

typedef struct NzVersion
{
    tz_uint32 length;    // includes length bytes
    tz_uint16 opcode;
    tz_uint16 version;

} PACKED NzVersion;

typedef struct NzHsMsg    // base level Nz handshake msg header
{
    tz_uint32 length;     // includes length bytes
    tz_uint16 opcode;     // 
    tz_int8   data[];     // message payload, string or int

} PACKED NzHsMsg;

typedef struct NzAuth     // 'R'
{
    tz_uint8 opcode;
    tz_uint32 type;

} PACKED NzAuth;

typedef struct NzMsg      // base level Nz msg header (Query phase)
{
    tz_uint8  opcode;     // 
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // includes length bytes

} PACKED NzMsg;

typedef struct NzBackendKeyData
{
    tz_uint8  opcode;     // 'K'
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes (just data following)
    tz_uint32 pid;
    tz_uint32 key;

} PACKED NzBackendKeyData;

typedef struct NzError
{
    tz_uint8  opcode;     // 'E'
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes (just data following)
    tz_int8   data[];     // error string text

} PACKED NzError;

typedef struct NzQuery    // 'Q'
{
    tz_uint8  opcode;     // 'Q'
    tz_uint32 cmdNum;     // 
    tz_int8   data[];     // SQL text

} PACKED NzQuery;

typedef struct NzPortal   // from server, returned result set
{
    tz_uint8  opcode;     // 'P'
    tz_uint32 cmdNum;     // 
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // SQL text

} PACKED NzPortal;

typedef struct NzParse    // from client, 
{
    tz_uint8  opcode;     // 'P'
    tz_uint32 cmdNum;     // 
    tz_int8   data[];     // SQL text

} PACKED NzParse;

typedef struct NzRowDesc
{
    tz_uint8  opcode;     // 'T'
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // descriptor list

} PACKED NzRowDesc;

typedef struct NzDataRow
{
    tz_uint8  opcode;     // 'D' ASCII data row
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // descriptor list

} PACKED NzDataRow;

typedef struct NzBinDataRow
{
    tz_uint8  opcode;     // 'B' binary data row
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // descriptor list

} PACKED NzBinDataRow;

typedef struct NzDbosExtTup
{
    tz_uint8  opcode;     // 'X' ASCII data row
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // descriptor list

} PACKED NzDbosExtTup;

typedef struct NzDbosTup
{
    tz_uint8  opcode;     // 'Y' ASCII data row
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // descriptor list

} PACKED NzDbosTup;

typedef struct NzEmptyQueryResp
{
    tz_uint8  opcode;     // 'I'
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_uint8  code;       // expect '\0'

} PACKED NzEmptyQueryResp;

typedef struct NzClose
{
    tz_uint8  opcode;     // 'C'
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // descriptor list

} PACKED NzClose;

typedef struct NzRdyQuery
{
    tz_uint8  opcode;     // 'Z'  Ready For Query
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes

} PACKED NzRdyQuery;

typedef struct NzNotice
{
    tz_uint8  opcode;     // 'N'  Notice
    tz_uint32 cmdNum;     //
    tz_uint32 length;     // EXCLUDES length bytes
    tz_int8   data[];     // message

} PACKED NzNotice;

typedef struct NzTerminate
{
    tz_uint8  opcode;     // 'X' to backend
    tz_uint8  value;

} PACKED NzTerminate;

//----------------------------------------------------------------------
// Standard Postgres Messages
//----------------------------------------------------------------------

typedef struct PgStartupMsg
{
    tz_uint32 length;    // includes length bytes
    tz_uint32 protVer;   // 196608, 0x00030000
    tz_int8   data[];    // type:value pairs
                         // type (user, database, options)
                         // followed by parameter value

} PACKED PgStartupMsg;

typedef struct PgMsg      // base level Postgres msg header
{
    tz_uint8  opcode;     // 
    tz_uint32 length;     // includes length bytes

} PACKED PgMsg;

typedef struct PgAuth    // base level Authentication msg header
{                        // (issued by server)
    tz_uint8  opcode;    // 'R'
    tz_uint32 length;    // includes length bytes
    tz_uint32 authType;  // auth subtype

} PACKED PgAuth;

typedef struct PgAuthOk
{
    tz_uint8  opcode;    // 'R'
    tz_uint32 length;    // includes length bytes
    tz_uint32 authType;  // 0 == success

} PACKED PgAuthOk;

typedef struct PgAuthKrbV5
{
    tz_uint8  opcode;      // 'R'
    tz_uint32 length;      // includes length bytes
    tz_uint32 authType  ;  // 2 == auth required

} PACKED PgAuthKrbV5;

typedef struct PgAuthCleartextPwd
{
    tz_uint8  opcode;    // 'R'
    tz_uint32 length;    // includes length bytes
    tz_uint32 type;      // 3 == cleartext pwd required

} PACKED PgAuthCleartextPwd;

typedef struct PgAuthMd5Pwd
{
    tz_uint8  opcode;    // 'R'
    tz_uint32 length;    // includes length bytes
    tz_uint32 authType;  // 5 == MD5-encrypt pwd required
    tz_int8   data[];    // salt value

} PACKED PgAuthMd5Pwd;

// Other AuthTypes: SCMCredential, GSS, SSPI, GSSContinue
//        authType:     6           7    9       8

typedef struct PgPwdMsg
{
    tz_uint8  opcode;    // 'p'
    tz_uint32 length;    // includes length bytes
    tz_int8   data[];

} PACKED PgPwdMsg;

typedef struct PgParmStatus
{
    tz_uint8  opcode;     // 'S'
    tz_uint32 length;     // includes length bytes
    tz_int8   parmName[];
    tz_int8   parmVal[];

} PACKED PgParmStatus;

typedef struct PgBackendKeyData
{
    tz_uint8  opcode;     // 'K'
    tz_uint32 length;     // includes length bytes
    tz_uint32 pid;
    tz_uint32 key;

} PACKED PgBackendKeyData;

typedef struct PgReadyForQuery
{
    tz_uint8  opcode;     // 'Z'
    tz_uint32 length;     // includes length bytes
    tz_uint8  status;     // 'I' idle (not in transaction block),
                          // 'T' transaction block,
                          // 'E' failed transaction
} PACKED PgReadyForQuery;

typedef struct PgParse
{
    tz_uint8  opcode;     // 'P'
    tz_uint32 length;     // includes length bytes
    tz_int8   statement[];// name of destination prepared statement
    tz_int8   query[];    // query string to be parsed
    tz_uint16 parms;      // trailing tz_uint32 oid for each parm

} PACKED PgParse;

typedef struct PgBind
{
    tz_uint8  opcode;     // 'B'
    tz_uint32 length;     // includes length bytes
  tz_int8  portal[];
  tz_int8  statement[];
  tz_uint16 parmFormats;
  tz_uint16 parmValues;

  // more payload here...

} PACKED PgBind;

typedef struct PgDescribe
{
    tz_uint8  opcode;     // 'D'
    tz_uint32 length;     // includes length bytes
    tz_uint8   value;      // 'S' prepared statement, 'P' portal

} PACKED PgDescribe;

typedef struct PgExecute
{
    tz_uint8  opcode;     // 'E'
    tz_uint32 length;     // includes length bytes
    tz_int8   portal[];   // (string)
    tz_uint32 maxRows;    // 0 == no limit

} PACKED PgExecute;

typedef struct PgSync
{
    tz_uint8  opcode;     // 'S'
    tz_uint32 length;     // (4) includes length bytes

} PACKED PgSync;

/*
typedef struct
{
    tz_uint8  opcode;     // '?'
    tz_uint32 length;     // includes length bytes
} PACKED
*/

// Handler Types (used by IdentifyHandler)
typedef enum
{
    HndOther,
    HndProcessSync,
    HndNzProcessResync,
    HndNzProcessStreamMode,
    HndNzProcessResyncCont,
    HndNzProcessHandshake,
    HndNzProcessAuth,
    HndNzProcessNullSsn,
    HndNzProcessLoadUnload,
    HndNzProcessQuery,
    HndNzProcessQueryCont,
} PgHandlerType;


//======================================================================
// Buffer Manager
//     SQL strings are stored in linked lists of these elements.  Each
//     element is a total size of PGSQL_BUFMGR_BUFSIZE and the beginning
//     portion of the block contains the next pointer and a length
//     value.  The remainder of the area is for data storage.
//======================================================================
#define PGSQL_BUFMGR_BUFSIZE   2048      // page size, fits an Eth MTU

#define PGSQL_BUFMGR_MAX_LEN  (  PGSQL_BUFMGR_BUFSIZE               \
                               - sizeof(PgSqlDataBuf *)             \
                               - sizeof(tz_uint16))

typedef struct PgSqlDataBuf
{
    PgSqlDataBuf *next;
    tz_uint16     len;
    tz_int8       data[PGSQL_BUFMGR_MAX_LEN];

}  __attribute__((packed)) PgSqlDataBuf;


class PgDecode;

//-----------------------------------------------------------------------
// PgInfo (AppInfo) per-session data
//-----------------------------------------------------------------------
typedef struct PgInfo
{
    // Decoder Session ID number (for debugging)
    tz_uint32 sessionIdNum;
    tz_uint32 pktCount;
    tz_uint32 cpCount;      // codepoint count this state

    // Event data
    tz_uint32     evtRespBytes;
    tz_uint32     evtRespRows;
    tz_uint32     evtCmdNum;      // The pending command number
    PgHandlerType evtPrevHnd;     // prior to a TCP hole

    struct evtStatus
    {
        tz_uint16 evtIsComplete      : 1; // both client and server seen
        tz_uint16 evtIsIssued        : 1; // to Mantra database
        tz_uint16 unused1            : 1;
        tz_uint16 unused2            : 1;
        tz_uint16 evtRespStatus      : 4; // successful, failed, ...
        tz_uint16 unused3            : 8;
    } evtStatus;

    // Content Scanners
    ContentScanner *clientCs;          // client-to-server command requests
    ContentScanner *serverCs;          // server-to-client server responses

    // NzStreamMode counters
    tz_uint32 streamModeTotExpected;
    tz_uint32 streamModeTotRemaining;
    tz_uint8 streamModeCodepoint;

    // Session characteristics
    tz_uint8 ssnIsSecured;
    tz_uint8 nzClientType;

    // Parser state
    tz_uint32 connState;

    // SQL Buffer Chain
    tz_uint32     bufMgrBufCount; // Current number allocated buffers
    PgSqlDataBuf *bufMgrHead;     // First buffer in current chain
    PgSqlDataBuf *bufMgrTail;     // Last buffer in current chain

    // Session Detail data structure
    SessionDetail *sd;

    // Session Buffer layer
    SsnBuf *ssnBuf;   

    // Current message handler
    bool (PgDecode::*handler)(SessionEntry *se);

} PgInfo;

//-----------------------------------------------------------------------
// class PgDecode
//-----------------------------------------------------------------------

class PgDecode
{
public:

    // -- Public Functions --

    PgDecode(NetMonDriver *nmd, EncodingEngine *ee);
    ~PgDecode();

    // SessionEntry appInfo
    PgInfo *CreateProtocolData( SessionEntry * se );
    void DeleteProtocolData( SessionEntry *se );

    tz_uint32 PostgresProcess( SessionEntry *se,
                               const u_char *data, 
                               tz_uint32     length,
                               tz_uint32     tcpHole );

    void SumDecodeStats( void *context);
    static tz_int8 *GenerateDump( void );
    tz_uint32 GetTotSessionsUnsecured( void ) 
        { return decodeStats.totSessionsUnsecured; }
    tz_uint32 GetTotSessionsSecured( void )
        { return decodeStats.totSessionsSecured; }
    tz_uint32 GetTotSessionsIgnored( void )
        { return decodeStats.totSessionsIgnored; }
    tz_uint32 GetTotSessionsNull( void )
        { return decodeStats.totSessionsNull; }

    // D E B U G
    tz_uint32 PostgresTest( SessionEntry *se,
                            const u_char *data, 
                            tz_uint32     length,
                            tz_uint32     tcpHole );
    char *ShowNetmonDebugNz(const char *substring);

    // -- Public Data --

    // Content Scanner Pattern Matchers
    PatternManager *rspDataPatMgr;
    PatternManager *cmdDataPatMgr;

    // packet counters
    tz_uint32 pgClientPkts;
    tz_uint32 pgServerPkts;

private:

    // -- Private Functions --

    // Event related
    tz_uint32 CopyDimString(tz_int8 *dst, tz_int8 *src, tz_uint32 max);
    void NormalizeString(tz_int8 *stg);
    SessionDetail *CreateSessionDetail(SessionEntry *sessionEntry);
    void PrepareEvent( SessionEntry *sessionEntry );
    void InjectEvent ( SessionEntry    *sessionEntry,
                       DimValListEntry *contentListEntry,
                       DimValListEntry *operationListEntry,
                       DimValListEntry *commandDataListEntry,
                       DimValListEntry *responseDataListEntry,
                       DimValListEntry *responseEntry,
                       DimValListEntry *sizeEntry,
                       tz_int8         *commandStg,
                       tz_uint8         isCompleteEvt,
                       tz_uint8         loginIsSuccess);
    void InjectFailedLogin( SessionEntry *sessionEntry,
                            tz_int8      *command);

    // Generic handlers
    bool ProcessSync(SessionEntry *se);

    // Postgres specific handlers
    bool PgProcessStartupMsg(SessionEntry *se);
    bool PgDispatchMsg(SessionEntry *se);
    bool PgProcessAuthMsg(SessionEntry *se, tz_uint32 msgLen);
    bool PgProcessPwdMsg(SessionEntry *se, tz_uint32 msgLen);
    bool PgProcessParseMsg(SessionEntry *se, tz_uint32 msgLen);
    bool PgProcessParmStatus(SessionEntry *se, tz_uint32 msgLen);
    bool PgProcessMsgHeader(SessionEntry *se, tz_uint32 msgLen);

    // Netezza specific handlers 
    // (NOTE: new ones affect PgHandlerType and IdentifyHandler() )
    bool NzProcessResync(SessionEntry *se);
    bool NzProcessResyncCont(SessionEntry *se);
    bool NzProcessStreamMode(SessionEntry *se);
    bool NzProcessHandshake(SessionEntry *se);
    bool NzProcessAuth(SessionEntry *se);
    bool NzProcessNullSsn(SessionEntry *se);
    bool NzProcessLoadUnload(SessionEntry *se);
    bool NzProcessQuery(SessionEntry *se);
    bool NzProcessQueryCont(SessionEntry *se);

    PgHandlerType IdentifyHandler(SessionEntry *se);
    bool VersionIsValid(tz_uint16 ver);

    // SQL buffer manager
    void pgSqlBufMgrInit( SessionEntry *se );
    tz_uint32 pgSqlBufMgrAlloc( SessionEntry *se,
                                tz_uint32     len,
                                tz_int8     **buf );
    void pgSqlBufMgrFree( SessionEntry *se );

    // Debug
    void DumpPkt(SessionEntry *se, tz_int8 *data, tz_uint32 length);
    void TrapUnknown(tz_uint8 opcode);
    void TrapUnderflow();
    char *Auth2String(tz_uint32 type);
    char *State2String(SessionEntry *se);
    char *ClientType2String(tz_uint32 type);


    // -- Private Data --

    NetMonDriver   *netMonDriver;
    EncodingEngine *encEng;

    bool (PgDecode::*handler)(SessionEntry *se);

    // Session ID number (for debugging)
    tz_uint32 sessionIdNum;

    // "show netmon debug" variables
    static bool dbgLvl0;
    static bool dbgLvl1;
    static bool dbgDump;

    // Global statistics counters (summed across each instance)
    // The instantaneous ones are to determine if sessions are getting
    // stuck in a particular state (decoder correctness).  The total
    // ones are for user consumption.
    struct DecodeStats
    {
        tz_uint32 sessionsNotLoggedIn;     // instantaneous
        tz_uint32 sessionsLoggedIn;        //      "
        tz_uint32 sessionsHandshake;       //      "
        tz_uint32 sessionsAuth;            //      "
        tz_uint32 sessionsSsl;             //      "
        tz_uint32 totSessionsUnsecured;    //    total
        tz_uint32 totSessionsSecured;      //      "
        tz_uint32 totSessionsIgnored;      //      "
        tz_uint32 totSessionsNull;         //      "
        tz_uint32 unknownCodepoints;
        tz_uint32 tcpHoles;
        tz_uint32 eventsPartial;
        tz_uint32 ssnBufMaxBlocks;
        tz_uint32 sqlBufMaxBlocks;
        tz_uint32 syncLost;
        tz_uint32 syncResyncSuccess;
        tz_uint32 sslErrors[TTAS_ENUM_COUNT];

    } decodeStats;

};  // class PgDecode


#endif



