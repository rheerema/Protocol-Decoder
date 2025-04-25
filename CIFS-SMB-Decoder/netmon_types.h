//-----------------------------------------------------------------------
//   Copyright (c) <2003> by Tizor Sysiems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   Created:  22 Oct 2003
//
//   Log:
//
//   Date         Person  Comment 
//   ----         ------  ------- 
//   22 Oct 2003   peter  created 
//   23 June 2005  mostman clean up and merge with other header files 
//
//-----------------------------------------------------------------------


#ifndef __NETMON_TYPES_H__
#define __NETMON_TYPES_H__

#include <sys/types.h>
#include <tizor_types.h>
#include <sys/time.h>
#include <util/tz_watch.h>
// #include <pcap.h>  // This include breaks the tallmaple build...

// Definitions for various MAX sizes
#define TZX_MAXIMUM_USERS        4096 
#define LARGEST_PCAP_FILTER      4096
#define TZX_LARGEST_AUTH_STRING  129
#define TZX_1024_STRING          1024
#define TZX_512_STRING           512
#define TZX_128_STRING           128
#define TZX_64_STRING            64
#define MAX_COMMAND_STRING       1098304

// Flow directions
#define TRAFFIC_FROM_SERVER  0
#define TRAFFIC_FROM_CLIENT  1
#define TRAFFIC_FROM_PEER(direction) (TRAFFIC_FROM_CLIENT - (direction))
                  
// Descriptor packet source
//   NONE => Descriptor not in use
//   NIC  => Packet is from local network interface (ie mon0)
//   TAP  => Packet is from tap remote agent
//   FILE => Packet is read from cap file (debug only)
typedef tz_uint16 PacketSrc_t;
#define PACKET_SRC_NONE     0
#define PACKET_SRC_NIC      1
#define PACKET_SRC_TAP      2
#define PACKET_SRC_FILE     3
#define PACKET_SRC_LOCAL    4

// Pending protocol command types
#define ADD_PROTOCOL 1
#define DELETE_PROTOCOL 2

// Pending protocol entry types
#define PROTOCOL_TYPE_PORT  1
#define PROTOCOL_TYPE_PIPE  2

// LayerManager dispatch counters/settings
#define MANAGEMENT_SLEEP_USECS  500000
#define MANAGEMENT_AGE_LIMIT    (120*1000000)/MANAGEMENT_SLEEP_USECS
#define DEFAULT_EXPECTED_TIMEOUT 120
#define DEFAULT_SESSION_TIMEOUT 900
#define CLOSED_SESSION_TIMEOUT  2

// Session TCP flags:
// What have we already encountered in this "direction"
#define SESS_FIN        0x01    // FIN seen
#define SESS_SYN        0x02    // SYN seen
#define SESS_FIN_ACK    0x04    // FIN has been acked
#define SESS_QUEUED     0x08    // segments queued.

// Dimensions we support - Content,Operation,Session have base values because
// they also have stand alone enumerations in the database.  These _must_ be
// ordered just as they are in the database
#define CONTENT_BASE                 100
#define TZX_CONTENT                  101
#define TZX_CONTENT_TABLE            102
#define TZX_CONTENT_COL              103
#define TZX_CONTENT_FILENAME         104
#define TZX_CONTENT_FILEPATH         105
#define TZX_CONTENT_FILEEXT          106
#define TZX_CONTENT_FOLDERNAME       107
#define TZX_CONTENT_SHARENAME        108
#define TZX_CONTENT_FILEATTR         109

#define OPERATION_BASE               200
#define TZX_OPERATION                201
#define TZX_OPERATION_SQL            202
#define TZX_OPERATION_PROCEDURE      203
#define TZX_OPERATION_FILE           204
#define TZX_OPERATION_PROCPARAM      205

#define SESSION_BASE                 300
#define TZX_SESSION_CLIENTPID        301
#define TZX_SESSION_LOGINSUCCESS     302
#define TZX_SESSION_PROGRAMNAME      303
#define TZX_SESSION_SERVERINFO       304
#define TZX_SESSION_SERVERTYPE       305
#define TZX_SESSION_SERVERVERSION    306
#define TZX_SESSION_SERVERAPP        307
#define TZX_SESSION_CLIENTIP         308
#define TZX_SESSION_CLIENTPORT       309
#define TZX_SESSION_SERVERIP         310
#define TZX_SESSION_SERVERPORT       311
#define TZX_SESSION_HOSTUSER         312
#define TZX_SESSION_SERVERUSER       313
#define TZX_SESSION_SOURCE           314
#define TZX_SESSION_MARKER           315
#define TZX_SESSION_SOURCENAME       316

#define EVENT_BASE                   350

#define RESPONSE_BASE                400
#define TZX_RESPONSE_STATUS          401
#define TZX_RESPONSE_DATA            402

#define TZX_SIZE                     501
#define TZX_SIZE_BYTES               502
#define TZX_SIZE_ROWS                503

#define TZX_HOUR                     600

#define COMMAND_BASE                 700
#define TZX_COMMAND_TEXT             701
#define TZX_COMMAND_DATA             702

// An enum of the above dimensions (for passing to functions)
typedef enum DimensionTypes {
 NullType                 = 0,
 ContentType              = TZX_CONTENT,
 ContentTableType         = TZX_CONTENT_TABLE,
 ContentColumnType        = TZX_CONTENT_COL,
 ContentFileNameType      = TZX_CONTENT_FILENAME,
 ContentFolderNameType    = TZX_CONTENT_FOLDERNAME,
 ContentFilePathType      = TZX_CONTENT_FILEPATH,
 ContentFileExtType       = TZX_CONTENT_FILEEXT,
 ContentShareNameType     = TZX_CONTENT_SHARENAME,
 ContentFileAttrType      = TZX_CONTENT_FILEATTR,
 OperationType            = TZX_OPERATION,
 OperationSqlType         = TZX_OPERATION_SQL,
 OperationProcedureType   = TZX_OPERATION_PROCEDURE,
 OperationFileType        = TZX_OPERATION_FILE,
 OperationProcparamType   = TZX_OPERATION_PROCPARAM,
 ResponseStatusType       = TZX_RESPONSE_STATUS,
 ResponseDataType         = TZX_RESPONSE_DATA,
 SizeType                 = TZX_SIZE,
 SizeBytesType            = TZX_SIZE_BYTES,
 SizeRowsType             = TZX_SIZE_ROWS,
 SessionClientIPType      = TZX_SESSION_CLIENTIP,
 SessionClientPortType    = TZX_SESSION_CLIENTPORT,
 SessionClientPIDType     = TZX_SESSION_CLIENTPID,
 SessionProgramNameType   = TZX_SESSION_PROGRAMNAME,
 SessionHostUserType      = TZX_SESSION_HOSTUSER,
 SessionServerUserType    = TZX_SESSION_SERVERUSER,
 SessionServerIPType      = TZX_SESSION_SERVERIP,
 SessionServerPortType    = TZX_SESSION_SERVERPORT,
 SessionServerTypeType    = TZX_SESSION_SERVERTYPE,
 SessionServerVersionType = TZX_SESSION_SERVERVERSION,
 SessionServerInfoType    = TZX_SESSION_SERVERINFO,
 SessionServerAppType     = TZX_SESSION_SERVERAPP,
 SessionLoginSuccessType  = TZX_SESSION_LOGINSUCCESS,
 SessionMarkerType        = TZX_SESSION_MARKER,
 HourType                 = TZX_HOUR,
 CommandTextType          = TZX_COMMAND_TEXT,
 CommandDataType          = TZX_COMMAND_DATA,
 SessionSourceType        = TZX_SESSION_SOURCE,
 SessionSourceNameType    = TZX_SESSION_SOURCENAME
} DimensionTypes;

typedef enum encEngineEventType {
    ENCENGINE_EVENT_FAILEDLOGIN = 1,
    ENCENGINE_EVENT_UNSUPPORTED,
    ENCENGINE_EVENT_NORMAL
} EncEngineEventType;

typedef enum eventMatchEnum {
 EVENT_MATCH_RESPONSE_STATUS = 1,
 EVENT_MATCH_SIZE_BYTES,
 EVENT_MATCH_SIZE_ROWS,
 EVENT_MATCH_HOUR,
 EVENT_MATCH_COMMAND_TEXT,
 EVENT_MATCH_RESPONSE_DATA,
 EVENT_MATCH_COMMAND_DATA
} EventMatchEnum;

typedef enum matchTypeEnum {
 MATCH_TYPE_NONE = 1,
 MATCH_TYPE_SIG,
 MATCH_TYPE_RARE,
 MATCH_TYPE_NEW,
 MATCH_TYPE_LARGE,
 MATCH_TYPE_PATTERN
} MatchTypeEnum;

typedef enum sessionStateEnum {
 SESSION_STATE_IDLE = 1,
 SESSION_STATE_READY,
 SESSION_STATE_BUSY,
 SESSION_STATE_DONE
} SessionStateEnum;

typedef enum sessionOperEnum {
 SESSION_OPER_PROCESS_PKT = 1,
 SESSION_OPER_CLOSE_SESSION,
 SESSION_OPER_RESET_SESSION,
 SESSION_OPER_AGE_SESSION,
 SESSION_OPER_AGE_SEGMENTS
} SessionOperEnum;

typedef enum blockStateEnum {
 BLOCK_STATE_NONE = 0,
 BLOCK_STATE_TRIGGER,
 BLOCK_STATE_PENDING,
 BLOCK_STATE_SUCCESS,
 BLOCK_STATE_FAILURE
} BlockStateEnum;

typedef enum blockActionEnum {
 BLOCK_ACTION_NONE = 0,
 BLOCK_ACTION_TAP_PROXY,
 BLOCK_ACTION_TAP_NOPROXY,
 BLOCK_ACTION_LOCAL_SNIPE,
 BLOCK_ACTION_SIZE
} BlockActionEnum;

typedef enum blockResultEnum {
    BLOCK_RESULT_NONE = 0,                      // Result not yet known
    BLOCK_RESULT_SUCCESS_ETAP_PROXY,            // Etap blocked proxy session
    BLOCK_RESULT_SUCCESS_ETAP_TCP,              // Etap blocked TCP session
    BLOCK_RESULT_SUCCESS_RST_SEEN,              // Netmon saw RST packet
    BLOCK_RESULT_SUCCESS_SYN_SEEN,              // Netmon saw SYN packet
    BLOCK_RESULT_SUCCESS_APP_TIMEOUT,           // App timed out with no new data
    BLOCK_RESULT_FAILURE_FIN_SEEN,              // Hosts gracefully terminated session
    BLOCK_RESULT_FAILURE_DATA_SEEN,             // Data seen on session after wait period
    BLOCK_RESULT_FAILURE_SNIPE_ERROR,           // Couldn't send snipes to either host
    BLOCK_RESULT_FAILURE_ETAP_ERROR,            // Etap block command did not complete
    BLOCK_RESULT_FAILURE_ETAP_PROXY_INACTIVE,   // Proxy not active
    BLOCK_RESULT_FAILURE_ETAP_PROXY_NOT_FOUND,  // Proxy could not find TCP session
    BLOCK_RESULT_FAILURE_ETAP_TCP_NOT_FOUND,    // Etap TCP syscall could not find session
    BLOCK_RESULT_FAILURE_ETAP_TCP_ERROR,        // Etap TCP syscall returned error
    BLOCK_RESULT_FAILURE_ETAP_TCP_RESET_ERROR,  // Etap TCP reset send failed
    BLOCK_RESULT_FAILURE_ETAP_ACCESS_DENIED,    // Etap insufficient privilege to block session
    BLOCK_RESULT_FAILURE_ETAP_NOT_SUPPORTED,    // Etap blocking not supported on platform
    BLOCK_RESULT_SIZE
} BlockResultEnum;

// Map table names
#define MAP_CONTENT   "contentMap"
#define MAP_OPERATION "operationMap"
#define MAP_SESSION   "sessionMap"

// used for server.application
#define PROTOCOL_TNS_STR        "1"
#define PROTOCOL_SMB_STR        "2"
#define PROTOCOL_TDS_MS_SS_STR  "3"
#define PROTOCOL_TDS_SYBASE_STR "4"
#define PROTOCOL_DRDA_STR       "5"
#define PROTOCOL_NETEZZA_STR    "6"
#define PROTOCOL_LAA_STR        "7"

#define PROTOCOL_NULL        0
#define PROTOCOL_TNS         1
#define PROTOCOL_SMB         2
#define PROTOCOL_TDS_MS_SS   3
#define PROTOCOL_TDS_SYBASE  4
#define PROTOCOL_DRDA        5
#define PROTOCOL_NETEZZA     6  // last "real" protocol adapter
#define PROTOCOL_LAA         7  // a "fake" procol adapter
#define PROTOCOL_IGNORE      8
#define PROTOCOL_VALID_COUNT 8  
#define PROTOCOL_COUNT       9  // includes "default" index= 0

// used for session.source
#define SOURCE_INTERFACE  1
#define SOURCE_LOCAL      2
#define SOURCE_TAP        3
#define SOURCE_ENFORCER   4

#define SOURCE_INTERFACE_STR  "1"
#define SOURCE_LOCAL_STR      "2"
#define SOURCE_TAP_STR        "3"
#define SOURCE_ENFORCER_STR   "4"

// used for session.loginSuccess
#define LOGIN_SUCCESS_TRUE  1
#define LOGIN_SUCCESS_FALSE 2

// used for server.type
#define SERVER_DATABASE_STR "1"
#define SERVER_FILE_STR     "2"
#define SERVER_UNKNOWN_STR  "3"

#define SERVER_DATABASE 1
#define SERVER_FILE     2
#define SERVER_UNKNOWN  3

// used for response dimension
#define SUCCESSFUL_OPERATION           1
#define FAILED_OPERATION               2
#define FAILED_QUERY_DOESNT_EXIST      3
#define FAILED_OPERATION_NO_PERMISSION 4
#define FAILED_OPERATION_DUPLICATE     5
#define UNKNOWN_OPERATION              6
#define KILL_OPERATION                 7
#define MONITOR_OPERATION              8

// used by the driver to indicate how a session was terminated
#define SESSION_CLOSE_CLEAN 1
#define SESSION_CLOSE_AGE   2

// used for event command types
#define EVENT_LOGIN      1
#define EVENT_OPERATION  2
#define EVENT_UNKNOWN    3
#define EVENT_LOGOUT     4
#define EVENT_ENFORCER   5

// This is copied from /usr/include/pcap.h and converted to tz types
struct tz_pcap_pkthdr 
{
    struct timeval ts;  // time stamp
    tz_uint32 caplen;   // length of portion present
    tz_uint32 len;      // length this packet (off wire)
};

// SessionBlocker counters type. 
typedef struct
{
    tz_uint32       successCnt;             // Cnt of session blocking successes
    tz_uint32       failureCnt;             // Cnt of session blocking failures
    tz_uint32       etapCtxtCreate;         // Cnt of Etap contexts created
    tz_uint32       etapCtxtDelete;         // Cnt of Etap contexts deleted

    tz_uint32       clientPktCnt;           // Client pkts since trigger
    tz_uint32       serverPktCnt;           // Server pkts since trigger
    tz_uint32       clientRstCnt;           // Client-sent Resets since trigger
    tz_uint32       serverRstCnt;           // Server-sent Resets since trigger
    tz_uint32       etapRstToClientCnt;     // Etap snipes to client monitored
    tz_uint32       etapRstToServerCnt;     // Etap snipes to server monitored
    tz_uint32       mantraRstToClientCnt;   // Mantra snipes to client monitored
    tz_uint32       mantraRstToServerCnt;   // Mantra snipes to server monitored
} blocker_cntrs_t;

// DriverCounters
//
// These counters are always incremented by a single thread. There is only
// one instance of the counters per packet source, and the instance is 
// pointed to by the packet descriptor. These counters should NEVER be 
// touched by a worker thread!
typedef struct {
    tz_uint16 index;                // Same as sourceId
    tz_uint32 pktRefCnt;            // Number of outstanding pkts
    tz_uint32 overSizeLength;       // longest oversize frame 

    tz_uint64 inBytes;
    tz_uint64 inBytesLast;
    tz_uint64 inPackets;
    tz_uint64 inPacketsLast;
    tz_uint64 inIpPackets;
    tz_uint64 inTcpPackets;
    tz_uint64 inNonIpPackets;
    tz_uint64 inNonTcpPackets;
    tz_uint64 monitoredPackets;
    tz_uint64 monitoredPacketsLast;
    tz_uint64 monitoredBytes;
    tz_uint64 monitoredBytesLast;
    tz_uint64 fragments;            // fragments ignored
    tz_uint64 droppedBufferOverflow;// Out of buffer mem
    tz_uint64 undersizeIpPackets;   // caplen < ip_len
    tz_uint64 oversizePackets;      // caplen < pcapLength.
    tz_uint64 sessions;             // Number of active sessions
    tz_uint64 totalSessions;
    tz_uint64 tooManySessions;      // unmatched session && activeSessions at limit
    tz_uint64 midFlows;             // did not see SYN-handshake.
    tz_uint64 agedSessions;         // sessions terminated by age
    tz_uint64 ignoredSegments;      // segments of non-monitored flows

    blocker_cntrs_t blockCntrs;     // Session blocking counters per interface
    tz_uint32       blockActionHist[BLOCK_ACTION_SIZE]; // Session blocking action histogram
    tz_uint32       blockResultHist[BLOCK_RESULT_SIZE]; // Session blocking result histogram
} DriverCounters;

// WorkerCounters
//
// These counters are maintained by the workers. Each worker thread has
// one instance of the counters per packet source. They must be summed 
// over the workers to display the aggregate counts.
typedef struct {
    tz_uint64 packetsProcessed;
    tz_uint64 finSessions;
    tz_uint64 rstSessions;
    tz_uint64 dupSegments;        // == seq/length as last delivered seg
    tz_uint64 overlapSegments;    // overlap with another buffered seg
    tz_uint64 gapSegments;        // gaps delivered to adaptors
    tz_uint64 reTxSegments;       // seq < expected
    tz_uint64 reassemblyActive;   // reassembly segments active
    tz_uint64 reassemblyOverflows;// reassembly queue exceeded max length
    tz_uint64 reassemblyTimeouts; // reassembly queue flushe due to timeout
    tz_uint64 reassemblyAck;      // peer acked missing segment
    tz_uint64 reassemblyTotal;    // buffered segments
    tz_uint64 segmentsDelivered;  // to decoder
    tz_uint64 badSessionDiscards; // segs discarded as EE marked session bad
    tz_uint64 supSegments;        // non-payload segments (ACKs, FIN, SYN, RST).
    tz_uint64 throttledSegments;  // throttled before decoder delivery by NM.
} WorkerCounters;

// A srcIp/srcPort/dstIp/dstPort TCP address tuple
// Address and port are network-ordered in sessionEntry.
// Tuple extended to include the source of the packet
typedef struct AddressTuple {
 tz_uint32      src;   // Source IP address      - network order
 tz_uint32      dst;   // Destination IP address - network order
 tz_uint16      sport; // Source port number     - network order
 tz_uint16      dport; // Destination port number- network order
 PacketSrc_t    pktSrc;   // packet source (NIC, LOCAL, TAP, FILE)
 tz_uint16      sourceId; // particular instance of source (ie. which TAP)
} AddressTuple;

// The list of interfaces that netmon is listening to
typedef struct MonitorPort {
  struct MonitorPort *next;
  char *interface;
} MonitorPort;

// The list of applications netmon is listening for
typedef struct ProtocolPortEntry {
 struct ProtocolPortEntry *prev;
 struct ProtocolPortEntry *next;
 tz_uint32 server; // Server address - host order
 tz_uint16 port;
 tz_uint32 application;
 tz_int8   *interface;  // Name of interface or tap
 tz_uint16 sourceId;
 tz_uint8  sourceType;
} ProtocolPortEntry;

// The list of proxied named pipe applications netmon is listening for
typedef struct ProtocolPipeEntry {
 struct ProtocolPipeEntry *prev;
 struct ProtocolPipeEntry *next;
 tz_int8   *pipeName;
 tz_uint32 application;
 tz_int8   *interface;  // Name of interface or tap
 tz_uint16 sourceId;
 tz_uint8  sourceType;
} ProtocolPipeEntry;

// Application changes that are waiting (from mgmtd) to be issued
typedef struct PendingProtocolEntry {
 tz_uint16 op;              // Add or delete
 tz_uint8  entryType;       // Type PORT or PIPE
 tz_uint8  sourceType;      // Type INTERFACE or TAP
 tz_int8   *interface;      // Name of interface or tap
 tz_uint32 application;

 // Pipe params
 tz_int8   *pipeName;       // Name of PIPE, null if PORT

 // Port params
 tz_uint32 server;          // Server address - host order
 tz_uint8  nullServer;
 tz_uint16 port;
 tz_uint8  nullPort;
} PendingProtocolEntry;

// A list of dimensional values for a particular type (CONTENT.TABLE) for example
typedef struct DimValListEntry {
 struct DimValListEntry *next;                       // next entry
 tz_uint32 type;                                     // what type of entry is this?
 tz_int8   stringValue[TZX_512_STRING];              // used when the value is a string
 tz_uint32 stringValueLength;                        // length of string value
 tz_uint32 numericalValue;                           // Encoding of string or numerical value
 tz_uint64 databaseId;                               // What Id this dimension will be assigned
 tz_uint32 databaseType;
 tz_uint32 referenceCount;                           // how many of these dimensional values
 tz_uint32 newStatsEntryFlag;                        // flag indicating this dim val is new to the stats table - used internally by stats engine
} DimValListEntry;

// a list of encodings for a particular dimension - as sent to the database
typedef struct dbEncoding {
 struct dbEncoding *next;
 tz_uint32         encID;
 tz_int8           *encValue;
 tz_uint8          type;
} DBEncoding;

// Created when an event triggers a policy
typedef struct policyMatch {
 struct policyMatch *next;
 struct policyMatch *prev;
 tz_uint64 eventId;
 tz_uint64 policyId;
 tz_uint64 actionId;
} PolicyMatch;

// Used to outline that a policy matched something in the eventDetail
typedef struct matchEventDetail {
 struct matchEventDetail *next;
 struct matchEventDetail *prev;
 tz_uint64 eventId;
 tz_uint64 policyId;
 EventMatchEnum dimension;
 MatchTypeEnum matchType;
 tz_uint64 actionId;
 double frequency; 
} MatchEventDetail;

// Used to outline that a policy matched something in the sessionDetail
typedef struct matchSessionDetail {
 struct matchSessionDetail *next;
 struct matchSessionDetail *prev;
 tz_uint64 eventId;
 tz_uint64 sessionId;
 tz_uint64 policyId;
 tz_uint32 dimension;
 MatchTypeEnum matchType;
 tz_uint64 actionId;
 double frequency;
} MatchSessionDetail;

// Used to outline that a policy matched some content/operation
typedef struct matchDimensionDetail {
 struct matchDimensionDetail *next;
 struct matchDimensionDetail *prev;
 tz_uint64 eventId;
 tz_uint64 dimensionId;
 tz_uint64 policyId;
 tz_uint32 dimension;
 MatchTypeEnum matchType;
 tz_uint64 actionId;
 double frequency;
} MatchDimensionDetail;

// Used to outline that a policy matched some PatternMatch
typedef struct matchPatternDetail {
 struct matchPatternDetail *next;
 struct matchPatternDetail *prev;
 tz_uint64 eventId;
 tz_uint64 policyId;
 tz_int8 *patternName;
 tz_int8 *dimension;
 tz_uint32 count;
 tz_uint64 actionId;
} MatchPatternDetail;

// an event - as sent to the database
typedef struct eventDetail {
 tz_uint64            id;
 tz_uint32            eventTime;
 tz_uint32            nativeTime;
 tz_uint8             eventHour;
 tz_uint64            sessionId;
 tz_int8              *command;
 tz_uint32            commandLength;
 tz_uint32            rowCount;
 tz_uint32            byteCount;
 tz_uint8             returnCode;
 tz_uint8             eventType;           // what kind of event is this (ie, login) 
 tz_uint8             dropFlag;            // did this event match only actions with drop enabled
 tz_uint8             unmatchedFlag;       // set when event does not match any policies
 tz_uint8             blockFlag;           // set when matched policy action is blockSession
 tz_uint8             unsupportedFlag;     // set when there is a parser error
 tz_uint8             redactedFlag;        // set when there command redaction
 tz_int8              *redactPolicy;       // the name of the policy that caused redaction
 tz_int8              *blockRule;          // ptr to rule (policy) that caused session block
 DimValListEntry      *content;            // the content for this event
 DimValListEntry      *operation;          // the operations for this event
 DimValListEntry      *commandData;        // the cs matches on command data for this event
 DimValListEntry      *responseData;       // the cs matches on response data for this event
 MatchEventDetail     *matchEventHead;     // head of list of matches on this event 
 MatchEventDetail     *matchEventTail;     // tail
 MatchDimensionDetail *matchContentHead;   // head of list of content matches on this event 
 MatchDimensionDetail *matchContentTail;   // tail
 MatchDimensionDetail *matchOperationHead; // head of list of operation matches on this event
 MatchDimensionDetail *matchOperationTail; // tail
 MatchSessionDetail   *matchSessionHead;   // head of list of matches on the session information
 MatchSessionDetail   *matchSessionTail;   // tail
 MatchPatternDetail   *matchPatternHead;   // head of list of pattern matches
 MatchPatternDetail   *matchPatternTail;   // tail
 PolicyMatch          *policyMatchesHead;  // head of list of policies this event matched
 PolicyMatch          *policyMatchesTail;  // tail
 tz_uint32            lastSequenceNumber;  // used for debugging - to identify this event in a capture file
 tz_uint32            cSequenceNumber;     // most recent client seq num
 tz_uint32            sSequenceNumber;     // most recent server seq num
} EventDetail;

// a session - as sent to the database
typedef struct sessionDetail {
 tz_uint64   id;
 tz_uint32   incomplete;            
 tz_uint8    loginSuccess;
 tz_uint8    loginEventIssued;
 // Login Event Control
 tz_uint8    lecModeIsDeferred;            // mode of operation
 tz_uint8    lecState;                     // current operational state
 void       *lecLoginEventDetail;
 void       *lecSessionEntry;
 // Session Parameters
 tz_uint8    source;
 tz_int8     sourceName[TZX_512_STRING];
 tz_uint32   sourceNameLength;
 tz_uint32   clientIP;
 tz_uint32   clientPort;
 tz_uint32   clientPID;
 tz_int8     sessionMarker[TZX_512_STRING];
 tz_uint32   sessionMarkerLength;
 tz_uint8    newMarker;
 tz_int8     programName[TZX_512_STRING];
 tz_uint32   programNameLength;
 tz_uint32   programNameEncoding;
 tz_int8     hostUser[TZX_512_STRING];
 tz_uint32   hostUserLength;
 tz_uint32   hostUserEncoding;
 tz_int8     serverUser[TZX_512_STRING];
 tz_uint32   serverUserLength;
 tz_uint32   serverUserEncoding;
 tz_int32    serverUserPersistentFlag;
 tz_uint32   serverIP;
 tz_uint32   serverPort;
 tz_uint8    serverType;
 tz_uint8    serverApplication;
 tz_int8     serverVersion[TZX_512_STRING];
 tz_uint32   serverVersionLength;
 tz_int8     serverInfo[TZX_512_STRING];
 tz_uint32   serverInfoLength;
} SessionDetail;


#define PACKET_DESC_FLAGS_ETAP_CONTEXT  1

// A Packet Descriptor is associated with every monitored packet. The start ptr
// is always the beginning of the packet (ptr to mac header) and is the value 
// that must be returned to the tz_ring when freeing the packet.
typedef struct PacketDesc_s {
    struct PacketDesc_s *next;
    struct PacketDesc_s *prev;
    const struct tz_pcap_pkthdr *pcapHdr;   // Pcap header ptr
    tz_uint8            *start;     // Beginning of packet (pass this to Free)
    tz_uint8            *data;      // Current place in packet
    tz_uint8            *ipHdr;     // Ptr to IP header in packet
    tz_uint8            *tcpHdr;    // Ptr to TCP header in packet
    DriverCounters      *counters;  // Ptr to counters for source of pkt
    tz_uint16           dataLen;    // Valid bytes at data ptr
    PacketSrc_t         pktSrc;     // packet source (NIC, LOCAL, TAP, FILE)
    tz_uint16           sourceId;   // instance of source (ie. which TAP)
    tz_uint8            trafficDirection;   // TRAFFIC_FROM_{CLIENT, SERVER}
    tz_uint8            flags;      // PACKET_DESC_FLAGS_*
} PacketDesc;

typedef struct {
    PacketDesc          *head;  // Older pkts
    PacketDesc          *tail;  // Newer pkts
    tz_uint16           cnt;    // Num pkts on queue
} PacketDescQueue;
    
// a buffered (possibly partial) segment pending the arrival of
// segments "earlier" in the sequence space.
// We retain the "original" length and sequenceNumber of the segment,
// even though we may not retain the data, for comparison with the
// most recent segment passed to the application (saved in the session
// Entry), in order to detect "duplicate" segments.  We will not detect
// all sorts of other duplicates (defined as same sequence/length)
// depending on ordering.
typedef struct SessionEntry SessionEntry;
typedef struct SegmentQueueEntry SegmentQueueEntry;
struct SegmentQueueEntry        // queued segment pending a gap fill
{
    struct SegmentQueueEntry *next;
    SessionEntry * parent;              // session (not flow!) owning segment
    SegmentQueueEntry *ageOlder, *ageYounger;
    tz_uint32 seqNum;                   // sequence # of the payload
    tz_uint32 origSeqNum;               // before we trimmed overlaps
    tz_uint64 timeStamp;                // when this buffer added.
    tz_uint16 length;                   // length of the buffered payload
    tz_uint16 origLength;               // before we trimmed any overlap
    tz_uint8  data[0];                  // copied bytes
};

// Assumed that the oldest packet in the queue is not that much older than the
// agewatch (not true for very asymmetric flows)
// An alternative: keep another linked list (once for each direction) based on
// oldest buffered segment, and a timestamp per buffer.
typedef struct {
    tz_uint32  seqNum;              // sequence number of next octet to be
                                    // passed to adaptor - indexed by direction
    tz_uint32 expNextSeqNum;        // sequence # of byte AFTER payload.
    tz_uint32  finSeq;              // seq number of FIN from each side
    SegmentQueueEntry *first;
    SegmentQueueEntry *last;
    tz_uint64  packets;             // packets seen on this session
    tz_uint32  lastSeqNum;          // sequence # last delivered seg
    tz_uint16  lastSegLength;       // length last delivered seg
    tz_uint16  segCount;            // # segments in queue
    tz_int8    flags;               // SESS_FIN, SESS_SYN, SESS_FIN_ACK, SESS_QUEUED
} TcpState;

// Maintain state of a session we are trying to block
typedef struct 
{
  BlockStateEnum    state;                  // Current state of blocking
  BlockActionEnum   action;                 // Type of action
  BlockResultEnum   result;                 // Final result of block action
  tz_uint64         eventId;                // Event that triggered block
  time_t            triggerTime;            // Time when first triggered
  time_t            resultTime;             // Time when result declared
  time_t            actionTime;             // Time of last block action 
  tz_uint32         actionCnt;              // Num block actions attempted
  tz_int8           ruleName[128];          // Name of policy that caused block
  tz_uint16         tapIsExternal;          // True if session pkts not from tap
  tz_uint16         tapId;                  // Tap ID to send block message to
  blocker_cntrs_t   cntrs;                  // Mostly pkt counters
} SessionBlocking;

// Some decoders handle multiple logins for the same "session", some
// handle midflows (SMB, TDS), and some (TDS) attempt to handle
// encrypted logins.  This distinction has proven to be significant.
// (Ex: a midflow would still have a "Successful Login" event despite
// the fact that the decoder never saw the login messages, and was
// therefore unable to determine the serverUser, serverInfo,
// programName, etc.)

typedef enum {
    TZ_LOGIN_APP_SUCCESSFUL,
    TZ_LOGIN_APP_APPLICATION,
    TZ_LOGIN_APP_MIDFLOW,       // missed login message
    TZ_LOGIN_APP_ENCRYPTED,     // login is encrypted, and could not decrypt
    TZ_LOGIN_APP_KRB_ENCRYPTED, // login could not decrypt Kerberos ticket
    TZ_LOGIN_APP_PARTIAL,       // only saw part of the login
    TZ_LOGIN_APP_LOCAL,         // login user is local (no username in packets)
    TZ_LOGIN_APP_ERROR,         // error decoding login message
    TZ_LOGIN_APP_COUNT
} TzLoginAppType;

// The list of sessions we are tracking
struct SessionEntry {
    struct SessionEntry *prev;         // previous entry in this session bucket
    struct SessionEntry *next;         // next entry in this session bucket
    struct SessionEntry *ageYounger;   // ordered by age - this points to the next most recent session
    struct SessionEntry *ageOlder;     // ordered by age - this points to the next oldest session 
    struct SessionEntry *workNext;     // next session in work queue
    struct SessionEntry *workPrev;     // prev session in work queue
    SessionStateEnum    state;         // state of session in work queue
    SessionOperEnum     oper;          // operation to be performed on session

    PacketDescQueue     pktReadyQ;     // New pkts staged here while session busy
    PacketDescQueue     pktBusyQ;      // Pkts to be processed next
    PacketDescQueue     pktDoneQ;      // Pkts to be returned to driver
    tz_uint16           pktReassCnt;   // Num pkts in Reassembly Queue

    tz_uint64       id;                // the unique id for this session
    AddressTuple    addressTuple;      // address information
    TcpState        tcpState[2];       // indexed by direction;
    SessionDetail   *sessionDetail;    // session based information for this session (Session.* dimension)
    tz_uint32       application;       // what is the upper level decode? also magic key to application struct
    tz_uint32       incomplete;        // were packets dropped recently on this session
    DriverCounters  *counters;         // ptr to counters for source of this session
    SessionBlocking *blocking;         // ptr to blocking state, null if not blocking
    tz_uint8        *pipeName;         // ptr to name of pipe when session is proxied named pipe
    tz_watch_t      *ageWatch;         // the watch used to measure the age of this session
    tz_uint8        badSession;        // set to 1 when the session is deemed to be bad (over max users)
    tz_uint8        loggedOut;         // have we logged a logout event for this session yet
    TzLoginAppType  loginIsApp;        // application login flavors
    tz_uint8        clientIsDst;       // to save lookups, address tuple ordered by value
    tz_uint8        trafficDirection;  // Direction of pkt currently being processed
    tz_uint8        lastTrafficDir;    // Direction of last pkt received
    tz_uint8        ageTcpSegments;    // 1 => need to flush reassembly queues
    tz_uint8        serverInfoEpoch;   // server info epoch at time session created
    tz_uint8        fastAging;         // 1 => session is on fast age list
    tz_uint8        workerIdx;         // index of worker this session assigned to
    tz_uint8        segsThrottled;     // segments throttled before decoder delivery
    void            *appInfo;          // a ptr to the protocol based information
} ;

// A session that we expect to be created 
typedef struct ExpectedSession {
    struct ExpectedSession *next;
    struct ExpectedSession *prev;
    AddressTuple addressTuple;
    PacketSrc_t pktSrc;
    int refCount;
    tz_uint16  sourceId;
    tz_uint32  application;          // what is the upper level decode?
    tz_watch_t *creationWatch;       // how long has this been expected
} ExpectedSession;

#endif
