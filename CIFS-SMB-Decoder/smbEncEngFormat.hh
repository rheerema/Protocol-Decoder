//-----------------------------------------------------------------------
//   Copyright (c) <2005> by Tizor Systems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   File: smbEncEngFormat.cc
// 
//   Component: SMB Protocol Encoding Engine Formatter
//
//              The Encoding Engine Formatter provides a service to
//              the SMB protocol decoder.  It creates dimensions to be
//              passed up to the Encoding Engine and offers formatting
//              functions to allow SMB to create events and a push
//              function to actually send the event up.  All the gory
//              and necessary details to make this happen are hidden
//              inside this class.
//-----------------------------------------------------------------------

#ifndef _SMB_ENC_ENG_FORMAT_H
#define _SMB_ENC_ENG_FORMAT_H

#include <netmon/netmon_types.h>


//======================================================================
// Event Filter
//======================================================================

// Abstracted Events
//     NOTE: If you add here, update SMB_EVT_FILT_NUM_EVTS
typedef enum SmbEvtFiltEvent
{
    EVT_UNKNOWN,
    EVT_OPEN,
    EVT_CREATE,
    EVT_TRUNCATE,
    EVT_READ,
    EVT_WRITE,
    EVT_CLOSE,
    EVT_DELETE,
    EVT_RENAME,
    EVT_PRINT,

} SmbEvtFiltEvent;

// The number of events (must match above).  There's got to be
// a better way to do this.
//
#define SMB_EVT_FILT_NUM_EVTS 10


//======================================================================
// File Info Hash Table
//     For all file operations a decision is made on whether or not
//     to generate an event.  The control data for the decision is
//     stored in the SmbFileInfoEntry.
//
//     There is one table for all sessions.  There could be many users
//     and it's possible that two different users are accessing a file
//     with the exact same path and filename.  Therefore a "session hash"
//     of the AddressTuple is rolled into the hash used to index the
//     table.
//======================================================================
#define SMB_FILE_HASHTABLE_SZ 4073
#define SMB_FILE_MAX_LEN       512     // FIX, what is actual value ?
                                       // POSIX name lengh 255 char max.
                                       // we also store path

typedef struct SmbFileInfo
{
    // All counters and stuff needed to make a decision about whether
    // or not to send up an event goes here

   // Most recent access.  This array is indexed by event values in
   // the enum SmbEvtFiltEvent
    struct timeval evtFiltMostRecent[SMB_EVT_FILT_NUM_EVTS];

} SmbFileInfo;


typedef struct SmbFileInfoEntry
{
#if 0
    SmbFileInfoEntry * next;
#endif  

    // The path string is the key used to store
    tz_uint32   pathStgLen;
    tz_int8     pathStg[SMB_FILE_MAX_LEN];

    // The file info structure contains the data necessary to make a
    // decision about whether or not to send an event
    SmbFileInfo fileInfo;

} SmbFileInfoEntry;

typedef enum
{
  EVT_FILT_UNDECIDED,
  EVT_FILT_REJECT,
  EVT_FILT_ACCEPT,

} EvtFiltState;


//======================================================================
// File Info Tree
//     Each UID can store a collection of files that are subject
//     to event filtering.  The UID contains the root of the tree.
//======================================================================
void evtFiltRemoveTree( void *fileInfoTree );


//======================================================================
//
// SMB Encoding Engine Formatter Class
//
//======================================================================
class smbEncEngFormatter
{
public:

  // -- Public Functions --

  // Ctor
  smbEncEngFormatter( SmbDecode *sd );

  // Dtor
  ~smbEncEngFormatter( void );

  // Formatting Operations
  void resetEvent( SessionEntry *sessionEntry);
  void sendCOSREvent( EncodingEngine *encEng,
                      SessionEntry   *sessionEntry,
                      SmbSsnUid      *ssnUid,
                      SmbSsnTid      *ssnTid,
                      tz_int8        *cmdStg );
  void sendUnsuppEvent( EncodingEngine *encEng,
                        SessionEntry   *sessionEntry,
                        SmbSsnUid      *ssnUid,
                        SmbSsnTid      *ssnTid,
                        tz_int8        *cmdStg );
  void sendLoginFailureEvent( EncodingEngine *encEng,
                              SessionEntry   *sessionEntry,
                              tz_int8        *cmdStg );
  void setDimFileContent( SessionEntry *sessionEntry,
                          tz_int8      *fileStg,
                          tz_int8      *fileStg2,
                          tz_int8      *shareNameStg,
                          tz_uint32     len );
  void setDimFolderContent( SessionEntry   *sessionEntry,
                            tz_int8        *folderStg,
                            tz_int8        *folderStg2,
                            tz_int8        *shareNameStg,
                            tz_uint32       len );
  void setDimOperation( SessionEntry   *sessionEntry,
                        SmbEvtFiltEvent evt,
                        tz_int8        *operStg,
                        tz_uint32       len );
  void setDimSize( SessionEntry   *sessionEntry,
                   tz_uint64       size );
  void setDimResponse( SessionEntry   *sessionEntry,
                       tz_uint32       respCode );
  void setDimResponseData( SessionEntry    *sessionEntry,
                           DimValListEntry *respData );
  void setDimCommandData( SessionEntry    *sessionEntry,
                          DimValListEntry *respData );
  void parseServerShare( tz_int8 *stg, tz_int8 *serv,
                                       tz_int8 *share );

  void saveSessionEntry( SessionEntry *sessionEntry,
                         SmbSsnSeCtxt *seCtxt );
  void restoreSessionEntry( SessionEntry *sessionEntry,
                            SmbSsnSeCtxt *seCtxt );

  bool evtFiltEvaluate( SessionEntry    *sessionEntry,
                        SmbEvtFiltEvent  event,
                        SmbSsnUid       *ssnUid,
                        SmbSsnFid       *ssnFid );

  void evtFiltOverride( EvtFiltState state );


  // -- Public Data --

  // Event filter
  tz_uint32 evtFiltIsEnabled;             // overall control
  EvtFiltState evtFiltState;              // decision state
  tz_int8 evtFiltDbgInfo[TZX_512_STRING]; // debug info
  struct timeval evtFiltTimeZero;         // for initializing

private:

  // -- Private Functions --

  void freeVector(DimValListEntry *vector);
  void parsePathFile( tz_int8 *stg, tz_int8 *path, tz_int8 *name );
  void parseFileExt( tz_int8 *stg, tz_int8 *ext );

#if 0
  // FileInfo
  tz_uint32 fileTblStgHash( tz_int8 *pathStg );
  tz_uint32 fileTblLookup( tz_int8 *pathStg, SmbFileInfoEntry **tblEntry );
  tz_uint32 fileTblInsert( tz_int8 *pathStg, SmbFileInfoEntry **tblEntry );
  tz_uint32 fileTblRemove( tz_int8 *pathStg );
  tz_uint32 fileTblGetFirstEntry( SmbFileInfoEntry **tblEntry );
  tz_uint32 fileTblGetNextEntry( SmbFileInfoEntry **tblEntry );
#endif

  // Event Filtering
  bool evtFiltEventIsGenerated( SessionEntry *sessionEntry,
                                void **FileInfoTree );

  // -- Private Data --

#if 0
  // FileInfo hash table
  SmbFileInfoEntry *fileTblHashTbl[SMB_FILE_HASHTABLE_SZ];
#endif

  // SMB Decoder parent
  SmbDecode *smbDecode;

  // FileInfo iterator indices
  tz_uint32 getFileInfoEntryIdx;
  tz_uint32 getFileInfoEntryChainListIdx;

  // Event filter
  tz_uint32       evtFiltCurrSessionHash;
  SmbEvtFiltEvent evtFiltCurrEvent;

  tz_int8 fileDirName[TZX_512_STRING];
  tz_int8 fileDirPath[TZX_512_STRING];

  tz_int8 fileDirName2[TZX_512_STRING];
  tz_int8 fileDirPath2[TZX_512_STRING];
  tz_int8 fileExt2[TZX_512_STRING];
};

#endif /* _SMB_ENC_ENG_FORMAT_H */

