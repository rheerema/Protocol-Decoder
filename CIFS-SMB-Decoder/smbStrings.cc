//-----------------------------------------------------------------------
//   Copyright (c) <2005> by Tizor Systems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   File: smbStrings.cc
// 
//   Component: This file provides a translation service between
//              SMB protocol codes (commands, errors, etc.) and
//              their ASCII equivalent strings.  It is mainly intended
//              for use in debugging.
//
//-----------------------------------------------------------------------

#include <tizor_types.h>
#include <netmon/netmon_types.h>
#include <netmon/layerManager.hh>
#include <netmon/smb.h>

#include <arpa/inet.h>  // inet_ntoa

#include <netmon/smbNtStatus.h>

extern LayerManager *TZ_layerManager;

// define _CASE_ for the entire file
//
#define _CASE_(x) case x: stg=#x;

//-----------------------------------------------------------------------
// smbUtilCmd2String()
//     Display command codes as an ASCII string
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilCmd2String( tz_uint8 cmd )
{
  char * stg;

  switch( cmd )
  {
  _CASE_(SMB_COM_CREATE_DIRECTORY)
      break;
  _CASE_(SMB_COM_DELETE_DIRECTORY)
      break;
  _CASE_(SMB_COM_OPEN)
      break;
  _CASE_(SMB_COM_CREATE)
      break;
  _CASE_(SMB_COM_CLOSE)
      break;
  _CASE_(SMB_COM_FLUSH)
      break;
  _CASE_(SMB_COM_DELETE)
      break;
  _CASE_(SMB_COM_RENAME)
      break;
  _CASE_(SMB_COM_QUERY_INFORMATION)
      break;
  _CASE_(SMB_COM_SET_INFORMATION)
      break;
  _CASE_(SMB_COM_READ)
      break;
  _CASE_(SMB_COM_WRITE)
      break;
  _CASE_(SMB_COM_LOCK_BYTE_RANGE)
      break;
  _CASE_(SMB_COM_UNLOCK_BYTE_RANGE)
      break;
  _CASE_(SMB_COM_CREATE_TEMPORARY)
      break;
  _CASE_(SMB_COM_CREATE_NEW)
      break;
  _CASE_(SMB_COM_CHECK_DIRECTORY)
      break;
  _CASE_(SMB_COM_PROCESS_EXIT)
      break;
  _CASE_(SMB_COM_SEEK)
      break;
  _CASE_(SMB_COM_LOCK_AND_READ)
      break;
  _CASE_(SMB_COM_WRITE_AND_UNLOCK)
      break;
  _CASE_(SMB_COM_READ_RAW)
      break;
  _CASE_(SMB_COM_READ_MPX)
      break;
  _CASE_(SMB_COM_READ_MPX_SECONDARY)
      break;
  _CASE_(SMB_COM_WRITE_RAW)
      break;
  _CASE_(SMB_COM_WRITE_MPX)
      break;
  _CASE_(SMB_COM_WRITE_MPX_SECONDARY)
      break;
  _CASE_(SMB_COM_WRITE_COMPLETE)
      break;
  _CASE_(SMB_COM_QUERY_SERVER)
      break;
  _CASE_(SMB_COM_SET_INFORMATION2)
      break;
  _CASE_(SMB_COM_QUERY_INFORMATION2)
      break;
  _CASE_(SMB_COM_LOCKING_ANDX)
      break;
  _CASE_(SMB_COM_TRANSACTION)
      break;
  _CASE_(SMB_COM_TRANSACTION_SECONDARY)
      break;
  _CASE_(SMB_COM_IOCTL)
      break;
  _CASE_(SMB_COM_IOCTL_SECONDARY)
      break;
  _CASE_(SMB_COM_COPY)
      break;
  _CASE_(SMB_COM_MOVE)
      break;
  _CASE_(SMB_COM_ECHO)
      break;
  _CASE_(SMB_COM_WRITE_AND_CLOSE)
      break;
  _CASE_(SMB_COM_OPEN_ANDX)
      break;
  _CASE_(SMB_COM_READ_ANDX)
      break;
  _CASE_(SMB_COM_WRITE_ANDX)
      break;
  _CASE_(SMB_COM_NEW_FILE_SIZE)
      break;
  _CASE_(SMB_COM_CLOSE_AND_TREE_DISC)
      break;
  _CASE_(SMB_COM_TRANSACTION2)
      break;
  _CASE_(SMB_COM_TRANSACTION2_SECONDARY)
      break;
  _CASE_(SMB_COM_FIND_CLOSE2)
      break;
  _CASE_(SMB_COM_FIND_NOTIFY_CLOSE)
      break;
  _CASE_(SMB_COM_TREE_CONNECT)
      break;
  _CASE_(SMB_COM_TREE_DISCONNECT)
      break;
  _CASE_(SMB_COM_NEGOTIATE)
      break;
  _CASE_(SMB_COM_SESSION_SETUP_ANDX)
      break;
  _CASE_(SMB_COM_LOGOFF_ANDX)
      break;
  _CASE_(SMB_COM_TREE_CONNECT_ANDX)
      break;
  _CASE_(SMB_COM_QUERY_INFORMATION_DISK)
      break;
  _CASE_(SMB_COM_SEARCH)
      break;
  _CASE_(SMB_COM_FIND)
      break;
  _CASE_(SMB_COM_FIND_UNIQUE)
      break;
  _CASE_(SMB_COM_FIND_CLOSE)
      break;
  _CASE_(SMB_COM_NT_TRANSACT)
      break;
  _CASE_(SMB_COM_NT_TRANSACT_SECONDARY)
      break;
  _CASE_(SMB_COM_NT_CREATE_ANDX)
      break;
  _CASE_(SMB_COM_NT_CANCEL)
      break;
  _CASE_(SMB_COM_NT_RENAME)
      break;
  _CASE_(SMB_COM_OPEN_PRINT_FILE)
      break;
  _CASE_(SMB_COM_WRITE_PRINT_FILE)
      break;
  _CASE_(SMB_COM_CLOSE_PRINT_FILE)
      break;
  _CASE_(SMB_COM_GET_PRINT_QUEUE)
      break;
  _CASE_(SMB_COM_READ_BULK)
      break;
  _CASE_(SMB_COM_WRITE_BULK)
      break;
  _CASE_(SMB_COM_WRITE_BULK_DATA)
      break;
  default:
      stg = "SMB_COM_UNKNOWN_CMD";
      break;
  }
  return stg;
}

//-----------------------------------------------------------------------
// smbUtilTcpContinString()
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilTcpContinString( void )
{
  return "TCP_continuation                                     ";
}

//-----------------------------------------------------------------------
// smbUtilBlankString()
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilBlankString( void )
{
  return "                                                     ";
}

//-----------------------------------------------------------------------
// smbUtilError2String()
//     Display SMB error codes as an ASCII string
//
// NOTE: if changes here, also change smbUtilErrorUpdateStats()
//                                and smbUtilErrorDisplayStats()
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilError2String( tz_uint32 error )
{
  char * stg;

  switch( error )
  {
  _CASE_(SMB_ERROR_NONE)
      break;
  _CASE_(SMB_ERROR_NO_SESSION)
      break;
  _CASE_(SMB_ERROR_NO_SMB_INFO_DESCR)
      break;
  _CASE_(SMB_ERROR_NO_UID_DESCR)
      break;
  _CASE_(SMB_ERROR_UID_CREATE)
      break;
  _CASE_(SMB_ERROR_NO_PID_MID_DESCR)
      break;
  _CASE_(SMB_ERROR_PID_MID_CREATE)
      break;
  _CASE_(SMB_ERROR_NO_FID_DESCR)
      break;
  _CASE_(SMB_ERROR_FID_CREATE)
      break;
  _CASE_(SMB_ERROR_NO_TID_DESCR)
      break;
  _CASE_(SMB_ERROR_TID_CREATE)
      break;
  default:
      stg = "SMB_ERROR_UNKNOWN";
      break;
  }
  return stg;
}

//-----------------------------------------------------------------------
// smbUtilErrorUpdateStats()
//     Update debug stats based on error code
//
// NOTE: if changes here, also change smbUtilError2String()
//                                and smbUtilErrorDisplayStats()
//-----------------------------------------------------------------------
void SmbDecode::smbUtilErrorUpdateStats( tz_uint32 error )
{
  switch( error )
  {
  case SMB_ERROR_NONE:
      break;
  case SMB_ERROR_NO_SESSION:
      ++decodeStats.noSession;
      break;
  case SMB_ERROR_NO_SMB_INFO_DESCR:
      ++decodeStats.noSmbInfoDescr;
      break;
  case SMB_ERROR_NO_UID_DESCR:
      ++decodeStats.noUidDescr;
      break;
  case SMB_ERROR_UID_CREATE:
      ++decodeStats.uidCreateError;
      break;
  case SMB_ERROR_NO_PID_MID_DESCR:
      ++decodeStats.noPidMidDescr;
      break;
  case SMB_ERROR_PID_MID_CREATE:
      ++decodeStats.pidMidCreateError;
      break;
  case SMB_ERROR_NO_FID_DESCR:
      ++decodeStats.noFidDescr;
      break;
  case SMB_ERROR_FID_CREATE:
      ++decodeStats.fidCreateError;
      break;
  case SMB_ERROR_NO_TID_DESCR:
      ++decodeStats.noTidDescr;
      break;
  case SMB_ERROR_TID_CREATE:
      ++decodeStats.tidCreateError;
      break;
  default:

      break;
  }
}

//-----------------------------------------------------------------------
// SmbIteratorSumStats()
//     Callback function to accumulate stats from each of the
//     smbDecode objects.
//-----------------------------------------------------------------------
void SmbIteratorSumStats (void *object, void *context)
{
    SmbDecode   *smbDecode = (SmbDecode *)object;

    smbDecode->SumDecodeStats (context);
}

//-----------------------------------------------------------------------
// SmbIteratorCsEnab()
//-----------------------------------------------------------------------
void SmbIteratorCsEnab (void *object, void *context)
{
    SmbDecode   *smbDecode = (SmbDecode *)object;

    smbDecode->CsEnab (context);
}

#define _D_(x) lc_log_basic x
//-----------------------------------------------------------------------
// smbUtilErrorDisplayStats()
//     Display debug stats
//
// NOTE: if changes here, also change smbUtilError2String()
//                                and smbUtilErrorUpdateStats()
//
// NOTE2: parallels smbUtilDebugGenerateDump(), below
//-----------------------------------------------------------------------
void SmbDecode::smbUtilErrorDisplayStats( void )
{
  int           lvl = LOG_NOTICE;
  DecodeStats   decodeStatsSum;

  bool          ret;
  bool          csEnab;
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;
  SessionEntry *sessionEntry;
  SmbInfo      *smbInfo;
  ThisSsnStats  ssnStats;

  // Sum the Decoder Stats
  memset (&decodeStatsSum, 0, sizeof(DecodeStats));
  nmd->NetmonThreadIterate (PROTOCOL_SMB, 
                            SmbIteratorSumStats, 
                            &decodeStatsSum);

  // Sum the Session Stats
  memset (&ssnStats, 0, sizeof(ThisSsnStats));

  // Content Scanning state
  nmd->NetmonThreadIterate (PROTOCOL_SMB,
                            SmbIteratorCsEnab,
                            &csEnab);

  do
  {
      ret = nmd->DbgSmbGetFirstSession(&sessionEntry);
      if( ret != IIMS_SUCCESS )  break;

      smbInfo = (SmbInfo *)sessionEntry->appInfo;
      if( sessionEntry->application == PROTOCOL_SMB && smbInfo )
      {
          ssnStats.currUidCount    += smbInfo->thisSsnStats.currUidCount;
          ssnStats.currPidMidCount += smbInfo->thisSsnStats.currPidMidCount;
          ssnStats.currTidCount    += smbInfo->thisSsnStats.currTidCount;
          ssnStats.currFidCount    += smbInfo->thisSsnStats.currFidCount;

          // Compare this session's maximums to those of departed sessions
          if( decodeStatsSum.oldSsnMaxUidCount < 
                                       smbInfo->thisSsnStats.maxUidCount ) {
              decodeStatsSum.oldSsnMaxUidCount =
                                        smbInfo->thisSsnStats.maxUidCount;
          }
          if( decodeStatsSum.oldSsnMaxPidMidCount < 
                                    smbInfo->thisSsnStats.maxPidMidCount ) {
              decodeStatsSum.oldSsnMaxPidMidCount =
                                       smbInfo->thisSsnStats.maxPidMidCount;
          }
          if( decodeStatsSum.oldSsnMaxTidCount < 
                                       smbInfo->thisSsnStats.maxTidCount ) {
              decodeStatsSum.oldSsnMaxTidCount =
                                        smbInfo->thisSsnStats.maxTidCount;
          }
          if( decodeStatsSum.oldSsnMaxFidCount < 
                                       smbInfo->thisSsnStats.maxFidCount ) {
              decodeStatsSum.oldSsnMaxFidCount =
                                        smbInfo->thisSsnStats.maxFidCount;
          }
          if( decodeStatsSum.oldSsnMaxPidMidLife <
                                      smbInfo->thisSsnStats.maxPidMidLife) {
              decodeStatsSum.oldSsnMaxPidMidLife = 
                                       smbInfo->thisSsnStats.maxPidMidLife;
          }
      }

      ret = nmd->DbgSmbGetNextSession(&sessionEntry);
      while( ret == IIMS_SUCCESS )
      {
          smbInfo = (SmbInfo *)sessionEntry->appInfo;
          if( sessionEntry->application == PROTOCOL_SMB && smbInfo )
          {
              smbInfo = (SmbInfo *)sessionEntry->appInfo;
              ssnStats.currUidCount    += smbInfo->thisSsnStats.currUidCount;
              ssnStats.currPidMidCount += smbInfo->thisSsnStats.currPidMidCount;
              ssnStats.currTidCount    += smbInfo->thisSsnStats.currTidCount;
              ssnStats.currFidCount    += smbInfo->thisSsnStats.currFidCount;

              // Compare this session's maximums to those of departed sessions
              if( decodeStatsSum.oldSsnMaxUidCount < 
                                      smbInfo->thisSsnStats.maxUidCount ) {
                  decodeStatsSum.oldSsnMaxUidCount =
                                         smbInfo->thisSsnStats.maxUidCount;
              }
              if( decodeStatsSum.oldSsnMaxPidMidCount < 
                                   smbInfo->thisSsnStats.maxPidMidCount ) {
                  decodeStatsSum.oldSsnMaxPidMidCount =
                                      smbInfo->thisSsnStats.maxPidMidCount;
              }
              if( decodeStatsSum.oldSsnMaxTidCount < 
                                      smbInfo->thisSsnStats.maxTidCount ) {
                  decodeStatsSum.oldSsnMaxTidCount =
                                         smbInfo->thisSsnStats.maxTidCount;
              }
              if( decodeStatsSum.oldSsnMaxFidCount < 
                                      smbInfo->thisSsnStats.maxFidCount ) {
                  decodeStatsSum.oldSsnMaxFidCount =
                                         smbInfo->thisSsnStats.maxFidCount;
              }
              if( decodeStatsSum.oldSsnMaxPidMidLife <
                                      smbInfo->thisSsnStats.maxPidMidLife) {
                  decodeStatsSum.oldSsnMaxPidMidLife = 
                                       smbInfo->thisSsnStats.maxPidMidLife;
              }
          }

          ret = nmd->DbgSmbGetNextSession(&sessionEntry);
      }

  } while (0);

  _D_((lvl, "     notSyncCount : %d", (int)decodeStatsSum.notSyncCount ));
  _D_((lvl, "    reSyncSuccess : %d", (int)decodeStatsSum.reSyncSuccess ));
  _D_((lvl, "   unimplCmdCount : %d", (int)decodeStatsSum.unimplCmdCount ));
  _D_((lvl, "          tcpHole : %d", (int)decodeStatsSum.tcpHole ));
  _D_((lvl, "  contentScanEnab : %d", (int)csEnab ));
  _D_((lvl, "  possibNbssCount : %d", (int)decodeStatsSum.possibNbssCount ));
  _D_((lvl, "        miscError : %d", (int)decodeStatsSum.miscError ));
  _D_((lvl, "        noSession : %d", (int)decodeStatsSum.noSession ));
  _D_((lvl, "   noSmbInfoDescr : %d", (int)decodeStatsSum.noSmbInfoDescr ));
  _D_((lvl, "       noUidDescr : %d", (int)decodeStatsSum.noUidDescr ));
  _D_((lvl, "   uidCreateError : %d", (int)decodeStatsSum.uidCreateError ));
  _D_((lvl, "    noPidMidDescr : %d", (int)decodeStatsSum.noPidMidDescr ));
  _D_((lvl, "pidMidCreateError : %d", (int)decodeStatsSum.pidMidCreateError ));
  _D_((lvl, "  pidMidAgedDescr : %d", (int)decodeStatsSum.pidMidAgedDescr ));
  _D_((lvl, "       noFidDescr : %d", (int)decodeStatsSum.noFidDescr ));
  _D_((lvl, "   fidCreateError : %d", (int)decodeStatsSum.fidCreateError ));
  _D_((lvl, "       noTidDescr : %d", (int)decodeStatsSum.noTidDescr ));
  _D_((lvl, "   tidCreateError : %d", (int)decodeStatsSum.tidCreateError ));
  _D_((lvl, "     failedRemove : %d", (int)decodeStatsSum.failedRemove ));
  _D_((lvl, "\n" ));
  _D_((lvl, "     currUidCount : %d", (int)ssnStats.currUidCount ));
  _D_((lvl, "  currPidMidCount : %d", (int)ssnStats.currPidMidCount ));
  _D_((lvl, "     currTidCount : %d", (int)ssnStats.currTidCount ));
  _D_((lvl, "     currFidCount : %d", (int)ssnStats.currFidCount ));
  _D_((lvl, "\n" ));
  _D_((lvl, "      maxUidCount : %d", (int)decodeStatsSum.oldSsnMaxUidCount ));
  _D_((lvl, "   maxPidMidCount : %d", (int)decodeStatsSum.oldSsnMaxPidMidCount ));
  _D_((lvl, "      maxTidCount : %d", (int)decodeStatsSum.oldSsnMaxTidCount ));
  _D_((lvl, "      maxFidCount : %d", (int)decodeStatsSum.oldSsnMaxFidCount ));
  _D_((lvl, "    maxPidMidLife : %0.6Lf", (long double)
                  decodeStatsSum.oldSsnMaxPidMidLife / nmd->cyclesPerSecond ));
}

//-----------------------------------------------------------------------
// smbUtilDebugGenerateDump()
//     Produce a text string which dumps the current state of 
//     interesting decoder variables
//
// NOTE: parallels smbUtilErrorDisplayStats(), above
//-----------------------------------------------------------------------
tz_int8 *SmbDecode::smbUtilDebugGenerateDump( void )
{
 tz_int8       *output;
  DecodeStats   decodeStatsSum;

  bool          ret;
  bool          csEnab;
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;
  SessionEntry *sessionEntry;
  SmbInfo      *smbInfo;
  ThisSsnStats  ssnStats;

  // Sum the Decoder Stats
  memset (&decodeStatsSum, 0, sizeof(DecodeStats));
  nmd->NetmonThreadIterate (PROTOCOL_SMB, 
                            SmbIteratorSumStats, 
                            &decodeStatsSum);

  // Sum the Session Stats
  memset (&ssnStats, 0, sizeof(ThisSsnStats));

  // Content Scanning state
  nmd->NetmonThreadIterate (PROTOCOL_SMB,
                            SmbIteratorCsEnab,
                            &csEnab);

  do
  {
      ret = nmd->DbgSmbGetFirstSession(&sessionEntry);
      if( ret != IIMS_SUCCESS )  break;

      smbInfo = (SmbInfo *)sessionEntry->appInfo;
      if( sessionEntry->application == PROTOCOL_SMB && smbInfo )
      {
          ssnStats.currUidCount    += smbInfo->thisSsnStats.currUidCount;
          ssnStats.currPidMidCount += smbInfo->thisSsnStats.currPidMidCount;
          ssnStats.currTidCount    += smbInfo->thisSsnStats.currTidCount;
          ssnStats.currFidCount    += smbInfo->thisSsnStats.currFidCount;

          // Compare this session's maximums to those of departed sessions
          if( decodeStatsSum.oldSsnMaxUidCount < 
                                       smbInfo->thisSsnStats.maxUidCount ) {
              decodeStatsSum.oldSsnMaxUidCount =
                                        smbInfo->thisSsnStats.maxUidCount;
          }
          if( decodeStatsSum.oldSsnMaxPidMidCount < 
                                    smbInfo->thisSsnStats.maxPidMidCount ) {
              decodeStatsSum.oldSsnMaxPidMidCount =
                                       smbInfo->thisSsnStats.maxPidMidCount;
          }
          if( decodeStatsSum.oldSsnMaxTidCount < 
                                       smbInfo->thisSsnStats.maxTidCount ) {
              decodeStatsSum.oldSsnMaxTidCount =
                                        smbInfo->thisSsnStats.maxTidCount;
          }
          if( decodeStatsSum.oldSsnMaxFidCount < 
                                       smbInfo->thisSsnStats.maxFidCount ) {
              decodeStatsSum.oldSsnMaxFidCount =
                                        smbInfo->thisSsnStats.maxFidCount;
          }
          if( decodeStatsSum.oldSsnMaxPidMidLife <
                                      smbInfo->thisSsnStats.maxPidMidLife) {
              decodeStatsSum.oldSsnMaxPidMidLife = 
                                       smbInfo->thisSsnStats.maxPidMidLife;
          }
      }

      ret = nmd->DbgSmbGetNextSession(&sessionEntry);
      while( ret == IIMS_SUCCESS )
      {
          smbInfo = (SmbInfo *)sessionEntry->appInfo;
          if( sessionEntry->application == PROTOCOL_SMB && smbInfo )
          {
              smbInfo = (SmbInfo *)sessionEntry->appInfo;
              ssnStats.currUidCount    += smbInfo->thisSsnStats.currUidCount;
              ssnStats.currPidMidCount += smbInfo->thisSsnStats.currPidMidCount;
              ssnStats.currTidCount    += smbInfo->thisSsnStats.currTidCount;
              ssnStats.currFidCount    += smbInfo->thisSsnStats.currFidCount;

              // Compare this session's maximums to those of departed sessions
              if( decodeStatsSum.oldSsnMaxUidCount < 
                                      smbInfo->thisSsnStats.maxUidCount ) {
                  decodeStatsSum.oldSsnMaxUidCount =
                                         smbInfo->thisSsnStats.maxUidCount;
              }
              if( decodeStatsSum.oldSsnMaxPidMidCount < 
                                   smbInfo->thisSsnStats.maxPidMidCount ) {
                  decodeStatsSum.oldSsnMaxPidMidCount =
                                      smbInfo->thisSsnStats.maxPidMidCount;
              }
              if( decodeStatsSum.oldSsnMaxTidCount < 
                                      smbInfo->thisSsnStats.maxTidCount ) {
                  decodeStatsSum.oldSsnMaxTidCount =
                                         smbInfo->thisSsnStats.maxTidCount;
              }
              if( decodeStatsSum.oldSsnMaxFidCount < 
                                      smbInfo->thisSsnStats.maxFidCount ) {
                  decodeStatsSum.oldSsnMaxFidCount =
                                         smbInfo->thisSsnStats.maxFidCount;
              }
              if( decodeStatsSum.oldSsnMaxPidMidLife <
                                     smbInfo->thisSsnStats.maxPidMidLife) {
                  decodeStatsSum.oldSsnMaxPidMidLife = 
                                        smbInfo->thisSsnStats.maxPidMidLife;
              }
          }

          ret = nmd->DbgSmbGetNextSession(&sessionEntry);
      }

  } while (0);

  output = smprintf("SMB Debug Stats\n"
                     "   notSyncCount:         %lu\n"
                     "   reSyncSuccess:        %lu\n"
                     "   unimplCmdCount:       %lu\n"
                     "   tcpHole:              %lu\n"
                     "   contentScanEnab:      %d\n"
                     "   possibNbssCount:      %lu\n"
                     "   miscError:            %lu\n"
                     "   noSession:            %lu\n"
                     "   noSmbInfoDescr:       %lu\n"
                     "   noUidDescr:           %lu\n"
                     "   uidCreateError:       %lu\n"
                     "   noPidMidDescr:        %lu\n"
                     "   pidMidCreateError:    %lu\n"
                     "   pidMidAgedDescr:      %lu\n"
                     "   noFidDescr:           %lu\n"
                     "   fidCreateError:       %lu\n"
                     "   noTidDescr:           %lu\n"
                     "   tidCreateError:       %lu\n"
                     "   failedRemove:         %lu\n"
                     "   currUidCount:         %lu\n"
                     "   currPidMidCount:      %lu\n"
                     "   currTidCount:         %lu\n"
                     "   currFidCount:         %lu\n"
                     "   maxUidCount:          %lu\n"
                     "   maxPidMidCount:       %lu\n"
                     "   maxTidCount:          %lu\n"
                     "   maxFidCount:          %lu\n"
                     "   maxPidMidLife:        %0.6Lf\n",
                     decodeStatsSum.notSyncCount,
                     decodeStatsSum.reSyncSuccess,
                     decodeStatsSum.unimplCmdCount,
                     decodeStatsSum.tcpHole,
                     (int)csEnab,
                     decodeStatsSum.possibNbssCount,
                     decodeStatsSum.miscError,
                     decodeStatsSum.noSession,
                     decodeStatsSum.noSmbInfoDescr,
                     decodeStatsSum.noUidDescr,
                     decodeStatsSum.uidCreateError,
                     decodeStatsSum.noPidMidDescr,
                     decodeStatsSum.pidMidCreateError,
                     decodeStatsSum.pidMidAgedDescr,
                     decodeStatsSum.noFidDescr,
                     decodeStatsSum.fidCreateError,
                     decodeStatsSum.noTidDescr,
                     decodeStatsSum.tidCreateError,
                     decodeStatsSum.failedRemove,
                     ssnStats.currUidCount,
                     ssnStats.currPidMidCount,
                     ssnStats.currTidCount,
                     ssnStats.currFidCount,
                     decodeStatsSum.oldSsnMaxUidCount,
                     decodeStatsSum.oldSsnMaxPidMidCount,
                     decodeStatsSum.oldSsnMaxTidCount,
                     decodeStatsSum.oldSsnMaxFidCount,
                     (long double)decodeStatsSum.oldSsnMaxPidMidLife /
                                  nmd->cyclesPerSecond );

  return output;
}


//-----------------------------------------------------------------------
// smbUtilDisplaySmbInfo()
//     Display smbInfo and the session it's on
//-----------------------------------------------------------------------
void SmbDecode::smbUtilDisplaySmbInfo( SessionEntry *sessionEntry )
{
  int       lvl = LOG_NOTICE;
  tz_int8   direction;
  tz_int8   src[64];
  tz_int8   dst[64];
  tz_uint16 clientPort, serverPort;

  struct in_addr srcAddress;
  struct in_addr dstAddress;
  SmbInfo       *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT )
  {
      direction = '>';  // request,  client ---> server
  } else {
      direction = '<';  // response, client <--- server
  }
  srcAddress.s_addr = sessionEntry->addressTuple.src;
  dstAddress.s_addr = sessionEntry->addressTuple.dst;
  if (sessionEntry->clientIsDst)
  {
      strcpy(&src[0], inet_ntoa(dstAddress));
      strcpy(&dst[0], inet_ntoa(srcAddress));
      clientPort = ntohs (sessionEntry->addressTuple.dport);
      serverPort = ntohs (sessionEntry->addressTuple.sport);
  }
  else
  {
      strcpy(&src[0], inet_ntoa(srcAddress));
      strcpy(&dst[0], inet_ntoa(dstAddress));
      clientPort = ntohs (sessionEntry->addressTuple.sport);
      serverPort = ntohs (sessionEntry->addressTuple.dport);
  }
  _D_((lvl, "     Session: C %c S  %s  %d  %s  %d", direction,
                                   src, clientPort,
                                   dst, serverPort ));

  _D_((lvl, "  serverUser: %s", smbInfo->serverUser));
  _D_((lvl, "    hostUser: %s", smbInfo->hostUser));
  _D_((lvl, "  serverInfo: %s", smbInfo->serverInfo));
  _D_((lvl, "  domainName: %s", smbInfo->domainName));
  _D_((lvl, "ntlmSspState: %08lx             krb5State: %08lx", 
                              smbInfo->ntlmSspState, smbInfo->krb5State));
  _D_((lvl, "    authMode: %08lx           authFailCnt: %08lx", 
                                smbInfo->authMode, smbInfo->authFailCnt));
}
#undef _D_

//-----------------------------------------------------------------------
// smbUtilTrans2_2String()
//     Display Trans2 subcommand codes
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilTrans2_2String( tz_uint32 subcmd )
{
  char * stg;

  switch( subcmd )
  {
    _CASE_(TRANS2_OPEN2)
      break;
    _CASE_(TRANS2_FIND_FIRST2)
      break;
    _CASE_(TRANS2_FIND_NEXT2)
      break;
    _CASE_(TRANS2_QUERY_FS_INFORMATION)
      break;
//  _CASE_(TRANS_SET_FS_INFORMATION)
//    break;
    _CASE_(TRANS2_QUERY_PATH_INFORMATION)
      break;
    _CASE_(TRANS2_SET_PATH_INFORMATION)
      break;
    _CASE_(TRANS2_QUERY_FILE_INFORMATION)
      break;
    _CASE_(TRANS2_SET_FILE_INFORMATION)
      break;
    _CASE_(TRANS2_FSCTL)
      break;
    _CASE_(TRANS2_IOCTL2)
      break;
    _CASE_(TRANS2_FIND_NOTIFY_FIRST)
      break;
    _CASE_(TRANS2_FIND_NOTIFY_NEXT)
      break;
    _CASE_(TRANS2_CREATE_DIRECTORY)
      break;
    _CASE_(TRANS2_SESSION_SETUP)
      break;
    _CASE_(TRANS2_GET_DFS_REFERRAL)
      break;
    _CASE_(TRANS2_REPORT_DFS_INCONSISTENCY)
      break;
  default:
      stg = "TRANS2_UNKNOWN_SUBCMD";
      break;
  }
  return stg;
}

//-----------------------------------------------------------------------
// smbUtilNtlmssp2String()
//     Display NTLMSSP codes
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilNtlmssp2String( tz_uint32 code )
{
  char * stg;

  switch( code )
  {
    _CASE_(SMB_NTLMSSP_UNKNOWN)
      break;
    _CASE_(SMB_NTLMSSP_NEGOTIATE)
      break;
    _CASE_(SMB_NTLMSSP_CHALLENGE)
      break;
    _CASE_(SMB_NTLMSSP_AUTH)
      break;
  default:
      stg = "NTLMSSP_UNKNOWN_CODE";
      break;
  }
  return stg;
}

//-----------------------------------------------------------------------
// smbUtilSpoolss2String()
//     Display MS SPOOLSS Subsystem codes
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilSpoolss2String( tz_uint32 code )
{
  char * stg;

  switch( code )
  {
    _CASE_(SPOOLSS_ENUM_PRINTERS)
      break;
    _CASE_(SPOOLSS_OPEN_PRINTER)
      break;
    _CASE_(SPOOLSS_SET_JOB)
      break;
    _CASE_(SPOOLSS_GET_JOB)
      break;
    _CASE_(SPOOLSS_ENUM_JOBS)
      break;
    _CASE_(SPOOLSS_ADD_PRINTER)
      break;
    _CASE_(SPOOLSS_DELETE_PRINTER)
      break;
    _CASE_(SPOOLSS_SET_PRINTER)
      break;
    _CASE_(SPOOLSS_GET_PRINTER)
      break;
    _CASE_(SPOOLSS_ADD_PRINTER_DRIVER)
      break;
    _CASE_(SPOOLSS_ENUM_PRINTER_DRIVERS)
      break;
    _CASE_(SPOOLSS_GET_PRINTER_DRIVER_DIR)
      break;
    _CASE_(SPOOLSS_DELETE_PRINTER_DRIVER)
      break;
    _CASE_(SPOOLSS_ADD_PRINT_PROCESSOR)
      break;
    _CASE_(SPOOLSS_ENUM_PRINT_PROCESSORS)
      break;
    _CASE_(SPOOLSS_GET_PRINT_PROCESSOR_DIR)
      break;
    _CASE_(SPOOLSS_START_DOC_PRINTER)
      break;
    _CASE_(SPOOLSS_START_PAGE_PRINTER)
      break;
    _CASE_(SPOOLSS_WRITE_PRINTER)
      break;
    _CASE_(SPOOLSS_END_PAGEP_RINTER)
      break;
    _CASE_(SPOOLSS_ABORT_PRINTER)
      break;
    _CASE_(SPOOLSS_END_DOC_PRINTER)
      break;
    _CASE_(SPOOLSS_ADD_JOB)
      break;
    _CASE_(SPOOLSS_SCHEDULE_JOB)
      break;
    _CASE_(SPOOLSS_GET_PRINTER_DATA)
      break;
    _CASE_(SPOOLSS_SET_PRINTER_DATA)
      break;
    _CASE_(SPOOLSS_CLOSE_PRINTER)
      break;
    _CASE_(SPOOLSS_ADD_FORM)
      break;
    _CASE_(SPOOLSS_DELETE_FORM)
      break;
    _CASE_(SPOOLSS_GET_FORM)
      break;
    _CASE_(SPOOLSS_SET_FORM)
      break;
    _CASE_(SPOOLSS_ENUM_FORMS)
      break;
    _CASE_(SPOOLSS_ENUM_PORTS)
      break;
    _CASE_(SPOOLSS_ENUM_MONITORS)
      break;
    _CASE_(SPOOLSS_ENUM_PRINT_PROCDATATYPES)
      break;
    _CASE_(SPOOLSS_RESET_PRINTER)
      break;
    _CASE_(SPOOLSS_GET_PRINTER_DRIVER2)
      break;
    _CASE_(SPOOLSS_FCPN)
      break;
    _CASE_(SPOOLSS_REPLY_OPEN_PRINTER)
      break;
    _CASE_(SPOOLSS_ROUTER_REPLY_PRINTER)
      break;
    _CASE_(SPOOLSS_REPLY_CLOSE_PRINTER)
      break;
    _CASE_(SPOOLSS_RFFPCNEX)
      break;
    _CASE_(SPOOLSS_RRPCN)
      break;
    _CASE_(SPOOLSS_RFNPCNEX)
      break;
    _CASE_(SPOOLSS_OPEN_PRINTER_EX)
      break;
    _CASE_(SPOOLSS_ADD_PRINTER_EX)
      break;
    _CASE_(SPOOLSS_ENUM_PRINTER_DATA)
      break;
    _CASE_(SPOOLSS_DELETE_PRINTER_DATA)
      break;
    _CASE_(SPOOLSS_SET_PRINTER_DATA_EX)
      break;
    _CASE_(SPOOLSS_GET_PRINTER_DATA_EX)
      break;
    _CASE_(SPOOLSS_ENUM_PRINTER_DATA_EX)
      break;
    _CASE_(SPOOLSS_ENUM_PRINTER_KEY)
      break;
    _CASE_(SPOOLSS_DELETE_PRINTER_DATA_EX)
      break;
    _CASE_(SPOOLSS_DELETE_PRINTER_KEY)
      break;
    _CASE_(SPOOLSS_DELETE_PRINTER_DRIVER_EX)
      break;
    _CASE_(SPOOLSS_ADD_PRINTER_DRIVER_EX)
      break;
  default:
      stg = "SPOOLSS_UNKNOWN_CODE";
      break;
  }
  return stg;
}

//-----------------------------------------------------------------------
// smbUtilNtStatus2String()
//     Display NT Status codes
//-----------------------------------------------------------------------
char * SmbDecode::smbUtilNtStatus2String( tz_uint32 code )
{
  char * stg;

  switch( code )
  {
    _CASE_(STATUS_SUCCESS)
      break;
#if 0
    _CASE_(STATUS_WAIT_0)
      break;
#endif
    _CASE_(STATUS_WAIT_1)
      break;
    _CASE_(STATUS_WAIT_2)
      break;
    _CASE_(STATUS_WAIT_3)
      break;
    _CASE_(STATUS_WAIT_63)
      break;
    _CASE_(STATUS_ABANDONED)
      break;
#if 0
    _CASE_(STATUS_ABANDONED_WAIT_0)
      break;
#endif
    _CASE_(STATUS_ABANDONED_WAIT_63)
      break;
    _CASE_(STATUS_USER_APC)
      break;
    _CASE_(STATUS_KERNEL_APC)
      break;
    _CASE_(STATUS_ALERTED)
      break;
    _CASE_(STATUS_TIMEOUT)
      break;
    _CASE_(STATUS_PENDING)
      break;
    _CASE_(STATUS_REPARSE)
      break;
    _CASE_(STATUS_MORE_ENTRIES)
      break;
    _CASE_(STATUS_NOT_ALL_ASSIGNED)
      break;
    _CASE_(STATUS_SOME_NOT_MAPPED)
      break;
    _CASE_(STATUS_OPLOCK_BREAK_IN_PROGRESS)
      break;
    _CASE_(STATUS_VOLUME_MOUNTED)
      break;
    _CASE_(STATUS_RXACT_COMMITTED)
      break;
    _CASE_(STATUS_NOTIFY_CLEANUP)
      break;
    _CASE_(STATUS_NOTIFY_ENUM_DIR)
      break;
    _CASE_(STATUS_NO_QUOTAS_FOR_ACCOUNT)
      break;
    _CASE_(STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED)
      break;
    _CASE_(STATUS_PAGE_FAULT_TRANSITION)
      break;
    _CASE_(STATUS_PAGE_FAULT_DEMAND_ZERO)
      break;
    _CASE_(STATUS_PAGE_FAULT_COPY_ON_WRITE)
      break;
    _CASE_(STATUS_PAGE_FAULT_GUARD_PAGE)
      break;
    _CASE_(STATUS_PAGE_FAULT_PAGING_FILE)
      break;
    _CASE_(STATUS_CACHE_PAGE_LOCKED)
      break;
    _CASE_(STATUS_CRASH_DUMP)
      break;
    _CASE_(STATUS_BUFFER_ALL_ZEROS)
      break;
    _CASE_(STATUS_REPARSE_OBJECT)
      break;
    _CASE_(STATUS_RESOURCE_REQUIREMENTS_CHANGED)
      break;
    _CASE_(STATUS_TRANSLATION_COMPLETE)
      break;
    _CASE_(STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY)
      break;
    _CASE_(STATUS_NOTHING_TO_TERMINATE)
      break;
    _CASE_(STATUS_PROCESS_NOT_IN_JOB)
      break;
    _CASE_(STATUS_PROCESS_IN_JOB)
      break;
    _CASE_(STATUS_VOLSNAP_HIBERNATE_READY)
      break;
    _CASE_(STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY)
      break;
    _CASE_(DBG_EXCEPTION_HANDLED)
      break;
    _CASE_(DBG_CONTINUE)
      break;
    _CASE_(STATUS_OBJECT_NAME_EXISTS)
      break;
    _CASE_(STATUS_THREAD_WAS_SUSPENDED)
      break;
    _CASE_(STATUS_WORKING_SET_LIMIT_RANGE)
      break;
    _CASE_(STATUS_IMAGE_NOT_AT_BASE)
      break;
    _CASE_(STATUS_RXACT_STATE_CREATED)
      break;
    _CASE_(STATUS_SEGMENT_NOTIFICATION)
      break;
    _CASE_(STATUS_LOCAL_USER_SESSION_KEY)
      break;
    _CASE_(STATUS_BAD_CURRENT_DIRECTORY)
      break;
    _CASE_(STATUS_SERIAL_MORE_WRITES)
      break;
    _CASE_(STATUS_REGISTRY_RECOVERED)
      break;
    _CASE_(STATUS_FT_READ_RECOVERY_FROM_BACKUP)
      break;
    _CASE_(STATUS_FT_WRITE_RECOVERY)
      break;
    _CASE_(STATUS_SERIAL_COUNTER_TIMEOUT)
      break;
    _CASE_(STATUS_NULL_LM_PASSWORD)
      break;
    _CASE_(STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
      break;
    _CASE_(STATUS_RECEIVE_PARTIAL)
      break;
    _CASE_(STATUS_RECEIVE_EXPEDITED)
      break;
    _CASE_(STATUS_RECEIVE_PARTIAL_EXPEDITED)
      break;
    _CASE_(STATUS_EVENT_DONE)
      break;
    _CASE_(STATUS_EVENT_PENDING)
      break;
    _CASE_(STATUS_CHECKING_FILE_SYSTEM)
      break;
    _CASE_(STATUS_FATAL_APP_EXIT)
      break;
    _CASE_(STATUS_PREDEFINED_HANDLE)
      break;
    _CASE_(STATUS_WAS_UNLOCKED)
      break;
    _CASE_(STATUS_SERVICE_NOTIFICATION)
      break;
    _CASE_(STATUS_WAS_LOCKED)
      break;
    _CASE_(STATUS_LOG_HARD_ERROR)
      break;
    _CASE_(STATUS_ALREADY_WIN32)
      break;
    _CASE_(STATUS_WX86_UNSIMULATE)
      break;
    _CASE_(STATUS_WX86_CONTINUE)
      break;
    _CASE_(STATUS_WX86_SINGLE_STEP)
      break;
    _CASE_(STATUS_WX86_BREAKPOINT)
      break;
    _CASE_(STATUS_WX86_EXCEPTION_CONTINUE)
      break;
    _CASE_(STATUS_WX86_EXCEPTION_LASTCHANCE)
      break;
    _CASE_(STATUS_WX86_EXCEPTION_CHAIN)
      break;
    _CASE_(STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE)
      break;
    _CASE_(STATUS_NO_YIELD_PERFORMED)
      break;
    _CASE_(STATUS_TIMER_RESUME_IGNORED)
      break;
    _CASE_(STATUS_ARBITRATION_UNHANDLED)
      break;
    _CASE_(STATUS_CARDBUS_NOT_SUPPORTED)
      break;
    _CASE_(STATUS_WX86_CREATEWX86TIB)
      break;
    _CASE_(STATUS_MP_PROCESSOR_MISMATCH)
      break;
    _CASE_(STATUS_HIBERNATED)
      break;
    _CASE_(STATUS_RESUME_HIBERNATION)
      break;
    _CASE_(STATUS_FIRMWARE_UPDATED)
      break;
    _CASE_(STATUS_DRIVERS_LEAKING_LOCKED_PAGES)
      break;
    _CASE_(DBG_REPLY_LATER)
      break;
    _CASE_(DBG_UNABLE_TO_PROVIDE_HANDLE)
      break;
    _CASE_(DBG_TERMINATE_THREAD)
      break;
    _CASE_(DBG_TERMINATE_PROCESS)
      break;
    _CASE_(DBG_CONTROL_C)
      break;
    _CASE_(DBG_PRINTEXCEPTION_C)
      break;
    _CASE_(DBG_RIPEXCEPTION)
      break;
    _CASE_(DBG_CONTROL_BREAK)
      break;
    _CASE_(DBG_COMMAND_EXCEPTION)
      break;
    _CASE_(STATUS_GUARD_PAGE_VIOLATION)
      break;
    _CASE_(STATUS_DATATYPE_MISALIGNMENT)
      break;
    _CASE_(STATUS_BREAKPOINT)
      break;
    _CASE_(STATUS_SINGLE_STEP)
      break;
    _CASE_(STATUS_BUFFER_OVERFLOW)
      break;
    _CASE_(STATUS_NO_MORE_FILES)
      break;
    _CASE_(STATUS_WAKE_SYSTEM_DEBUGGER)
      break;
    _CASE_(STATUS_HANDLES_CLOSED)
      break;
    _CASE_(STATUS_NO_INHERITANCE)
      break;
    _CASE_(STATUS_GUID_SUBSTITUTION_MADE)
      break;
    _CASE_(STATUS_PARTIAL_COPY)
      break;
    _CASE_(STATUS_DEVICE_PAPER_EMPTY)
      break;
    _CASE_(STATUS_DEVICE_POWERED_OFF)
      break;
    _CASE_(STATUS_DEVICE_OFF_LINE)
      break;
    _CASE_(STATUS_DEVICE_BUSY)
      break;
    _CASE_(STATUS_NO_MORE_EAS)
      break;
    _CASE_(STATUS_INVALID_EA_NAME)
      break;
    _CASE_(STATUS_EA_LIST_INCONSISTENT)
      break;
    _CASE_(STATUS_INVALID_EA_FLAG)
      break;
    _CASE_(STATUS_VERIFY_REQUIRED)
      break;
    _CASE_(STATUS_EXTRANEOUS_INFORMATION)
      break;
    _CASE_(STATUS_RXACT_COMMIT_NECESSARY)
      break;
    _CASE_(STATUS_NO_MORE_ENTRIES)
      break;
    _CASE_(STATUS_FILEMARK_DETECTED)
      break;
    _CASE_(STATUS_MEDIA_CHANGED)
      break;
    _CASE_(STATUS_BUS_RESET)
      break;
    _CASE_(STATUS_END_OF_MEDIA)
      break;
    _CASE_(STATUS_BEGINNING_OF_MEDIA)
      break;
    _CASE_(STATUS_MEDIA_CHECK)
      break;
    _CASE_(STATUS_SETMARK_DETECTED)
      break;
    _CASE_(STATUS_NO_DATA_DETECTED)
      break;
    _CASE_(STATUS_REDIRECTOR_HAS_OPEN_HANDLES)
      break;
    _CASE_(STATUS_SERVER_HAS_OPEN_HANDLES)
      break;
    _CASE_(STATUS_ALREADY_DISCONNECTED)
      break;
    _CASE_(STATUS_LONGJUMP)
      break;
    _CASE_(STATUS_CLEANER_CARTRIDGE_INSTALLED)
      break;
    _CASE_(STATUS_PLUGPLAY_QUERY_VETOED)
      break;
    _CASE_(STATUS_UNWIND_CONSOLIDATE)
      break;
    _CASE_(STATUS_REGISTRY_HIVE_RECOVERED)
      break;
    _CASE_(STATUS_DLL_MIGHT_BE_INSECURE)
      break;
    _CASE_(STATUS_DLL_MIGHT_BE_INCOMPATIBLE)
      break;
    _CASE_(DBG_EXCEPTION_NOT_HANDLED)
      break;
    _CASE_(STATUS_CLUSTER_NODE_ALREADY_UP)
      break;
    _CASE_(STATUS_CLUSTER_NODE_ALREADY_DOWN)
      break;
    _CASE_(STATUS_CLUSTER_NETWORK_ALREADY_ONLINE)
      break;
    _CASE_(STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE)
      break;
    _CASE_(STATUS_CLUSTER_NODE_ALREADY_MEMBER)
      break;
    _CASE_(STATUS_UNSUCCESSFUL)
      break;
    _CASE_(STATUS_NOT_IMPLEMENTED)
      break;
    _CASE_(STATUS_INVALID_INFO_CLASS)
      break;
    _CASE_(STATUS_INFO_LENGTH_MISMATCH)
      break;
    _CASE_(STATUS_ACCESS_VIOLATION)
      break;
    _CASE_(STATUS_IN_PAGE_ERROR)
      break;
    _CASE_(STATUS_PAGEFILE_QUOTA)
      break;
    _CASE_(STATUS_INVALID_HANDLE)
      break;
    _CASE_(STATUS_BAD_INITIAL_STACK)
      break;
    _CASE_(STATUS_BAD_INITIAL_PC)
      break;
    _CASE_(STATUS_INVALID_CID)
      break;
    _CASE_(STATUS_TIMER_NOT_CANCELED)
      break;
    _CASE_(STATUS_INVALID_PARAMETER)
      break;
    _CASE_(STATUS_NO_SUCH_DEVICE)
      break;
    _CASE_(STATUS_NO_SUCH_FILE)
      break;
    _CASE_(STATUS_INVALID_DEVICE_REQUEST)
      break;
    _CASE_(STATUS_END_OF_FILE)
      break;
    _CASE_(STATUS_WRONG_VOLUME)
      break;
    _CASE_(STATUS_NO_MEDIA_IN_DEVICE)
      break;
    _CASE_(STATUS_UNRECOGNIZED_MEDIA)
      break;
    _CASE_(STATUS_NONEXISTENT_SECTOR)
      break;
    _CASE_(STATUS_MORE_PROCESSING_REQUIRED)
      break;
    _CASE_(STATUS_NO_MEMORY)
      break;
    _CASE_(STATUS_CONFLICTING_ADDRESSES)
      break;
    _CASE_(STATUS_NOT_MAPPED_VIEW)
      break;
    _CASE_(STATUS_UNABLE_TO_FREE_VM)
      break;
    _CASE_(STATUS_UNABLE_TO_DELETE_SECTION)
      break;
    _CASE_(STATUS_INVALID_SYSTEM_SERVICE)
      break;
    _CASE_(STATUS_ILLEGAL_INSTRUCTION)
      break;
    _CASE_(STATUS_INVALID_LOCK_SEQUENCE)
      break;
    _CASE_(STATUS_INVALID_VIEW_SIZE)
      break;
    _CASE_(STATUS_INVALID_FILE_FOR_SECTION)
      break;
    _CASE_(STATUS_ALREADY_COMMITTED)
      break;
    _CASE_(STATUS_ACCESS_DENIED)
      break;
    _CASE_(STATUS_BUFFER_TOO_SMALL)
      break;
    _CASE_(STATUS_OBJECT_TYPE_MISMATCH)
      break;
    _CASE_(STATUS_NONCONTINUABLE_EXCEPTION)
      break;
    _CASE_(STATUS_INVALID_DISPOSITION)
      break;
    _CASE_(STATUS_UNWIND)
      break;
    _CASE_(STATUS_BAD_STACK)
      break;
    _CASE_(STATUS_INVALID_UNWIND_TARGET)
      break;
    _CASE_(STATUS_NOT_LOCKED)
      break;
    _CASE_(STATUS_PARITY_ERROR)
      break;
    _CASE_(STATUS_UNABLE_TO_DECOMMIT_VM)
      break;
    _CASE_(STATUS_NOT_COMMITTED)
      break;
    _CASE_(STATUS_INVALID_PORT_ATTRIBUTES)
      break;
    _CASE_(STATUS_PORT_MESSAGE_TOO_LONG)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_MIX)
      break;
    _CASE_(STATUS_INVALID_QUOTA_LOWER)
      break;
    _CASE_(STATUS_DISK_CORRUPT_ERROR)
      break;
    _CASE_(STATUS_OBJECT_NAME_INVALID)
      break;
    _CASE_(STATUS_OBJECT_NAME_NOT_FOUND)
      break;
    _CASE_(STATUS_OBJECT_NAME_COLLISION)
      break;
    _CASE_(STATUS_PORT_DISCONNECTED)
      break;
    _CASE_(STATUS_DEVICE_ALREADY_ATTACHED)
      break;
    _CASE_(STATUS_OBJECT_PATH_INVALID)
      break;
    _CASE_(STATUS_OBJECT_PATH_NOT_FOUND)
      break;
    _CASE_(STATUS_OBJECT_PATH_SYNTAX_BAD)
      break;
    _CASE_(STATUS_DATA_OVERRUN)
      break;
    _CASE_(STATUS_DATA_LATE_ERROR)
      break;
    _CASE_(STATUS_DATA_ERROR)
      break;
    _CASE_(STATUS_CRC_ERROR)
      break;
    _CASE_(STATUS_SECTION_TOO_BIG)
      break;
    _CASE_(STATUS_PORT_CONNECTION_REFUSED)
      break;
    _CASE_(STATUS_INVALID_PORT_HANDLE)
      break;
    _CASE_(STATUS_SHARING_VIOLATION)
      break;
    _CASE_(STATUS_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_INVALID_PAGE_PROTECTION)
      break;
    _CASE_(STATUS_MUTANT_NOT_OWNED)
      break;
    _CASE_(STATUS_SEMAPHORE_LIMIT_EXCEEDED)
      break;
    _CASE_(STATUS_PORT_ALREADY_SET)
      break;
    _CASE_(STATUS_SECTION_NOT_IMAGE)
      break;
    _CASE_(STATUS_SUSPEND_COUNT_EXCEEDED)
      break;
    _CASE_(STATUS_THREAD_IS_TERMINATING)
      break;
    _CASE_(STATUS_BAD_WORKING_SET_LIMIT)
      break;
    _CASE_(STATUS_INCOMPATIBLE_FILE_MAP)
      break;
    _CASE_(STATUS_SECTION_PROTECTION)
      break;
    _CASE_(STATUS_EAS_NOT_SUPPORTED)
      break;
    _CASE_(STATUS_EA_TOO_LARGE)
      break;
    _CASE_(STATUS_NONEXISTENT_EA_ENTRY)
      break;
    _CASE_(STATUS_NO_EAS_ON_FILE)
      break;
    _CASE_(STATUS_EA_CORRUPT_ERROR)
      break;
    _CASE_(STATUS_FILE_LOCK_CONFLICT)
      break;
    _CASE_(STATUS_LOCK_NOT_GRANTED)
      break;
    _CASE_(STATUS_DELETE_PENDING)
      break;
    _CASE_(STATUS_CTL_FILE_NOT_SUPPORTED)
      break;
    _CASE_(STATUS_UNKNOWN_REVISION)
      break;
    _CASE_(STATUS_REVISION_MISMATCH)
      break;
    _CASE_(STATUS_INVALID_OWNER)
      break;
    _CASE_(STATUS_INVALID_PRIMARY_GROUP)
      break;
    _CASE_(STATUS_NO_IMPERSONATION_TOKEN)
      break;
    _CASE_(STATUS_CANT_DISABLE_MANDATORY)
      break;
    _CASE_(STATUS_NO_LOGON_SERVERS)
      break;
    _CASE_(STATUS_NO_SUCH_LOGON_SESSION)
      break;
    _CASE_(STATUS_NO_SUCH_PRIVILEGE)
      break;
    _CASE_(STATUS_PRIVILEGE_NOT_HELD)
      break;
    _CASE_(STATUS_INVALID_ACCOUNT_NAME)
      break;
    _CASE_(STATUS_USER_EXISTS)
      break;
    _CASE_(STATUS_NO_SUCH_USER)
      break;
    _CASE_(STATUS_GROUP_EXISTS)
      break;
    _CASE_(STATUS_NO_SUCH_GROUP)
      break;
    _CASE_(STATUS_MEMBER_IN_GROUP)
      break;
    _CASE_(STATUS_MEMBER_NOT_IN_GROUP)
      break;
    _CASE_(STATUS_LAST_ADMIN)
      break;
    _CASE_(STATUS_WRONG_PASSWORD)
      break;
    _CASE_(STATUS_ILL_FORMED_PASSWORD)
      break;
    _CASE_(STATUS_PASSWORD_RESTRICTION)
      break;
    _CASE_(STATUS_LOGON_FAILURE)
      break;
    _CASE_(STATUS_ACCOUNT_RESTRICTION)
      break;
    _CASE_(STATUS_INVALID_LOGON_HOURS)
      break;
    _CASE_(STATUS_INVALID_WORKSTATION)
      break;
    _CASE_(STATUS_PASSWORD_EXPIRED)
      break;
    _CASE_(STATUS_ACCOUNT_DISABLED)
      break;
    _CASE_(STATUS_NONE_MAPPED)
      break;
    _CASE_(STATUS_TOO_MANY_LUIDS_REQUESTED)
      break;
    _CASE_(STATUS_LUIDS_EXHAUSTED)
      break;
    _CASE_(STATUS_INVALID_SUB_AUTHORITY)
      break;
    _CASE_(STATUS_INVALID_ACL)
      break;
    _CASE_(STATUS_INVALID_SID)
      break;
    _CASE_(STATUS_INVALID_SECURITY_DESCR)
      break;
    _CASE_(STATUS_PROCEDURE_NOT_FOUND)
      break;
    _CASE_(STATUS_INVALID_IMAGE_FORMAT)
      break;
    _CASE_(STATUS_NO_TOKEN)
      break;
    _CASE_(STATUS_BAD_INHERITANCE_ACL)
      break;
    _CASE_(STATUS_RANGE_NOT_LOCKED)
      break;
    _CASE_(STATUS_DISK_FULL)
      break;
    _CASE_(STATUS_SERVER_DISABLED)
      break;
    _CASE_(STATUS_SERVER_NOT_DISABLED)
      break;
    _CASE_(STATUS_TOO_MANY_GUIDS_REQUESTED)
      break;
    _CASE_(STATUS_GUIDS_EXHAUSTED)
      break;
    _CASE_(STATUS_INVALID_ID_AUTHORITY)
      break;
    _CASE_(STATUS_AGENTS_EXHAUSTED)
      break;
    _CASE_(STATUS_INVALID_VOLUME_LABEL)
      break;
    _CASE_(STATUS_SECTION_NOT_EXTENDED)
      break;
    _CASE_(STATUS_NOT_MAPPED_DATA)
      break;
    _CASE_(STATUS_RESOURCE_DATA_NOT_FOUND)
      break;
    _CASE_(STATUS_RESOURCE_TYPE_NOT_FOUND)
      break;
    _CASE_(STATUS_RESOURCE_NAME_NOT_FOUND)
      break;
    _CASE_(STATUS_ARRAY_BOUNDS_EXCEEDED)
      break;
    _CASE_(STATUS_FLOAT_DENORMAL_OPERAND)
      break;
    _CASE_(STATUS_FLOAT_DIVIDE_BY_ZERO)
      break;
    _CASE_(STATUS_FLOAT_INEXACT_RESULT)
      break;
    _CASE_(STATUS_FLOAT_INVALID_OPERATION)
      break;
    _CASE_(STATUS_FLOAT_OVERFLOW)
      break;
    _CASE_(STATUS_FLOAT_STACK_CHECK)
      break;
    _CASE_(STATUS_FLOAT_UNDERFLOW)
      break;
    _CASE_(STATUS_INTEGER_DIVIDE_BY_ZERO)
      break;
    _CASE_(STATUS_INTEGER_OVERFLOW)
      break;
    _CASE_(STATUS_PRIVILEGED_INSTRUCTION)
      break;
    _CASE_(STATUS_TOO_MANY_PAGING_FILES)
      break;
    _CASE_(STATUS_FILE_INVALID)
      break;
    _CASE_(STATUS_ALLOTTED_SPACE_EXCEEDED)
      break;
    _CASE_(STATUS_INSUFFICIENT_RESOURCES)
      break;
    _CASE_(STATUS_DFS_EXIT_PATH_FOUND)
      break;
    _CASE_(STATUS_DEVICE_DATA_ERROR)
      break;
    _CASE_(STATUS_DEVICE_NOT_CONNECTED)
      break;
    _CASE_(STATUS_DEVICE_POWER_FAILURE)
      break;
    _CASE_(STATUS_FREE_VM_NOT_AT_BASE)
      break;
    _CASE_(STATUS_MEMORY_NOT_ALLOCATED)
      break;
    _CASE_(STATUS_WORKING_SET_QUOTA)
      break;
    _CASE_(STATUS_MEDIA_WRITE_PROTECTED)
      break;
    _CASE_(STATUS_DEVICE_NOT_READY)
      break;
    _CASE_(STATUS_INVALID_GROUP_ATTRIBUTES)
      break;
    _CASE_(STATUS_BAD_IMPERSONATION_LEVEL)
      break;
    _CASE_(STATUS_CANT_OPEN_ANONYMOUS)
      break;
    _CASE_(STATUS_BAD_VALIDATION_CLASS)
      break;
    _CASE_(STATUS_BAD_TOKEN_TYPE)
      break;
    _CASE_(STATUS_BAD_MASTER_BOOT_RECORD)
      break;
    _CASE_(STATUS_INSTRUCTION_MISALIGNMENT)
      break;
    _CASE_(STATUS_INSTANCE_NOT_AVAILABLE)
      break;
    _CASE_(STATUS_PIPE_NOT_AVAILABLE)
      break;
    _CASE_(STATUS_INVALID_PIPE_STATE)
      break;
    _CASE_(STATUS_PIPE_BUSY)
      break;
    _CASE_(STATUS_ILLEGAL_FUNCTION)
      break;
    _CASE_(STATUS_PIPE_DISCONNECTED)
      break;
    _CASE_(STATUS_PIPE_CLOSING)
      break;
    _CASE_(STATUS_PIPE_CONNECTED)
      break;
    _CASE_(STATUS_PIPE_LISTENING)
      break;
    _CASE_(STATUS_INVALID_READ_MODE)
      break;
    _CASE_(STATUS_IO_TIMEOUT)
      break;
    _CASE_(STATUS_FILE_FORCED_CLOSED)
      break;
    _CASE_(STATUS_PROFILING_NOT_STARTED)
      break;
    _CASE_(STATUS_PROFILING_NOT_STOPPED)
      break;
    _CASE_(STATUS_COULD_NOT_INTERPRET)
      break;
    _CASE_(STATUS_FILE_IS_A_DIRECTORY)
      break;
    _CASE_(STATUS_NOT_SUPPORTED)
      break;
    _CASE_(STATUS_REMOTE_NOT_LISTENING)
      break;
    _CASE_(STATUS_DUPLICATE_NAME)
      break;
    _CASE_(STATUS_BAD_NETWORK_PATH)
      break;
    _CASE_(STATUS_NETWORK_BUSY)
      break;
    _CASE_(STATUS_DEVICE_DOES_NOT_EXIST)
      break;
    _CASE_(STATUS_TOO_MANY_COMMANDS)
      break;
    _CASE_(STATUS_ADAPTER_HARDWARE_ERROR)
      break;
    _CASE_(STATUS_INVALID_NETWORK_RESPONSE)
      break;
    _CASE_(STATUS_UNEXPECTED_NETWORK_ERROR)
      break;
    _CASE_(STATUS_BAD_REMOTE_ADAPTER)
      break;
    _CASE_(STATUS_PRINT_QUEUE_FULL)
      break;
    _CASE_(STATUS_NO_SPOOL_SPACE)
      break;
    _CASE_(STATUS_PRINT_CANCELLED)
      break;
    _CASE_(STATUS_NETWORK_NAME_DELETED)
      break;
    _CASE_(STATUS_NETWORK_ACCESS_DENIED)
      break;
    _CASE_(STATUS_BAD_DEVICE_TYPE)
      break;
    _CASE_(STATUS_BAD_NETWORK_NAME)
      break;
    _CASE_(STATUS_TOO_MANY_NAMES)
      break;
    _CASE_(STATUS_TOO_MANY_SESSIONS)
      break;
    _CASE_(STATUS_SHARING_PAUSED)
      break;
    _CASE_(STATUS_REQUEST_NOT_ACCEPTED)
      break;
    _CASE_(STATUS_REDIRECTOR_PAUSED)
      break;
    _CASE_(STATUS_NET_WRITE_FAULT)
      break;
    _CASE_(STATUS_PROFILING_AT_LIMIT)
      break;
    _CASE_(STATUS_NOT_SAME_DEVICE)
      break;
    _CASE_(STATUS_FILE_RENAMED)
      break;
    _CASE_(STATUS_VIRTUAL_CIRCUIT_CLOSED)
      break;
    _CASE_(STATUS_NO_SECURITY_ON_OBJECT)
      break;
    _CASE_(STATUS_CANT_WAIT)
      break;
    _CASE_(STATUS_PIPE_EMPTY)
      break;
    _CASE_(STATUS_CANT_ACCESS_DOMAIN_INFO)
      break;
    _CASE_(STATUS_CANT_TERMINATE_SELF)
      break;
    _CASE_(STATUS_INVALID_SERVER_STATE)
      break;
    _CASE_(STATUS_INVALID_DOMAIN_STATE)
      break;
    _CASE_(STATUS_INVALID_DOMAIN_ROLE)
      break;
    _CASE_(STATUS_NO_SUCH_DOMAIN)
      break;
    _CASE_(STATUS_DOMAIN_EXISTS)
      break;
    _CASE_(STATUS_DOMAIN_LIMIT_EXCEEDED)
      break;
    _CASE_(STATUS_OPLOCK_NOT_GRANTED)
      break;
    _CASE_(STATUS_INVALID_OPLOCK_PROTOCOL)
      break;
    _CASE_(STATUS_INTERNAL_DB_CORRUPTION)
      break;
    _CASE_(STATUS_INTERNAL_ERROR)
      break;
    _CASE_(STATUS_GENERIC_NOT_MAPPED)
      break;
    _CASE_(STATUS_BAD_DESCRIPTOR_FORMAT)
      break;
    _CASE_(STATUS_INVALID_USER_BUFFER)
      break;
    _CASE_(STATUS_UNEXPECTED_IO_ERROR)
      break;
    _CASE_(STATUS_UNEXPECTED_MM_CREATE_ERR)
      break;
    _CASE_(STATUS_UNEXPECTED_MM_MAP_ERROR)
      break;
    _CASE_(STATUS_UNEXPECTED_MM_EXTEND_ERR)
      break;
    _CASE_(STATUS_NOT_LOGON_PROCESS)
      break;
    _CASE_(STATUS_LOGON_SESSION_EXISTS)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_1)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_2)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_3)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_4)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_5)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_6)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_7)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_8)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_9)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_10)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_11)
      break;
    _CASE_(STATUS_INVALID_PARAMETER_12)
      break;
    _CASE_(STATUS_REDIRECTOR_NOT_STARTED)
      break;
    _CASE_(STATUS_REDIRECTOR_STARTED)
      break;
    _CASE_(STATUS_STACK_OVERFLOW)
      break;
    _CASE_(STATUS_NO_SUCH_PACKAGE)
      break;
    _CASE_(STATUS_BAD_FUNCTION_TABLE)
      break;
    _CASE_(STATUS_VARIABLE_NOT_FOUND)
      break;
    _CASE_(STATUS_DIRECTORY_NOT_EMPTY)
      break;
    _CASE_(STATUS_FILE_CORRUPT_ERROR)
      break;
    _CASE_(STATUS_NOT_A_DIRECTORY)
      break;
    _CASE_(STATUS_BAD_LOGON_SESSION_STATE)
      break;
    _CASE_(STATUS_LOGON_SESSION_COLLISION)
      break;
    _CASE_(STATUS_NAME_TOO_LONG)
      break;
    _CASE_(STATUS_FILES_OPEN)
      break;
    _CASE_(STATUS_CONNECTION_IN_USE)
      break;
    _CASE_(STATUS_MESSAGE_NOT_FOUND)
      break;
    _CASE_(STATUS_PROCESS_IS_TERMINATING)
      break;
    _CASE_(STATUS_INVALID_LOGON_TYPE)
      break;
    _CASE_(STATUS_NO_GUID_TRANSLATION)
      break;
    _CASE_(STATUS_CANNOT_IMPERSONATE)
      break;
    _CASE_(STATUS_IMAGE_ALREADY_LOADED)
      break;
    _CASE_(STATUS_ABIOS_NOT_PRESENT)
      break;
    _CASE_(STATUS_ABIOS_LID_NOT_EXIST)
      break;
    _CASE_(STATUS_ABIOS_LID_ALREADY_OWNED)
      break;
    _CASE_(STATUS_ABIOS_NOT_LID_OWNER)
      break;
    _CASE_(STATUS_ABIOS_INVALID_COMMAND)
      break;
    _CASE_(STATUS_ABIOS_INVALID_LID)
      break;
    _CASE_(STATUS_ABIOS_SELECTOR_NOT_AVAILABLE)
      break;
    _CASE_(STATUS_ABIOS_INVALID_SELECTOR)
      break;
    _CASE_(STATUS_NO_LDT)
      break;
    _CASE_(STATUS_INVALID_LDT_SIZE)
      break;
    _CASE_(STATUS_INVALID_LDT_OFFSET)
      break;
    _CASE_(STATUS_INVALID_LDT_DESCRIPTOR)
      break;
    _CASE_(STATUS_INVALID_IMAGE_NE_FORMAT)
      break;
    _CASE_(STATUS_RXACT_INVALID_STATE)
      break;
    _CASE_(STATUS_RXACT_COMMIT_FAILURE)
      break;
    _CASE_(STATUS_MAPPED_FILE_SIZE_ZERO)
      break;
    _CASE_(STATUS_TOO_MANY_OPENED_FILES)
      break;
    _CASE_(STATUS_CANCELLED)
      break;
    _CASE_(STATUS_CANNOT_DELETE)
      break;
    _CASE_(STATUS_INVALID_COMPUTER_NAME)
      break;
    _CASE_(STATUS_FILE_DELETED)
      break;
    _CASE_(STATUS_SPECIAL_ACCOUNT)
      break;
    _CASE_(STATUS_SPECIAL_GROUP)
      break;
    _CASE_(STATUS_SPECIAL_USER)
      break;
    _CASE_(STATUS_MEMBERS_PRIMARY_GROUP)
      break;
    _CASE_(STATUS_FILE_CLOSED)
      break;
    _CASE_(STATUS_TOO_MANY_THREADS)
      break;
    _CASE_(STATUS_THREAD_NOT_IN_PROCESS)
      break;
    _CASE_(STATUS_TOKEN_ALREADY_IN_USE)
      break;
    _CASE_(STATUS_PAGEFILE_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_COMMITMENT_LIMIT)
      break;
    _CASE_(STATUS_INVALID_IMAGE_LE_FORMAT)
      break;
    _CASE_(STATUS_INVALID_IMAGE_NOT_MZ)
      break;
    _CASE_(STATUS_INVALID_IMAGE_PROTECT)
      break;
    _CASE_(STATUS_INVALID_IMAGE_WIN_16)
      break;
    _CASE_(STATUS_LOGON_SERVER_CONFLICT)
      break;
    _CASE_(STATUS_TIME_DIFFERENCE_AT_DC)
      break;
    _CASE_(STATUS_SYNCHRONIZATION_REQUIRED)
      break;
    _CASE_(STATUS_DLL_NOT_FOUND)
      break;
    _CASE_(STATUS_OPEN_FAILED)
      break;
    _CASE_(STATUS_IO_PRIVILEGE_FAILED)
      break;
    _CASE_(STATUS_ORDINAL_NOT_FOUND)
      break;
    _CASE_(STATUS_ENTRYPOINT_NOT_FOUND)
      break;
    _CASE_(STATUS_CONTROL_C_EXIT)
      break;
    _CASE_(STATUS_LOCAL_DISCONNECT)
      break;
    _CASE_(STATUS_REMOTE_DISCONNECT)
      break;
    _CASE_(STATUS_REMOTE_RESOURCES)
      break;
    _CASE_(STATUS_LINK_FAILED)
      break;
    _CASE_(STATUS_LINK_TIMEOUT)
      break;
    _CASE_(STATUS_INVALID_CONNECTION)
      break;
    _CASE_(STATUS_INVALID_ADDRESS)
      break;
    _CASE_(STATUS_DLL_INIT_FAILED)
      break;
    _CASE_(STATUS_MISSING_SYSTEMFILE)
      break;
    _CASE_(STATUS_UNHANDLED_EXCEPTION)
      break;
    _CASE_(STATUS_APP_INIT_FAILURE)
      break;
    _CASE_(STATUS_PAGEFILE_CREATE_FAILED)
      break;
    _CASE_(STATUS_NO_PAGEFILE)
      break;
    _CASE_(STATUS_INVALID_LEVEL)
      break;
    _CASE_(STATUS_WRONG_PASSWORD_CORE)
      break;
    _CASE_(STATUS_ILLEGAL_FLOAT_CONTEXT)
      break;
    _CASE_(STATUS_PIPE_BROKEN)
      break;
    _CASE_(STATUS_REGISTRY_CORRUPT)
      break;
    _CASE_(STATUS_REGISTRY_IO_FAILED)
      break;
    _CASE_(STATUS_NO_EVENT_PAIR)
      break;
    _CASE_(STATUS_UNRECOGNIZED_VOLUME)
      break;
    _CASE_(STATUS_SERIAL_NO_DEVICE_INITED)
      break;
    _CASE_(STATUS_NO_SUCH_ALIAS)
      break;
    _CASE_(STATUS_MEMBER_NOT_IN_ALIAS)
      break;
    _CASE_(STATUS_MEMBER_IN_ALIAS)
      break;
    _CASE_(STATUS_ALIAS_EXISTS)
      break;
    _CASE_(STATUS_LOGON_NOT_GRANTED)
      break;
    _CASE_(STATUS_TOO_MANY_SECRETS)
      break;
    _CASE_(STATUS_SECRET_TOO_LONG)
      break;
    _CASE_(STATUS_INTERNAL_DB_ERROR)
      break;
    _CASE_(STATUS_FULLSCREEN_MODE)
      break;
    _CASE_(STATUS_TOO_MANY_CONTEXT_IDS)
      break;
    _CASE_(STATUS_LOGON_TYPE_NOT_GRANTED)
      break;
    _CASE_(STATUS_NOT_REGISTRY_FILE)
      break;
    _CASE_(STATUS_NT_CROSS_ENCRYPTION_REQUIRED)
      break;
    _CASE_(STATUS_DOMAIN_CTRLR_CONFIG_ERROR)
      break;
    _CASE_(STATUS_FT_MISSING_MEMBER)
      break;
    _CASE_(STATUS_ILL_FORMED_SERVICE_ENTRY)
      break;
    _CASE_(STATUS_ILLEGAL_CHARACTER)
      break;
    _CASE_(STATUS_UNMAPPABLE_CHARACTER)
      break;
    _CASE_(STATUS_UNDEFINED_CHARACTER)
      break;
    _CASE_(STATUS_FLOPPY_VOLUME)
      break;
    _CASE_(STATUS_FLOPPY_ID_MARK_NOT_FOUND)
      break;
    _CASE_(STATUS_FLOPPY_WRONG_CYLINDER)
      break;
    _CASE_(STATUS_FLOPPY_UNKNOWN_ERROR)
      break;
    _CASE_(STATUS_FLOPPY_BAD_REGISTERS)
      break;
    _CASE_(STATUS_DISK_RECALIBRATE_FAILED)
      break;
    _CASE_(STATUS_DISK_OPERATION_FAILED)
      break;
    _CASE_(STATUS_DISK_RESET_FAILED)
      break;
    _CASE_(STATUS_SHARED_IRQ_BUSY)
      break;
    _CASE_(STATUS_FT_ORPHANING)
      break;
    _CASE_(STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT)
      break;
    _CASE_(STATUS_PARTITION_FAILURE)
      break;
    _CASE_(STATUS_INVALID_BLOCK_LENGTH)
      break;
    _CASE_(STATUS_DEVICE_NOT_PARTITIONED)
      break;
    _CASE_(STATUS_UNABLE_TO_LOCK_MEDIA)
      break;
    _CASE_(STATUS_UNABLE_TO_UNLOAD_MEDIA)
      break;
    _CASE_(STATUS_EOM_OVERFLOW)
      break;
    _CASE_(STATUS_NO_MEDIA)
      break;
    _CASE_(STATUS_NO_SUCH_MEMBER)
      break;
    _CASE_(STATUS_INVALID_MEMBER)
      break;
    _CASE_(STATUS_KEY_DELETED)
      break;
    _CASE_(STATUS_NO_LOG_SPACE)
      break;
    _CASE_(STATUS_TOO_MANY_SIDS)
      break;
    _CASE_(STATUS_LM_CROSS_ENCRYPTION_REQUIRED)
      break;
    _CASE_(STATUS_KEY_HAS_CHILDREN)
      break;
    _CASE_(STATUS_CHILD_MUST_BE_VOLATILE)
      break;
    _CASE_(STATUS_DEVICE_CONFIGURATION_ERROR)
      break;
    _CASE_(STATUS_DRIVER_INTERNAL_ERROR)
      break;
    _CASE_(STATUS_INVALID_DEVICE_STATE)
      break;
    _CASE_(STATUS_IO_DEVICE_ERROR)
      break;
    _CASE_(STATUS_DEVICE_PROTOCOL_ERROR)
      break;
    _CASE_(STATUS_BACKUP_CONTROLLER)
      break;
    _CASE_(STATUS_LOG_FILE_FULL)
      break;
    _CASE_(STATUS_TOO_LATE)
      break;
    _CASE_(STATUS_NO_TRUST_LSA_SECRET)
      break;
    _CASE_(STATUS_NO_TRUST_SAM_ACCOUNT)
      break;
    _CASE_(STATUS_TRUSTED_DOMAIN_FAILURE)
      break;
    _CASE_(STATUS_TRUSTED_RELATIONSHIP_FAILURE)
      break;
    _CASE_(STATUS_EVENTLOG_FILE_CORRUPT)
      break;
    _CASE_(STATUS_EVENTLOG_CANT_START)
      break;
    _CASE_(STATUS_TRUST_FAILURE)
      break;
    _CASE_(STATUS_MUTANT_LIMIT_EXCEEDED)
      break;
    _CASE_(STATUS_NETLOGON_NOT_STARTED)
      break;
    _CASE_(STATUS_ACCOUNT_EXPIRED)
      break;
    _CASE_(STATUS_POSSIBLE_DEADLOCK)
      break;
    _CASE_(STATUS_NETWORK_CREDENTIAL_CONFLICT)
      break;
    _CASE_(STATUS_REMOTE_SESSION_LIMIT)
      break;
    _CASE_(STATUS_EVENTLOG_FILE_CHANGED)
      break;
    _CASE_(STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT)
      break;
    _CASE_(STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT)
      break;
    _CASE_(STATUS_NOLOGON_SERVER_TRUST_ACCOUNT)
      break;
    _CASE_(STATUS_DOMAIN_TRUST_INCONSISTENT)
      break;
    _CASE_(STATUS_FS_DRIVER_REQUIRED)
      break;
    _CASE_(STATUS_NO_USER_SESSION_KEY)
      break;
    _CASE_(STATUS_USER_SESSION_DELETED)
      break;
    _CASE_(STATUS_RESOURCE_LANG_NOT_FOUND)
      break;
    _CASE_(STATUS_INSUFF_SERVER_RESOURCES)
      break;
    _CASE_(STATUS_INVALID_BUFFER_SIZE)
      break;
    _CASE_(STATUS_INVALID_ADDRESS_COMPONENT)
      break;
    _CASE_(STATUS_INVALID_ADDRESS_WILDCARD)
      break;
    _CASE_(STATUS_TOO_MANY_ADDRESSES)
      break;
    _CASE_(STATUS_ADDRESS_ALREADY_EXISTS)
      break;
    _CASE_(STATUS_ADDRESS_CLOSED)
      break;
    _CASE_(STATUS_CONNECTION_DISCONNECTED)
      break;
    _CASE_(STATUS_CONNECTION_RESET)
      break;
    _CASE_(STATUS_TOO_MANY_NODES)
      break;
    _CASE_(STATUS_TRANSACTION_ABORTED)
      break;
    _CASE_(STATUS_TRANSACTION_TIMED_OUT)
      break;
    _CASE_(STATUS_TRANSACTION_NO_RELEASE)
      break;
    _CASE_(STATUS_TRANSACTION_NO_MATCH)
      break;
    _CASE_(STATUS_TRANSACTION_RESPONDED)
      break;
    _CASE_(STATUS_TRANSACTION_INVALID_ID)
      break;
    _CASE_(STATUS_TRANSACTION_INVALID_TYPE)
      break;
    _CASE_(STATUS_NOT_SERVER_SESSION)
      break;
    _CASE_(STATUS_NOT_CLIENT_SESSION)
      break;
    _CASE_(STATUS_CANNOT_LOAD_REGISTRY_FILE)
      break;
    _CASE_(STATUS_DEBUG_ATTACH_FAILED)
      break;
    _CASE_(STATUS_SYSTEM_PROCESS_TERMINATED)
      break;
    _CASE_(STATUS_DATA_NOT_ACCEPTED)
      break;
    _CASE_(STATUS_NO_BROWSER_SERVERS_FOUND)
      break;
    _CASE_(STATUS_VDM_HARD_ERROR)
      break;
    _CASE_(STATUS_DRIVER_CANCEL_TIMEOUT)
      break;
    _CASE_(STATUS_REPLY_MESSAGE_MISMATCH)
      break;
    _CASE_(STATUS_MAPPED_ALIGNMENT)
      break;
    _CASE_(STATUS_IMAGE_CHECKSUM_MISMATCH)
      break;
    _CASE_(STATUS_LOST_WRITEBEHIND_DATA)
      break;
    _CASE_(STATUS_CLIENT_SERVER_PARAMETERS_INVALID)
      break;
    _CASE_(STATUS_PASSWORD_MUST_CHANGE)
      break;
    _CASE_(STATUS_NOT_FOUND)
      break;
    _CASE_(STATUS_NOT_TINY_STREAM)
      break;
    _CASE_(STATUS_RECOVERY_FAILURE)
      break;
    _CASE_(STATUS_STACK_OVERFLOW_READ)
      break;
    _CASE_(STATUS_FAIL_CHECK)
      break;
    _CASE_(STATUS_DUPLICATE_OBJECTID)
      break;
    _CASE_(STATUS_OBJECTID_EXISTS)
      break;
    _CASE_(STATUS_CONVERT_TO_LARGE)
      break;
    _CASE_(STATUS_RETRY)
      break;
    _CASE_(STATUS_FOUND_OUT_OF_SCOPE)
      break;
    _CASE_(STATUS_ALLOCATE_BUCKET)
      break;
    _CASE_(STATUS_PROPSET_NOT_FOUND)
      break;
    _CASE_(STATUS_MARSHALL_OVERFLOW)
      break;
    _CASE_(STATUS_INVALID_VARIANT)
      break;
    _CASE_(STATUS_DOMAIN_CONTROLLER_NOT_FOUND)
      break;
    _CASE_(STATUS_ACCOUNT_LOCKED_OUT)
      break;
    _CASE_(STATUS_HANDLE_NOT_CLOSABLE)
      break;
    _CASE_(STATUS_CONNECTION_REFUSED)
      break;
    _CASE_(STATUS_GRACEFUL_DISCONNECT)
      break;
    _CASE_(STATUS_ADDRESS_ALREADY_ASSOCIATED)
      break;
    _CASE_(STATUS_ADDRESS_NOT_ASSOCIATED)
      break;
    _CASE_(STATUS_CONNECTION_INVALID)
      break;
    _CASE_(STATUS_CONNECTION_ACTIVE)
      break;
    _CASE_(STATUS_NETWORK_UNREACHABLE)
      break;
    _CASE_(STATUS_HOST_UNREACHABLE)
      break;
    _CASE_(STATUS_PROTOCOL_UNREACHABLE)
      break;
    _CASE_(STATUS_PORT_UNREACHABLE)
      break;
    _CASE_(STATUS_REQUEST_ABORTED)
      break;
    _CASE_(STATUS_CONNECTION_ABORTED)
      break;
    _CASE_(STATUS_BAD_COMPRESSION_BUFFER)
      break;
    _CASE_(STATUS_USER_MAPPED_FILE)
      break;
    _CASE_(STATUS_AUDIT_FAILED)
      break;
    _CASE_(STATUS_TIMER_RESOLUTION_NOT_SET)
      break;
    _CASE_(STATUS_CONNECTION_COUNT_LIMIT)
      break;
    _CASE_(STATUS_LOGIN_TIME_RESTRICTION)
      break;
    _CASE_(STATUS_LOGIN_WKSTA_RESTRICTION)
      break;
    _CASE_(STATUS_IMAGE_MP_UP_MISMATCH)
      break;
    _CASE_(STATUS_INSUFFICIENT_LOGON_INFO)
      break;
    _CASE_(STATUS_BAD_DLL_ENTRYPOINT)
      break;
    _CASE_(STATUS_BAD_SERVICE_ENTRYPOINT)
      break;
    _CASE_(STATUS_LPC_REPLY_LOST)
      break;
    _CASE_(STATUS_IP_ADDRESS_CONFLICT1)
      break;
    _CASE_(STATUS_IP_ADDRESS_CONFLICT2)
      break;
    _CASE_(STATUS_REGISTRY_QUOTA_LIMIT)
      break;
    _CASE_(STATUS_PATH_NOT_COVERED)
      break;
    _CASE_(STATUS_NO_CALLBACK_ACTIVE)
      break;
    _CASE_(STATUS_LICENSE_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_PWD_TOO_SHORT)
      break;
    _CASE_(STATUS_PWD_TOO_RECENT)
      break;
    _CASE_(STATUS_PWD_HISTORY_CONFLICT)
      break;
    _CASE_(STATUS_PLUGPLAY_NO_DEVICE)
      break;
    _CASE_(STATUS_UNSUPPORTED_COMPRESSION)
      break;
    _CASE_(STATUS_INVALID_HW_PROFILE)
      break;
    _CASE_(STATUS_INVALID_PLUGPLAY_DEVICE_PATH)
      break;
    _CASE_(STATUS_DRIVER_ORDINAL_NOT_FOUND)
      break;
    _CASE_(STATUS_DRIVER_ENTRYPOINT_NOT_FOUND)
      break;
    _CASE_(STATUS_RESOURCE_NOT_OWNED)
      break;
    _CASE_(STATUS_TOO_MANY_LINKS)
      break;
    _CASE_(STATUS_QUOTA_LIST_INCONSISTENT)
      break;
    _CASE_(STATUS_FILE_IS_OFFLINE)
      break;
    _CASE_(STATUS_EVALUATION_EXPIRATION)
      break;
    _CASE_(STATUS_ILLEGAL_DLL_RELOCATION)
      break;
    _CASE_(STATUS_LICENSE_VIOLATION)
      break;
    _CASE_(STATUS_DLL_INIT_FAILED_LOGOFF)
      break;
    _CASE_(STATUS_DRIVER_UNABLE_TO_LOAD)
      break;
    _CASE_(STATUS_DFS_UNAVAILABLE)
      break;
    _CASE_(STATUS_VOLUME_DISMOUNTED)
      break;
    _CASE_(STATUS_WX86_INTERNAL_ERROR)
      break;
    _CASE_(STATUS_WX86_FLOAT_STACK_CHECK)
      break;
    _CASE_(STATUS_VALIDATE_CONTINUE)
      break;
    _CASE_(STATUS_NO_MATCH)
      break;
    _CASE_(STATUS_NO_MORE_MATCHES)
      break;
    _CASE_(STATUS_NOT_A_REPARSE_POINT)
      break;
    _CASE_(STATUS_IO_REPARSE_TAG_INVALID)
      break;
    _CASE_(STATUS_IO_REPARSE_TAG_MISMATCH)
      break;
    _CASE_(STATUS_IO_REPARSE_DATA_INVALID)
      break;
    _CASE_(STATUS_IO_REPARSE_TAG_NOT_HANDLED)
      break;
    _CASE_(STATUS_REPARSE_POINT_NOT_RESOLVED)
      break;
    _CASE_(STATUS_DIRECTORY_IS_A_REPARSE_POINT)
      break;
    _CASE_(STATUS_RANGE_LIST_CONFLICT)
      break;
    _CASE_(STATUS_SOURCE_ELEMENT_EMPTY)
      break;
    _CASE_(STATUS_DESTINATION_ELEMENT_FULL)
      break;
    _CASE_(STATUS_ILLEGAL_ELEMENT_ADDRESS)
      break;
    _CASE_(STATUS_MAGAZINE_NOT_PRESENT)
      break;
    _CASE_(STATUS_REINITIALIZATION_NEEDED)
      break;
    _CASE_(STATUS_DEVICE_REQUIRES_CLEANING)
      break;
    _CASE_(STATUS_DEVICE_DOOR_OPEN)
      break;
    _CASE_(STATUS_ENCRYPTION_FAILED)
      break;
    _CASE_(STATUS_DECRYPTION_FAILED)
      break;
    _CASE_(STATUS_RANGE_NOT_FOUND)
      break;
    _CASE_(STATUS_NO_RECOVERY_POLICY)
      break;
    _CASE_(STATUS_NO_EFS)
      break;
    _CASE_(STATUS_WRONG_EFS)
      break;
    _CASE_(STATUS_NO_USER_KEYS)
      break;
    _CASE_(STATUS_FILE_NOT_ENCRYPTED)
      break;
    _CASE_(STATUS_NOT_EXPORT_FORMAT)
      break;
    _CASE_(STATUS_FILE_ENCRYPTED)
      break;
    _CASE_(STATUS_WAKE_SYSTEM)
      break;
    _CASE_(STATUS_WMI_GUID_NOT_FOUND)
      break;
    _CASE_(STATUS_WMI_INSTANCE_NOT_FOUND)
      break;
    _CASE_(STATUS_WMI_ITEMID_NOT_FOUND)
      break;
    _CASE_(STATUS_WMI_TRY_AGAIN)
      break;
    _CASE_(STATUS_SHARED_POLICY)
      break;
    _CASE_(STATUS_POLICY_OBJECT_NOT_FOUND)
      break;
    _CASE_(STATUS_POLICY_ONLY_IN_DS)
      break;
    _CASE_(STATUS_VOLUME_NOT_UPGRADED)
      break;
    _CASE_(STATUS_REMOTE_STORAGE_NOT_ACTIVE)
      break;
    _CASE_(STATUS_REMOTE_STORAGE_MEDIA_ERROR)
      break;
    _CASE_(STATUS_NO_TRACKING_SERVICE)
      break;
    _CASE_(STATUS_SERVER_SID_MISMATCH)
      break;
    _CASE_(STATUS_DS_NO_ATTRIBUTE_OR_VALUE)
      break;
    _CASE_(STATUS_DS_INVALID_ATTRIBUTE_SYNTAX)
      break;
    _CASE_(STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED)
      break;
    _CASE_(STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS)
      break;
    _CASE_(STATUS_DS_BUSY)
      break;
    _CASE_(STATUS_DS_UNAVAILABLE)
      break;
    _CASE_(STATUS_DS_NO_RIDS_ALLOCATED)
      break;
    _CASE_(STATUS_DS_NO_MORE_RIDS)
      break;
    _CASE_(STATUS_DS_INCORRECT_ROLE_OWNER)
      break;
    _CASE_(STATUS_DS_RIDMGR_INIT_ERROR)
      break;
    _CASE_(STATUS_DS_OBJ_CLASS_VIOLATION)
      break;
    _CASE_(STATUS_DS_CANT_ON_NON_LEAF)
      break;
    _CASE_(STATUS_DS_CANT_ON_RDN)
      break;
    _CASE_(STATUS_DS_CANT_MOD_OBJ_CLASS)
      break;
    _CASE_(STATUS_DS_CROSS_DOM_MOVE_FAILED)
      break;
    _CASE_(STATUS_DS_GC_NOT_AVAILABLE)
      break;
    _CASE_(STATUS_DIRECTORY_SERVICE_REQUIRED)
      break;
    _CASE_(STATUS_REPARSE_ATTRIBUTE_CONFLICT)
      break;
    _CASE_(STATUS_CANT_ENABLE_DENY_ONLY)
      break;
    _CASE_(STATUS_FLOAT_MULTIPLE_FAULTS)
      break;
    _CASE_(STATUS_FLOAT_MULTIPLE_TRAPS)
      break;
    _CASE_(STATUS_DEVICE_REMOVED)
      break;
    _CASE_(STATUS_JOURNAL_DELETE_IN_PROGRESS)
      break;
    _CASE_(STATUS_JOURNAL_NOT_ACTIVE)
      break;
    _CASE_(STATUS_NOINTERFACE)
      break;
    _CASE_(STATUS_DS_ADMIN_LIMIT_EXCEEDED)
      break;
    _CASE_(STATUS_DRIVER_FAILED_SLEEP)
      break;
    _CASE_(STATUS_MUTUAL_AUTHENTICATION_FAILED)
      break;
    _CASE_(STATUS_CORRUPT_SYSTEM_FILE)
      break;
    _CASE_(STATUS_DATATYPE_MISALIGNMENT_ERROR)
      break;
    _CASE_(STATUS_WMI_READ_ONLY)
      break;
    _CASE_(STATUS_WMI_SET_FAILURE)
      break;
    _CASE_(STATUS_COMMITMENT_MINIMUM)
      break;
    _CASE_(STATUS_REG_NAT_CONSUMPTION)
      break;
    _CASE_(STATUS_TRANSPORT_FULL)
      break;
    _CASE_(STATUS_DS_SAM_INIT_FAILURE)
      break;
    _CASE_(STATUS_ONLY_IF_CONNECTED)
      break;
    _CASE_(STATUS_DS_SENSITIVE_GROUP_VIOLATION)
      break;
    _CASE_(STATUS_PNP_RESTART_ENUMERATION)
      break;
    _CASE_(STATUS_JOURNAL_ENTRY_DELETED)
      break;
    _CASE_(STATUS_DS_CANT_MOD_PRIMARYGROUPID)
      break;
    _CASE_(STATUS_SYSTEM_IMAGE_BAD_SIGNATURE)
      break;
    _CASE_(STATUS_PNP_REBOOT_REQUIRED)
      break;
    _CASE_(STATUS_POWER_STATE_INVALID)
      break;
    _CASE_(STATUS_DS_INVALID_GROUP_TYPE)
      break;
    _CASE_(STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN)
      break;
    _CASE_(STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN)
      break;
    _CASE_(STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER)
      break;
    _CASE_(STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER)
      break;
    _CASE_(STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER)
      break;
    _CASE_(STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER)
      break;
    _CASE_(STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER)
      break;
    _CASE_(STATUS_DS_HAVE_PRIMARY_MEMBERS)
      break;
    _CASE_(STATUS_WMI_NOT_SUPPORTED)
      break;
    _CASE_(STATUS_INSUFFICIENT_POWER)
      break;
    _CASE_(STATUS_SAM_NEED_BOOTKEY_PASSWORD)
      break;
    _CASE_(STATUS_SAM_NEED_BOOTKEY_FLOPPY)
      break;
    _CASE_(STATUS_DS_CANT_START)
      break;
    _CASE_(STATUS_DS_INIT_FAILURE)
      break;
    _CASE_(STATUS_SAM_INIT_FAILURE)
      break;
    _CASE_(STATUS_DS_GC_REQUIRED)
      break;
    _CASE_(STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY)
      break;
    _CASE_(STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS)
      break;
    _CASE_(STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_MULTIPLE_FAULT_VIOLATION)
      break;
    _CASE_(STATUS_CURRENT_DOMAIN_NOT_ALLOWED)
      break;
    _CASE_(STATUS_CANNOT_MAKE)
      break;
    _CASE_(STATUS_SYSTEM_SHUTDOWN)
      break;
    _CASE_(STATUS_DS_INIT_FAILURE_CONSOLE)
      break;
    _CASE_(STATUS_DS_SAM_INIT_FAILURE_CONSOLE)
      break;
    _CASE_(STATUS_UNFINISHED_CONTEXT_DELETED)
      break;
    _CASE_(STATUS_NO_TGT_REPLY)
      break;
    _CASE_(STATUS_OBJECTID_NOT_FOUND)
      break;
    _CASE_(STATUS_NO_IP_ADDRESSES)
      break;
    _CASE_(STATUS_WRONG_CREDENTIAL_HANDLE)
      break;
    _CASE_(STATUS_CRYPTO_SYSTEM_INVALID)
      break;
    _CASE_(STATUS_MAX_REFERRALS_EXCEEDED)
      break;
    _CASE_(STATUS_MUST_BE_KDC)
      break;
    _CASE_(STATUS_STRONG_CRYPTO_NOT_SUPPORTED)
      break;
    _CASE_(STATUS_TOO_MANY_PRINCIPALS)
      break;
    _CASE_(STATUS_NO_PA_DATA)
      break;
    _CASE_(STATUS_PKINIT_NAME_MISMATCH)
      break;
    _CASE_(STATUS_SMARTCARD_LOGON_REQUIRED)
      break;
    _CASE_(STATUS_KDC_INVALID_REQUEST)
      break;
    _CASE_(STATUS_KDC_UNABLE_TO_REFER)
      break;
    _CASE_(STATUS_KDC_UNKNOWN_ETYPE)
      break;
    _CASE_(STATUS_SHUTDOWN_IN_PROGRESS)
      break;
    _CASE_(STATUS_SERVER_SHUTDOWN_IN_PROGRESS)
      break;
    _CASE_(STATUS_NOT_SUPPORTED_ON_SBS)
      break;
    _CASE_(STATUS_WMI_GUID_DISCONNECTED)
      break;
    _CASE_(STATUS_WMI_ALREADY_DISABLED)
      break;
    _CASE_(STATUS_WMI_ALREADY_ENABLED)
      break;
    _CASE_(STATUS_MFT_TOO_FRAGMENTED)
      break;
    _CASE_(STATUS_COPY_PROTECTION_FAILURE)
      break;
    _CASE_(STATUS_CSS_AUTHENTICATION_FAILURE)
      break;
    _CASE_(STATUS_CSS_KEY_NOT_PRESENT)
      break;
    _CASE_(STATUS_CSS_KEY_NOT_ESTABLISHED)
      break;
    _CASE_(STATUS_CSS_SCRAMBLED_SECTOR)
      break;
    _CASE_(STATUS_CSS_REGION_MISMATCH)
      break;
    _CASE_(STATUS_CSS_RESETS_EXHAUSTED)
      break;
    _CASE_(STATUS_PKINIT_FAILURE)
      break;
    _CASE_(STATUS_SMARTCARD_SUBSYSTEM_FAILURE)
      break;
    _CASE_(STATUS_NO_KERB_KEY)
      break;
    _CASE_(STATUS_HOST_DOWN)
      break;
    _CASE_(STATUS_UNSUPPORTED_PREAUTH)
      break;
    _CASE_(STATUS_EFS_ALG_BLOB_TOO_BIG)
      break;
    _CASE_(STATUS_PORT_NOT_SET)
      break;
    _CASE_(STATUS_DEBUGGER_INACTIVE)
      break;
    _CASE_(STATUS_DS_VERSION_CHECK_FAILURE)
      break;
    _CASE_(STATUS_AUDITING_DISABLED)
      break;
    _CASE_(STATUS_PRENT4_MACHINE_ACCOUNT)
      break;
    _CASE_(STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER)
      break;
    _CASE_(STATUS_INVALID_IMAGE_WIN_32)
      break;
    _CASE_(STATUS_INVALID_IMAGE_WIN_64)
      break;
    _CASE_(STATUS_BAD_BINDINGS)
      break;
    _CASE_(STATUS_NETWORK_SESSION_EXPIRED)
      break;
    _CASE_(STATUS_APPHELP_BLOCK)
      break;
    _CASE_(STATUS_ALL_SIDS_FILTERED)
      break;
    _CASE_(STATUS_NOT_SAFE_MODE_DRIVER)
      break;
    _CASE_(STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT)
      break;
    _CASE_(STATUS_ACCESS_DISABLED_BY_POLICY_PATH)
      break;
    _CASE_(STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER)
      break;
    _CASE_(STATUS_ACCESS_DISABLED_BY_POLICY_OTHER)
      break;
    _CASE_(STATUS_FAILED_DRIVER_ENTRY)
      break;
    _CASE_(STATUS_DEVICE_ENUMERATION_ERROR)
      break;
    _CASE_(STATUS_WAIT_FOR_OPLOCK)
      break;
    _CASE_(STATUS_MOUNT_POINT_NOT_RESOLVED)
      break;
    _CASE_(STATUS_INVALID_DEVICE_OBJECT_PARAMETER)
      break;
    _CASE_(STATUS_MCA_OCCURED)
      break;
    _CASE_(STATUS_DRIVER_BLOCKED_CRITICAL)
      break;
    _CASE_(STATUS_DRIVER_BLOCKED)
      break;
    _CASE_(STATUS_DRIVER_DATABASE_ERROR)
      break;
    _CASE_(STATUS_SYSTEM_HIVE_TOO_LARGE)
      break;
    _CASE_(STATUS_INVALID_IMPORT_OF_NON_DLL)
      break;
    _CASE_(STATUS_DS_SHUTTING_DOWN)
      break;
    _CASE_(STATUS_SMARTCARD_WRONG_PIN)
      break;
    _CASE_(STATUS_SMARTCARD_CARD_BLOCKED)
      break;
    _CASE_(STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED)
      break;
    _CASE_(STATUS_SMARTCARD_NO_CARD)
      break;
    _CASE_(STATUS_SMARTCARD_NO_KEY_CONTAINER)
      break;
    _CASE_(STATUS_SMARTCARD_NO_CERTIFICATE)
      break;
    _CASE_(STATUS_SMARTCARD_NO_KEYSET)
      break;
    _CASE_(STATUS_SMARTCARD_IO_ERROR)
      break;
    _CASE_(STATUS_DOWNGRADE_DETECTED)
      break;
    _CASE_(STATUS_SMARTCARD_CERT_REVOKED)
      break;
    _CASE_(STATUS_ISSUING_CA_UNTRUSTED)
      break;
    _CASE_(STATUS_REVOCATION_OFFLINE_C)
      break;
    _CASE_(STATUS_PKINIT_CLIENT_FAILURE)
      break;
    _CASE_(STATUS_SMARTCARD_CERT_EXPIRED)
      break;
    _CASE_(STATUS_DRIVER_FAILED_PRIOR_UNLOAD)
      break;
    _CASE_(STATUS_SMARTCARD_SILENT_CONTEXT)
      break;
    _CASE_(STATUS_PER_USER_TRUST_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_DS_NAME_NOT_UNIQUE)
      break;
    _CASE_(STATUS_DS_DUPLICATE_ID_FOUND)
      break;
    _CASE_(STATUS_DS_GROUP_CONVERSION_ERROR)
      break;
    _CASE_(STATUS_VOLSNAP_PREPARE_HIBERNATE)
      break;
    _CASE_(STATUS_USER2USER_REQUIRED)
      break;
    _CASE_(STATUS_STACK_BUFFER_OVERRUN)
      break;
    _CASE_(STATUS_NO_S4U_PROT_SUPPORT)
      break;
    _CASE_(STATUS_CROSSREALM_DELEGATION_FAILURE)
      break;
    _CASE_(STATUS_REVOCATION_OFFLINE_KDC)
      break;
    _CASE_(STATUS_ISSUING_CA_UNTRUSTED_KDC)
      break;
    _CASE_(STATUS_KDC_CERT_EXPIRED)
      break;
    _CASE_(STATUS_KDC_CERT_REVOKED)
      break;
    _CASE_(STATUS_PARAMETER_QUOTA_EXCEEDED)
      break;
    _CASE_(STATUS_HIBERNATION_FAILURE)
      break;
    _CASE_(STATUS_DELAY_LOAD_FAILED)
      break;
    _CASE_(STATUS_AUTHENTICATION_FIREWALL_FAILED)
      break;
    _CASE_(STATUS_VDM_DISALLOWED)
      break;
    _CASE_(STATUS_HUNG_DISPLAY_DRIVER_THREAD)
      break;
    _CASE_(STATUS_WOW_ASSERTION)
      break;
    _CASE_(DBG_NO_STATE_CHANGE)
      break;
    _CASE_(DBG_APP_NOT_IDLE)
      break;
    _CASE_(RPC_NT_INVALID_STRING_BINDING)
      break;
    _CASE_(RPC_NT_WRONG_KIND_OF_BINDING)
      break;
    _CASE_(RPC_NT_INVALID_BINDING)
      break;
    _CASE_(RPC_NT_PROTSEQ_NOT_SUPPORTED)
      break;
    _CASE_(RPC_NT_INVALID_RPC_PROTSEQ)
      break;
    _CASE_(RPC_NT_INVALID_STRING_UUID)
      break;
    _CASE_(RPC_NT_INVALID_ENDPOINT_FORMAT)
      break;
    _CASE_(RPC_NT_INVALID_NET_ADDR)
      break;
    _CASE_(RPC_NT_NO_ENDPOINT_FOUND)
      break;
    _CASE_(RPC_NT_INVALID_TIMEOUT)
      break;
    _CASE_(RPC_NT_OBJECT_NOT_FOUND)
      break;
    _CASE_(RPC_NT_ALREADY_REGISTERED)
      break;
    _CASE_(RPC_NT_TYPE_ALREADY_REGISTERED)
      break;
    _CASE_(RPC_NT_ALREADY_LISTENING)
      break;
    _CASE_(RPC_NT_NO_PROTSEQS_REGISTERED)
      break;
    _CASE_(RPC_NT_NOT_LISTENING)
      break;
    _CASE_(RPC_NT_UNKNOWN_MGR_TYPE)
      break;
    _CASE_(RPC_NT_UNKNOWN_IF)
      break;
    _CASE_(RPC_NT_NO_BINDINGS)
      break;
    _CASE_(RPC_NT_NO_PROTSEQS)
      break;
    _CASE_(RPC_NT_CANT_CREATE_ENDPOINT)
      break;
    _CASE_(RPC_NT_OUT_OF_RESOURCES)
      break;
    _CASE_(RPC_NT_SERVER_UNAVAILABLE)
      break;
    _CASE_(RPC_NT_SERVER_TOO_BUSY)
      break;
    _CASE_(RPC_NT_INVALID_NETWORK_OPTIONS)
      break;
    _CASE_(RPC_NT_NO_CALL_ACTIVE)
      break;
    _CASE_(RPC_NT_CALL_FAILED)
      break;
    _CASE_(RPC_NT_CALL_FAILED_DNE)
      break;
    _CASE_(RPC_NT_PROTOCOL_ERROR)
      break;
    _CASE_(RPC_NT_UNSUPPORTED_TRANS_SYN)
      break;
    _CASE_(RPC_NT_UNSUPPORTED_TYPE)
      break;
    _CASE_(RPC_NT_INVALID_TAG)
      break;
    _CASE_(RPC_NT_INVALID_BOUND)
      break;
    _CASE_(RPC_NT_NO_ENTRY_NAME)
      break;
    _CASE_(RPC_NT_INVALID_NAME_SYNTAX)
      break;
    _CASE_(RPC_NT_UNSUPPORTED_NAME_SYNTAX)
      break;
    _CASE_(RPC_NT_UUID_NO_ADDRESS)
      break;
    _CASE_(RPC_NT_DUPLICATE_ENDPOINT)
      break;
    _CASE_(RPC_NT_UNKNOWN_AUTHN_TYPE)
      break;
    _CASE_(RPC_NT_MAX_CALLS_TOO_SMALL)
      break;
    _CASE_(RPC_NT_STRING_TOO_LONG)
      break;
    _CASE_(RPC_NT_PROTSEQ_NOT_FOUND)
      break;
    _CASE_(RPC_NT_PROCNUM_OUT_OF_RANGE)
      break;
    _CASE_(RPC_NT_BINDING_HAS_NO_AUTH)
      break;
    _CASE_(RPC_NT_UNKNOWN_AUTHN_SERVICE)
      break;
    _CASE_(RPC_NT_UNKNOWN_AUTHN_LEVEL)
      break;
    _CASE_(RPC_NT_INVALID_AUTH_IDENTITY)
      break;
    _CASE_(RPC_NT_UNKNOWN_AUTHZ_SERVICE)
      break;
    _CASE_(EPT_NT_INVALID_ENTRY)
      break;
    _CASE_(EPT_NT_CANT_PERFORM_OP)
      break;
    _CASE_(EPT_NT_NOT_REGISTERED)
      break;
    _CASE_(RPC_NT_NOTHING_TO_EXPORT)
      break;
    _CASE_(RPC_NT_INCOMPLETE_NAME)
      break;
    _CASE_(RPC_NT_INVALID_VERS_OPTION)
      break;
    _CASE_(RPC_NT_NO_MORE_MEMBERS)
      break;
    _CASE_(RPC_NT_NOT_ALL_OBJS_UNEXPORTED)
      break;
    _CASE_(RPC_NT_INTERFACE_NOT_FOUND)
      break;
    _CASE_(RPC_NT_ENTRY_ALREADY_EXISTS)
      break;
    _CASE_(RPC_NT_ENTRY_NOT_FOUND)
      break;
    _CASE_(RPC_NT_NAME_SERVICE_UNAVAILABLE)
      break;
    _CASE_(RPC_NT_INVALID_NAF_ID)
      break;
    _CASE_(RPC_NT_CANNOT_SUPPORT)
      break;
    _CASE_(RPC_NT_NO_CONTEXT_AVAILABLE)
      break;
    _CASE_(RPC_NT_INTERNAL_ERROR)
      break;
    _CASE_(RPC_NT_ZERO_DIVIDE)
      break;
    _CASE_(RPC_NT_ADDRESS_ERROR)
      break;
    _CASE_(RPC_NT_FP_DIV_ZERO)
      break;
    _CASE_(RPC_NT_FP_UNDERFLOW)
      break;
    _CASE_(RPC_NT_FP_OVERFLOW)
      break;
    _CASE_(RPC_NT_NO_MORE_ENTRIES)
      break;
    _CASE_(RPC_NT_SS_CHAR_TRANS_OPEN_FAIL)
      break;
    _CASE_(RPC_NT_SS_CHAR_TRANS_SHORT_FILE)
      break;
    _CASE_(RPC_NT_SS_IN_NULL_CONTEXT)
      break;
    _CASE_(RPC_NT_SS_CONTEXT_MISMATCH)
      break;
    _CASE_(RPC_NT_SS_CONTEXT_DAMAGED)
      break;
    _CASE_(RPC_NT_SS_HANDLES_MISMATCH)
      break;
    _CASE_(RPC_NT_SS_CANNOT_GET_CALL_HANDLE)
      break;
    _CASE_(RPC_NT_NULL_REF_POINTER)
      break;
    _CASE_(RPC_NT_ENUM_VALUE_OUT_OF_RANGE)
      break;
    _CASE_(RPC_NT_BYTE_COUNT_TOO_SMALL)
      break;
    _CASE_(RPC_NT_BAD_STUB_DATA)
      break;
    _CASE_(RPC_NT_CALL_IN_PROGRESS)
      break;
    _CASE_(RPC_NT_NO_MORE_BINDINGS)
      break;
    _CASE_(RPC_NT_GROUP_MEMBER_NOT_FOUND)
      break;
    _CASE_(EPT_NT_CANT_CREATE)
      break;
    _CASE_(RPC_NT_INVALID_OBJECT)
      break;
    _CASE_(RPC_NT_NO_INTERFACES)
      break;
    _CASE_(RPC_NT_CALL_CANCELLED)
      break;
    _CASE_(RPC_NT_BINDING_INCOMPLETE)
      break;
    _CASE_(RPC_NT_COMM_FAILURE)
      break;
    _CASE_(RPC_NT_UNSUPPORTED_AUTHN_LEVEL)
      break;
    _CASE_(RPC_NT_NO_PRINC_NAME)
      break;
    _CASE_(RPC_NT_NOT_RPC_ERROR)
      break;
    _CASE_(RPC_NT_UUID_LOCAL_ONLY)
      break;
    _CASE_(RPC_NT_SEC_PKG_ERROR)
      break;
    _CASE_(RPC_NT_NOT_CANCELLED)
      break;
    _CASE_(RPC_NT_INVALID_ES_ACTION)
      break;
    _CASE_(RPC_NT_WRONG_ES_VERSION)
      break;
    _CASE_(RPC_NT_WRONG_STUB_VERSION)
      break;
    _CASE_(RPC_NT_INVALID_PIPE_OBJECT)
      break;
    _CASE_(RPC_NT_INVALID_PIPE_OPERATION)
      break;
    _CASE_(RPC_NT_WRONG_PIPE_VERSION)
      break;
    _CASE_(RPC_NT_PIPE_CLOSED)
      break;
    _CASE_(RPC_NT_PIPE_DISCIPLINE_ERROR)
      break;
    _CASE_(RPC_NT_PIPE_EMPTY)
      break;
    _CASE_(RPC_NT_INVALID_ASYNC_HANDLE)
      break;
    _CASE_(RPC_NT_INVALID_ASYNC_CALL)
      break;
    _CASE_(RPC_NT_SEND_INCOMPLETE)
      break;
    _CASE_(STATUS_ACPI_INVALID_OPCODE)
      break;
    _CASE_(STATUS_ACPI_STACK_OVERFLOW)
      break;
    _CASE_(STATUS_ACPI_ASSERT_FAILED)
      break;
    _CASE_(STATUS_ACPI_INVALID_INDEX)
      break;
    _CASE_(STATUS_ACPI_INVALID_ARGUMENT)
      break;
    _CASE_(STATUS_ACPI_FATAL)
      break;
    _CASE_(STATUS_ACPI_INVALID_SUPERNAME)
      break;
    _CASE_(STATUS_ACPI_INVALID_ARGTYPE)
      break;
    _CASE_(STATUS_ACPI_INVALID_OBJTYPE)
      break;
    _CASE_(STATUS_ACPI_INVALID_TARGETTYPE)
      break;
    _CASE_(STATUS_ACPI_INCORRECT_ARGUMENT_COUNT)
      break;
    _CASE_(STATUS_ACPI_ADDRESS_NOT_MAPPED)
      break;
    _CASE_(STATUS_ACPI_INVALID_EVENTTYPE)
      break;
    _CASE_(STATUS_ACPI_HANDLER_COLLISION)
      break;
    _CASE_(STATUS_ACPI_INVALID_DATA)
      break;
    _CASE_(STATUS_ACPI_INVALID_REGION)
      break;
    _CASE_(STATUS_ACPI_INVALID_ACCESS_SIZE)
      break;
    _CASE_(STATUS_ACPI_ACQUIRE_GLOBAL_LOCK)
      break;
    _CASE_(STATUS_ACPI_ALREADY_INITIALIZED)
      break;
    _CASE_(STATUS_ACPI_NOT_INITIALIZED)
      break;
    _CASE_(STATUS_ACPI_INVALID_MUTEX_LEVEL)
      break;
    _CASE_(STATUS_ACPI_MUTEX_NOT_OWNED)
      break;
    _CASE_(STATUS_ACPI_MUTEX_NOT_OWNER)
      break;
    _CASE_(STATUS_ACPI_RS_ACCESS)
      break;
    _CASE_(STATUS_ACPI_INVALID_TABLE)
      break;
    _CASE_(STATUS_ACPI_REG_HANDLER_FAILED)
      break;
    _CASE_(STATUS_ACPI_POWER_REQUEST_FAILED)
      break;
    _CASE_(STATUS_CTX_WINSTATION_NAME_INVALID)
      break;
    _CASE_(STATUS_CTX_INVALID_PD)
      break;
    _CASE_(STATUS_CTX_PD_NOT_FOUND)
      break;
    _CASE_(STATUS_CTX_CDM_CONNECT)
      break;
    _CASE_(STATUS_CTX_CDM_DISCONNECT)
      break;
    _CASE_(STATUS_CTX_CLOSE_PENDING)
      break;
    _CASE_(STATUS_CTX_NO_OUTBUF)
      break;
    _CASE_(STATUS_CTX_MODEM_INF_NOT_FOUND)
      break;
    _CASE_(STATUS_CTX_INVALID_MODEMNAME)
      break;
    _CASE_(STATUS_CTX_RESPONSE_ERROR)
      break;
    _CASE_(STATUS_CTX_MODEM_RESPONSE_TIMEOUT)
      break;
    _CASE_(STATUS_CTX_MODEM_RESPONSE_NO_CARRIER)
      break;
    _CASE_(STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE)
      break;
    _CASE_(STATUS_CTX_MODEM_RESPONSE_BUSY)
      break;
    _CASE_(STATUS_CTX_MODEM_RESPONSE_VOICE)
      break;
    _CASE_(STATUS_CTX_TD_ERROR)
      break;
    _CASE_(STATUS_CTX_LICENSE_CLIENT_INVALID)
      break;
    _CASE_(STATUS_CTX_LICENSE_NOT_AVAILABLE)
      break;
    _CASE_(STATUS_CTX_LICENSE_EXPIRED)
      break;
    _CASE_(STATUS_CTX_WINSTATION_NOT_FOUND)
      break;
    _CASE_(STATUS_CTX_WINSTATION_NAME_COLLISION)
      break;
    _CASE_(STATUS_CTX_WINSTATION_BUSY)
      break;
    _CASE_(STATUS_CTX_BAD_VIDEO_MODE)
      break;
    _CASE_(STATUS_CTX_GRAPHICS_INVALID)
      break;
    _CASE_(STATUS_CTX_NOT_CONSOLE)
      break;
    _CASE_(STATUS_CTX_CLIENT_QUERY_TIMEOUT)
      break;
    _CASE_(STATUS_CTX_CONSOLE_DISCONNECT)
      break;
    _CASE_(STATUS_CTX_CONSOLE_CONNECT)
      break;
    _CASE_(STATUS_CTX_SHADOW_DENIED)
      break;
    _CASE_(STATUS_CTX_WINSTATION_ACCESS_DENIED)
      break;
    _CASE_(STATUS_CTX_INVALID_WD)
      break;
    _CASE_(STATUS_CTX_WD_NOT_FOUND)
      break;
    _CASE_(STATUS_CTX_SHADOW_INVALID)
      break;
    _CASE_(STATUS_CTX_SHADOW_DISABLED)
      break;
    _CASE_(STATUS_RDP_PROTOCOL_ERROR)
      break;
    _CASE_(STATUS_CTX_CLIENT_LICENSE_NOT_SET)
      break;
    _CASE_(STATUS_CTX_CLIENT_LICENSE_IN_USE)
      break;
    _CASE_(STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE)
      break;
    _CASE_(STATUS_CTX_SHADOW_NOT_RUNNING)
      break;
    _CASE_(STATUS_PNP_BAD_MPS_TABLE)
      break;
    _CASE_(STATUS_PNP_TRANSLATION_FAILED)
      break;
    _CASE_(STATUS_PNP_IRQ_TRANSLATION_FAILED)
      break;
    _CASE_(STATUS_PNP_INVALID_ID)
      break;
    _CASE_(STATUS_SXS_SECTION_NOT_FOUND)
      break;
    _CASE_(STATUS_SXS_CANT_GEN_ACTCTX)
      break;
    _CASE_(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
      break;
    _CASE_(STATUS_SXS_ASSEMBLY_NOT_FOUND)
      break;
    _CASE_(STATUS_SXS_MANIFEST_FORMAT_ERROR)
      break;
    _CASE_(STATUS_SXS_MANIFEST_PARSE_ERROR)
      break;
    _CASE_(STATUS_SXS_ACTIVATION_CONTEXT_DISABLED)
      break;
    _CASE_(STATUS_SXS_KEY_NOT_FOUND)
      break;
    _CASE_(STATUS_SXS_VERSION_CONFLICT)
      break;
    _CASE_(STATUS_SXS_WRONG_SECTION_TYPE)
      break;
    _CASE_(STATUS_SXS_THREAD_QUERIES_DISABLED)
      break;
    _CASE_(STATUS_SXS_ASSEMBLY_MISSING)
      break;
    _CASE_(STATUS_SXS_RELEASE_ACTIVATION_CONTEXT)
      break;
    _CASE_(STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET)
      break;
    _CASE_(STATUS_SXS_EARLY_DEACTIVATION)
      break;
    _CASE_(STATUS_SXS_INVALID_DEACTIVATION)
      break;
    _CASE_(STATUS_SXS_MULTIPLE_DEACTIVATION)
      break;
    _CASE_(STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY)
      break;
    _CASE_(STATUS_SXS_PROCESS_TERMINATION_REQUESTED)
      break;
    _CASE_(STATUS_SXS_CORRUPT_ACTIVATION_STACK)
      break;
    _CASE_(STATUS_SXS_CORRUPTION)
      break;
    _CASE_(STATUS_CLUSTER_INVALID_NODE)
      break;
    _CASE_(STATUS_CLUSTER_NODE_EXISTS)
      break;
    _CASE_(STATUS_CLUSTER_JOIN_IN_PROGRESS)
      break;
    _CASE_(STATUS_CLUSTER_NODE_NOT_FOUND)
      break;
    _CASE_(STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND)
      break;
    _CASE_(STATUS_CLUSTER_NETWORK_EXISTS)
      break;
    _CASE_(STATUS_CLUSTER_NETWORK_NOT_FOUND)
      break;
    _CASE_(STATUS_CLUSTER_NETINTERFACE_EXISTS)
      break;
    _CASE_(STATUS_CLUSTER_NETINTERFACE_NOT_FOUND)
      break;
    _CASE_(STATUS_CLUSTER_INVALID_REQUEST)
      break;
    _CASE_(STATUS_CLUSTER_INVALID_NETWORK_PROVIDER)
      break;
    _CASE_(STATUS_CLUSTER_NODE_DOWN)
      break;
    _CASE_(STATUS_CLUSTER_NODE_UNREACHABLE)
      break;
    _CASE_(STATUS_CLUSTER_NODE_NOT_MEMBER)
      break;
    _CASE_(STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS)
      break;
    _CASE_(STATUS_CLUSTER_INVALID_NETWORK)
      break;
    _CASE_(STATUS_CLUSTER_NO_NET_ADAPTERS)
      break;
    _CASE_(STATUS_CLUSTER_NODE_UP)
      break;
    _CASE_(STATUS_CLUSTER_NODE_PAUSED)
      break;
    _CASE_(STATUS_CLUSTER_NODE_NOT_PAUSED)
      break;
    _CASE_(STATUS_CLUSTER_NO_SECURITY_CONTEXT)
      break;
    _CASE_(STATUS_CLUSTER_NETWORK_NOT_INTERNAL)
      break;
    _CASE_(STATUS_CLUSTER_POISONED)
      break;
  default:
      stg = "NT_STATUS_UNKNOWN_CODE";
      break;
  }
  return stg;
}

// Undefine _CASE_ for the entire file
//
#undef _CASE_



