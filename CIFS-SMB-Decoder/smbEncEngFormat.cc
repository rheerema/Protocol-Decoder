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

#include <stdlib.h>
#include <sys/time.h> // gettimeofday()
#include <time.h>     // localtime()
#include <search.h>  // tree facility (tsearch(), twalk(), etc.)

#include <arpa/inet.h>

#include <tizor_types.h>
#include <netmon/netmon_types.h>
#include <netmon/layerManager.hh>
#include <netmon/smb.h>
#include <netmon/smbEncEngFormat.hh>



//-----------------------------------------------------------------------
// setDimFileContent()
//     Dimensions TZX_CONTENT_FILENAME, TZX_CONTENT_FILEPATH,
//                TZX_CONTENT_FILEEXT,  TZX_CONTENT_FILEATTR
//
// FIX - if fileDirPath == fileDirPath2 or ext == ext2 then there should
//       only be one dimension pushed up with a ref count of 2
//
// in:
//     fileStg: required argument, path and file
//     fileStg2: optional argument
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimFileContent( SessionEntry  *sessionEntry,
                                            tz_int8       *fileStg,
                                            tz_int8       *fileStg2,
                                            tz_int8       *shareNameStg,
                                            tz_uint32      len )
{
  DimValListEntry  *lastEntry, *newEntry;

  // These are needed for managing reference counts
  DimValListEntry *fileName, *fileExt, *filePath;

  do
  {
      fileName = fileExt = filePath = NULL;

      parsePathFile( fileStg, fileDirPath, fileDirName );

      // FileName - we assume there always is one.  This is reasonable
      // because the client OS will not allow a file op where the filename
      // is not specified.
      newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));

      if( strlen(fileDirName) != 0 )
      {
          memcpy( newEntry->stringValue, fileDirName, 
                                                 strlen(fileDirName) +1);
          newEntry->stringValueLength = strlen(fileDirName);
      }
      else
      {
          strcpy( newEntry->stringValue, "\\" );
          newEntry->stringValueLength = strlen("\\");
      }

      newEntry->type = TZX_CONTENT_FILENAME;
      newEntry->referenceCount = 1;
      fileName = newEntry;

      // Set first entry
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      smbInfo->contDimValListEntry = lastEntry = newEntry;

      // Extension
      newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));
      parseFileExt( fileDirName, newEntry->stringValue );
      newEntry->stringValueLength = strlen(newEntry->stringValue);
      newEntry->type = TZX_CONTENT_FILEEXT;
      newEntry->referenceCount = 1;

      if( newEntry->stringValue[0] != '\0' )
      {
          // Append next entry
          lastEntry->next = newEntry;
          lastEntry = newEntry;
          fileExt = newEntry;
      } else {
          // No extension so don't add it
          free( newEntry );
      }

      if( strlen(fileDirPath) != 0 )
      {
          // FilePath
          newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));
          memcpy( newEntry->stringValue, fileDirPath, 
                                                   strlen(fileDirPath) +1);
          newEntry->stringValueLength = strlen(fileDirPath);
          newEntry->type = TZX_CONTENT_FILEPATH;
          newEntry->referenceCount = 1;
          filePath = newEntry;

          // Append next entry
          lastEntry->next = newEntry;
          lastEntry = newEntry;
      }

      if( fileStg2 != NULL )
      {
          parsePathFile( fileStg2, fileDirPath2, fileDirName2 );

          // FileName
          if( !strcmp( fileName->stringValue, fileDirName2) )
          {
              // The second filename is identical to the first
              ++fileName->referenceCount;
          }
          else
          {
              newEntry = (DimValListEntry *)calloc(1, 
                                                  sizeof(DimValListEntry));

              memcpy( newEntry->stringValue, fileDirName2, 
                                                  strlen(fileDirName2) +1);
              newEntry->stringValueLength = strlen(fileDirName2);
              newEntry->type = TZX_CONTENT_FILENAME;
              newEntry->referenceCount = 1;

              // Append next entry
              lastEntry->next = newEntry;
              lastEntry = newEntry;
          }

          // Extension
          parseFileExt( fileDirName2, fileExt2 );

          // Check if both files had an extension and if they're identical
          if(    fileExt != NULL
              && fileExt2[0] != '\0'
              && !strcmp( fileExt->stringValue, fileExt2) )
          {
              // The second extension is identical to the first
              ++fileExt->referenceCount;
          }
          else
          {
              newEntry = (DimValListEntry *)calloc(1, 
                                                  sizeof(DimValListEntry));
              memcpy( newEntry->stringValue, fileExt2, strlen(fileExt2) +1);
              newEntry->stringValueLength = strlen(fileExt2);
              newEntry->type = TZX_CONTENT_FILEEXT;
              newEntry->referenceCount = 1;

              if( newEntry->stringValue[0] != '\0' )
              {
                  // Append next entry
                  lastEntry->next = newEntry;
                  lastEntry = newEntry;
              } else {
                  // No extension so don't add it
                  free( newEntry );
              }
          }
      }

      if(    fileStg2 != NULL
          && strlen(fileDirPath2) != 0 )
      {
          // Check if the first had a path
          if(    filePath != NULL
                 && !strcmp( filePath->stringValue, fileDirPath2 ) )
          {
              // The second path is identical to the first
              ++filePath->referenceCount;
          }
          else
          {
              // FilePath
              newEntry = (DimValListEntry *)calloc(1, 
                                                  sizeof(DimValListEntry));
              memcpy( newEntry->stringValue, fileDirPath2, 
                                                  strlen(fileDirPath2) +1);
              newEntry->stringValueLength = strlen(fileDirPath2);
              newEntry->type = TZX_CONTENT_FILEPATH;
              newEntry->referenceCount = 1;

              // Append next entry
              lastEntry->next = newEntry;
              lastEntry = newEntry;
          }
      }

      // sharename is now part of serverInfo and is "static" to a virtual
      // session.
#if 0
      if( shareNameStg )
      {
          // ShareName
          newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));
          memcpy( newEntry->stringValue, shareNameStg, 
                                                  strlen(shareNameStg) +1);
          newEntry->stringValueLength = strlen(shareNameStg);
          newEntry->type = TZX_CONTENT_SHARENAME;
          newEntry->referenceCount = 1;

          // Append next entry
          lastEntry->next = newEntry;
          lastEntry = newEntry;
      }
#endif

      // Terminate the list
      lastEntry->next = NULL;

  } while (0);

}

//-----------------------------------------------------------------------
// setDimFolderContent()
//     Dimensions TZX_CONTENT_FOLDERNAME, TZX_CONTENT_FILEPATH
//
// NOTE: For RENAME this code is untested.  That's because the command
//       does not distinguish between files and directories so all
//       renames are handled as files.
//
// FIX - if fileDirPath == fileDirPath2 or ext == ext2 then there should
//       only be one dimension pushed up with a ref count of 2
//       See code in setDimFileContent(), above.
//
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimFolderContent( SessionEntry *sessionEntry,
                                              tz_int8      *folderStg,
                                              tz_int8      *folderStg2,
                                              tz_int8      *shareNameStg,
                                              tz_uint32     len )
{
  DimValListEntry  *lastEntry, *newEntry;

  do
  {
      parsePathFile( folderStg, fileDirPath, fileDirName );

      // FolderName - either there is one or else it's "\"
      newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));

      if( strlen(fileDirName) != 0 )
      {
          memcpy( newEntry->stringValue, fileDirName, 
                                                   strlen(fileDirName) +1);
          newEntry->stringValueLength = strlen(fileDirName);
      }
      else
      {
          strcpy( newEntry->stringValue, "\\" );
          newEntry->stringValueLength = strlen("\\");
      }

      newEntry->type = TZX_CONTENT_FOLDERNAME;
      newEntry->referenceCount = 1;

      // Set first entry
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      smbInfo->contDimValListEntry = lastEntry = newEntry;

      if( strlen(fileDirPath) != 0 )
      {
          // FilePath
          newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));
          memcpy( newEntry->stringValue, fileDirPath, 
                                                   strlen(fileDirPath) +1);
          newEntry->stringValueLength = strlen(fileDirPath);
          newEntry->type = TZX_CONTENT_FILEPATH;
          newEntry->referenceCount = 1;

          // Append next entry
          lastEntry->next = newEntry;
          lastEntry = newEntry;
      }

      if( folderStg2 != NULL )
      {
          parsePathFile( folderStg2, fileDirPath2, fileDirName2 );

          // FolderName - either there is one or else it's "\"
          newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));

          if( strlen(fileDirName2) != 0 )
          {
              memcpy( newEntry->stringValue, fileDirName2, 
                                                  strlen(fileDirName2) +1);
              newEntry->stringValueLength = strlen(fileDirName2);
          }
          else
          {
              strcpy( newEntry->stringValue, "\\" );
              newEntry->stringValueLength = strlen("\\");
          }

          newEntry->type = TZX_CONTENT_FOLDERNAME;
          newEntry->referenceCount = 1;

          // Append next entry
          lastEntry->next = newEntry;
          lastEntry = newEntry;

          if( strlen(fileDirPath2) != 0 )
          {
              // FilePath
              newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));
              memcpy( newEntry->stringValue, fileDirPath2, 
                                                       strlen(fileDirPath2) +1);
              newEntry->stringValueLength = strlen(fileDirPath2);
              newEntry->type = TZX_CONTENT_FILEPATH;
              newEntry->referenceCount = 1;

              // Append next entry
              lastEntry->next = newEntry;
              lastEntry = newEntry;
          }
      }

      // sharename is now part of serverInfo and is "static" to a virtual
      // session.
#if 0
      if( shareNameStg )
      {
          // ShareName
          newEntry = (DimValListEntry *)calloc(1, sizeof(DimValListEntry));
          memcpy( newEntry->stringValue, shareNameStg, 
                                                  strlen(shareNameStg) +1);
          newEntry->stringValueLength = strlen(shareNameStg);
          newEntry->type = TZX_CONTENT_SHARENAME;
          newEntry->referenceCount = 1;

          // Append next entry
          lastEntry->next = newEntry;
          lastEntry = newEntry;
      }
#endif

      // Terminate the list
      lastEntry->next = NULL;

  } while (0);
}

//-----------------------------------------------------------------------
// setDimOperation()
//     The Operation dimension is used for both Files and Folders
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimOperation( SessionEntry   *sessionEntry,
                                          SmbEvtFiltEvent evt,
                                          tz_int8        *operStg,
                                          tz_uint32       len )
{
  evtFiltCurrEvent = evt;

  if( evt != EVT_UNKNOWN )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      smbInfo->operDimValListEntry = (DimValListEntry *)calloc(1, 
                                                 sizeof(DimValListEntry));

      memcpy( smbInfo->operDimValListEntry->stringValue,
              operStg, len );
      // length shall NOT include the NULL (as of r4418, 12-6-05)
      smbInfo->operDimValListEntry->stringValueLength = len - 1;
      smbInfo->operDimValListEntry->type = TZX_OPERATION_FILE;
      smbInfo->operDimValListEntry->referenceCount = 1;
      smbInfo->operDimValListEntry->next = NULL;
  }
}

//-----------------------------------------------------------------------
// setDimSize()
//     Dimensions TZX_SIZE, TZX_SIZE_FILES
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimSize( SessionEntry   *sessionEntry,
                                     tz_uint64       size )
{

  if( size )
  {
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      smbInfo->sizeDimValListEntry = (DimValListEntry *)calloc(1, 
                                                sizeof(DimValListEntry));
      smbInfo->sizeDimValListEntry->numericalValue = size;
      smbInfo->sizeDimValListEntry->type = TZX_SIZE_BYTES;
      //smbInfo->sizeDimValListEntry->referenceCount= 1;
      smbInfo->sizeDimValListEntry->next = NULL;
  }
}


//-----------------------------------------------------------------------
// setDimResponse()
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimResponse( SessionEntry   *sessionEntry,
                                         tz_uint32       respCode )
{
  SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  smbInfo->respDimValListEntry = (DimValListEntry *)calloc(1,
                                                sizeof(DimValListEntry));
  smbInfo->respDimValListEntry->numericalValue = respCode;
  smbInfo->respDimValListEntry->type = TZX_RESPONSE_STATUS;
  smbInfo->respDimValListEntry->next = NULL;
}

//-----------------------------------------------------------------------
// setDimResponseData()
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimResponseData( SessionEntry    *sessionEntry,
                                             DimValListEntry *respData )
{
  SmbInfo         *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  smbInfo->respDataDimValListEntry = respData;
}

//-----------------------------------------------------------------------
// setDimCommandData()
//-----------------------------------------------------------------------
void smbEncEngFormatter::setDimCommandData( SessionEntry    *sessionEntry,
                                            DimValListEntry *cmdData )
{
  SmbInfo         *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  smbInfo->cmdDataDimValListEntry = cmdData;
}

//-----------------------------------------------------------------------
// resetEvent()
//     Reset the Enc Eng Formatter so that a new event can be
//     formatted
//
//     Note:  this function formerly had a parameter sessionHash of
//     type tz_uint32 which was used for the FileInfo hash table method
//     of event filtering.  That method has been commented out so the
//     parameter has been removed from this function.  Should we want
//     to reinstate that code someday, the client must pass the value
//     HASH_SESSION(sessionEntry->addressTuple) for the sessionHash
//     parameter.
//     WARNING: the hash function has been changed, and made local to driver.cc
//-----------------------------------------------------------------------
void smbEncEngFormatter::resetEvent( SessionEntry *sessionEntry )
{
  SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbInfo->contDimValListEntry     = NULL;
  smbInfo->operDimValListEntry     = NULL;
  smbInfo->sizeDimValListEntry     = NULL;
  smbInfo->respDimValListEntry     = NULL;
  smbInfo->respDataDimValListEntry = NULL;
  smbInfo->cmdDataDimValListEntry  = NULL;

  //evtFiltCurrSessionHash = sessionHash;

  // Reset any event filtering debug information
  evtFiltDbgInfo[0] = '\0';
}

//-----------------------------------------------------------------------
// sendCOSREvent()
//     Push the Content, Operation, Size, Response event up to the 
//     Encoding Engine
//
//-----------------------------------------------------------------------
void smbEncEngFormatter::sendCOSREvent( EncodingEngine *encEng,
                                        SessionEntry   *sessionEntry,
                                        SmbSsnUid      *ssnUid,
                                        SmbSsnTid      *ssnTid,
                                        tz_int8        *cmdStg )
{
  SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  bool     sendEvent = true;

  do
  {
      sendEvent = evtFiltEventIsGenerated( sessionEntry,
                                               &ssnUid->fileInfoTree );

      // Now that the decision has been made, reset the filtering
      // decision mechanism for the next time
      evtFiltState = EVT_FILT_UNDECIDED;

      if( sendEvent == false )
      {
          // We're not generating an event so the Encoding Engine will
          // not clean up the vectors so we must do it here
          freeVector(smbInfo->contDimValListEntry);
          freeVector(smbInfo->operDimValListEntry);
          freeVector(smbInfo->sizeDimValListEntry);
          freeVector(smbInfo->respDimValListEntry);

          break;
      }

      if( SmbDebug::logIsEnabled )
      {
          // Display an event issued
          strcat( &evtFiltDbgInfo[strlen(evtFiltDbgInfo)], "  EVT" );
      }

      if( ssnTid->ctxtIsEmpty )
      {
          // This is the first event being pushed up.  the encodingEngine
          // and statsEngine have not yet stamped the SessionEntry so we
          // do not need to restore SessionEntry context
          ssnTid->ctxtIsEmpty = false;


          // Set sessionDetail to NULL.  It may already be non-NULL due
          // to a successful login to another share on the server
          sessionEntry->sessionDetail = NULL;

          // Set up serverInfo which represents Server and Share
          SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
          sprintf(smbInfo->serverInfo, "%s\\%s", ssnTid->servername,
                                                     ssnTid->sharename );
      }
      else
      {
          restoreSessionEntry( sessionEntry,
                               &ssnTid->seCtxt );
      }

      // Clone the command string because the EncodingEngine takes the
      // liberty of freeing it.
      tz_int8 *tmpCmdStg = (tz_int8 *)calloc(1, strlen(cmdStg) +1 );
      if( !tmpCmdStg )
      {
          SmbErrLog(LOG_INFO,"Failed command string alloc" );
          break;
      }

      memcpy( tmpCmdStg, cmdStg, strlen(cmdStg) +1 );

      encEng->IncomingTransaction( sessionEntry,
                                   smbInfo->contDimValListEntry, // content
                                   smbInfo->operDimValListEntry, // operation
                                   smbInfo->cmdDataDimValListEntry,  // command.data content scan
                                   smbInfo->respDataDimValListEntry, // response.data content scan
                                   smbInfo->respDimValListEntry, // response
                                   smbInfo->sizeDimValListEntry, // size
                                   ENCENGINE_EVENT_NORMAL,
                                   tmpCmdStg );         // command (freed!)

      // Mem Dealloc - 
      // The content, operation, size, and response vectors are all
      // freed by ClearEventDetail() in encodingEngine.cc
      // 

      // Store the virtual sessionDetail in its associated TID
      saveSessionEntry( sessionEntry,
                        &ssnTid->seCtxt );
  } while (0);
}

//-----------------------------------------------------------------------
// sendUnsuppEvent()
//     Push an "unsupported command" event up to the Encoding Engine
//
//-----------------------------------------------------------------------
void smbEncEngFormatter::sendUnsuppEvent( EncodingEngine *encEng,
                                          SessionEntry   *sessionEntry,
                                          SmbSsnUid      *ssnUid,
                                          SmbSsnTid      *ssnTid,
                                          tz_int8        *cmdStg )
{
  SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  do
  {
      if( ssnTid->ctxtIsEmpty )
      {
          // This is the first event being pushed up.  the encodingEngine
          // and statsEngine have not yet stamped the SessionEntry so we
          // do not need to restore SessionEntry context
          ssnTid->ctxtIsEmpty = false;


          // Set sessionDetail to NULL.  It may already be non-NULL due
          // to a successful login to another share on the server
          sessionEntry->sessionDetail = NULL;

          // Set up serverInfo which represents Server and Share
          SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
          sprintf(smbInfo->serverInfo, "%s\\%s", ssnTid->servername,
                                                     ssnTid->sharename );
      }
      else
      {
          restoreSessionEntry( sessionEntry,
                               &ssnTid->seCtxt );
      }

      // Clone the command string because the EncodingEngine takes the
      // liberty of freeing it.
      tz_int8 *tmpCmdStg = (tz_int8 *)calloc(1, strlen(cmdStg) +1 );
      if( !tmpCmdStg )
      {
          SmbErrLog(LOG_INFO,"Failed command string alloc" );
          break;
      }

      memcpy( tmpCmdStg, cmdStg, strlen(cmdStg) +1 );

      encEng->IncomingTransaction( sessionEntry,
                                   smbInfo->contDimValListEntry, // content
                                   smbInfo->operDimValListEntry, // operation
                                   smbInfo->cmdDataDimValListEntry,  // command.data content scan
                                   smbInfo->respDataDimValListEntry, // response.data content scan
                                   smbInfo->respDimValListEntry, // response
                                   smbInfo->sizeDimValListEntry, // size
                                   ENCENGINE_EVENT_UNSUPPORTED,
                                   tmpCmdStg );         // command (freed!)

      // Mem Dealloc - 
      // The content, operation, size, and response vectors are all
      // freed by ClearEventDetail() in encodingEngine.cc
      // 

      saveSessionEntry( sessionEntry,
                        &ssnTid->seCtxt );

  } while (0);
}

//-----------------------------------------------------------------------
// sendLoginFailureEvent()
//-----------------------------------------------------------------------
void smbEncEngFormatter::sendLoginFailureEvent( EncodingEngine *encEng,
                                                SessionEntry   *sessionEntry,
                                                tz_int8        *cmdStg )
{
  SmbInfo *ssnData = (SmbInfo *)sessionEntry->appInfo;

  do
  {
      // Clone the command string because the EncodingEngine takes the
      // liberty of freeing it.
      tz_int8 *tmpCmdStg = (tz_int8 *)calloc(1, strlen(cmdStg) +1 );
      if( !tmpCmdStg )
      {
          SmbErrLog(LOG_INFO,"Failed command string alloc" );
          break;
      }

      memcpy( tmpCmdStg, cmdStg, strlen(cmdStg) +1 );

      // Check to see if serverUser has been initialized and, if not,
      // do so now.
      if( ssnData->serverUser[0] == '\0' )
      {
          struct in_addr srcAddr;
          srcAddr.s_addr = sessionEntry->clientIsDst ?
                           sessionEntry->addressTuple.dst :
                           sessionEntry->addressTuple.src;

          strcpy( ssnData->serverUser, "USER_" );
          strcat( ssnData->serverUser, inet_ntoa(srcAddr) );
      }

      encEng->IncomingTransaction(sessionEntry,
                                  NULL, // no content on failed login
                                  NULL, // no operation on failed login
                                  NULL, // no command.data  content scanning
                                  NULL, // no response.data content scanning
                                  NULL, // no response on failed login 
                                  NULL, // no size on failed login
                                  ENCENGINE_EVENT_FAILEDLOGIN,
                                  tmpCmdStg );
  } while (0);
}

//-----------------------------------------------------------------------
// saveSessionEntry()
//-----------------------------------------------------------------------
void smbEncEngFormatter::saveSessionEntry( SessionEntry  *sessionEntry,
                                           SmbSsnSeCtxt  *seCtxt )
{
    seCtxt->sessionDetail    = sessionEntry->sessionDetail;
    seCtxt->id               = sessionEntry->id;
}

//-----------------------------------------------------------------------
// restoreSessionEntry()
//-----------------------------------------------------------------------
void smbEncEngFormatter::restoreSessionEntry( SessionEntry *sessionEntry,
                                              SmbSsnSeCtxt *seCtxt )
{
  sessionEntry->sessionDetail    = seCtxt->sessionDetail;
  sessionEntry->id               = seCtxt->id;
}

//-----------------------------------------------------------------------
// Ctor()
//-----------------------------------------------------------------------
smbEncEngFormatter::smbEncEngFormatter( SmbDecode *sd )
  : smbDecode(sd)
{
#if 0
  // Ensure that the FileInfo hastable is empty
  memset( fileTblHashTbl, 0, sizeof(SmbFileInfoEntry *) 
                                              * SMB_FILE_HASHTABLE_SZ );
#endif

  // Enable event filtering
  evtFiltIsEnabled = true;

  // Clear out temporary string buffers so Valgrind is happy
  memset( fileDirName, 0, TZX_512_STRING );
  memset( fileDirPath, 0, TZX_512_STRING );
  memset( fileDirName2, 0, TZX_512_STRING );
  memset( fileDirPath2, 0, TZX_512_STRING );
  memset( fileExt2, 0, TZX_512_STRING );

  // Terminate the debug log buffer
  evtFiltDbgInfo[0] = '\0';

  // Record the current time and wind it back so that it can be used
  // as an initial value for event filtering comparisons
  gettimeofday( &evtFiltTimeZero, NULL );

  // Make time artificially earlier so first events will not be filtered
  evtFiltTimeZero.tv_sec -= 60 * 60;  // 60 min

  // Reset the event filtering decision mechanism
  evtFiltState = EVT_FILT_UNDECIDED;
}

//-----------------------------------------------------------------------
// Dtor()
//-----------------------------------------------------------------------
smbEncEngFormatter::~smbEncEngFormatter( void )
{
}

//-----------------------------------------------------------------------
// freeVector()
//     This should be available as a general utility for all protocols
//-----------------------------------------------------------------------
void smbEncEngFormatter::freeVector(DimValListEntry *vector)
{
DimValListEntry *tmp;

    while (vector)
    {
        tmp = vector->next;
        free(vector);
        vector = tmp;  
    }
}

//-----------------------------------------------------------------------
// parsePathFile()
//     Accept a string with a path + directory or path + file and
//     separate the path from the file or directory name
//-----------------------------------------------------------------------
void smbEncEngFormatter::parsePathFile( tz_int8 *stg, tz_int8 *path, 
                                                      tz_int8 *name )
{
  char *slash, *begin, *end;
  tz_uint32 safeLen = 0;

  do
  {
      if( strlen(stg) == 0)
      {
          *path = '\0';
          *name = '\0';
          break;
      }
      slash = strstr( stg, "\\" );
      begin = slash;
      if( !slash )  end = stg;
      while( slash != NULL )
      {
          end = slash;
          ++slash;
          slash = strstr( slash, "\\" );
      }

      char *ptr = begin;
      safeLen = TZX_512_STRING - 1;
      while( ptr && ptr != end )
      {
          *path++ = *ptr++;
          --safeLen;
          if( !safeLen )  break;
      }
      *path = '\0';

      // If end is pointing to a '\\' skip past it
      if( *end == '\\' ) ++ end;

      safeLen = MIN( TZX_512_STRING - 1,
                     strlen(end) +1 );
      memcpy( name, end, safeLen );
      name[safeLen] = '\0';

  } while (0);

}

//-----------------------------------------------------------------------
// parseServerShare()
//     Accept a string with server + share and separate it into the
//     server and share components
//-----------------------------------------------------------------------
void smbEncEngFormatter::parseServerShare( tz_int8 *stg, tz_int8 *serv,
                                                         tz_int8 *share )
{
  char *slash, *begin, *end = NULL;
  tz_uint32 safeLen = 0;

  do
  {
      if( strlen(stg) == 0)
      {
          *serv = '\0';
          *share = '\0';
          break;
      }

      if(     *stg      != '\\'
          || *(stg + 1) != '\\' )
      {
          // We expect the server name to begin with two backslashes
          lc_log_basic(LOG_INFO,"Unexpected server string at %s:%d", 
                                                __FILE__, __LINE__);
          *serv = '\0';
          *share = '\0';
          break;
      }

      begin = slash = stg;
      // skip over the two leading backslashes
      slash +=2;
      slash = strstr( slash, "\\" );
      if( slash != NULL )
      {
          // now we're at the end of the server string
          end = slash;
      }

      char *ptr = begin;

      if( end )
      {
          //  Case \\<server>\<share>
          safeLen = TZX_64_STRING - 1;
          while( ptr != end )
          {
              *serv++ = *ptr++;
              --safeLen;
              if( !safeLen )  break;
          }
          *serv = '\0';

          safeLen = MIN( TZX_64_STRING - 1,
                         strlen(end+1) +1 );
          memcpy( share, end+1, safeLen );
          share[safeLen] = '\0';
      }
      else
      {
          // Case \\<server>
          safeLen = TZX_64_STRING - 1;
          while( *ptr )
          {
              *serv++ = *ptr++;
              --safeLen;
              if( !safeLen )  break;
          }
          *serv = '\0';

          *share = '\0';
      }

  } while (0);
}

//-----------------------------------------------------------------------
// parseFileExt()
//     Accept a string with a file name and extract the extension
//     (if any) from it
//-----------------------------------------------------------------------
void smbEncEngFormatter::parseFileExt( tz_int8 *stg, tz_int8 *ext )
{
  char *dot, *begin, *end;
  tz_uint32 safeLen = 0;

  do
  {
      if( strlen(stg) == 0)
      {
          *ext = '\0';
          break;
      }

      begin = dot = stg;
      dot = strstr( stg, "." );

      if( dot == NULL )
      {
          // no extension
          *ext = '\0';
          break;
      }
      while( dot != NULL )
      {
          end = dot;
          ++dot;
          dot = strstr( dot, "." );
      }

      safeLen = MIN( TZX_512_STRING - 1,
                     strlen(end+1) +1 );
      memcpy( ext, end+1, safeLen );
      ext[safeLen] = '\0';

  } while (0);
}

//=======================================================================
//
// Event Filtering Functions
//
//=======================================================================

static
int evtFiltTreeCompare( const void *fi1, const void *fi2 );
#if 0
static
void evtFiltTreeAction( const void *nodep, const VISIT which, const int depth);
#endif
static
void evtFiltDeleteNode( void *nodep );

// FileInfo for testing
//static SmbFileInfoEntry testEntry;

//-----------------------------------------------------------------------
// evtFiltEvaluate()
//     Evaluate what the filtering decision will be for a particular
//     event at this moment in time.  The decision will be retained and
//     used when the event is actually generated.
//
// returns:  true or false
//-----------------------------------------------------------------------
bool smbEncEngFormatter::evtFiltEvaluate( SessionEntry    *sessionEntry,
                                          SmbEvtFiltEvent  event,
                                          SmbSsnUid       *ssnUid,
                                          SmbSsnFid       *ssnFid )
{
    bool             ret = true;
    SmbInfo         *smbInfo = (SmbInfo *)sessionEntry->appInfo;
    DimValListEntry  entry;

    resetEvent( sessionEntry );
    evtFiltCurrEvent = event;

    // Format a DimValListEntry with the filename
    entry.type = TZX_CONTENT_FILENAME;
    entry.referenceCount = 1;

    tz_uint32 filenameLen = strlen( ssnFid->filename );
    memcpy( entry.stringValue, ssnFid->filename, filenameLen );
    entry.stringValue[filenameLen] = '\0';
    entry.stringValueLength = filenameLen + 1;
    entry.next = NULL;

    smbInfo->contDimValListEntry = &entry;

    ret = evtFiltEventIsGenerated( sessionEntry, &ssnUid->fileInfoTree );

    // Remember the evaluation for when normal event generation occurs
    evtFiltState = ret ? EVT_FILT_ACCEPT : EVT_FILT_REJECT;

    return ret;
}

//-----------------------------------------------------------------------
// evtFiltOverride()
//     Override the event filtering decision.  This is used when we want
//     to force an event to be reported (or not reported).
//-----------------------------------------------------------------------
void smbEncEngFormatter:: evtFiltOverride( EvtFiltState state )
{
    evtFiltState = state;
}

//-----------------------------------------------------------------------
// evtFiltEventIsGenerated()
//     Make a decision about whether to generate an event for this
//     particular protocol operation
//
// returns:  true or false
//-----------------------------------------------------------------------
bool smbEncEngFormatter::evtFiltEventIsGenerated( SessionEntry *sessionEntry,
                                                  void **fileInfoTree )
{
  bool              ret = true;
  SmbFileInfoEntry *testEntry;
  SmbFileInfoEntry *infoEntry;
  struct timeval    tvCurr;
  struct tm        *tm;

  do
  {
      // If filtering is disabled then we're done here
      if( !evtFiltIsEnabled )  break;

      // If a decision has already been made we're done here
      if( evtFiltState != EVT_FILT_UNDECIDED )
      {
          if( evtFiltState == EVT_FILT_ACCEPT ) {
              ret = true;
              break;
          }
          if( evtFiltState == EVT_FILT_REJECT ) {
              ret = false;
              break;
          }
      }

      // If the current event is not one that we apply filtering to then
      // we're done here
      if(   evtFiltCurrEvent != EVT_OPEN
         && evtFiltCurrEvent != EVT_READ
         && evtFiltCurrEvent != EVT_WRITE
         && evtFiltCurrEvent != EVT_CLOSE  )
      {
          break;
      }

      // Recover the string for the path and file/dir
      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      tz_int8 *pathFile = smbInfo->contDimValListEntry->stringValue;

#if 0
      // Find via Hash Table implementation
      SmbFileInfoEntry *infoEntry;

      if( IIMS_FAILURE == fileTblLookup( pathFile, &infoEntry) )
      {
          // An entry does not exist so create it
          fileTblInsert( pathFile, &infoEntry );

          if( SmbDebug::logIsEnabled )
          {
              // Indicate that a FileInfo has been created
              strcat( evtFiltDbgInfo, "$ " );
          }
      }
#else
      // Find via Tree implementation

      // Create an entry and use it to test.  If it already exists
      // then deallocate it.
      testEntry = (SmbFileInfoEntry *)calloc(1,
                                              sizeof(SmbFileInfoEntry) );
      if( testEntry == NULL ) {
          SmbErrLog(LOG_NOTICE,"FileInfo tree failure - "
                                                  "insufficient memory");
          break;
      }
 
      // Format a FileInfo in order to do a lookup
      testEntry->pathStgLen = strlen( pathFile );
      memcpy( testEntry->pathStg, pathFile, testEntry->pathStgLen );

      // Look it up and, if it does not exist, allocate a new one
      void * find;
      find = tfind( testEntry, fileInfoTree, evtFiltTreeCompare );

      if( find == NULL )
      {
          // Format the rest of fileInfo.
          for( tz_uint32 i = 0; i < SMB_EVT_FILT_NUM_EVTS; ++i )
          {
              testEntry->fileInfo.evtFiltMostRecent[i] = evtFiltTimeZero;
          }

          void *rv;
          rv = tsearch( testEntry, fileInfoTree, evtFiltTreeCompare );
          if( rv == NULL )
          {
              SmbErrLog(LOG_NOTICE,"FileInfo tree failure - "
                                                 "insufficient memory");
              break;
          }

          infoEntry = testEntry;

          if( SmbDebug::logIsEnabled )
          {
              // Indicate that a FileInfo has been created
              strcat( evtFiltDbgInfo, "$ " );
          }
      }
      else
      {
          // It exists so use it
          infoEntry = *((SmbFileInfoEntry **)find);

          // FIX - Free the value used for testing.  This is crazy, I
          // know, but I could not get it to work with an auto variable
          // as it should be
          free( testEntry );
      }
#endif

      gettimeofday( &tvCurr, NULL );
      tm = localtime( (const time_t *)&tvCurr.tv_sec );

      if( SmbDebug::logIsEnabled )
      {
          sprintf( &evtFiltDbgInfo[strlen(evtFiltDbgInfo)], 
          "%02d:%02d:%02d.%06d", tm->tm_hour, tm->tm_min, tm->tm_sec,
                                                  (int)tvCurr.tv_usec );
      }

      // And now, the decision.  We determine if enough time has passed
      // since the last time the event was issued.  If it has not, we ignore
      // the event.
      struct timeval tvAdj;
      tvAdj = infoEntry->fileInfo.evtFiltMostRecent[evtFiltCurrEvent];
      tvAdj.tv_sec += 1;     // 1 sec OFFSET

      ret = !timercmp( &tvCurr, &tvAdj, < );

      // Save the current time as the "most recent" for the event
      infoEntry->fileInfo.evtFiltMostRecent[evtFiltCurrEvent] = tvCurr;

      if( SmbDebug::logIsEnabled )
      {
          // Print Accept or Reject in the debug log
          strcat( &evtFiltDbgInfo[strlen(evtFiltDbgInfo)], ret ? " A" : " R" );
      }

  } while (0);

  return ret;
}

// evtFiltRemove tree uses twalk which invokes the action handler
// evtFiltTreeAction().  It is passed the root of the tree via this 
// variable
static void *evtFiltRemoveTreeRootOfTree;

//-----------------------------------------------------------------------
// evtFiltRemoveTree()
//     This function removes the tree of FileInfo data when a UID is 
//     destroyed.
//-----------------------------------------------------------------------
void evtFiltRemoveTree( void *fileInfoTree )
{
    evtFiltRemoveTreeRootOfTree = fileInfoTree;

#if 0
    // I had problems with the idea of using twalk to visit every
    // node on the tree, remove the storage and then remove it as a
    // tree element
    twalk( fileInfoTree, evtFiltTreeAction );
#else
    // GLIBC tree destroy
    tdestroy( fileInfoTree,evtFiltDeleteNode );
#endif
}

//-----------------------------------------------------------------------
// evtFiltTreeCompare()
//-----------------------------------------------------------------------
static
int evtFiltTreeCompare( const void *fi1, const void *fi2 )
{
  SmbFileInfoEntry *f1 = (SmbFileInfoEntry *)fi1;
  SmbFileInfoEntry *f2 = (SmbFileInfoEntry *)fi2;

  int res = strcmp( f1->pathStg,  f2->pathStg ); 
  //printf( "cmp %d\n",res );
  return res;
}

#if 0
//-----------------------------------------------------------------------
// evtFiltTreeAction()
//     This action is executed on each node found on the FileInfo tree
//
// in:
//     evtFiltRemoveTreeRootOfTree
//-----------------------------------------------------------------------
static
void evtFiltTreeAction( const void *nodep, const VISIT which, const int depth)
{
  SmbFileInfoEntry *fi = *((SmbFileInfoEntry **)nodep);

  //printf( "action VISIT %d depth %d\n", which, depth );

  switch( which )
  {
  case postorder:
  case leaf:
      //printf("%s\n", fi->pathStg);
      free( fi );
      tdelete( fi, &evtFiltRemoveTreeRootOfTree, evtFiltTreeCompare );
      break;
  case preorder:
  case endorder:
  default:
      break;
  }

}
#endif

//-----------------------------------------------------------------------
// evtFiltDeleteNode
//-----------------------------------------------------------------------
static
void evtFiltDeleteNode( void *nodep )
{
  free( nodep );
}

#if 0  // Hash Table removed in favor of Binary Search Tree on UID descr
//=======================================================================
//
// FileInfo Hashtable Manipulation Functions
//
//=======================================================================

//-----------------------------------------------------------------------
// fileTblStgHash()
//
//     Calculate a hash on the path and file string provided for a
//     particular session.  The string is assumed to be NULL terminated.
//-----------------------------------------------------------------------
tz_uint32 smbEncEngFormatter::fileTblStgHash( tz_int8 *pathStg )
{
  tz_int8   *p = pathStg;
  tz_uint32  h = *p;

  if( h )
  {
      for( p += 1; *p != '\0'; p++ )
      {
          h = (h<<5) - h + *p;
      }
  }

  // Factor in the "session hash" (hash of the AddressTuple)
  h = h ^ evtFiltCurrSessionHash;

  return (h % SMB_FILE_HASHTABLE_SZ);
}

//-----------------------------------------------------------------------
// fileTblLookup()
//     Lookup FileInfo from the path and file string provided.  A
//     reference to FileInfo is returned.  The caller must not disturb
//     its contents.
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE, not found
//-----------------------------------------------------------------------
tz_uint32 smbEncEngFormatter::fileTblLookup( tz_int8 *pathStg, 
                                             SmbFileInfoEntry **tblEntry )
{
  tz_uint32 status = IIMS_FAILURE;
  SmbFileInfoEntry *entry;
  tz_uint32         index;
  tz_uint32         currLen = strlen( pathStg );

  do
  {
      index = fileTblStgHash( pathStg );
      entry = fileTblHashTbl[ index ];

      while( entry != NULL )
      {
          if(    entry->pathStgLen == currLen 
              && !memcmp(pathStg, entry->pathStg, entry->pathStgLen) )
          {
              *tblEntry = entry;
              status = IIMS_SUCCESS;
              break;
          }
          entry = entry->next;
      }
      break;
  }
  while (0);

  return status;
}

//-----------------------------------------------------------------------
// fileTblInsert()
//
// out:
//     tblEntry, the new entry (valid if IIMS_SUCCESS)
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE
//-----------------------------------------------------------------------
tz_uint32 smbEncEngFormatter::fileTblInsert( tz_int8 *pathStg,
                                             SmbFileInfoEntry **tblEntry )
{
  tz_uint32 status = IIMS_SUCCESS;
  SmbFileInfoEntry *entry;
  tz_uint32         index;

  do
  {
      entry = (SmbFileInfoEntry *)calloc(1, sizeof(SmbFileInfoEntry) );
      if( entry == NULL ) {
          status = IIMS_FAILURE;
          break;
      }
      index = fileTblStgHash( pathStg );

      // Insert as first on the chain (if there is one)
      entry->next = fileTblHashTbl[ index ];
      fileTblHashTbl[ index ] = entry;

      // Format the entry
      entry->pathStgLen = strlen( pathStg );
      memcpy( entry->pathStg, pathStg, entry->pathStgLen );

      // Let the caller have it
      *tblEntry = entry;

      // Format fileInfo.  (I'm in the mood today for straightline code)
      entry->fileInfo.evtFiltMostRecent[0] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[1] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[2] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[3] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[4] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[5] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[6] = evtFiltTimeZero;
      entry->fileInfo.evtFiltMostRecent[7] = evtFiltTimeZero;
  }
  while (0);

  return status;
}

//-----------------------------------------------------------------------
// fileTblRemove()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE
//-----------------------------------------------------------------------
tz_uint32 smbEncEngFormatter::fileTblRemove( tz_int8 *pathStg )
{
  tz_uint32 status = IIMS_SUCCESS;
  SmbFileInfoEntry *entry, *prevEntry;
  tz_uint32         index;
  tz_uint32         currLen = strlen( pathStg );

  do
  {
      index = fileTblStgHash( pathStg );
      entry = fileTblHashTbl[ index ];
      prevEntry = NULL;

      while( entry != NULL )
      {
          if(    entry->pathStgLen == currLen 
              && !memcmp(pathStg, entry->pathStg, entry->pathStgLen) )
          {
              if( prevEntry == NULL ) {
                  // We're at the beginning of the chain
                  fileTblHashTbl[ index ] = entry->next;
              } else {
                  // Remove the current from the chain
                  prevEntry->next = entry->next;
              }
              free( entry );
              break;
          }
          prevEntry = entry;
          entry = entry->next;
      }
      break;
  }
  while (0);

  return status;
}

//-----------------------------------------------------------------------
// fileTblGetFirstEntry()
//
// IIMS_SUCCESS  - an entry has been found
// IIMS_FALILURE - no entry found
//-----------------------------------------------------------------------
tz_uint32 smbEncEngFormatter::fileTblGetFirstEntry( SmbFileInfoEntry **tblEntry )
{
  tz_uint32 status = IIMS_FAILURE;
  SmbFileInfoEntry *entry;
  tz_uint32 tblIdx, listIdx;

  getFileInfoEntryIdx = getFileInfoEntryChainListIdx = 0;

  for( tblIdx=0, listIdx=0; tblIdx < SMB_FILE_HASHTABLE_SZ; ++tblIdx )
  {
      if( fileTblHashTbl[tblIdx] )
      {
          // We've found one so make it available
          entry = fileTblHashTbl[tblIdx];
          *tblEntry = entry;

          // Save the current session state
          getFileInfoEntryIdx = tblIdx;
          getFileInfoEntryChainListIdx = ++listIdx;
          status = IIMS_SUCCESS;
          break;
      }
  }
  return status;
}

//-----------------------------------------------------------------------
// fileTblGetNextEntry()
//
// IIMS_SUCCESS  - an entry has been found
// IIMS_FALILURE - no entry found
//-----------------------------------------------------------------------
tz_uint32 smbEncEngFormatter::fileTblGetNextEntry( SmbFileInfoEntry **tblEntry )
{
  tz_uint32 status = IIMS_FAILURE;
  SmbFileInfoEntry *entry;

  tz_uint32 tblIdx = getFileInfoEntryIdx;
  tz_uint32 listIdx;

  for(  ; tblIdx < SMB_FILE_HASHTABLE_SZ; ++tblIdx )
  {
      if( fileTblHashTbl[tblIdx] )
      {
          listIdx = 0;
          if( tblIdx == getFileInfoEntryIdx )
          {
              // Pick up on this list from where we left off last time
              // by ignoring previously returned entries
              entry = fileTblHashTbl[tblIdx];
              while( entry  )
              {
                  if( listIdx >= getFileInfoEntryChainListIdx )
                  {
                      // Save the parameters of interest
                      *tblEntry = entry;

                      // Save the current session state
                      getFileInfoEntryIdx = tblIdx;
                      getFileInfoEntryChainListIdx = ++listIdx;
                      status = IIMS_SUCCESS;
                      return status;
                  }

                  ++listIdx;
                  entry = entry->next;
              }
          }
          else
          {
              // We're on a new chain and we found a SessionEntry
              entry = fileTblHashTbl[tblIdx];

              // Save the parameters of interest
              *tblEntry = entry;

              // Save the current session state
              getFileInfoEntryIdx = tblIdx;
              getFileInfoEntryChainListIdx = ++listIdx;
              status = IIMS_SUCCESS;
              break;
          }
      }
  }
  return status;
}
#endif  // // Hash Table removed in favor of Binary Search Tree on UID descr




