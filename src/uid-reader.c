// Original source: http://code.google.com/p/libnfc/source/browse/trunk/examples/doc/quick_start_example1.c
//
// Modifications:
//  - List all passive tags, up to 10, instead of first tag.
//
// Compile with C99 mode to be able to say for (int i = 0; ...). Else have to declare
// the loop variable outside the loop.
// c.f. http://cplusplus.syntaxerrors.info/index.php?title='for'_loop_initial_declaration_used_outside_C99_mode

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdlib.h>
#include <nfc/nfc.h>
#include <string.h>

///////////////////////////////////////////////////////
// Some useful hardware constants from the ACR122u API
//
// Load a key {FF FF FF FF FF FF} into the key location 0x04.
// APDU = {FF 82 00 *04* *06* *FF FF FF FF FF FF*} (*06* is the key length)
const byte_t acr122u_loadAuthKeys[] = { 0xFF, 0x82, 0x00 };
const byte_t mifare_default_key[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// To authenticate the Block 0x07 with a { TypeA, key number 0x04 }. For PC/SC V2.07
// alaAPDU = { FF 86 00 00 05 01 00 *07* *60* *04* } (TypeA = 0x60)
const byte_t acr122u_authenticate[] = { 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00 };

// 1. Read 16 bytes from the binary block 0x04 (Mifare 1K or 4K)
//    APDU = { FF B0 00 *04* *10* }
// 2. Read 4 bytes from the binary Page 0x08 (Mifare Ultralight)
//    APDU = { FF B0 00 *04* *08* }
// 3. Read 16 bytes starting from the binary Page 0x04 (Mifare Ultralight) (Pages 4, 5, 6 and 7 will be read)
//    APDU = { FF B0 00 *04* *10* }
// const byte_t acr122u_read[] = { 0xFF, 0xB0, 0x00 };
// c.f. http://www.nxp.com/documents/data_sheet/MF1S503x.pdf Section 10.2. This is only for MiFare 1k Classics, but also seems to work for MiFare Ultralight C.
const byte_t acr122u_read[] = { 0x30 }; 

// 1. Update the binary block 0x08 of Mifare 1K/4K with data { 00 01 .. 0F }
//    APDU = { FF D6 00 *08* *10* *00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F* }
// 2. Update the binary block 0x08 of Mifare Ultralight with data { 00 01 02 03 }
//    APDU = { FF D6 00 *08* *04* *00 01 02 03* }
// const byte_t acr122u_write[] = { 0xFF, 0xD6, 0x00 };
const byte_t acr122u_write[] = { 0xA0 };

void
print_hex (const byte_t * pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf ("%02x  ", pbtData[szPos]);
  }
  printf ("\n");
}

void 
printISO14443ATagInfo(nfc_target_t * nt)
{
  printf ("The following (NFC) ISO14443A tag was found:\n");
  printf ("    ATQA (SENS_RES): ");
  print_hex (nt->nti.nai.abtAtqa, 2);
  printf ("       UID (NFCID%c): ", (nt->nti.nai.abtUid[0] == 0x08 ? '3' : '1'));
  print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
  printf ("      SAK (SEL_RES): ");
  print_hex (&(nt->nti.nai.btSak), 1);
  if (nt->nti.nai.szAtsLen) {
    printf ("          ATS (ATR): ");
    print_hex (nt->nti.nai.abtAts, nt->nti.nai.szAtsLen);
  }
  printf ("\n");
}


// Given a reader and target info (typically from nfc_initiator_list_passive_targets),
// selects this target. After this is done, can authenticate and read/write to this
// target.
bool
selectPassiveTarget(nfc_device_t * pnd, nfc_target_t * target)
{
  return nfc_initiator_select_passive_target(pnd, target->nm,
    target->nti.nai.abtUid, target->nti.nai.szUidLen, NULL);
}

// The card reader can store some auth keys. Once we store these auth keys
// in the card reader, they can be used to authenticate with the tag being read/written.
//
// This function sets the given reader's key at keyNum equal to keyVal.
bool
loadAuthKeysIntoReader(nfc_device_t * reader, const byte_t keyNum,
                       const byte_t * keyVal, const size_t keyValSize)
{
  // Allocate the command and receive buffers
  size_t byte_t_size = sizeof(byte_t);
  size_t commandBufferSize = byte_t_size * (sizeof(acr122u_loadAuthKeys) + 2 + keyValSize);
  const size_t MAX_CMD_BUF_SIZE = 1024;
  if (commandBufferSize > MAX_CMD_BUF_SIZE) {
    return false;
  }

  byte_t commandBuffer[MAX_CMD_BUF_SIZE];
  byte_t receiveBuffer[2];
  size_t receiveBufferSize = sizeof(receiveBuffer);

  // Build the command according to the API
  unsigned int idx = 0;
  memcpy(commandBuffer,
         acr122u_loadAuthKeys,
         byte_t_size * sizeof(acr122u_loadAuthKeys));
  idx += sizeof(acr122u_loadAuthKeys);
  commandBuffer[idx++] = keyNum;
  commandBuffer[idx++] = keyValSize;
  memcpy(commandBuffer + idx, keyVal, keyValSize);

  // Send the command with no timeout
  bool ret = nfc_initiator_transceive_bytes(reader, commandBuffer, commandBufferSize,
    receiveBuffer, &receiveBufferSize, NULL);

  return ret;
}

// Once we have auth keys saved into the reader, we need to use them
// to auth the appropriate blocks on the tag.
//
// This function auths the given target tag block with the key stored at the
// given key number of the given card.
bool
authenticateWithTag(nfc_device_t * reader, const byte_t keyNum, const byte_t blockNum)
{
  // TODO
  return false;
}

// Once we have auth'ed the appropriate sector on the target tag, we can
// read or write to the blocks in that sector.
//
// This function reads some bytes from a block on the target tag.
bool
readBlocks(nfc_device_t * reader, 
           const byte_t blockNum, const size_t numBytes,
           byte_t * receiveBuffer, size_t * receiveBufferSize)
{
  // Allocate the command and receive buffers
  size_t byte_t_size = sizeof(byte_t);
  size_t commandBufferSize = byte_t_size * (sizeof(acr122u_read) + 1);
  const size_t MAX_CMD_BUF_SIZE = 1024;
  if (commandBufferSize > MAX_CMD_BUF_SIZE) {
    return false;
  }
  byte_t commandBuffer[MAX_CMD_BUF_SIZE];

  // Build the command according to the API
  unsigned int idx = 0;
  memcpy(commandBuffer, acr122u_read, byte_t_size * sizeof(acr122u_read));
  idx += sizeof(acr122u_read);
  commandBuffer[idx++] = blockNum;
  // commandBuffer[idx++] = numBytes;

  // Send the command with no timeout
  print_hex(commandBuffer, commandBufferSize);
  printf ("Error before transceive: %d\n", reader->iLastError);
  bool ret = nfc_initiator_transceive_bytes(reader, commandBuffer, commandBufferSize,
    receiveBuffer, receiveBufferSize, NULL);
  print_hex(receiveBuffer, *receiveBufferSize);
  printf ("Error after transceive: %x\n", reader->iLastError);

  return ret;
}
           

// This function writes some bytes to a block on the target tag.
bool
writeBlocks(nfc_device_t * reader, const byte_t blockNum,
            const byte_t * data, const size_t dataSize)
{
  // Allocate the command and receive buffers
  size_t byte_t_size = sizeof(byte_t);
  size_t commandBufferSize = byte_t_size * (sizeof(acr122u_write) + 1) + dataSize;
  const size_t MAX_CMD_BUF_SIZE = 1024;
  if (commandBufferSize > MAX_CMD_BUF_SIZE) {
    return false;
  }
  byte_t commandBuffer[MAX_CMD_BUF_SIZE];

  byte_t receiveBuffer[64];
  size_t receiveBufferSize = sizeof(receiveBuffer);

  // Build the command according to the API
  unsigned int idx = 0;
  memcpy(commandBuffer, acr122u_write, byte_t_size * sizeof(acr122u_write));
  idx += sizeof(acr122u_write);
  commandBuffer[idx++] = blockNum;
  memcpy(commandBuffer + idx, data, dataSize);

  // Send the command with no timeout
  print_hex(commandBuffer, commandBufferSize);
  printf ("Error before transceive: %d\n", reader->iLastError);
  bool ret = nfc_initiator_transceive_bytes(reader, commandBuffer, commandBufferSize,
    receiveBuffer, &receiveBufferSize, NULL);
  print_hex(receiveBuffer, receiveBufferSize);
  printf ("Error after transceive: %x\n", reader->iLastError);

  return ret;
}


int
main (int argc, const char *argv[])
{
  // Display libnfc version
  const char *acLibnfcVersion = nfc_version();
  printf ("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

  // Connect using the first available NFC device
  nfc_device_t * pnd = nfc_connect(NULL);

  if (pnd == NULL) {
    fprintf (stderr, "Unable to connect to NFC device.\n");
    return EXIT_FAILURE;
  }
  // Set connected NFC device to initiator mode
  nfc_initiator_init(pnd);

  printf ("Connected to NFC reader: %s\n", pnd->acName);

  // Poll for a ISO14443A (MIFARE) tag
  const nfc_modulation_t nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
  };

  // Only list up to MAX_TARGETS targets
  const size_t MAX_TARGETS = 10;
  size_t numTargetsFound = 0;
  nfc_target_t targets[MAX_TARGETS];
  if (nfc_initiator_list_passive_targets(pnd, nmMifare, targets, MAX_TARGETS, &numTargetsFound)) {
    printf ("[Found %zu target(s).]\n", numTargetsFound);

    for (size_t i = 0; i < numTargetsFound; ++i) {
      // Select targets[i] as the target
      nfc_target_t * nt = &targets[i];;
      if (!selectPassiveTarget(pnd, nt)) {
        printf ("Failed to select tag with UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      printISO14443ATagInfo(nt);

      // (1) Load authentication keys into the reader
      /************************************************************************
      if (!loadAuthKeysIntoReader(pnd, 0, mifare_default_key, sizeof(mifare_default_key))) {
        printf ("Failed to load auth keys into reader for target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      printf ("[Successfully loaded auth key into reader.]\n");

      // (2) Authenticate with tag using the loaded auth keys
      if (!authenticateWithTag(pnd, ...)) {
        printf ("Failed to authenticate with target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      ************************************************************************/

      // (3) Read data from tag
      byte_t blockData[1024];
      memset(blockData, 0, 1024);
      size_t blockDataSize = 0;
      if (!readBlocks(pnd, 0x04, 0x10, blockData, &blockDataSize)) {
        printf ("Failed to read blocks from target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      printf ("[Read %zu bytes from block %d.]\n", blockDataSize, 0x04);
      print_hex (blockData, blockDataSize);

      // (4) Write data to tag
      const byte_t writeData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08, 0x09, 0x0A, 0x0b, 0x0C, 0x0D, 0x0E, 0x0F };
      /*
      if (!writeBlocks(pnd, 0x04,  writeData, sizeof(writeData))) {
        printf ("Failed to write blocks into target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      */
      writeBlocks(pnd, 0x04, writeData, 16);
      writeBlocks(pnd, 0x05, writeData + 4, 16);
      writeBlocks(pnd, 0x06, writeData + 8, 16);
      writeBlocks(pnd, 0x07, writeData + 12, 16);
      printf ("[Wrote %d bytes to block %d.]\n", 16, 0x10);

      // (5) Read data from tag and confirm it was the written data
      memset(blockData, 0, 1024);
      if (!readBlocks(pnd, 0x04, 0x10, blockData, &blockDataSize)) {
        printf ("Failed to read blocks from target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      printf ("[Read %zu bytes from block %d.]\n", blockDataSize, 0x04);
      print_hex (blockData, blockDataSize);
    }
  }
  // Disconnect from NFC device
  nfc_disconnect(pnd);
  return EXIT_SUCCESS;
}

