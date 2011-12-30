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
  // TODO
  return false;
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
           byte_t * response, size_t * responseSize)
{
  // TODO
  return false;
}
           

// This function writes some bytes to a block on the target tag.
bool
writeBlocks(nfc_device_t * reader, const byte_t blockNum,
            const byte_t * data, const size_t dataSize)
{
  // TODO
  return false;
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

      /************************************************************************
      // (1) Load authentication keys into the reader
      if (!loadAuthKeysIntoReader(pnd, ...)) {
        printf ("Failed to load auth keys into reader for target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }

      // (2) Authenticate with tag using the loaded auth keys
      if (!authenticateWithTag(pnd, ...)) {
        printf ("Failed to authenticate with target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }

      // (3) Read data from tag
      if (!readBlocks(pnd, ...)) {
        printf ("Failed to read blocks from target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }

      // (4) Write data to tag
      if (!writeBlocks(pnd, ...)) {
        printf ("Failed to read blocks 2nd time from target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }

      // (5) Read data from tag and confirm it was the written data
      if (!readBlocks(pnd, ...)) {
        printf ("Failed to read blocks 2nd time from target tag UID: ");
        print_hex (nt->nti.nai.abtUid, nt->nti.nai.szUidLen);
        continue;
      }
      ************************************************************************/
    }
  }
  // Disconnect from NFC device
  nfc_disconnect(pnd);
  return EXIT_SUCCESS;
}

