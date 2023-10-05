#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define LUKS_NAME_SIZE 32
#define LUKS_UUID_SIZE 40
#define NUM_KEYSLOTS 8

typedef struct {
  char data[48];
} LUKS_KEYSLOT;

typedef struct {
  char magic[6];                       // offset 0
  uint16_t version;                    // offset 6
  char cipherName[LUKS_NAME_SIZE];     // offset 8
  char cipherMode[LUKS_NAME_SIZE];     // offset 40
  char hashSpec[LUKS_NAME_SIZE];       // offset 72
  uint32_t payloadOffset;              // offset 104
  uint32_t numKeyBytes;                // offset 108
  char mkDigest[20];                   // offset 112
  char mkDigestSalt[32];               // offset 132
  uint32_t mkDigestIter;               // offset 164
  char partitionUUID[LUKS_UUID_SIZE];  // offset 168
  LUKS_KEYSLOT keyslots[NUM_KEYSLOTS]; // offset 208
} LUKS_HEADER;

typedef struct {
  char Value[52];
} LUKS_DECRYPTION_KEY;

LUKS_DECRYPTION_KEY CalculateDecryptionKey(LUKS_HEADER header)
{
  LUKS_DECRYPTION_KEY decryptionKey;
  char generatedKey[52];
  char digestAndDigestSalt[52];

  memcpy(&digestAndDigestSalt, header.mkDigest, 52);

  for (uint32_t i = 0; i < 52; i++) {
    char xoredValue = digestAndDigestSalt[i] ^ digestAndDigestSalt[sizeof(digestAndDigestSalt) - i - 1];

    if((uint32_t)xoredValue < 0x20) {
      xoredValue = xoredValue | 0x20;
    }

    decryptionKey.Value[i] = xoredValue;
  }

  return decryptionKey;
}

int main() {
  LUKS_HEADER header;
  LUKS_DECRYPTION_KEY generatedKey;

  FILE *file = fopen("test.bin", "rb");
  if (file == NULL) {
    perror("Error opening file");
    return 1; 
  }

  size_t header_size = sizeof(LUKS_HEADER);
  size_t elements_read = fread(&header, header_size, 1, file);

  if (elements_read != 1) {
    perror("Error reading file");
    fclose(file); // Close the file before exiting
    return 2; // Return an error code
  }

  generatedKey = CalculateDecryptionKey(header);

  fclose(file);

  FILE *outputFile = stdout;
  fwrite(generatedKey.Value, sizeof(unsigned char), sizeof(generatedKey)/sizeof(unsigned char), outputFile);

  return 0;
}
