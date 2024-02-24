#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_WARNINGS

// Function to decode Ethernet header and read payload
void decodeEthernetHeader(FILE* file) {
    // Structure to store MAC addresses and type info
    typedef struct {
        unsigned char destMAC[6];
        unsigned char srcMAC[6];
        unsigned char bType[2];
    }EthernetHeader;

    // Read Ethernet header from file
    EthernetHeader ethHeader;
    fread(&ethHeader, sizeof(EthernetHeader), 1, file);

    // Display Ethernet header info
    printf("Ethernet header:\n");
    printf("--------------------\n");
    // Print destination MAC address
    printf("Destination MAC address:\t %02x:%02x:%02x:%02x:%02x:%02x\n",
        ethHeader.destMAC[0], ethHeader.destMAC[1], ethHeader.destMAC[2],
        ethHeader.destMAC[3], ethHeader.destMAC[4], ethHeader.destMAC[5]);

    // Print source MAC address
    printf("Source MAC address:\t\t %02x:%02x:%02x:%02x:%02x:%02x\n",
        ethHeader.srcMAC[0], ethHeader.srcMAC[1], ethHeader.srcMAC[2],
        ethHeader.srcMAC[3], ethHeader.srcMAC[4], ethHeader.srcMAC[5]);

    // Print type
    printf("Type: ");
    printf("\t\t\t\t %02x%02x", ethHeader.bType[0], ethHeader.bType[1]);
    printf("\n\n");

    // Display IPv4 Header info
    printf("IPv4 Header:\n");
    printf("--------------------\n");

    // Read the version field from the IPv4 header
    unsigned char version[1];
    fread(version, sizeof(version), 1, file);

    // Print the version of the IPv4 header
    printf("Version:\t\t\t %02d\n", version[0] >> 4);

    // Print the header length of the IPv4 header
    printf("Internet Header Length:\t\t %02x ", version[0] & 0x0F);

    // Read the DSCP field from the IPv4 header
    unsigned char dscp;
    fread(&dscp, sizeof(dscp), 1, file);

    // Print the (DSCP) in the IPv4 header
    printf("\nDSCP:\t\t\t\t %02x\n", dscp >> 10);

    // Print the ECN bits
    unsigned char ecn = dscp;
    printf("ECN Bits:\t\t\t %d%d", (ecn >> 1) & 1, ecn & 1);
    if (ecn == 00) {
        printf("\t Non-ECT Packet\n");
    }
    // Read the total length field from the IPv4 header
    unsigned char totalLength[2]; // IPv4 total length is 2 bytes
    fread(totalLength, sizeof(totalLength), 1, file);
    if (totalLength[0] != ' ') {
        printf("Total Length:\t\t\t %d\n", (totalLength[0] << 8 | totalLength[1]));
    }

    // Read the identification field from the IPv4 header
    unsigned short identification;
    fread(&identification, sizeof(identification), 1, file);
    printf("Identification:\t\t\t %d\n", identification);


    // Read the flags and fragment offset fields from the IPv4 header
    unsigned short flagsAndOffset;
    fread(&flagsAndOffset, sizeof(flagsAndOffset), 1, file);
    flagsAndOffset = _byteswap_ushort(flagsAndOffset);
    // Extracting flags
    unsigned char flags = (flagsAndOffset >> 13);
    if (flags == 0b00) {
        // last frag
        printf("Flags:\t\t\t\t %s\n", "Last Fragment");
    }
    else if (flags == 0b01) {
        // more frags
        printf("Flags:\t\t\t\t %s\n", "More Fragments");
    }
    else if (flags == 0b10) {
        //dont frag
        printf("Flags:\t\t\t\t %s\n", "Don't Fragment");
    }
    else if (flags == 0b11) {
        //frag error
        printf("Flags:\t\t\t\t %s\n", "Fragment Error");
    }

    // Extracting fragment offset
    unsigned short fragmentOffset = flagsAndOffset & 0x1FFF;

    printf("Fragment Offset:\t\t %u\n", fragmentOffset);

    // Read the Time to Live field from the IPv4 header
    unsigned char ttl;
    fread(&ttl, sizeof(ttl), 1, file);

    // Print the Time to Live
    printf("Time to Live:\t\t\t %d\n", ttl);

    // Read the Protocol field from the IPv4 header
    unsigned char protocol;
    fread(&protocol, sizeof(protocol), 1, file);

    // Print the Protocol
    printf("Protocol:\t\t\t %d\n", protocol);

    // Read and print the checksum of the IPv4 header
    unsigned short checksum;
    fread(&checksum, sizeof(checksum), 1, file);
    checksum = _byteswap_ushort(checksum);
    printf("Checksum:\t\t\t 0x%04x\n", checksum);

    // Read and print the Source IP address of the IPv4 header
    unsigned char sourceIp[4];
    fread(&sourceIp, sizeof(sourceIp), 1, file);
    printf("Source Ip:\t\t\t %02d.%02d.%02d.%02d\n", sourceIp[0], sourceIp[1], sourceIp[2], sourceIp[3]);

    // Read and print the Destination IP address of the IPv4 header
    unsigned char destinationIp[4];
    fread(&destinationIp, sizeof(destinationIp), 1, file);
    printf("Destination Ip:\t\t\t %02d.%02d.%02d.%02d\n", destinationIp[0], destinationIp[1], destinationIp[2], destinationIp[3]);

    // Read and print the Options of the IPv4 header
    unsigned int headerLength = version[0] & 0x0F;
    headerLength *= 4;  //  Convert header lenght to bytes
    headerLength -= 20;  //  Get options in bytes

    if (headerLength == 0) {
        printf("Options:\t\t\t No Options\n");
    }
    else {
        while (headerLength) {
            unsigned char opt[4];
            fread(&opt, sizeof(opt), 1, file);
            printf("Options Word:\t\t\t 0x%02x%02x%02x%02x\n", opt[0], opt[1], opt[2], opt[3]);
            headerLength -= 4;
        }
    }


    printf("\n");

    // Display payload info
    printf("Payload:\n");

    // Seek to the beginning of the payload

    // Read and print the payload until the end of the file
    int ch;
    int byteCount = 0;
    while ((ch = fgetc(file)) != EOF) {
        printf("%02x ", (unsigned char)ch);
        byteCount++;

        // Print \t after every 8 bytes
        if (byteCount % 8 == 0) {
            printf("     ");
        }

        // Print \n after every 16 bytes
        if (byteCount % 32 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

int main(int argc, char* argv[]) {
    // Check if filename is provided
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Open the binary file for reading
    FILE* file;
    fopen_s(&file, argv[1], "rb");

    // Check if file is opened successfully
    if (file == NULL) {
        printf("Error opening file: %s\n", argv[1]);
        return 1;
    }

    // Decode Ethernet header and print payload
    decodeEthernetHeader(file);

    // Close the file
    fclose(file);

    return 0;
}