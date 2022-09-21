/*
 * t8015_bootkit - main.c
 *
 * Copyright (c) 2021 - 2022 dora2ios
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <getopt.h>

#include <io/iousb.h>
#include <common/common.h>
#include <common/log.h>
#include <exploit/checkm8_t8015.h>

io_client_t client;
bool debug_enabled = false;

checkra1n_payload_t payload;

static int open_file(char *file, unsigned int *sz, unsigned char **buf)
{
    FILE *fd = fopen(file, "r");
    if (!fd) {
        ERROR("opening %s", file);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    *sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    *buf = malloc(*sz);
    if (!*buf) {
        ERROR("allocating file buffer");
        fclose(fd);
        return -1;
    }
    
    fread(*buf, *sz, 1, fd);
    fclose(fd);
    
    return 0;
}

static void usage(char** argv)
{
    printf("Usage: %s [-hcdf] shellcode\n", argv[0]);
    printf("  -h, --help\t\t\t\x1b[36mshow usage\x1b[39m\n");
    printf("  -c, --cleandfu\t\t\x1b[36muse cleandfu [BETA]\x1b[39m\n");
    printf("  -d, --debug\t\t\t\x1b[36menable debug log\x1b[39m\n");
    printf("  -f, --file <args>\t\t\x1b[36mset shellcode\x1b[39m\n");
    
    printf("\n");
}

int main(int argc, char** argv)
{
    memset(&payload, '\0', sizeof(checkra1n_payload_t));
    
    bool useRecovery = false;
    char* extraFile = NULL;
    
    int opt = 0;
    static struct option longopts[] = {
        { "help",           no_argument,       NULL, 'h' },
        { "cleandfu",       no_argument,       NULL, 'c' },
        { "debug",          no_argument,       NULL, 'd' },
        { "file",           required_argument, NULL, 'f' },
        { NULL, 0, NULL, 0 }
    };
    
    while ((opt = getopt_long(argc, argv, "hcdf:", longopts, NULL)) > 0) {
        switch (opt) {
            case 'h':
                usage(argv);
                return 0;
                
            case 'd':
                debug_enabled = true;
                DEBUGLOG("enabled: debug log");
                break;
                
            case 'c':
                useRecovery = true;
                break;
                
            case 'f':
                if (optarg) {
                    extraFile = strdup(optarg);
                    LOG("extraFile: [%s]", extraFile);
                }
                break;
                
            default:
                usage(argv);
                return -1;
        }
    }
    
    if(!extraFile)
    {
        usage(argv);
        return -1;
    }
        
    if(open_file(extraFile, &payload.stage1_len, &payload.stage1) != 0)
        return -1;
    
    if(payload.stage1_len > 0x700)
    {
        ERROR("shellcode too large");
        return -1;
    }
    
    if(useRecovery)
    {
        if(enter_dfu_via_recovery(client))
            return -1;
    }
    
    LOG("Waiting for device in DFU mode...");
    while(get_device(DEVICE_DFU, true))
        sleep(1);
    
    LOG("CONNECTED: DFU mode");
    sleep(2);
    
    if(client->hasSerialStr == false)
        read_serial_number(client); // For iOS 10 and lower
    
    DEBUGLOG("CPID: 0x%02x, STRG: [%s]", client->devinfo.cpid, client->devinfo.srtg);
    
    if(client->hasSerialStr != true)
    {
        ERROR("serial number was not found!");
        return -1;
    }
    
    switch(client->devinfo.cpid)
    {
        case 0x8015:
            break;
            
        default:
            ERROR("This device is not supported!");
            return -1;
    }
    
    checkm8_t8015(client, payload);
    
    return 0;
}

