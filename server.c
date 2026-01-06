#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <net/if.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <strings.h>

#define PORT 3670

extern int errno;

// --- STRUCTURI ---
typedef struct {
    pthread_t idThread;
    int thCount;
} Thread;

typedef struct {
    char id[20];
    char ip[20];
    char mac[20];
    char user[50];
    char pass[50];
    int on;
    int os_type; // 1=Linux, 2=Windows
    char cwd[256];
} PC;

// --- GLOBALE ---
Thread *threadsPool;
int sd;
int nthreads;
int current_admin = -1;

PC statii[500];
int nr_statii = 0;

pthread_mutex_t mlock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t admin_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;

unsigned char aes_key[32];
unsigned char aes_iv[16];

// --- (Curata spatii si newline) ---
void trim(char *s)
{
    if (!s)
        return;
    char *p=s;
    int l=strlen(p);
    while(l > 0 && isspace((unsigned char)p[l-1]))
        p[--l] = 0;
    while(*p && isspace((unsigned char)*p))
        p++;
    memmove(s, p, l + 1);
}

// --- (Transforma \ in / pentru a nu strica SSH-ul) ---
void slash(char *path)
{
    int i;
    if (!path)
        return;
    for(i=0;path[i];i++)
    {
        if(path[i]=='\\')
            path[i]='/';
    }
}

void escape_quotes(char *dest, const char *src)
{
    int i=0,j=0;
    while(src[i])
    {
        if(src[i]=='"')
        {
            dest[j++]='\\';
            dest[j++]='"';
        }
        else
            dest[j++]=src[i];
        i++;
    }
    dest[j]='\0';
}

void threadCreate(int i);
void *treat(void * arg);
void raspunde(int cl, int idThread);
void wake_on_lan(char *addrMac);
int mac_arp(char *ip1, char *rez_mac);
int verific_port_ssh(char *ip);
void scan_network();
void get_ip_prefix(char *prefix);
int executa_ssh_cmd(char *ip, char *user, char *pass, char *cmd, char *result_buffer);
void show_available_ips();
int detect_os(char *ip, char *user, char *pass);
int find_pc_index(char *id);
void handle_exec(int idx, char *cmd_user, char *raspuns);
void handle_cd(int index, char *target_dir, char *raspuns);
void save_pcuri();
void load_config();
void save_pc(PC *pc);
int get_local_broadcast_addr(char *buffer_ip);

// --- CRIPTARE ---
void init_crypto(const char *parola)
{
    const EVP_CIPHER *tip_criptare = EVP_aes_256_cbc();
    const EVP_MD *tip_hash = EVP_sha256();

    unsigned char *salt=NULL;
    int iteratii=1;

    int rezultat=EVP_BytesToKey(tip_criptare,tip_hash,salt,(unsigned char *) parola, strlen(parola),iteratii,aes_key,aes_iv);

   if(rezultat==0)
   {
        fprintf(stderr,"Nu s-au putut genera cheile de criptare.\n");
        exit(1);
   }
}

int aes_encrypt(unsigned char *msjclar, int lgmsj, unsigned char *criptat)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if(!context)
        return -1;

    int lg, lgtotala;
    EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    EVP_EncryptUpdate(context, criptat, &lg, msjclar, lgmsj);
    lgtotala = lg;
    EVP_EncryptFinal_ex(context, criptat + lg, &lg);
    lgtotala += lg;
    EVP_CIPHER_CTX_free(context);
    return lgtotala;
}

int aes_decrypt(unsigned char *criptat, int lgcriptat, unsigned char *msjclar)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context)
        return -1;

    int lg, lgfin;
    EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    EVP_DecryptUpdate(context, msjclar, &lg, criptat, lgcriptat);
    lgfin = lg;
    if (EVP_DecryptFinal_ex(context, msjclar + lg, &lg) != 1)
    {
        EVP_CIPHER_CTX_free(context);
        return -1;
    }
    lgfin += lg;
    msjclar[lgfin]='\0';
    EVP_CIPHER_CTX_free(context);
    return lgfin;
}

// --- PREFIXARE ---
int scrie_prefixat(int fd, char *msj)
{
    int lg=strlen(msj);
    unsigned char *buf_criptat=malloc(lg+AES_BLOCK_SIZE+10);
    if(!buf_criptat)
        return -1;
    int lg_criptata=aes_encrypt((unsigned char *)msj,lg,buf_criptat);
    int lg_net = htonl(lg_criptata);
    if (write(fd, &lg_net, sizeof(int)) <= 0)
    {
        free(buf_criptat);
        return -1;
    }
    if (write(fd, buf_criptat, lg_criptata) <= 0)
    {
        free(buf_criptat);
        return -1;
    }
    free(buf_criptat);
    return 1;
}

int citeste_prefixat(int fd, char *buf, int lgmax)
{
    int lg_retea, lg_criptata;
    //citesc lungimea
    if (read(fd, &lg_retea, sizeof(int)) <= 0)
        return -1;
    lg_criptata = ntohl(lg_retea);
    if (lg_criptata > lgmax + AES_BLOCK_SIZE || lg_criptata <= 0)
        return -1;

    unsigned char *buf_criptat = malloc(lg_criptata);
    if (!buf_criptat)
        return -1;

    int cnt=0;
    while(cnt<lg_criptata)
    {
        int r=read(fd, buf_criptat + cnt, lg_criptata - cnt);
        if(r<=0)
        {
            free(buf_criptat);
            return -1;
        }
        cnt+=r;
    }
    int lgfin=aes_decrypt(buf_criptat,lg_criptata,(unsigned char *)buf);
    free(buf_criptat);
    if(lgfin<0)
    {
        strcpy(buf, "[SEC ERROR]");
        return 1;
    }
    return lgfin;
}

// --- NETWORK UTILS ---
int get_local_broadcast_addr(char *buffer_ip)
{
    struct ifaddrs *ifaddr, *ifa;
    int gasit = 0;
    if (getifaddrs(&ifaddr)==-1)
        return -1;
    for(ifa=ifaddr;ifa!=NULL; ifa=ifa->ifa_next)
    {
        if(!ifa->ifa_addr || ifa->ifa_addr->sa_family!=AF_INET || strcmp(ifa->ifa_name, "lo")==0)
            continue;
        if(ifa->ifa_flags & IFF_BROADCAST)
        {
            struct sockaddr_in *ceva = (struct sockaddr_in *)ifa->ifa_broadaddr;
            if(ceva)
            {
                strcpy(buffer_ip, inet_ntoa(ceva->sin_addr));
                gasit = 1;
                if(strncmp(ifa->ifa_name, "tun", 3) == 0 ||
                    strncmp(ifa->ifa_name, "eth", 3) == 0 ||
                    strncmp(ifa->ifa_name, "en", 2) == 0  ||
                    strncmp(ifa->ifa_name, "wl", 2) == 0)
                    break;
            }
        }
    }
    freeifaddrs(ifaddr);
    if(gasit)
        return 0;
    else
        return -1;
}

void wake_on_lan(char *addrMac)
{
    int udpSocket, i;
    struct sockaddr_in dest;
    int on=1;

    unsigned char packet[102], mac[6];
    char broadcast_ip[100];

    if(sscanf(addrMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
        return;
    for(i=0;i<6;i++)
        packet[i]=0xFF;
    for(i=1;i<=16;i++)
        memcpy(&packet[i * 6], mac, 6);

    if(get_local_broadcast_addr(broadcast_ip)==-1)
        strcpy(broadcast_ip, "255.255.255.255");

    if((udpSocket = socket(AF_INET, SOCK_DGRAM, 0))==-1)
        return;

    setsockopt(udpSocket, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    memset(&dest, 0, sizeof(dest));

    dest.sin_family=AF_INET;
    dest.sin_addr.s_addr=inet_addr(broadcast_ip);
    dest.sin_port=htons(9);
    sendto(udpSocket, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest));
    close(udpSocket);
}

int verific_port_ssh(char *ip)
{
    int sock=socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0)
        return 0;

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    addr.sin_addr.s_addr = inet_addr(ip);

    int res=connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return (res == 0);
}

int mac_arp(char *ip1, char *rez_mac)
{
    char buf[256], ip[100], mac[100];

    FILE *fp=fopen("/proc/net/arp", "r");
    if(!fp)
        return 0;

    if(fgets(buf, sizeof(buf), fp)) {} //sare peste prima linie din fisier

    while(fgets(buf, sizeof(buf), fp))
    {
        sscanf(buf, "%s %*s %*s %s", ip, mac);
        if(strcmp(ip1, ip) == 0 && strcmp(mac, "00:00:00:00:00:00") != 0)
        {
            strcpy(rez_mac, mac);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

// --- FIX OBLIGATORIU PENTRU MEMORIE ---
void get_ip_prefix(char *prefix)
{
    struct ifaddrs *ifaddr, *ifa;
    char host[INET_ADDRSTRLEN];
    char ip_lan[100]="";
    char ip_vpn[100]="";

    // Fallback sigur
    strcpy(prefix, "127.0.0");

    if(getifaddrs(&ifaddr) == -1)
        return;

    for(ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next)
    {
        if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET || strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        // Folosim inet_ntop (Sigur pe orice server)
        struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
        if(inet_ntop(AF_INET, &pAddr->sin_addr, host, INET_ADDRSTRLEN) == NULL)
            continue;

        if (strncmp(ifa->ifa_name, "tun", 3) == 0)
            strcpy(ip_vpn, host);
        else if (strncmp(ifa->ifa_name, "eth", 3) == 0 ||
                 strncmp(ifa->ifa_name, "en", 2) == 0 ||
                 strncmp(ifa->ifa_name, "wl", 2) == 0)
            strcpy(ip_lan, host);
    }

    char *selected_ip = (strlen(ip_vpn) > 0) ? ip_vpn : ip_lan;
    if (strlen(selected_ip) > 0)
    {
        char *dot = strrchr(selected_ip, '.');
        if (dot) *dot = '\0';
        strcpy(prefix, selected_ip);
    }

    freeifaddrs(ifaddr);
}

// --- VERSIUNE NOUA SI SIGURA ---
void show_available_ips()
{
    struct ifaddrs *ifaddr, *ifa;
    char ip_str[INET_ADDRSTRLEN];

    // Obtine lista de interfete
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return;
    }

    printf("[INFO] IP-uri disponibile pe acest server:\n");

    // Itereaza prin lista
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        // Ne intereseaza doar IPv4 (AF_INET)
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            // Convertim adresa binara in string (ex: "10.0.0.1")
            struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &pAddr->sin_addr, ip_str, INET_ADDRSTRLEN);

            // Afisam interfata si IP-ul (ignoram Loopback-ul "lo" daca vrei, dar e bine sa apara)
            if (strcmp(ifa->ifa_name, "lo") != 0)
            {
                 printf(" -> Interfata: %s \t IP: %s\n", ifa->ifa_name, ip_str);
            }
        }
    }

    freeifaddrs(ifaddr); // Eliberam memoria corect
}

//BAZA DE DATE sqlite3

sqlite3 *db;

int load_callback(void *NotUsed, int argc, char **argv, char **azColName)
{

    if(nr_statii>=500)
        return 0;

    strcpy(statii[nr_statii].id, argv[0] ? argv[0] : "PC_Unknown");
    strcpy(statii[nr_statii].ip, argv[1] ? argv[1] : "0.0.0.0");
    strcpy(statii[nr_statii].mac, argv[2] ? argv[2] : "00:00:00");
    strcpy(statii[nr_statii].user, argv[3] ? argv[3] : "student");
    strcpy(statii[nr_statii].pass, argv[4] ? argv[4] : "test1234");

    statii[nr_statii].os_type = argv[5] ? atoi(argv[5]) : 0;

    strcpy(statii[nr_statii].cwd, argv[6] ? argv[6] : ".");

    statii[nr_statii].on = 0;
    nr_statii++;

    return 0;
}

void init_db()
{
    int ret = sqlite3_open("grid_admin.db", &db);

    if(ret)
    {
        fprintf(stderr, "[DB] Eroare fatala: Nu pot deschide baza de date: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    char *err=0;
    // Creez tabelul daca nu exista deja
    char *query = "CREATE TABLE IF NOT EXISTS Stations("
                  "Id TEXT PRIMARY KEY, "
                  "Ip TEXT, "
                  "Mac TEXT, "
                  "User TEXT, "
                  "Pass TEXT, "
                  "OsType INT, "
                  "Cwd TEXT);";

    ret = sqlite3_exec(db, query, 0, 0, &err);

    if(ret != SQLITE_OK)
    {
        printf("[DB] Eroare la crearea tabelului: %s\n", err);
        sqlite3_free(err);
    }
    else
    {
        printf("[DB] Conexiune baza de date: OK.\n");
    }
}

void update_db_station(PC *pc)
{
    char *err = 0;
    char query[1024];

    trim(pc->cwd);
    slash(pc->cwd);

    sprintf(query, "REPLACE INTO Stations (Id, Ip, Mac, User, Pass, OsType, Cwd) "
                   "VALUES ('%s', '%s', '%s', '%s', '%s', %d, '%s');",
            pc->id, pc->ip, pc->mac, pc->user, pc->pass, pc->os_type, pc->cwd);

    int ret=sqlite3_exec(db, query, 0, 0, &err);

    if(ret!=SQLITE_OK)
    {
        printf("[DB] Eroare la salvare statie (%s): %s\n", pc->id, err);
        sqlite3_free(err);
    }
}

void load_from_db()
{
    char *err=0;
    nr_statii=0;

    char *query="SELECT * FROM Stations";

    int ret=sqlite3_exec(db, query, load_callback, 0, &err);

    if(ret!=SQLITE_OK)
    {
        printf("[DB] Eroare la incarcare date: %s\n", err);
        sqlite3_free(err);
    }

    printf("[DB] S-au incarcat %d statii.\n", nr_statii);
}


// --- LOGICA DE EXECUTIE (SSH) ---
int executa_ssh_cmd(char *ip, char *user, char *pass, char *cmd, char *result_buffer)
{
    char ssh_buf[4096], buf[512], escaped_cmd[2048];
    escape_quotes(escaped_cmd, cmd);
    sprintf(ssh_buf, "sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 %s@%s \"%s\" 2>&1", pass, user, ip, escaped_cmd);

    FILE *fp=popen(ssh_buf,"r");
    if(!fp)
    {
        strcpy(result_buffer, "EROARE INTERNA: popen failed");
        return -1;
    }

    strcpy(result_buffer, "");

    while (fgets(buf,sizeof(buf),fp))
        if (strlen(result_buffer)+strlen(buf)<19000)
            strcat(result_buffer,buf);

    pclose(fp);
    return 0;
}

void handle_exec(int idx, char *cmd_user, char *raspuns)
{
    char final_cmd[3000], out_ssh[20480],cmd_prelucrata[2048];
    trim(statii[idx].cwd);
    slash(statii[idx].cwd);
    trim(cmd_user);

    if(statii[idx].os_type==1 && strncmp(cmd_user,"sudo ",5)==0)
    {
        sprintf(cmd_prelucrata, "echo '%s' | sudo -S %s", statii[idx].pass, cmd_user + 5);
    }
    else
    {
        strcpy(cmd_prelucrata,cmd_user);
    }

    if(statii[idx].os_type == 2)
    {
        if(strcmp(statii[idx].cwd, ".")==0)
            sprintf(final_cmd, "%s", cmd_prelucrata);
        else
            sprintf(final_cmd, "cd /d \"%s\" && %s", statii[idx].cwd, cmd_prelucrata);
    }
    else
        sprintf(final_cmd, "cd \"%s\" && %s", statii[idx].cwd, cmd_prelucrata);

    executa_ssh_cmd(statii[idx].ip, statii[idx].user, statii[idx].pass, final_cmd, out_ssh);

    if(strlen(out_ssh)==0)
        sprintf(raspuns, "[%s]> Comanda executata.", statii[idx].cwd);
    else if(strstr(out_ssh, "command not found") || strstr(out_ssh, "is not recognized"))
        sprintf(raspuns, "[%s]> EROARE COMANDA:\n%s", statii[idx].cwd, out_ssh);
    else
        sprintf(raspuns, "[%s]> \n%s", statii[idx].cwd, out_ssh);
}

void handle_cd(int index, char *target_dir, char *raspuns)
{
    char cmd[1024];
    trim(target_dir);
    trim(statii[index].cwd);
    slash(statii[index].cwd);

    if(statii[index].os_type == 2)
    {
        if(strcmp(statii[index].cwd, ".") == 0)
            sprintf(cmd, "cd /d \"%s\" && echo SUCCESS && cd", target_dir);
        else
            sprintf(cmd, "cd /d \"%s\" && cd /d \"%s\" && echo SUCCESS && cd", statii[index].cwd, target_dir);
    }
    else
        sprintf(cmd, "cd \"%s\" && cd \"%s\" && echo SUCCESS && pwd", statii[index].cwd, target_dir);

    char out_ssh[2048];
    executa_ssh_cmd(statii[index].ip, statii[index].user, statii[index].pass, cmd, out_ssh);

    char *succes=strstr(out_ssh, "SUCCESS");
    if(succes)
    {
        char *new_path = succes + 7;
        while(*new_path && (*new_path == '\r' || *new_path == '\n' || *new_path == ' '))
            new_path++;
        char *end = new_path;
        while(*end)
        {
            if(*end == '\r' || *end == '\n')
            {
                *end = '\0';
                break;
            }
            end++;
        }

        trim(new_path);
        slash(new_path);

        pthread_mutex_lock(&list_lock);
        strcpy(statii[index].cwd, new_path);
        update_db_station(&statii[index]);
        pthread_mutex_unlock(&list_lock);

        sprintf(raspuns, "CWD changed to: [%s]", statii[index].cwd);
    }
    else
        sprintf(raspuns, "Eroare CD: %s", out_ssh);
}

int detect_os(char *ip, char *user, char *pass)
{
    char buf[20480];
    executa_ssh_cmd(ip, user, pass, "uname", buf);
    if (strstr(buf, "Linux") != NULL)
    {
        return 1;
    }
    return 2;
}

int find_pc_index(char *id)
{
    int i;
    pthread_mutex_lock(&list_lock);
    for(i=0;i<nr_statii;i++)
    {
        if(strcasecmp(statii[i].id, id)==0)
        {
            pthread_mutex_unlock(&list_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&list_lock);
    return -1;
}

void scan_network()
{
    char prefix[100], ip1[128];
    int i,j;

    get_ip_prefix(prefix);
    pthread_mutex_lock(&list_lock);

    for(j=0; j<nr_statii; j++)
        statii[j].on=0;

    for(i=1; i<255; i++)
    {
        sprintf(ip1, "%s.%d", prefix, i);

        if(verific_port_ssh(ip1))
        {
            char mac_curent[50] = "??:??:??:??:??:??";
            mac_arp(ip1, mac_curent);

            int gasit=0;
            for(j=0; j<nr_statii; j++)
            {

                int ip_match = (strcmp(statii[j].ip, ip1) == 0);

                int mac_match = (strcmp(statii[j].mac, "??:??:??:??:??:??") != 0 && strcmp(statii[j].mac, mac_curent) == 0);

                if(ip_match || mac_match)
                {
                    if(mac_match && !ip_match)
                        strcpy(statii[j].ip, ip1);

                    if(ip_match)
                        strcpy(statii[j].mac, mac_curent);

                    statii[j].on=1;
                    gasit=1;
                    break;
                }
            }

            if(!gasit && nr_statii < 500)
            {
                strcpy(statii[nr_statii].ip, ip1);
                sprintf(statii[nr_statii].id, "PC_%d", i);
                statii[nr_statii].on = 1;
                strcpy(statii[nr_statii].user, "student");
                strcpy(statii[nr_statii].pass, "test1234");

                strcpy(statii[nr_statii].mac, mac_curent);

                statii[nr_statii].os_type = detect_os(ip1, "student", "test1234");

                if (statii[nr_statii].os_type==2)
                    strcpy(statii[nr_statii].cwd,"C:/");
                else
                    strcpy(statii[nr_statii].cwd,"/");

                update_db_station(&statii[nr_statii]);
                nr_statii++;
            }
        }
    }
    //save_pcuri();
    pthread_mutex_unlock(&list_lock);
}

// --- THREAD ---
void raspunde(int cl, int idThread)
{
    char buf[1024];
    char *raspuns=malloc(20480);
    int auth=0;
    char admin_user[]="admin", admin_pass[]="adminpass";

    while(1)
    {
        memset(buf, 0, 1024);
        if(citeste_prefixat(cl, buf, 1024) <= 0)
        {
            pthread_mutex_lock(&admin_lock);
            if(current_admin==idThread)
                current_admin=-1;
            pthread_mutex_unlock(&admin_lock);
            break;
        }
        buf[strcspn(buf,"\r\n")] = 0;
        printf("[Thread %d] CMD: %s\n", idThread, buf);
        memset(raspuns, 0, 20480);

        if (strncmp(buf, "AUTH", 4)==0)
        {
            char u[50], p[50];
            if(sscanf(buf + 5, "%s %s", u, p) == 2)
            {
                if(strcmp(u, admin_user) == 0 && strcmp(p, admin_pass) == 0)
                {
                    pthread_mutex_lock(&admin_lock);
                    if (current_admin == -1 || current_admin == idThread)
                    {
                        current_admin = idThread;
                        auth = 1;
                        sprintf(raspuns, "[AUTH-OK] Welcome admin.");
                    }
                    else
                        sprintf(raspuns, "[AUTH-FAIL] Alt admin este deja logat!");
                    pthread_mutex_unlock(&admin_lock);
                }
                else
                    sprintf(raspuns, "[AUTH-FAIL] User/Parola gresite.");
            }
            else
                sprintf(raspuns, "[AUTH-FAIL] Format invalid.");
        }
        else if(!auth)
            sprintf(raspuns, "Acces interzis. Login first.");
        else if(strcmp(buf, "SCAN")==0)
        {
            scan_network();
            sprintf(raspuns, "[SUCCESS] Scanare completa.\n[INFO] %d statii gasite.", nr_statii);
        }
        else if(strcmp(buf, "LIST")==0)
        {
            pthread_mutex_lock(&list_lock);
            strcpy(raspuns, "--- LISTA STATII --\n");
            for(int k=0; k<nr_statii; k++)
            {
                char tmp[512], status[20], os_text[20];
                if (statii[k].os_type == 1)
                    strcpy(os_text, "LINUX");
                else if (statii[k].os_type == 2)
                    strcpy(os_text, "WINDOWS");
                else
                    strcpy(os_text, "UNKNOWN");

                if(statii[k].on)
                    strcpy(status,"ONLINE");
                else
                    strcpy(status,"OFFLINE");
                sprintf(tmp," %d. %s [%s] <%s> MAC: %s -> %s\n", k + 1,statii[k].id,statii[k].ip, os_text, statii[k].mac, status);
                strcat(raspuns, tmp);
                char hidden[512];
                sprintf(hidden, "REC: %s %s %s %s %s\n", statii[k].id, statii[k].ip, statii[k].user, statii[k].pass, statii[k].cwd);
                strcat(raspuns, hidden);
            }
            pthread_mutex_unlock(&list_lock);
        }
        else if(strncmp(buf, "WAKE", 4)==0)
        {
            char target[100];
            if(sscanf(buf, "%*s %s", target)==1)
            {
                if(strcasecmp(target, "ALL")==0)
                {
                    pthread_mutex_lock(&list_lock);
                    for(int k = 0;k<nr_statii; k++)
                    {
                        wake_on_lan(statii[k].mac);
                        usleep(10000);
                    }
                    pthread_mutex_unlock(&list_lock);
                    sprintf(raspuns, "WAKE ALL executat.");
                }
                else
                {
                    int idx=find_pc_index(target);
                    if(idx!=-1)
                    {
                        wake_on_lan(statii[idx].mac);
                        sprintf(raspuns, "WAKE sent to %s (%s).", target, statii[idx].mac);
                    }
                    else
                    {
                        wake_on_lan(target);
                        sprintf(raspuns, "WAKE sent to MAC %s.", target);
                    }
                }
            }
            else
                sprintf(raspuns, "Eroare WAKE.");
        }
        else if(strncmp(buf, "SHUTDOWN", 8)==0)
        {
            char target[100];
            if(sscanf(buf, "%*s %s", target)==1)
            {
                if(strcasecmp(target,"ALL")==0)
                {
                    pthread_mutex_lock(&list_lock);
                    for(int k=0; k<nr_statii; k++)
                    {
                        if(statii[k].on)
                        {
                            char dump[200],cmd_sh[200];
                            if(statii[k].os_type==2)
                                sprintf(cmd_sh, "shutdown /s /f /t 0");
                            else
                                sprintf(cmd_sh, "echo '%s' | sudo -S poweroff", statii[k].pass);
                            executa_ssh_cmd(statii[k].ip, statii[k].user, statii[k].pass, cmd_sh, dump);
                        }
                        pthread_mutex_unlock(&list_lock);
                        sprintf(raspuns, "SHUTDOWN ALL sent.");
                    }

                }
                else
                {
                    int idx=find_pc_index(target);
                    if(idx!=-1)
                    {
                        char tmp[1024], cmd_sh[200];
                        if(statii[idx].os_type==2)
                            sprintf(cmd_sh, "shutdown /s /f /t 0");
                        else
                            sprintf(cmd_sh, "echo '%s' | sudo -S poweroff", statii[idx].pass);
                        executa_ssh_cmd(statii[idx].ip, statii[idx].user, statii[idx].pass, cmd_sh, tmp);
                        sprintf(raspuns, "SHUTDOWN sent to %s.", target);
                    }
                    else
                        sprintf(raspuns, "Target invalid.");
                }
            }
        }
        else if(strncmp(buf, "LOGOUT", 6)==0)
        {
            pthread_mutex_lock(&admin_lock);
            if(current_admin==idThread)
            {
                current_admin=-1;
                auth=0;
                sprintf(raspuns,"Logout OK.");
            }
            pthread_mutex_unlock(&admin_lock);
        }
        else if(strncmp(buf, "SET_CREDS", 9)==0)
        {
            char id[50], u[50], p[50];
            // Citim ID, User si Parola din comanda
            if (sscanf(buf, "%*s %s %s %s", id, u, p)==3)
            {
                int idx=find_pc_index(id);
                if (idx!=-1)
                {
                    pthread_mutex_lock(&list_lock);
                    strcpy(statii[idx].user, u);
                    strcpy(statii[idx].pass, p);
                    //save_pcuri();
                    update_db_station(&statii[idx]);
                    pthread_mutex_unlock(&list_lock);
                    sprintf(raspuns, "Credentiale actualizate pentru %s.\n", id);
                }
                else
                {
                    sprintf(raspuns, "Eroare: ID-ul %s nu exista.", id);
                }
            }
            else
            {
                sprintf(raspuns, "Format gresit. Foloseste: SET_CREDS <id> <user> <pass>");
            }
        }
        else if(strncmp(buf, "EXEC", 4)==0)
        {
             char id[50], cmd[500];
             if(sscanf(buf, "%*s %s %[^\n]", id, cmd)==2)
             {
                 if(strcasecmp(id, "ALL")==0)
                 {
                     strcpy(raspuns, "--- MASS EXEC ---\n");
                     pthread_mutex_lock(&list_lock);
                     for(int k = 0; k < nr_statii; k++)
                     {
                        if(statii[k].on)
                        {
                            char out[2048],final_cmd[1024];
                            if(statii[k].os_type == 2)
                                sprintf(final_cmd, "cd /d \"%s\" && %s", statii[k].cwd, cmd);
                            else
                                sprintf(final_cmd, "cd \"%s\" && %s", statii[k].cwd, cmd);

                            executa_ssh_cmd(statii[k].ip, statii[k].user, statii[k].pass, final_cmd, out);

                            if(strlen(raspuns) + strlen(out) < 19000)
                            {
                                strcat(raspuns, "\n[");
                                strcat(raspuns, statii[k].id);
                                strcat(raspuns, "]:\n");
                                strcat(raspuns, out);
                            }
                        }
                    }
                    pthread_mutex_unlock(&list_lock);
                 }
                 else
                 {
                     int idx = find_pc_index(id);
                     if(idx != -1)
                     {
                        if(strncmp(cmd, "cd ", 3)==0)
                            handle_cd(idx, cmd + 3, raspuns);
                        else
                        {
                            char out[20480];
                            handle_exec(idx, cmd, out);
                            strcpy(raspuns, out);
                        }
                    }
                    else
                        sprintf(raspuns, "Statie inexistenta (%s).", id);
                 }
             }
             else sprintf(raspuns, "Format EXEC gresit.");
        }
        else
            sprintf(raspuns, "Comanda invalida.");


        scrie_prefixat(cl, raspuns);
    }
    free(raspuns);
}

void *treat(void *arg)
{
    int client, idThread = (int)(long)arg;
    struct sockaddr_in from;
    socklen_t len=sizeof(from);
    while(1)
    {
        pthread_mutex_lock(&mlock);
        client=accept(sd, (struct sockaddr *)&from, &len);
        pthread_mutex_unlock(&mlock);
        if(client<0)
            continue;
        printf("[Thread %d] Client connected.\n", idThread);
        raspunde(client, idThread);
        close(client);
    }
    return NULL;
}

void threadCreate(int i)
{
    pthread_create(&threadsPool[i].idThread, NULL, &treat, (void *)(long)i);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in server;
    if (argc != 3)
    {
        fprintf(stderr, "Syntax: %s <NTHREADS> <PASS>\n", argv[0]);
        exit(1);
    }
    nthreads=atoi(argv[1]);
    init_crypto(argv[2]);
    threadsPool=calloc(sizeof(Thread), nthreads);

    if ((sd = socket(AF_INET, SOCK_STREAM, 0))==-1)
    {
        perror("[EROARE] Nu pot crea socket");
        return errno;
    }
    int on=1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if(bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("[EROARE] Nu pot face BIND");
        return errno;
    }

    if(listen(sd, 10) == -1)
    {
        perror("[EROARE] Nu pot face LISTEN");
        return errno;
    }
    init_db();
    load_from_db();
    printf("[OK] Server running on port %d with pass: %s\n", PORT, argv[2]);

    for(int i=0; i<nthreads; i++)
        threadCreate(i);

    show_available_ips();

    while(1)
        pause();
}
