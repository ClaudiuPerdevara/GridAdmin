#include <gtk/gtk.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define MAX_BUFFER 70000

typedef struct
{
    char id[50];
    char ip[50];
    char user[50];
    char pass[50];
    char cwd[256];
} PC;

PC statii[100];
int nr_statii = 0;

// --- GLOBALE ---
int sd=-1;
unsigned char aes_key[32];
unsigned char aes_iv[16];
int is_authenticated=0;

GtkWidget *entry_user, *entry_pass; //auth
GtkWidget *entry_target, *entry_cmd; // exec
GtkWidget *txt_log; // logs
GtkWidget *btn_login, *btn_scan, *btn_list, *btn_wake, *btn_shutdown, *btn_exec, *btn_set; //butoane
GtkWidget *lbl_status; // logat da/nu
GtkWidget *lbl_local_path, *lbl_remote_path; // pathuri

const gchar *css_style =
    "window, grid, scrolledwindow, viewport { background-color: #050505; color: #cfcfcf; }"
    "frame { border: 1px solid #222222; padding: 2px; margin-bottom: 5px; }"
    "frame > label { color: #555555; font-weight: bold; font-size: 11px; background-color: #050505; padding: 0 3px; }"
    "label { font-size: 12px; }"
    "#status_label { font-size: 12px; font-weight: bold; color: #888888; margin: 5px 0; }"
    ".status_admin { color: #27ae60 !important; }"
    "#path_label { font-family: 'Monospace'; font-weight: bold; color: #f39c12; background-color: #151515; padding: 4px; border-radius: 3px; }"
    "entry { background-color: #121212; color: #eeeeee; border: 1px solid #333333; border-radius: 2px; padding: 4px; font-family: 'Monospace'; }"
    "entry:focus { border-color: #555555; }"
    "button { background-color: #1a1a1a; color: #cccccc; border-radius: 2px; border: 1px solid #333333; padding: 2px 6px; font-size: 11px; font-weight: bold; min-height: 24px; }"
    "button:hover { background-color: #2a2a2a; border-color: #666666; color: #ffffff; }"
    "button:active { background-color: #000000; }"
    "#btn_run { background-color: #2c3e50; border-color: #34495e; }"
    "#btn_run:hover { background-color: #34495e; border-color: #5dade2; }"
    "textview { font-family: 'Monospace'; font-size: 12px; }"
    "textview text { background-color: #000000; color: #b0b0b0; }";

void load_css()
{
    GtkCssProvider *provider = gtk_css_provider_new();
    GdkDisplay *display = gdk_display_get_default();
    GdkScreen *screen = gdk_display_get_default_screen(display);
    gtk_css_provider_load_from_data(provider, css_style, -1, NULL);
    gtk_style_context_add_provider_for_screen(screen, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

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

// --- LOGGING FARA EMOJI (Doar Text si Culori) ---
void append_log(const char *format, ...)
{
    char buffer[MAX_BUFFER];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    time_t rawtime;

    struct tm *timeinfo;
    time(&rawtime);
    timeinfo=localtime(&rawtime);

    char time_str[20];
    strftime(time_str, 20, "[%H:%M:%S] ", timeinfo);

    GtkTextBuffer *tbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt_log));
    GtkTextIter end; gtk_text_buffer_get_end_iter(tbuf, &end);

    gtk_text_buffer_insert_with_tags_by_name(tbuf, &end, time_str, -1, "gray_fg", NULL);

    char *tag_name = NULL;

    if (strstr(buffer, "ERR:") || strstr(buffer, "Eroare") || strstr(buffer, "failed"))
        tag_name = "red_fg";
    else if (strstr(buffer, "OK:") || strstr(buffer, "SUCCESS") || strstr(buffer, "executat"))
        tag_name = "green_fg";
    else if (strncmp(buffer, "LOCAL", 5) == 0)
        tag_name = "yellow_fg";
    else if (strncmp(buffer, "REMOTE", 6) == 0)
        tag_name = "blue_fg";
    else if (strncmp(buffer, "SRV:", 4) == 0)
        tag_name = "blue_fg";

    char final_msg[MAX_BUFFER + 20];
    sprintf(final_msg, "%s\n", buffer); // Doar textul

    gtk_text_buffer_get_end_iter(tbuf, &end);

    if(tag_name)
        gtk_text_buffer_insert_with_tags_by_name(tbuf, &end, final_msg, -1, tag_name, NULL);
    else
        gtk_text_buffer_insert(tbuf, &end, final_msg, -1);

    GtkTextMark *mark = gtk_text_buffer_create_mark(tbuf, NULL, &end, FALSE);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(txt_log), mark, 0.0, TRUE, 0.0, 1.0);
}

// LOGGING SIMPLU (Fara ora - Fara Emoji - Cu Culori pt Lista)
void append_simple(const char *format, ...)
{
    char buffer[MAX_BUFFER];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    GtkTextBuffer *tbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt_log));
    GtkTextIter end; gtk_text_buffer_get_end_iter(tbuf, &end);

    char *tag_name = NULL;

    // Logica de colorare pentru lista
    if(strstr(buffer, "ONLINE"))
        tag_name = "green_fg";
    else if(strstr(buffer, "OFFLINE"))
        tag_name = "red_fg";
    else if(strstr(buffer, "--- LISTA"))
        tag_name = "header_fg";

    // Formatare cu indentare simpla
    char final_msg[MAX_BUFFER+20];
    sprintf(final_msg,"   %s\n", buffer);

    gtk_text_buffer_get_end_iter(tbuf, &end);
    if(tag_name)
        gtk_text_buffer_insert_with_tags_by_name(tbuf, &end, final_msg, -1, tag_name, NULL);
    else
        gtk_text_buffer_insert(tbuf, &end, final_msg, -1);

    GtkTextMark *mark=gtk_text_buffer_create_mark(tbuf, NULL, &end, FALSE);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(txt_log), mark, 0.0, TRUE, 0.0, 1.0);
}

// --- UI UPDATES ---
void update_paths_ui(const char *remote_id)
{
    char cwd[1024];
    if(getcwd(cwd, sizeof(cwd)) != NULL)
    {
        char tmp[1100];
        sprintf(tmp, "LOCAL: %s", cwd);
        gtk_label_set_text(GTK_LABEL(lbl_local_path), tmp);
    }
    if(remote_id != NULL && strlen(remote_id) > 0 && strcasecmp(remote_id, "ALL") != 0)
    {
        char gasit=0;
        for(int i=0; i<nr_statii; i++)
        {
            if(strcasecmp(statii[i].id, remote_id) == 0)
            {
                char tmp[1100];
                sprintf(tmp, "REMOTE [%s]: %s", statii[i].id, statii[i].cwd);
                gtk_label_set_text(GTK_LABEL(lbl_remote_path), tmp);
                gasit=1;
                break;
            }
        }
        if(!gasit)
            gtk_label_set_text(GTK_LABEL(lbl_remote_path), "REMOTE: [Select Target]");
    }
    else
    {
        gtk_label_set_text(GTK_LABEL(lbl_remote_path), "REMOTE: [Select Target]");
    }
}

void update_status_ui()
{
    GtkStyleContext *context = gtk_widget_get_style_context(lbl_status);
    if(is_authenticated)
    {
        gtk_label_set_text(GTK_LABEL(lbl_status), "ADMIN: ONLINE");
        gtk_style_context_add_class(context, "status_admin");
        gtk_widget_set_sensitive(btn_scan,TRUE);
        gtk_widget_set_sensitive(btn_list,TRUE);
        gtk_widget_set_sensitive(btn_wake,TRUE);
        gtk_widget_set_sensitive(btn_shutdown,TRUE);
        gtk_widget_set_sensitive(btn_set,TRUE);
        gtk_button_set_label(GTK_BUTTON(btn_login),"LOGOUT");
    }
    else
    {
        gtk_label_set_text(GTK_LABEL(lbl_status),"GUEST: LOCAL");
        gtk_style_context_remove_class(context,"status_admin");
        gtk_widget_set_sensitive(btn_scan,FALSE);
        gtk_widget_set_sensitive(btn_list,FALSE);
        gtk_widget_set_sensitive(btn_wake,FALSE);
        gtk_widget_set_sensitive(btn_shutdown,FALSE);
        gtk_widget_set_sensitive(btn_set,FALSE);
        gtk_button_set_label(GTK_BUTTON(btn_login),"LOGIN");
    }
}

// --- NETWORK ---
void send_cmd(const char *cmd, char *out_resp)
{
    if(sd==-1)
    {
        append_log("ERR: Disconnected.");
        return;
    }
    scrie_prefixat(sd, (char*)cmd);

    GdkWindow *win = gtk_widget_get_window(gtk_widget_get_toplevel(txt_log));
    if(win)
        gdk_window_set_cursor(win, gdk_cursor_new_from_name(gdk_window_get_display(win), "wait"));

    while(gtk_events_pending())
        gtk_main_iteration();

    char rasp[MAX_BUFFER];
    memset(rasp, 0, MAX_BUFFER);

    int rez=citeste_prefixat(sd, rasp, MAX_BUFFER);
    if(win)
        gdk_window_set_cursor(win,NULL);

    if(rez > 0)
    {
        if(strstr(rasp, "REC:") != NULL)
        {
             if(strstr(cmd,"LIST") || strstr(cmd,"SCAN"))
                nr_statii = 0;
             char *line=strtok(rasp,"\n");

             while(line != NULL)
             {
                if(strncmp(line,"REC:",4)==0)
                {
                    char trash[10];
                    if(nr_statii<100)
                    {
                        sscanf(line, "%s %49s %49s %49s %49s %49s", trash,statii[nr_statii].id, statii[nr_statii].ip,statii[nr_statii].user, statii[nr_statii].pass,statii[nr_statii].cwd);
                        nr_statii++;
                    }
                }
                else if(strlen(line)>1)
                {
                    append_simple("%s", line); // Lista curata (fara ora, fara emoji, dar colorata)
                }
                line = strtok(NULL, "\n");
             }
        }
        else
        {
            append_simple("%s", rasp); // Output fara ora
        }
        if(out_resp)
            strcpy(out_resp, rasp);
    }
    else
    {
        append_log("ERR: Link lost.");
    }
}

// --- ACTIONS ---
void on_scan_clicked(GtkWidget *w, gpointer d)
{
    append_log("Scanning network...");
    send_cmd("SCAN", NULL);
}

void on_list_clicked(GtkWidget *w, gpointer d)
{
    append_log("Refreshing list...");
    send_cmd("LIST", NULL);
    const char *t = gtk_entry_get_text(GTK_ENTRY(entry_target));
    update_paths_ui(t);
}

void on_wake_clicked(GtkWidget *w, gpointer d)
{
    const char *t = gtk_entry_get_text(GTK_ENTRY(entry_target));
    if (strlen(t)==0)
        return;
    append_log("Sending WAKE to %s...", t);

    char msg[256];
    sprintf(msg, "WAKE %s", t);
    send_cmd(msg, NULL);
}

void on_shutdown_clicked(GtkWidget *w, gpointer d)
{
    const char *t = gtk_entry_get_text(GTK_ENTRY(entry_target));
    if(strlen(t)==0)
        return;
    append_log("Sending SHUTDOWN to %s...", t);

    char msg[256];
    sprintf(msg, "SHUTDOWN %s", t);
    send_cmd(msg, NULL);
}

void on_login_clicked(GtkWidget *w, gpointer d)
{
    if(is_authenticated)
    {
        if(sd != -1)
        {
            scrie_prefixat(sd, "LOGOUT");
            char r[100];
            citeste_prefixat(sd, r, 100);
        }
        is_authenticated=0;
        update_status_ui();
        return;
    }

    if(sd==-1)
    {
        append_log("ERR: Not connected.");
        return;
    }


    const char *u = gtk_entry_get_text(GTK_ENTRY(entry_user));
    const char *p = gtk_entry_get_text(GTK_ENTRY(entry_pass));

    char msg[1024];
    sprintf(msg, "AUTH %s %s", u, p);
    scrie_prefixat(sd, msg);

    char rasp[MAX_BUFFER];
    memset(rasp, 0, MAX_BUFFER);

    if(citeste_prefixat(sd, rasp, MAX_BUFFER) > 0)
    {
        append_log("SRV: %s", rasp);
        if(strstr(rasp, "[AUTH-OK]") || strstr(rasp, "Welcome"))
        {
            is_authenticated=1;
            update_status_ui();
            gtk_entry_set_text(GTK_ENTRY(entry_user), "");
            gtk_entry_set_text(GTK_ENTRY(entry_pass), "");
        }
        else
            append_log("ERR: Login Failed!");
    }
}

void on_set_clicked(GtkWidget *w, gpointer d)
{
    GtkWidget *dialog, *content_area, *grid;
    GtkWidget *lbl_id, *lbl_u, *lbl_p;
    GtkWidget *e_id, *e_u, *e_p;

    dialog=gtk_dialog_new_with_buttons("Set Credentials", GTK_WINDOW(gtk_widget_get_toplevel(txt_log)), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "Save", GTK_RESPONSE_ACCEPT, "Cancel", GTK_RESPONSE_REJECT, NULL);
    content_area=gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    grid=gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid),5);
    gtk_grid_set_column_spacing(GTK_GRID(grid),5);
    gtk_container_set_border_width(GTK_CONTAINER(grid),10);
    gtk_container_add(GTK_CONTAINER(content_area), grid);

    lbl_id=gtk_label_new("Target ID:");
    e_id=gtk_entry_new();

    const char *current_target=gtk_entry_get_text(GTK_ENTRY(entry_target));

    if(strlen(current_target) > 0)
        gtk_entry_set_text(GTK_ENTRY(e_id), current_target);

    lbl_u=gtk_label_new("New User:");
    e_u=gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e_u), "student");

    lbl_p=gtk_label_new("New Pass:");
    e_p = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(e_p), FALSE);

    gtk_grid_attach(GTK_GRID(grid), lbl_id, 0, 0, 1, 1); gtk_grid_attach(GTK_GRID(grid), e_id, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), lbl_u, 0, 1, 1, 1); gtk_grid_attach(GTK_GRID(grid), e_u, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), lbl_p, 0, 2, 1, 1); gtk_grid_attach(GTK_GRID(grid), e_p, 1, 2, 1, 1);

    gtk_widget_show_all(dialog);

    if(gtk_dialog_run(GTK_DIALOG(dialog))==GTK_RESPONSE_ACCEPT)
    {
        const char *id=gtk_entry_get_text(GTK_ENTRY(e_id));
        const char *user=gtk_entry_get_text(GTK_ENTRY(e_u));
        const char *pass=gtk_entry_get_text(GTK_ENTRY(e_p));

        if (strlen(id) > 0 && strlen(user) > 0 && strlen(pass) > 0)
        {
            char cmd[512];
            sprintf(cmd,"SET_CREDS %s %s %s", id, user, pass);
            send_cmd(cmd,NULL);
        }
        else
            append_log("GUI ERR: All fields required!");
    }
    gtk_widget_destroy(dialog);
}

void on_exec_clicked(GtkWidget *w, gpointer d)
{
    const char *target = gtk_entry_get_text(GTK_ENTRY(entry_target));
    const char *cmd = gtk_entry_get_text(GTK_ENTRY(entry_cmd));

    if(strlen(cmd) == 0)
        return;

    int is_local=(!is_authenticated || strlen(target) == 0 || strcasecmp(target,"LOCAL") == 0);

    // 1. DETECTIE INTERACTIVA (Nano, Vim, Htop) - LOCAL SI REMOTE
    if(strncmp(cmd, "nano", 4) == 0 || strncmp(cmd, "vim", 3) == 0 || strncmp(cmd, "htop", 4) == 0)
    {
        char sys_cmd[2048];

        if(is_local)
        {
            append_log("LOCAL: Launching interactive terminal for %s...", cmd);
            sprintf(sys_cmd, "gnome-terminal -- %s", cmd);
            system(sys_cmd);
        }
        else
        {
            if(!is_authenticated)
            {
                append_log("ERR: Access denied. Admin only.");
                return;
            }

            int idx=-1;
            for(int i=0; i<nr_statii; i++)
            {
                if(strcasecmp(statii[i].id, target)==0)
                {
                    idx=i;
                    break;
                }
            }

            if(idx!=-1)
            {
                append_log("REMOTE: Launching interactive terminal for %s...", cmd);

                sprintf(sys_cmd, "gnome-terminal -- bash -c \"sshpass -p '%s' ssh -o StrictHostKeyChecking=no -t %s@%s 'cd \\\"%s\\\" && %s'; exec bash\"",
                        statii[idx].pass, statii[idx].user, statii[idx].ip, statii[idx].cwd, cmd);
                system(sys_cmd);
            }
            else
            {
                append_log("ERR: Target not found in statii list.");
            }
        }

        gtk_entry_set_text(GTK_ENTRY(entry_cmd), "");
        return;
    }


    // 2. EXECUTIE STANDARD

    if(!is_local && !is_authenticated)
    {
        append_log("ERR: Access denied. Admin only.");
        return;
    }

    if(is_local)
    {
        if(strncmp(cmd, "cd ", 3)==0 || strcmp(cmd, "cd")==0)
        {
            char *path = (strlen(cmd) > 3) ? (char *)cmd + 3 : ".";
            char clean_path[256];
            strcpy(clean_path, path);
            clean_path[strcspn(clean_path,"\n")] = 0;

            if(chdir(clean_path)==0)
            {
                append_log("LOCAL $ cd %s [OK]", clean_path);
                update_paths_ui(NULL);
            }
            else
            {
                append_log("LOCAL ERR: %s", strerror(errno));
            }
        }
        else
        {
            append_log("LOCAL $ %s", cmd);
            char cmd_with_err[1024];
            sprintf(cmd_with_err, "%s 2>&1", cmd);
            FILE *fp = popen(cmd_with_err, "r");

            if(fp)
            {
                char buf[1024];
                int has_output=0;
                while(fgets(buf, 1024, fp))
                {
                    buf[strcspn(buf,"\n")]=0;
                    append_simple("%s", buf);
                    has_output=1;
                    while(gtk_events_pending())
                        gtk_main_iteration();
                }
                pclose(fp);
                if(!has_output)
                    append_simple("Executat (fara output).");
            }
            else
            {
                append_log("ERR: Exec system fail.");
            }
        }
    }
    else
    {
        // --- REMOTE STANDARD ---
        char msg[1024];
        sprintf(msg,"EXEC %s %s", target, cmd);
        append_log("REMOTE [%s] $ %s", target, cmd);

        char resp[MAX_BUFFER];
        send_cmd(msg,resp);

        // Verificam daca s-a schimbat directorul (CD)
        char *ptr = strstr(resp, "CWD changed to: [");
        if(ptr!=NULL)
        {
            char *path_start=ptr+17;
            char *path_end=strchr(path_start, ']');
            if(path_end!=NULL)
            {
                *path_end='\0';
                for(int i=0;i<nr_statii;i++)
                {
                    if(strcasecmp(statii[i].id,target)==0)
                    {
                        strcpy(statii[i].cwd, path_start);
                        update_paths_ui(target);
                        break;
                    }
                }
            }
        }
    }

    gtk_entry_set_text(GTK_ENTRY(entry_cmd), "");
}


void on_target_activate(GtkWidget *w, gpointer d)
{
    const char *t = gtk_entry_get_text(GTK_ENTRY(entry_target));
    update_paths_ui(t);
    gtk_widget_grab_focus(entry_cmd);
}

void app_connect(const char *ip, int port)
{
    struct sockaddr_in server;

    if((sd=socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        append_log("ERR: Socket fail.");
        return;
    }

    server.sin_family=AF_INET;
    server.sin_addr.s_addr=inet_addr(ip);
    server.sin_port=htons(port);

    append_log("NET: Connecting %s:%d...", ip, port);
    while(gtk_events_pending())
        gtk_main_iteration();

    if(connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr))==-1)
    {
        append_log("ERR: Connection refused.");
        sd=-1;
    }
    else
    {
        append_log("OK: Connected.");
        update_paths_ui(NULL);
    }
}

int main(int argc, char *argv[])
{
    // Verificare argumente
    if (argc != 4)
    {
        printf("Syntax: %s <ip> <port> <pass>\n", argv[0]);
        return 1;
    }

    gtk_init(&argc, &argv);
    load_css();
    init_crypto(argv[3]);

    // fereastra principala
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Grid Admin");
    gtk_window_set_default_size(GTK_WINDOW(window), 1050, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // layout
    GtkWidget *main_grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(window), main_grid);
    gtk_container_set_border_width(GTK_CONTAINER(main_grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(main_grid), 5);
    gtk_grid_set_row_spacing(GTK_GRID(main_grid), 5);

    //--------------------------------------------------------------------------------panou stanga
    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(left_box, 160, -1);
    gtk_widget_set_vexpand(left_box, TRUE);

    //autentificarea
    GtkWidget *frm_auth = gtk_frame_new("Auth");
    GtkWidget *box_auth = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_add(GTK_CONTAINER(frm_auth), box_auth);

    //user
    entry_user = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_user), "User");

    //parola
    entry_pass = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry_pass), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_pass), "Pass");

    //login
    btn_login = gtk_button_new_with_label("LOGIN");
    g_signal_connect(btn_login, "clicked", G_CALLBACK(on_login_clicked), NULL);

    // pun toate in box_auth
    gtk_box_pack_start(GTK_BOX(box_auth), entry_user, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_auth), entry_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_auth), btn_login, FALSE, FALSE, 2);

    //pun box_auth in panoul stanga
    gtk_box_pack_start(GTK_BOX(left_box), frm_auth, FALSE, FALSE, 0);

    //statusul
    lbl_status = gtk_label_new("");
    gtk_widget_set_name(lbl_status, "status_label");
    gtk_box_pack_start(GTK_BOX(left_box), lbl_status, FALSE, FALSE, 5);

    //sectiunea de butoane
    GtkWidget *frm_act = gtk_frame_new("Controls");
    GtkWidget *box_act = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_add(GTK_CONTAINER(frm_act), box_act);

    //buton SCAN
    btn_scan = gtk_button_new_with_label("SCAN NET");
    g_signal_connect(btn_scan, "clicked", G_CALLBACK(on_scan_clicked), NULL);

    //buton LIST
    btn_list = gtk_button_new_with_label("LIST PCS");
    g_signal_connect(btn_list, "clicked", G_CALLBACK(on_list_clicked), NULL);

    //buton WAKE
    btn_wake = gtk_button_new_with_label("WAKE LAN");
    g_signal_connect(btn_wake, "clicked", G_CALLBACK(on_wake_clicked), NULL);

    //buton SHUTDOWN
    btn_shutdown = gtk_button_new_with_label("SHUTDOWN");
    g_signal_connect(btn_shutdown, "clicked", G_CALLBACK(on_shutdown_clicked), NULL);

    //buton SET CREDS
    btn_set = gtk_button_new_with_label("SET CREDS");
    g_signal_connect(btn_set, "clicked", G_CALLBACK(on_set_clicked), NULL);

    //adaug butoanele in box_act
    gtk_box_pack_start(GTK_BOX(box_act), btn_scan, FALSE, FALSE, 1);
    gtk_box_pack_start(GTK_BOX(box_act), btn_list, FALSE, FALSE, 1);
    gtk_box_pack_start(GTK_BOX(box_act), btn_wake, FALSE, FALSE, 1);
    gtk_box_pack_start(GTK_BOX(box_act), btn_set, FALSE, FALSE, 1);
    gtk_box_pack_start(GTK_BOX(box_act), btn_shutdown, FALSE, FALSE, 1);

    //le pun in stanga
    gtk_box_pack_start(GTK_BOX(left_box), frm_act, FALSE, FALSE, 0);

    // adaug panoul din stanga in gridul mare
    gtk_grid_attach(GTK_GRID(main_grid), left_box, 0, 0, 1, 1);

    //--------------------------------------------------------------------------------panou dreapta
    GtkWidget *right_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    //pathurile de sus
    GtkWidget *frm_paths = gtk_frame_new(NULL);
    GtkWidget *box_paths = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_container_add(GTK_CONTAINER(frm_paths), box_paths);
    gtk_container_set_border_width(GTK_CONTAINER(box_paths), 5);

    //path local
    lbl_local_path = gtk_label_new("LOCAL: /");
    gtk_widget_set_name(lbl_local_path, "path_label");

    //path target
    lbl_remote_path = gtk_label_new("REMOTE: [Select Target]");
    gtk_widget_set_name(lbl_remote_path, "path_label");

    //le adaug
    gtk_box_pack_start(GTK_BOX(box_paths), lbl_local_path, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box_paths), lbl_remote_path, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(right_box), frm_paths, FALSE, FALSE, 0);

    //zona logs
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_hexpand(scrolled, TRUE);
    gtk_widget_set_vexpand(scrolled, TRUE);

    txt_log = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(txt_log), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(txt_log), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(txt_log), 8);

    //CULORI
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt_log));
    gtk_text_buffer_create_tag(buffer, "red_fg", "foreground", "#ff5555", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buffer, "green_fg", "foreground", "#50fa7b", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buffer, "yellow_fg", "foreground", "#f1fa8c", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buffer, "blue_fg", "foreground", "#8be9fd", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buffer, "gray_fg", "foreground", "#6272a4", NULL);
    gtk_text_buffer_create_tag(buffer, "header_fg", "foreground", "#bd93f9", "weight", PANGO_WEIGHT_BOLD, NULL);

    //Asamblare Log
    gtk_container_add(GTK_CONTAINER(scrolled), txt_log);
    gtk_box_pack_start(GTK_BOX(right_box), scrolled, TRUE, TRUE, 0);

    //adaug panou dreapta in grid mare
    gtk_grid_attach(GTK_GRID(main_grid), right_box, 1, 0, 1, 1);

    //--------------------------------------------------------------------------------zona comanda
    GtkWidget *frm_exec = gtk_frame_new("Command Line Interface");
    GtkWidget *box_exec = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_container_add(GTK_CONTAINER(frm_exec), box_exec);

    //target
    GtkWidget *lbl_t = gtk_label_new("Target:");
    entry_target = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_target), "ID / MAC / ALL");
    gtk_entry_set_width_chars(GTK_ENTRY(entry_target), 13);
    g_signal_connect(entry_target, "activate", G_CALLBACK(on_target_activate), NULL);

    //comanda
    GtkWidget *lbl_c = gtk_label_new("Cmd:");
    entry_cmd = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_cmd), "Type command here...");
    g_signal_connect(entry_cmd, "activate", G_CALLBACK(on_exec_clicked), NULL);

    //run
    btn_exec = gtk_button_new_with_label("EXEC");
    gtk_widget_set_name(btn_exec, "btn_run");
    gtk_widget_set_size_request(btn_exec, 80, -1);
    g_signal_connect(btn_exec, "clicked", G_CALLBACK(on_exec_clicked), NULL);

    //le adaug
    gtk_box_pack_start(GTK_BOX(box_exec), lbl_t, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_exec), entry_target, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_exec), lbl_c, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_exec), entry_cmd, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box_exec), btn_exec, FALSE, FALSE, 0);

    //adaug in gridul mare
    gtk_grid_attach(GTK_GRID(main_grid), frm_exec, 1, 1, 1, 1);

    //pornesc aplicatia
    gtk_widget_show_all(window);
    app_connect(argv[1], atoi(argv[2]));
    gtk_main();

    return 0;
}
