/* Carlos McNulty
 * cmcnul3
 * Description:
 * This program implements a recursive DNS resolver.
 * It ignores IPV6 and SOA records. For testing purposes,
 * you should know that searching the hostname www.visaguide.world.ca
 * does end and isn't stuck in a loop, but it does take some time.
 * The same applies to the hostname wwww.google.com.ru.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns.h"

static int debug=0, nameserver_flag=0;

void usage() {
  printf("Usage: hw3 [-d] -n nameserver -i domain/ip_address\n\t-d: debug\n");
  exit(1);
}

int get_ip(int sock, char **servers, int n_servers, 
      char *server, char *hostname, char *ip);

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) {
  memset(query,0,max_query);

  in_addr_t rev_addr=inet_addr(hostname);
  if(rev_addr!=INADDR_NONE) {
    static char reverse_name[255];    
    sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
            (rev_addr&0xff000000)>>24,
            (rev_addr&0xff0000)>>16,
            (rev_addr&0xff00)>>8,
            (rev_addr&0xff));
    hostname=reverse_name;
  }
  // first part of the query is a fixed size header
  struct dns_hdr *hdr = (struct dns_hdr*)query;

  // generate a random 16-bit number for session
  uint16_t query_id = (uint16_t) (random() & 0xffff);
  hdr->id = htons(query_id);
  // set header flags to request recursive query
  hdr->flags = htons(0x0000); 
  // 1 question, no answers or other records
  hdr->q_count=htons(1);

  // add the name
  int query_len = sizeof(struct dns_hdr); 
  int name_len=to_dns_style(hostname,query+query_len);
  query_len += name_len; 
  
  // now the query type: A or PTR. 
  uint16_t *type = (uint16_t*)(query+query_len);
  char *inv_addr;
  if(rev_addr!=INADDR_NONE
      || strstr(hostname, "in-addr.arpa"))
    *type = htons(12);
  else
    *type = htons(1);

  query_len+=2;
  
  // finally the class: INET
  uint16_t *class = (uint16_t*)(query+query_len);
  *class = htons(1);
  query_len += 2;
 
  return query_len; 
}


int get_ip_aux(int sock, char **servers, int n_servers, 
         uint8_t *query, int query_len, 
         in_addr_t server_addr, char *hostname, char *ip){

  struct sockaddr_in addr;  // internet socket address data structure
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53); // port 53 for DNS
  addr.sin_addr.s_addr = server_addr; // destination address

  if(debug){
    printf("Resolving %s using server %s\n", 
      hostname, inet_ntoa(addr.sin_addr));
  }

  int send_count = sendto(sock, query, query_len, 0,
               (struct sockaddr*)&addr,sizeof(addr));
  if(send_count < 0){
    perror("Error sending dns query");
    exit(-1);
  } 
  // await the response 
  uint8_t answerbuf[1500];
  int rec_count = recv(sock,answerbuf,1500,0);
  // check for timeout
  if(rec_count < 0){
    if(errno == EAGAIN || errno == EWOULDBLOCK){
      return 0;
    }
    else{
      perror("Error receiving dns response");
      exit(-1);
    }
  }
  // parse the response to get our answer
  struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
  uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);
  
  // now answer_ptr points at the first question. 
  int question_count = ntohs(ans_hdr->q_count);
  int answer_count = ntohs(ans_hdr->a_count);
  int auth_count = ntohs(ans_hdr->auth_count);
  int other_count = ntohs(ans_hdr->other_count);
  
  // skip past all questions
  int q;
  for(q=0;q<question_count;q++) {
    char string_name[255];
    memset(string_name,0,255);
    int size=from_dns_style(answerbuf,answer_ptr,string_name);
    answer_ptr+=size;
    answer_ptr+=4; //2 for type, 2 for class
  }
  
  int a;
  // now answer_ptr points at the first answer. loop through
  // all answers in all sections
  for(a=0;a<answer_count+auth_count+other_count;a++) {
    // first the name this answer is referring to 
    char string_name[255];
    int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
    answer_ptr += dnsnamelen;

    // then fixed part of the RR record
    struct dns_rr* rr = (struct dns_rr*)answer_ptr;
    answer_ptr+=sizeof(struct dns_rr);

    const uint8_t RECTYPE_A=1;
    const uint8_t RECTYPE_NS=2;
    const uint8_t RECTYPE_CNAME=5;
    const uint8_t RECTYPE_SOA=6;
    const uint8_t RECTYPE_PTR=12;
    const uint8_t RECTYPE_AAAA=28;

    if(htons(rr->type)==RECTYPE_A) {
      struct in_addr addr = *((struct in_addr *)answer_ptr);
      char *ip_addr = inet_ntoa(addr);
      if(debug){
        printf("The name %s resolves to IP addr: %s\n", 
          string_name, ip_addr);
      }
      // A record in answer section
      if(a<answer_count){
        strcpy(ip, ip_addr);
        return 1;
      }
      else{
        // A record in additional information section
        if(get_ip_aux(sock, servers, n_servers, query, query_len,
          addr.s_addr, hostname, ip)){
          return 1;
        }
      }
    }
    // NS record
    else if(htons(rr->type)==RECTYPE_NS) {
      char ns_string[255];
      int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);  
      // additional information section doesn't have ip address
      if(other_count == 0){
        if(debug){
          printf("The name %s can be resolved by NS: %s\n",
               string_name, ns_string);
        }
        char ns_ip[100];
        // resolve NS record
        if(get_ip(sock, servers, n_servers, 
            NULL, ns_string, ns_ip)){
          // get scalar address of resolved ip address
          in_addr_t server_addr_s = inet_addr(ns_ip);
          // resolve using ip address
          if(get_ip_aux(sock, servers, n_servers,
                query, query_len,
                server_addr_s, hostname, ip)){
            return 1;
          }   
        }
      }     
    }
    // CNAME record
    else if(htons(rr->type)==RECTYPE_CNAME) {
      char ns_string[255];
      int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
      if(debug)
        printf("The name %s is also known as %s.\n",
               string_name, ns_string);
      // record is apart of answer section
      if(a<answer_count){
        // resolve alias
        if(get_ip(sock, servers, n_servers, 
            NULL, ns_string, ip)){
          return 1;
        }
      }
    }
    // PTR record
    else if(htons(rr->type)==RECTYPE_PTR) {
      char ns_string[255];
      int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
      if(a<answer_count){
        if(debug){
          printf("The host at %s is also known as %s.\n",
          string_name, ns_string);  
        }
        strcpy(ip, ns_string);
        return 1;
      }
    }
    // SOA record
    else if(htons(rr->type)==RECTYPE_SOA) {
      if(debug)
        printf("Ignoring SOA record\n");
    }
    // AAAA record
    else if(htons(rr->type)==RECTYPE_AAAA)  {
      if(debug)
        printf("Ignoring IPv6 record\n");
    }
    else {
      if(debug)
        printf("got unknown record type %hu\n",htons(rr->type));
    } 

    answer_ptr+=htons(rr->datalen);
  }
  return 0; 
}

int get_ip(int sock, char **servers, int n_servers, 
      char *server, char *hostname, char *ip){
  if(!servers){
    return 0;
  }
  // construct the query message
  uint8_t query[1500];
  int query_len=construct_query(query,1500,hostname);
  // check servers if server isn't provided
  if(!server){
    int i;
    for(i = 0; i < n_servers; i++){
      struct in_addr server_addr;
      in_addr_t server_addr_s = inet_addr(servers[i]);
      if(get_ip_aux(sock, servers, n_servers, 
              query, query_len, 
              server_addr_s, hostname, ip)){
        return 1;
      }
    } 
    return 0; 
  }
  // use server passed in as jumping off point
  struct in_addr server_addr;
  in_addr_t server_addr_s = inet_addr(server);
  return get_ip_aux(sock, servers, n_servers, 
            query, query_len,
              server_addr_s, hostname, ip);
}


int main(int argc, char** argv)
{

  if(argc<2) usage();
  // null-terminate strings (just in case)
  int i;
  for(i = 0; i < argc; i++){
    argv[i][strcspn(argv[i], "\r\n")] = 0;
  }
  char *hostname=0;
  char *nameserver=0;
  
  char *optString = "-d-n:-i:";
  int opt = getopt( argc, argv, optString );
  
  while( opt != -1 ) {
    switch( opt ) {      
    case 'd':
      debug = 1; 
      break;
    case 'n':
      nameserver_flag = 1; 
      nameserver = optarg;
      break;      
    case 'i':
      hostname = optarg;
      break;  
    case '?':
      usage();
      exit(1);               
    default:
      usage();
      exit(1);
    }
    opt = getopt( argc, argv, optString );
  }
    
  if(!hostname) {
    usage();
    exit(1);
  }
    
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0) {
    perror("Creating socket failed: ");
    exit(1);
  }
  
  // set timeout for sock
  struct timeval timeout;
  timeout.tv_sec = 7;
  timeout.tv_usec = 0;
  if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, 
        (char*)&timeout, sizeof(timeout)) < 0){
    perror("Error setting timeout option");
    exit(-1);
  } 
    
  // get root servers from file
  char **root_servers = (char**)malloc(sizeof(char*)*20);
  int n_servers = 0;
  char buffer[100];
  FILE *servers_file;
  if((servers_file = fopen("root-servers.txt", "r"))){
    while(fgets(buffer, 100, servers_file) && n_servers < 19){
      buffer[strcspn(buffer, "\r\n")] = 0;
      root_servers[n_servers] = (char*)malloc(strlen(buffer)+1);
      strcpy(root_servers[n_servers], buffer);
      n_servers++;
    }
    root_servers[n_servers] = 0;
  }
  else{
    fprintf(stderr, "root-servers not found!\n");
    exit(-1);
  }
  char ip[100];
  if(!get_ip(sock, root_servers, n_servers, nameserver, hostname, ip)){
    printf("Host not found!\n");
  }
  else{
    printf("The name %s resolves to IP addr: %s\n", 
          hostname, ip);

  }

  close(sock);
}
