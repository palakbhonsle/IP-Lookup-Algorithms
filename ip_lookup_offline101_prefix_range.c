#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "range1.h"
#include <inttypes.h>
#include <math.h>
int top;
//#define DEBUG

#define ETHER_ADDR_LEN  6   /* MAC address is 6 bytes */
#define SIZE_ETHERNET 14    /* Ethernet header is 14 bytes */

/* struct for Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* struct for IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr      ip_src;
    struct in_addr      ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

const struct sniff_ethernet     *eth_hdr;
const struct sniff_ip           *ip_hdr;
struct BtNode                   *bt_root;       /* pointer to the root node of the binary tree */
unsigned long int               pkt_cnt = 0;    /* total processed packet # */
std::map<int, int>              counters;       /* use a STL map to keep counters of each port */
long int max;
struct BtNode table[200002]; 

int parse_rules(char *in_fn, BtNode table[])
{
    FILE        *fp;/*For C File I/O you need to use a FILE pointer, which will let the program keep track of the file being accessed.   

(Memory Access)*/
    char        pre_exp[100];      /* prefix expression, e.g. 1.2.3.0/24 */
    int         portnum;    
    in_addr     prefix_in_addr;
    uint32_t    prefix;
    int         prelen;
    uint32_t prefix2;
    int i=0;
    int counter =0;	
    int p0[32],p1[32]; 
    fp = fopen(in_fn, "r");/*Passing in_fn to read only connecting fp to the in_fn.To open a file you need to use the fopen function, which returns a FILE pointer*/
    if( fp == NULL ){
        fprintf(stderr, "Cannot read routing table file %s.\n", in_fn);
        exit(1);
    }/*This is for reading input files which are entered in the filesystem I/o*/

    while( fscanf(fp, "%s %d\n", pre_exp, &portnum) != EOF )
    {
        char *slash_ptr = strchr(pre_exp, '/');         /* Find '/' location in pre_exp */
        if(slash_ptr != NULL){
            char    dot_notation[100];
            char    prelen_str[10];
            strncpy(dot_notation, pre_exp, slash_ptr-pre_exp);
            dot_notation[slash_ptr-pre_exp] = '\0';     /* Don't forget to add a '\0' to signal end of string! */
            strncpy(prelen_str, slash_ptr+1, 3 );
            prelen_str[3] = '\0';                       /* Don't forget to add a '\0' to signal end of string! */
            inet_aton(dot_notation, &prefix_in_addr);   /* Convert string to in_addr */
            prefix = htonl(prefix_in_addr.s_addr);      /* get the 32-bit integer in in_addr. htonl to correct the endian problem */
            prelen = atoi(prelen_str);                  /*string to integer Eg /24 */
        }
        else{
            inet_aton(pre_exp, &prefix_in_addr);
            prefix = htonl(prefix_in_addr.s_addr);      /* get the 32-bit integer in in_addr. htonl to correct the endian problem */
            prelen = 32;
        }
        
	prefix2 = prefix;
	/*printf("%u\n",prefix2);*/
	for ( int a=0;a<32;a++)
	{
		p0[a]=0;
		p1[a]=1;
	}

	for (int b= 0 ; b< prelen; b++)
	{
		if( (prefix2 & 0x80000000) ) {		
   			p0[b] = 1;
		} else {
			p0[b] = 0;
		}
		if( (prefix2 & 0x80000000) ) {		
   			p1[b] = 1;
		} else {
			p1[b] = 0;
		}		
		prefix2 = prefix2<<1;

	}

        
       for (int j=0;j<32;j++)
	{
		table[i].pref[j] = p0[j];

	}

        table[i].portno = portnum;
	table[i].scrid=0;        
	
	for (int c=0;c<32;c++)
	{  
		long long p=pow(2,31-c);
		table[i].value= table[i].value + p*table[i].pref[c];
	}
	
	i++;
	counter++;
	for (int j=0;j<32;j++)
	{
		table[i].pref[j] = p1[j];

	}
        
	table[i].portno = portnum;
	table[i].scrid=1; 
	for (int c=0;c<32;c++)
	{
		long long p=pow(2,31-c);
		table[i].value= table[i].value + p*table[i].pref[c];
	}	  
	i++; 
	counter++;           
	
    }
  return counter;
}
void my_callback(u_char *user, 
                 const struct pcap_pkthdr *pkthdr, 
                 const u_char *pktdata)
{
    static uint32_t     dst_addr;
    static int          verdict;
    int min = 0;
   
    ip_hdr =    (struct sniff_ip *)(pktdata + SIZE_ETHERNET);

    pkt_cnt ++;

    dst_addr = htonl(ip_hdr->ip_dst.s_addr);    

    verdict = lookup_ip(table, dst_addr, min , max);
    if (verdict == max + 1 ||verdict == 0)
	verdict = -1;


    if( counters.find(verdict) == counters.end() ){
        counters[verdict] = 1;
    }
    else{
        counters[verdict] ++;
    }

#ifdef DEBUG
    fprintf(stderr, "Packet #%-10ld - dest ip %s  port=%d\n", pkt_cnt, inet_ntoa(ip_hdr->ip_dst), verdict);
#endif
}

void print(BtNode table[], int counter)
{

 for (int i =0 ; i<counter; i++)
	
    {
	
	printf(" %d\t %d \t %d \t %d", table[i].scrid, table[i].portno, table[i].equal, table[i].greater);
        
	printf("\n");
    }
}

void push (int stack[], int port)
{
     ++top;
     stack[top] = port;	

}
void pop(int stack[])
{	
	--top;

}

int main(int argc, char **argv)/*The first argument is the number of parameters passed plus one to include the name of the program that was executed to get those process running.argv[2] is the name of the executable (including the path) that was run to begin this process.*/
{
    int     ret,i;        
    char    errbuf[PCAP_ERRBUF_SIZE];   
    pcap_t  *descr;     
    
    int stack[30000];
    int counter =0;
    top = -1;	 
    
	
    if( argc < 3 ){
        printf("You forgot to enter dump file and routing table file name!\n");
        exit(1);
    }
  
    
    counter = parse_rules(argv[2], table);
    max = counter -1;
    
    sort(table, counter);
   
   
    for (i= 0; i < counter; i++)
    {
		if (table[i].scrid == 0)
		{
			push(stack, table[i].portno);
			table[i].greater = table[i].portno;
			table[i].equal = table[i].portno;
		}
		else 
		{       
			table[i].equal = table[i].portno;
			pop(stack);
			if (top == -1)
			{
				table[i].greater = -1;
			}
			else
			{
				table[i].greater = stack[top];
				
			}
                         
		}		
     }
  	
    
     descr = pcap_open_offline(argv[1], errbuf);
    
    if(descr == NULL)
    {
        printf("pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }

    pcap_loop(descr, -1, my_callback, NULL);

    for( std::map<int,int>::iterator cit=counters.begin() ; cit != counters.end() ; ++cit){
        printf("Port #%-5d: %-10d packets\n", cit->first, cit->second);
    }

    fprintf(stderr, "Done with packet processing! Looked up %ld packets.\n", pkt_cnt);        

    return 0;       
}
