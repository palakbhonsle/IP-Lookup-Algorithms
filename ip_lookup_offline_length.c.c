#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "binarylength"

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




/* Parse the routing table file (in_fn is the variable for its file name) */
void parse_rules(char *in_fn){
    FILE        *fp;
    char        pre_exp[100];      /* prefix expression, e.g. 1.2.3.0/24 */
    int         portnum;    
    in_addr     prefix_in_addr;
    uint32_t    prefix;
    int         prelen;
hashTable = (struct hash *)calloc(33, sizeof (struct hash));

    fp = fopen(in_fn, "r");
    if( fp == NULL ){
        fprintf(stderr, "Cannot read routing table file %s.\n", in_fn);
        exit(1);
    }

    while( fscanf(fp, "%s %d\n", pre_exp, &portnum) != EOF ){
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
            prelen = atoi(prelen_str);  
            //printf("this is dotnation %s\n",dot_notation); 
	       
            //printf(" this is prelength %d\n",prelen); 
	     
            //printf(" this is prefix %u\n",prefix);   
	    
        
        }
        else{
            inet_aton(pre_exp, &prefix_in_addr);
            prefix = htonl(prefix_in_addr.s_addr);      
            prelen = 32;
            
        }


insertToHash(prelen,  prefix, portnum) ;


        
    }
}

void my_callback(u_char *user, 
                 const struct pcap_pkthdr *pkthdr, 
                 const u_char *pktdata)
{
	static uint32_t     dst_addr;
	static int          verdict;
	int i =0;
	uint32_t  sum =0;
	uint32_t    temp_ip = dst_addr;
	uint32_t  mult =0;
	int x =0;
	int curr_bit = 0;
	int min_prelen= 0;
	int max_prelen =32;
	int prelen =0;
	int temp_prelen =0;

    ip_hdr =    (struct sniff_ip *)(pktdata + SIZE_ETHERNET);

    pkt_cnt ++;

    dst_addr = htonl(ip_hdr->ip_dst.s_addr);    /* IMPORTANT! htonl to reverse the endian */
	//printf("IP ADDRESS IS:%u\n",dst_addr);
while((min_prelen + max_prelen)%2==0) // 
		{
	//printf("while loop entered");
	sum =0;
	prelen = (min_prelen + max_prelen )/2;
	temp_ip = dst_addr;
	//printf("prelen before:%u\n",prelen);
	for (i=0; i < prelen; i++){                  /* Masking IP address to different prefix for best possible lookup*/

			   curr_bit = (temp_ip & 0x80000000) ? 1 : 0;
				x = 31 -i;
				mult = (pow(2, x))*curr_bit;
			   //printf("mult is:%d", mult);
				sum = sum + mult;
				temp_ip = temp_ip << 1;
			
			}
	//printf("sum is:%u\n",sum);
	//printf("prelen after:%u\n",prelen);
	lookup_ip(sum,prelen); // Searching for the Masked Ip address coming from wireshark packet in hash table with index = prelen
		if (lookup_ip(sum,prelen)==0)
			{
		max_prelen = prelen;
			}	
		else{
		min_prelen = prelen;
		verdict = lookup_ip(sum,prelen);
			}
		}

		
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





/* main function */
int main(int argc, char **argv)
{
    int     ret;        /* return code */
    char    errbuf[PCAP_ERRBUF_SIZE];   /* Error message buffer */
    pcap_t  *descr;     /* pcap descriptor */

    /* argc < 3 means no filename is input from the command line. */
    if( argc < 3 ){
        printf("You forgot to enter dump file and routing table file name!\n");
        exit(1);
    }

 
    parse_rules(argv[2]);
/* open file for sniffing */
    
    descr = pcap_open_offline(argv[1], errbuf);
   
    /* error check - halt if cannot open file. */
    if(descr == NULL)
    {
        printf("pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }

    /* pcap looping! */
     
    pcap_loop(descr, -1, my_callback, NULL);
	
for( std::map<int,int>::iterator cit=counters.begin() ; cit != counters.end() ; ++cit){
        printf("Port #%-5d: %-10d packets\n", cit->first, cit->second);
    }

    /* finish up */
    fprintf(stderr, "Done with packet processing! Looked up %ld packets.\n", pkt_cnt);

    

    return 0;       
}
