#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include<math.h>

//#define DEBUG

/* Structure of binary trie node */
struct BtNode{
    int   equal;      /* for 0 */
    int   greater;     /* for 1 */
    int     portno;
    int pref[32];
    int index;
    int scrid;		
    long long value;
};

/* Initialize binary trie node */
BtNode* init_btnode()
{
    BtNode *ret = (BtNode *)malloc(sizeof(BtNode));
    ret->equal = 0;
    ret->greater = 0;
    ret->portno = -1;
    for (int i =0; i< 32; i++)
    {
       ret->pref[i] = 0;
    }
    ret->index =0;
    ret->scrid=0;
    ret->value=0;
    return ret;
}



void sort(BtNode table[], int counter)
{
	BtNode temp;	
	int s = counter;
        int i,j;
        
	for(i=s-2;i>0;i--)
	{
		for(j=0;j<=i;j++)
		{
			if(table[j].value>table[j+1].value)
			{
				
                              
        			temp.portno=table[j].portno;
				for(int i=0;i<32;i++)
				{
					temp.pref[i]=table[j].pref[i];
				}
				temp.index=table[j].index;
				temp.scrid=table[j].scrid;
				temp.value=table[j].value;
		
        			table[j].portno=table[j+1].portno;
				for(int i=0;i<32;i++)
				{
					table[j].pref[i]=table[j+1].pref[i];
				}
				table[j].index=table[j+1].index;
				table[j].scrid=table[j+1].scrid;
				table[j].value=table[j+1].value;

        			table[j+1].portno=temp.portno;
				for(int i=0;i<32;i++)
				{
					table[j+1].pref[i]=temp.pref[i];
				}
				table[j+1].index=temp.index;
				table[j+1].scrid=temp.scrid;
				table[j+1].value=temp.value;
			}
		}
	}


}


int lookup_ip(BtNode table[], uint32_t ip, int min , int max)

{
    uint32_t    temp_ip = ip;
    int temp[32]; 
    int middle= 0;
    long long tempval=0;
    int verdict = -1;
    int counter = max+1;
    for (int i = 0; i< 32; i++)
    {

	temp[i] = 0;
	temp[i] = (temp_ip & 0x80000000)? 1 : 0;
        temp_ip = temp_ip<<1;

    }
   
   
    for (int c=0;c<32;c++)
    {
		long long 
		p=pow(2,31-c);
		tempval= tempval + p*temp[c];
    }
	
    middle = (min + max) / 2;
    
    while (min <= max)
    {
 	if (table[middle].value < tempval)
        {
		
		min = middle +1;
   
                if (table[min].value > tempval)
		{
			verdict = table[middle].greater;
			
               		return verdict;
			break;

		}
        }
			
	else if (table[middle].value == tempval)
        {
		verdict = table[middle].equal;
		
                return verdict;
		break;
        
	}
        else 
	{
          max = middle -1;
	  
	}
        
        middle = (max + min)/2;
   }

}
   












