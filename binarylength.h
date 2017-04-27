/* Reference Code: http://see-programming.blogspot.com/2013/05/chain-hashing-separate-chaining-with.html*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>


  struct hash *hashTable = NULL;

  int eleCount = 33; // Elelment count in Hash Table; for testing purpose this value is kept low but can hold any postive integer 

  struct node {
        int prelen, portnum;
        uint32_t prefix;
        struct node *next;
  };

  struct hash {
        struct node *head;
        int count;
  };

  struct node * createNode( int prelen,uint32_t prefix, int portnum) {
        struct node *newnode;
        newnode = (struct node *)malloc(sizeof(struct node));
        newnode->prelen = prelen;
        newnode->portnum = portnum;
    newnode->prefix = prefix;
        //strcpy(newnode->prefix, prefix);
        newnode->next = NULL;
        return newnode;
  }

/* Inserting data read from Test_Table.txt to Hash Table*/
  void insertToHash(int prelen,  int prefix, int portnum) {
	//printf("hash executed!!! and added following in hash table %d %d %d", prelen, prefix, portnum);
        int hashIndex = prelen % eleCount;
        struct node *newnode =  createNode(prelen,prefix, portnum);
        /* head of list for the bucket with index "hashIndex" */
        if (!hashTable[hashIndex].head) {
                hashTable[hashIndex].head = newnode;
                hashTable[hashIndex].count = 1;
                return;
        }
        /* adding new node to the list */
        newnode->next = (hashTable[hashIndex].head);
        /*
         * update the head of the list and no of
         * nodes in the current bucket
         */
        hashTable[hashIndex].head = newnode;
        hashTable[hashIndex].count++;
        return;
  }
 /* Looking up required masked ip address, masking done with number of bits = prefix length */
  int lookup_ip(uint32_t prefix1, int prelen) {
        int hashIndex = prelen % eleCount, flag = 0;
        struct node *myNode;
        myNode = hashTable[hashIndex].head;
        if (!myNode) {
            //printf("Search element unavailable in hash table\n");
                return 0;
        }
			//printf("prefix1 is:%u\n",prefix1);
        while (myNode != NULL) {
                if (myNode->prelen == prelen) {
			
					if(myNode->prefix == prefix1)
					{
					//printf("MATCHED!!!");
					//printf("MYNODE PREFIX IS:%u\n",myNode->prefix);
					//printf("SUM IS:%u",prefix1);
					//printf("portnum is:%d\n",myNode->portnum);
							flag = 1;
				
						return myNode->portnum;
						break;
					}
                }
                myNode = myNode->next;
        }
        if (!flag)
            //printf("Search element unavailable in hash table\n");
        return 0;
  }

