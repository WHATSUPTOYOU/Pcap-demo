#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
//#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdint.h>


#define SIZE_IP  4
#define SIZE_MAC 6

typedef struct
{
	unsigned char des_mac[SIZE_MAC];
	unsigned char sou_mac[SIZE_MAC];
	uint16_t pcol;
}ETHdata;

typedef struct
{
	uint8_t  ver_headl;//version(4) headerLength(4);
	uint8_t  pcolServ;
	uint16_t totaLength;
	uint16_t identifi;
	uint16_t flag_offset;//flag(3) offset(13)
	uint8_t  liveTime;
	uint8_t  protocol;
	uint16_t headCheakSum;
	unsigned char souAddr[SIZE_IP];
	unsigned char desAddr[SIZE_IP];
}IPdata;

typedef struct
{
	uint16_t souPort;
	uint16_t desPort;
	uint16_t length;
	uint16_t checkSum;
}UDPdata;

typedef struct
{
	uint16_t ID;
	uint16_t FLAGS;//QR(1),opcode(4),AA(1),TC(1),RD(1),RA(1),zero(3),rcode(4)
	uint16_t queCount;
	uint16_t ansRss;
	uint16_t authority;
	uint16_t additional;
}DNSdata;

typedef struct
{
	ETHdata eth;
	IPdata  ip;
	UDPdata udp;
	DNSdata dnsHeader;
}DNS;

typedef struct domainip
{
    uint8_t flag;
    char ipstr[32];
}DOMAINIP;



void dnsAnswer(const u_char * pac,DNS * dnsType, char *domain, DOMAINIP **domainip, uint16_t *ipcount)
{
	int i = 0;
	int a = 0;
	int j;
	uint8_t *count = NULL;
	//uint8_t *temp  = NULL;
	uint16_t queSum,ansSum;

	queSum = ntohs(dnsType->dnsHeader.queCount);
	ansSum = ntohs(dnsType->dnsHeader.ansRss);

    if ((queSum > 5) || (ansSum > 5))
    {
        return;
    }

	printf("queSum = %d ansSum = %d\n",queSum,ansSum);	
	uint16_t *dnsAnsType  = NULL;
	uint16_t *dnsAnsClass = NULL;

	uint16_t tmp[4] = {0};
	DOMAINIP  *domainip_tmp  =  (DOMAINIP*)calloc(ansSum, sizeof(DOMAINIP)); 
	if(NULL == domainip_tmp)
	{
		return;
	}
	*ipcount = ansSum;

	while(queSum --)//output all quesion
	{
		while(1)
		{
			count = (uint8_t*)(pac+i);
			printf("count: %d\n",*count);
			if(*count == 0)
				break;
			//*count = ntohs(*count);
			for(i = i+1,j = 0; j < *count; i++,j++)
			{

				domain[a++] = *(pac+i);
				//	printf("%d\n",i);
				//fprintf(stdout,"%c",pac[i]);
			}
			//fprintf(stdout,".");
			domain[a++] = '.';
		}
		//fprintf(stdout,"\n");
		i = i + 5;
	}

    if (ntohs(dnsType->dnsHeader.queCount) == 1)
    {
        domain[a - 1] = '\0';
    }

	printf("domain: %s\n",domain);

	while(ansSum --)//output all answer
	{
		//fprintf(stdout, "\t");
		
		int I_temp = 0;

		//temp = (uint8_t*)(pac+i);
		i = i+2;
		dnsAnsType = (uint16_t*)(pac+i);
		*dnsAnsType = ntohs(*dnsAnsType);
		i = i+2;
		dnsAnsClass = (uint16_t*)(pac+i);
		*dnsAnsClass = ntohs(*dnsAnsClass);
		i = i+8;
		if(*dnsAnsType == 5)
		{
			//fprintf(stdout,"CNAME:");
			while(1)
			{
				count = (uint8_t*)(pac+i);
				
				if(*count == 0)
					break;

				if(*count == 0xc0)
				{
					//temp = (uint8_t *)(pac+i+1);
					//printANS(((*temp) - 13),pac);
					i = i+1;
					break;
				}
				for(i = i+1,j = 0; j < *count; i++,j++)
				{
			//		printf("%d\n",i);
					//fprintf(stdout,"%c",pac[i]);
				}
				if(I_temp != 0)
					i = I_temp;
				//fprintf(stdout,".");
			}
			i++;
			//fprintf(stdout,"\n");
		}
		else
		{
			memset(tmp,0,sizeof(tmp));
			for(i = i, j = 0; j < SIZE_IP; i++, j++)
			{
				tmp[j] = pac[i]; 
				//fprintf(stdout, "%d",pac[i]);
				if(j != SIZE_IP - 1)
					fprintf(stdout,".");
			}
			//fprintf(stdout,"\n");

		    snprintf(domainip_tmp[ansSum].ipstr, 32, "%d.%d.%d.%d", tmp[0],tmp[1], tmp[2], tmp[3]);
    		domainip_tmp[ansSum].flag = 1;
		}
	}
	//fprintf(stdout,"\n");

	*domainip = domainip_tmp;
}



int dns_check(const u_char * packet)
{
	int iRslt = 0;
	DNS *dnsType = NULL;
	dnsType = (DNS*)(packet);
	uint16_t Flags;
	char domain[256] = {0};
	DOMAINIP  *domainip = NULL;
	uint16_t ipcount = 0;
	int i = 0;
	
	Flags = ntohs(dnsType->dnsHeader.FLAGS);
	printf("FLAGS: %d, FLAG: %d\n", Flags, (Flags >> 15));
	if((Flags >> 15) == 1)
	{
		dnsAnswer(packet+sizeof(DNS),dnsType,domain, &domainip,&ipcount);

		if(0 != strlen(domain) &&  NULL != domainip && 0 != ipcount)
		{
			for(i = 0; i< ipcount; i++)
			{
				if(0 != domainip[i].flag && (0 != strlen(domainip[i].ipstr)))
				{
					printf("DNS report!!!!!!!!!!!!!!!\n");
				}
			}
			
		}
	}

	if(NULL != domainip)
	{
		free(domainip);
	}

	return  iRslt;
}
