//interfaz 3
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error en pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (Descripcion no disponible)\n");
	}
	
	if(i==0)
	{
		printf("\nNo se encontraron interfaces, asegurese que WinPcap esta instalado.\n");
		return -1;
	}
	
	printf("Ingresa el numero de interfaz (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nNumero de interfaz fuerda de rango.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nIncapaz de abrir el adaptador. %s no es compatible con WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nEscuchando en %s...\n\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 50, packet_handler, NULL);
	
	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
	if(tipo==2054)
	{
		int j=0,k=0;
		printf("MAC destino:\n");
		for(j=0;j<6;j++)
		{
		   printf("%02X:",pkt_data[j]);   
		}
  		printf("\n MAC origen:\n");
		for(k=6;k<12;k++)
		{
		   printf("%02X: ",pkt_data[k]);   
		}
		
		printf("\n");
	    printf("Tipo: %d   %02X %02X \n",tipo,pkt_data[12],pkt_data[13]);
	    
	    
	    
	    //Formato del protocolo ARP
	    if(pkt_data[15]==1)
		printf("Hardware type: %02X %02X\n",pkt_data[14],pkt_data[15]);
		else printf("Hardware type: %02X %02X\nLa condicional no funciona porque hay castearla");
		
		
		unsigned short tipo_dos = (pkt_data[16]*256)+pkt_data[17];
		if(tipo_dos==2048)
		printf("Protocol type: %d (Ethernet)   %02X %02X\n",tipo_dos,pkt_data[16],pkt_data[17]);
		
		printf("Hardware address length: %02X (Por direccion MAC)\n",pkt_data[18]);
		printf("Protocol addres length: %02X (Por direccion IP)\n",pkt_data[19]);
		
		if(pkt_data[21]==1)
		printf("Operation code: %02X %02X  ARP Request (Solicitud a ARP)\n",pkt_data[20],pkt_data[21]);
		else 
	 	if(pkt_data[21]==2)
	 	printf("Operation code: %02X %02X  ARP Reply (Respuesta a ARP)\n",pkt_data[20],pkt_data[21]);
	 	else	 
	  	if(pkt_data[21]==3)
	  	printf("Operation code: %02X %02X  RARP Request (Solicitud a ARP inverso)\n",pkt_data[20],pkt_data[21]);
		else
		if(pkt_data[21]==4)
	  	printf("Operation code: %02X %02X  RARP Reply (Respuesta a ARP inverso)\n",pkt_data[20],pkt_data[21]);
	  	else
	  	printf("Operation code: valor no identificado\n");
		
		printf("Sender hardware address: \n");
		for(j=22;j<28;j++)
		{
		   printf("%02X:",pkt_data[j]);   
		}
		printf("\nSender protocol address: \n");
		for(j=28;j<32;j++)
		{
		   printf("%02X:",pkt_data[j]);   
		}  	
		printf("\nTarget hardware address: \n");
		for(j=32;j<38;j++)
		{
		   printf("%02X:",pkt_data[j]);   
		}
		printf("\nTarget protocol address: \n");
		for(j=38;j<42;j++)
		{
		   printf("%02X:",pkt_data[j]);   
		}  	  			
		
		
		
		printf("\n\n\n");
	}
	else
	printf("La trama captada no es un formato del Procolo ARP\nTipo: %d  %02X %02X\n\n",tipo,pkt_data[12],pkt_data[13]);
	
	
}


