///interfaz 3
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old Depreciado and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <conio.h>

typedef struct datos{
	int ipv4;
		int icmp;
		int igmp;
	int ipv6;
	int arp;
	int llc;
	//int tcp;
	//int utp
}estadisticas;

estadisticas *stats;

char* filtro;
short estad_is_0;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(){
	int op=1;
	printf("Bienvenido(a) al interpretador de paquetes");

	while(1){
		system("cls");
		printf("Elija una opcion:\n\t1.Leer un archivo dada una direccion.\n\t2.Atrapar tramas con sniffer\n\t3.Creditos\n\t(Otro num).Salir\n");
		scanf("%d",&op);
		switch (op){
		case 1:
			system("cls");
			Archivo();
			break;
		case 2:
			system("cls");
			Sniffer();
			break;
		case 3:
			printf("Elaborado por:,,Gonzales Morelos Cesar Emiliano,Vazquez Hernandez Alan Mauricio y Lopez Gracia Angel Emmanuel");
			break;
		
		default:
			exit(0);
			break;
		}
	}

	return 0;
}

int Archivo(){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	char RUTA[100];
	printf("Escribe la direccion absoluta del archivo deseado: (Max 100 caracteres)\n");
	scanf("%s",&RUTA);

   /* if(argc != 2){

        printf("usage: %s filename", argv[0]);
        return -1;

    }*/

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creando la cadena fuente\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nNo se puede abrir el archivo: %s\n", source);
        return -1;
    }

    // read and dispatch packets until EOF is reached
	int cantidad;
	printf("\nEscribir cuantos paquetes se desean analizar:\n");
	scanf("%d",cantidad);
	printf("\nEscribir el numero del protocolo a filtrar [en decimal]\n(-1:sin filtro)\n");
	while (cantidad>0){
    	pcap_loop(fp, 1, packet_handler, NULL);
		
	}
	

    return 0;

}

int Sniffer(){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr,"Error en pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (Descripcion no disponible)\n");
	}
	
	if(i==0){
		printf("\nNo se encontraron interfaces, asegurese que WinPcap esta instalado.\n");
		return -1;
	}
	
	printf("Ingresa el numero de interfaz (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i){
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
							 )) == NULL){
		fprintf(stderr,"\nIncapaz de abrir el adaptador. %s no es compatible con WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nEscuchando en %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	int intaux;
	printf("1.Anadir filtro\n0.Sin filtro (estadisticas)\n");
	scanf("%d",&intaux);
	estad_is_0=intaux;
	if(intaux==1)
		;
		//codigo de 
	//pcap_compile()
	else{
		printf("\nEscribir cuantos paquetes se desean analizar:\n");
		scanf("%d",&intaux);
		system("cls");
		stats=(estadisticas*)(malloc(sizeof(estadisticas)));
		stats->ipv4=0;
		stats->icmp=0;
		stats->igmp=0;
		stats->ipv6=0;
		stats->arp=0;
		stats->llc=0;
		pcap_loop(adhandle, intaux, packet_handler, NULL);
		pcap_close(adhandle);
		puts("Presiona una tecla para continuar");
		getch() ;
	}


	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){

	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
	
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	printf("Trama completa:\n");
	int a;
	for(a=0;a!=header->len;a++){
		if(a%16==0)
			printf("\t");
		printf("%02X ",pkt_data[a]);
		if(a%16==15)
			printf("\n");
		if(a%16==7)
			printf("  ");

	}

	printf("\n\n");
	//Parametros no usados
	(VOID)(param);
	(VOID)(pkt_data);

	local_tv_sec = header->ts.tv_sec;

	//Analisis de encabezado Ethernet_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
		//Direccion MAC destino
			int j=0,k=0;
			printf("\n+MAC destino:\n");
			for(j=0;j<6;j++){
				printf("%02X",pkt_data[j]);
				if(j!=5)
					printf(":");   
			}
		
		//Direccion MAC origen
			printf("\n+MAC origen:\n");
			for(k=6;k<12;k++){
				printf("%02X",pkt_data[k]);
				if(k!=11)
					printf(":");  
			}
		//Tipo de protocolo
			printf("\n+Trama de tipo ");
			if (tipo>1500){
				switch (tipo){
					case 2048://08 00 IPv4
						printf("IPv4\n");
						registrar(tipo,0);
						IPv4(tipo,header,pkt_data);
						break;

					case 34525://86 DD IPv6
						printf("IPv6\n");
						registrar(tipo,0);
						IPv6(tipo,header,pkt_data);
						break;

					case 2054://08 06 ARP
						printf("ARP\n");
						registrar(tipo,0);
						ARP(tipo,header,pkt_data);
						break;
					
					default:
						printf("Protocolo no soportado: %02X %02X (%d)\n",pkt_data[12],pkt_data[13],tipo);
						break;
				}
			}
			else{
				//Trama IEEE 802.3
				switch (tipo,0){
					//LLC(tipo,header,pkt_data);
					default:
						printf("Protocolo no soportado o se trata de una trama de datos: %02X %02X (%d)\n",pkt_data[12],pkt_data[13],tipo);
						break;
				}
			}

	//checksum
	int aux=header->len;
	printf("Checksum: %ld",(pkt_data[aux-4]<<24)+(pkt_data[aux-3]<<16)+(pkt_data[aux-2]<<8)+(pkt_data[aux-1]));
	printf("\n_______________________________________________________________________\n\n");
	
}



//Catalogo de protocolos interpretables__________________________________________________________________________________________________________________________________
void ARP(unsigned short extra, const struct pcap_pkthdr *header,const u_char *pkt_data){
	printf("-Tipo de hardware:");
	
	switch ((pkt_data[14]<<8)+pkt_data[15]){
		case 0:
			printf("Reserved");
			break;
		case 1:
			printf("Ethernet (10Mb)");
			break;
		case 2:
			printf("Experimental Ethernet (3Mb)");
			break;
		case 3:
			printf("Amateur Radio AX.25");
			break;
		case 4:
			printf("Proteon ProNET Token Ring");
			break;
		case 5:
			printf("Chaos");
			break;
		case 6:
			printf("IEEE 802 Networks");
			break;
		case 7:
			printf("ARCNET");
			break;
		case 8:
			printf("Hyperchannel");
			break;
		case 9:
			printf("Lanstar");
			break;
		case 10:
			printf("Autonet Short Address");
			break;
		case 11:
			printf("LocalTalk");
			break;
		case 12:
			printf("LocalNet (IBM PCNet or SYTEK LocalNET)");
			break;
		case 13:
			printf("Ultra link");
			break;
		case 14:
			printf("SMDS");
			break;
		case 15:
			printf("Frame Relay");
			break;
		case 16:
			printf("Asynchronous Transmission Mode (ATM)");
			break;
		case 17:
			printf("HDLC");
			break;
		case 18:
			printf("Fibre Channel");
			break;
		case 19:
			printf("Asynchronous Transmission Mode (ATM)");
			break;
		case 20:
			printf("Serial Line");
			break;
		case 21:
			printf("Asynchronous Transmission Mode (ATM)");
			break;
		case 22:
			printf("MIL-STD-188-220");
			break;
		case 23:
			printf("Metricom");
			break;
		case 24:
			printf("IEEE 1394.1995");
			break;
		case 25:
			printf("MAPOS");
			break;
		case 26:
			printf("Twinaxial");
			break;
		case 27:
			printf("EUI-64");
			break;
		case 28:
			printf("HIPARP");
			break;
		case 29:
			printf("IP and ARP over ISO 7816-3");
			break;
		case 30:
			printf("ARPSec");
			break;
		case 31:
			printf("IPsec tunnel");
			break;
		case 32:
			printf("InfiniBand (TM)");
			break;
		case 33:
			printf("TIA-102 Project 25 Common Air Interface (CAI)");
			break;
		case 34:
			printf("Wiegand Interface");
			break;
		case 35:
			printf("Pure IP");
			break;
		case 36:
			printf("HW_EXP1");
			break;
		case 37:
			printf("HFI");
			break;
		case 256:
			printf("HW_EXP2");
			break;
		case 257:
			printf("AEthernet");
			break;
		case 65535:
			printf("Reserved");
			break;
		case 38:
		case 39:	
		case 40:	
		case 41:	
		case 42:	
		case 43:	
		case 44:	
		case 45:	
		case 46:	
		case 47:	
		case 48:	
		case 49:	
		case 50:	
		case 51:	
		case 52:	
		case 53:	
		case 54:	
		case 55:	
		case 56:	
		case 57:	
		case 58:	
		case 59:	
		case 60:	
		case 61:	
		case 62:	
		case 63:	
		case 64:	
		case 65:	
		case 66:	
		case 67:	
		case 68:	
		case 69:	
		case 70:	
		case 71:	
		case 72:	
		case 73:	
		case 74:	
		case 75:	
		case 76:	
		case 77:	
		case 78:	
		case 79:	
		case 80:	
		case 81:	
		case 82:	
		case 83:	
		case 84:	
		case 85:	
		case 86:	
		case 87:	
		case 88:	
		case 89:	
		case 90:	
		case 91:	
		case 92:	
		case 93:	
		case 94:	
		case 95:	
		case 96:	
		case 97:	
		case 98:	
		case 99:	
		case 100:	
		case 101:	
		case 102:	
		case 103:	
		case 104:	
		case 105:	
		case 106:	
		case 107:	
		case 108:	
		case 109:	
		case 110:	
		case 111:	
		case 112:	
		case 113:	
		case 114:	
		case 115:	
		case 116:	
		case 117:	
		case 118:	
		case 119:	
		case 120:	
		case 121:	
		case 122:	
		case 123:	
		case 124:	
		case 125:	
		case 126:	
		case 127:	
		case 128:	
		case 129:	
		case 130:	
		case 131:	
		case 132:	
		case 133:	
		case 134:	
		case 135:	
		case 136:	
		case 137:	
		case 138:	
		case 139:	
		case 140:	
		case 141:	
		case 142:	
		case 143:	
		case 144:	
		case 145:	
		case 146:	
		case 147:	
		case 148:	
		case 149:	
		case 150:	
		case 151:	
		case 152:	
		case 153:	
		case 154:	
		case 155:	
		case 156:	
		case 157:	
		case 158:	
		case 159:	
		case 160:	
		case 161:	
		case 162:	
		case 163:	
		case 164:	
		case 165:	
		case 166:	
		case 167:	
		case 168:	
		case 169:	
		case 170:	
		case 171:	
		case 172:	
		case 173:	
		case 174:	
		case 175:	
		case 176:	
		case 177:	
		case 178:	
		case 179:	
		case 180:	
		case 181:	
		case 182:	
		case 183:	
		case 184:	
		case 185:	
		case 186:	
		case 187:	
		case 188:	
		case 189:	
		case 190:	
		case 191:	
		case 192:	
		case 193:	
		case 194:	
		case 195:	
		case 196:	
		case 197:	
		case 198:	
		case 199:	
		case 200:	
		case 201:	
		case 202:	
		case 203:	
		case 204:	
		case 205:	
		case 206:	
		case 207:	
		case 208:	
		case 209:	
		case 210:	
		case 211:	
		case 212:	
		case 213:	
		case 214:	
		case 215:	
		case 216:	
		case 217:	
		case 218:	
		case 219:	
		case 220:	
		case 221:	
		case 222:	
		case 223:	
		case 224:	
		case 225:	
		case 226:	
		case 227:	
		case 228:	
		case 229:	
		case 230:	
		case 231:	
		case 232:	
		case 233:	
		case 234:	
		case 235:	
		case 236:	
		case 237:	
		case 238:	
		case 239:	
		case 240:	
		case 241:	
		case 242:	
		case 243:	
		case 244:	
		case 245:	
		case 246:	
		case 247:	
		case 248:	
		case 249:	
		case 250:	
		case 251:	
		case 252:	
		case 253:	
		case 254:	
		case 255:	
			printf("Sin asignar");
			break;

		default:
			printf("Unassigned");
			break;
	}
	
	printf("\n");
	unsigned short tipo_dos = (pkt_data[16]*256)+pkt_data[17];

	if(tipo_dos==2048)
		printf("-Tipo de protocolo: %d (Ethernet)   %02X %02X\n",tipo_dos,pkt_data[16],pkt_data[17]);
	
	printf("-Longitud de direccion de hardware: %02X (Por direccion MAC)\n",pkt_data[18]);
	printf("-Longitud de direccion segun el protocolo: %02X (Por direccion IP)\n",pkt_data[19]);
	
	printf("-Codigo de operacion: ");

	switch ((pkt_data[20]<<8)pkt_data[21]){
		case 0:	
			printf("Reserved");
			break;
		case 1:	
			printf("REQUEST");
			break;
		case 2:	
			printf("REPLY");
			break;
		case 3:	
			printf("request Reverse");
			break;
		case 4:	
			printf("reply Reverse");
			break;
		case 5:	
			printf("DRARP-Request");
			break;
		case 6:	
			printf("DRARP-Reply");
			break;
		case 7:	
			printf("DRARP-Error");
			break;
		case 8:	
			printf("InARP-Request");
			break;
		case 9:	
			printf("InARP-Reply");
			break;
		case 10:	
			printf("ARP-NAK");
			break;
		case 11:	
			printf("MARS-Request");
			break;
		case 12:	
			printf("MARS-Multi");
			break;
		case 13:	
			printf("MARS-MServ");
			break;
		case 14:	
			printf("MARS-Join");
			break;
		case 15:	
			printf("MARS-Leave");
			break;
		case 16:	
			printf("MARS-NAK");
			break;
		case 17:	
			printf("MARS-Unserv");
			break;
		case 18:	
			printf("MARS-SJoin");
			break;
		case 19:	
			printf("MARS-SLeave");
			break;
		case 20:	
			printf("MARS-Grouplist-Request");
			break;
		case 21:	
			printf("MARS-Grouplist-Reply");
			break;
		case 22:	
			printf("MARS-Redirect-Map");
			break;
		case 23:	
			printf("MAPOS-UNARP");
			break;
		case 24:	
			printf("OP_EXP1");
			break;
		case 25:	
			printf("OP_EXP2");
			break;
		case 65535:	
			printf("Reserved");
			break;
		default:	
			printf("Unassigned");
			break;
	}

	int j;
	printf("\n-Direccion del hardware emisor: ");
	for(j=22;j!=28;j++){
		printf("%02X",pkt_data[j]); 
		if(j!=27)printf(":");
	}
	//j=28
	printf("\n-Direccion del emisor segun el protocolo: ");
	for(j;j!=32;j++){
		printf("%02X",pkt_data[j]);  
		if(j!=31)printf(":");
	}
	//j=32
	printf("\n-Direccion del hardware receptor: ");
	for(j;j!=38;j++){
		printf("%02X",pkt_data[j]);   
		if(j!=37)printf(":");
	}
	//j=38
	printf("\n-Direccion del receptor segun el protocolo: ");
	for(j;j!=42;j++){
		printf("%02X",pkt_data[j]);   
		if(j!=41)printf(":");
	}
}

void IPv4(unsigned short extra, const struct pcap_pkthdr *header,const u_char *pkt_data){
	int i=14;//Existe un desface de 1 en el ínidice porque se inicia en 0 en lugar de 1 
	//i=14
	printf("\n-Version:%d\n",pkt_data[i]>>4);
	//i=14
	int IHL=pkt_data[i++]&15;
	printf("-Tamanno de cabecera(IHL):%d\n",IHL);
	//i=15
	printf("-Tipo de servicio(DSCP):");
	switch (pkt_data[i]>>2){
		case 0:
			printf("CS0");
			break;

		case 8:
			printf("CS1");
			break;

		case 16:
			printf("CS2");
			break;

		case 24:
			printf("CS3");
			break;

		case 32:
			printf("CS4");
			break;

		case 40:
			printf("CS5");
			break;

		case 48:
			printf("CS6");
			break;

		case 56:
			printf("CS7");
			break;

		case 10:
			printf("AF11");
			break;

		case 12:
			printf("AF12");
			break;

		case 14:
			printf("AF13");
			break;

		case 18:
			printf("AF21");
			break;

		case 20:
			printf("AF22");
			break;

		case 22:
			printf("AF23");
			break;

		case 26:
			printf("AF31");
			break;

		case 28:
			printf("AF32");
			break;

		case 30:
			printf("AF33");
			break;

		case 34:
			printf("AF41");
			break;

		case 36:
			printf("AF42");
			break;

		case 38:
			printf("AF43");
			break;

		case 46:
			printf("EF");
			break;

		case 44:
			printf("VOICE-ADMIT");
			break;

		default:
			printf("?");
			break;
	}
	//i=15
	printf("\n-ECN:");
	switch (pkt_data[i++]&3){
		case 0:
			printf("Not-ECT (Not ECN-Capable Transport)");
			break;
		case 1:
			printf("ECT(1) (ECN-Capable Transport(1))");
			break;
		case 2:
			printf("ECT(0) (ECN-Capable Transport(0))");
			break;
		case 3:
			printf("CE (Congestion Experienced)");
			break;
	}
	//i=16
	printf("\n-Longitud total:%d\n",pkt_data[i++]*256+pkt_data[i++]);
	//i=18
	printf("-Identificacion:%d\n",pkt_data[i++]*256+pkt_data[i++]);
	//i=20
	printf("-Banderas:\n\tbit_0:%d (debe ser 0)\n\tbit_1:%d %s\n\tbit_2:%d %s\n",
			pkt_data[i]>>7,
			(pkt_data[i]>>6)&1,
			((pkt_data[i]>>6)&1)? "No Divisible":"Divisible",
			(pkt_data[i]>>5)&1,
			((pkt_data[i]>>5)&1)? "Fragmento Intermedio":"Fragmento final");
	//i=20
	printf("-Posicion del fragmento: %d\n",(pkt_data[i++]&31)*256+pkt_data[i++]);
	//i=22
	printf("-Tiempo de vida: %d\n",pkt_data[i++]);
	//i=23
	int protocolo=pkt_data[i++];
	printf("-Protocolo:");
	switch (protocolo){
		case 0:
			printf("IPv6 Hop-by-Hop Option");
			break;
		case 1:
			printf("Internet Control Message Protocol");
			break;
		case 2:
			printf("Internet Group Management Protocol");
			break;
		case 3:
			printf("Gateway-to-Gateway Protocol");
			break;
		case 4:
			printf("IP en IP (encapsulación)");
			break;
		case 5:
			printf("Internet Stream Protocol");
			break;
		case 6:
			printf("Transmission Control Protocol");
			break;
		case 7:
			printf("Core-based trees");
			break;
		case 8:
			printf("Exterior Gateway Protocol");
			break;
		case 9:
			printf("Interior Gateway Protocol (cualquier gateway privado interior (usado por Cisco para su IGRP))");
			break;
		case 10:
			printf("Monitoreo BBN RCC");
			break;
		case 11:
			printf("Network Voice Protocol");
			break;
		case 12:
			printf("Xerox PUP");
			break;
		case 13:
			printf("ARGUS");
			break;
		case 14:
			printf("EMCON");
			break;
		case 15:
			printf("Cross Net Debugger");
			break;
		case 16:
			printf("Chaos");
			break;
		case 17:
			printf("User Datagram Protocol");
			break;
		case 18:
			printf("Multiplexing");
			break;
		case 19:
			printf("DCN Measurement Subsystems");
			break;
		case 20:
			printf("Host Monitoring Protocol");
			break;
		case 21:
			printf("Packet Radio Measurement");
			break;
		case 22:
			printf("XEROX NS IDP");
			break;
		case 23:
			printf("Trunk-1");
			break;
		case 24:
			printf("Trunk-2");
			break;
		case 25:
			printf("Leaf-1");
			break;
		case 26:
			printf("Leaf-2");
			break;
		case 27:
			printf("Reliable Datagram Protocol");
			break;
		case 28:
			printf("Internet Reliable Transaction Protocol");
			break;
		case 29:
			printf("ISO Transport Protocol Class 4");
			break;
		case 30:
			printf("Bulk Data Transfer Protocol");
			break;
		case 31:
			printf("MFE Network Services Protocol");
			break;
		case 32:
			printf("MERIT Internodal Protocol");
			break;
		case 33:
			printf("Datagram Congestion Control Protocol");
			break;
		case 34:
			printf("Third Party Connect Protocol");
			break;
		case 35:
			printf("Inter-Domain Policy Routing Protocol");
			break;
		case 36:
			printf("Xpress Transport Protocol");
			break;
		case 37:
			printf("Datagram Delivery Protocol");
			break;
		case 38:
			printf("IDPR Control Message Transport Protocol");
			break;
		case 39:
			printf("TP++ Transport Protocol");
			break;
		case 40:
			printf("IL Protocolo de Transporte");
			break;
		case 41:
			printf("IPv6");
			break;
		case 42:
			printf("Source Demand Routing Protocol");
			break;
		case 43:
			printf("Cabecera de Ruteo para IPv6");
			break;
		case 44:
			printf("Cabecera de Fragmento para IPv6");
			break;
		case 45:
			printf("Inter-Domain Routing Protocol");
			break;
		case 46:
			printf("Resource Reservation Protocol");
			break;
		case 47:
			printf("Generic Routing Encapsulation");
			break;
		case 48:
			printf("Mobile Host Routing Protocol");
			break;
		case 49:
			printf("BNA");
			break;
		case 50:
			printf("Encapsulating Security Payload");
			break;
		case 51:
			printf("Authentication Header");
			break;
		case 52:
			printf("Integrated Net Layer Security Protocol");
			break;
		case 53:
			printf("IP con cifrado");
			break;
		case 54:
			printf("NBMA Address Resolution Protocol");
			break;
		case 55:
			printf("IP Móvil (Min Encap)");
			break;
		case 56:
			printf("Transport Layer Security Protocol (usa felipendo manejo de llaves Kryptonet)");
			break;
		case 57:
			printf("Simple Key-Management for Internet Protocol");
			break;
		case 58:
			printf("ICMP para IPv6");
			break;
		case 59:
			printf("No Next Header para IPv6");
			break;
		case 60:
			printf("Opciones de Destino para IPv6");
			break;
		case 61:
			printf("Protocolo interno cualquier host");
			break;
		case 62:
			printf("CFTP");
			break;
		case 63:
			printf("Cualquier red local");
			break;
		case 64:
			printf("SATNET y Backroom EXPAK");
			break;
		case 65:
			printf("Kryptolan");
			break;
		case 66:
			printf("MIT Remote Virtual Disk Protocol");
			break;
		case 67:
			printf("Internet Pluribus Packet Core");
			break;
		case 68:
			printf("Cualquier sistema distribuido de archivos");
			break;
		case 69:
			printf("Monitoreo SATNET");
			break;
		case 70:
			printf("Protocolo VISA");
			break;
		case 71:
			printf("Internet Packet Core Utility");
			break;
		case 72:
			printf("Computer Protocol Network Executive");
			break;
		case 73:
			printf("Computer Protocol Heart Beat");
			break;
		case 74:
			printf("Wang Span Network");
			break;
		case 75:
			printf("Packet Video Protocol");
			break;
		case 76:
			printf("Backroom SATNET Monitoring");
			break;
		case 77:
			printf("SUN ND PROTOCOL-Temporary");
			break;
		case 78:
			printf("WIDEBAND Monitoring");
			break;
		case 79:
			printf("WIDEBAND EXPAK");
			break;
		case 80:
			printf("International Organization for Standardization Internet Protocol");
			break;
		case 81:
			printf("Versatile Message Transaction Protocol");
			break;
		case 82:
			printf("Secure Versatile Message Transaction Protocol");
			break;
		case 83:
			printf("VINES");
			break;
		case 84:
			printf("TTP");
			break;
		case 85:
			printf("NSFNET-IGP");
			break;
		case 86:
			printf("Dissimilar Gateway Protocol");
			break;
		case 87:
			printf("TCF");
			break;
		case 88:
			printf("EIGRP");
			break;
		case 89:
			printf("Open Shortest Path First");
			break;
		case 90:
			printf("Sprite RPC Protocol");
			break;
		case 91:
			printf("Locus Address Resolution Protocol");
			break;
		case 92:
			printf("Multicast Transport Protocol");
			break;
		case 93:
			printf("AX.25");
			break;
		case 94:
			printf("Protocolo de Encapsulación IP-en-IP");
			break;
		case 95:
			printf("Mobile Internetworking Control Protocol");
			break;
		case 96:
			printf("Semaphore Communications Sec. Pro");
			break;
		case 97:
			printf("Ethernet-within-IP Encapsulation");
			break;
		case 98:
			printf("Cabecera de Encapsulación");
			break;
		case 99:
			printf("Cualquier esquema privado de cifrado");
			break;
		case 100:
			printf("GMTP");
			break;
		case 101:
			printf("Ipsilon Flow Management Protocol");
			break;
		case 102:
			printf("PNNI sobre IP");
			break;
		case 103:
			printf("Protocol Independent Multicast");
			break;
		case 104:
			printf("ARIS");
			break;
		case 105:
			printf("SCPS (Space Communications Protocol Standards)");
			break;
		case 106:
			printf("QNX");
			break;
		case 107:
			printf("Active Networks");
			break;
		case 108:
			printf("IP Payload Compression Protocol");
			break;
		case 109:
			printf("Sitara Networks Protocol");
			break;
		case 110:
			printf("Compaq Peer Protocol");
			break;
		case 111:
			printf("IPX in IP");
			break;
		case 112:
			printf("Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (no asignado por IANA)");
			break;
		case 113:
			printf("PGM Reliable Transport Protocol");
			break;
		case 114:
			printf("Cualquier protocolo de 0-saltos");
			break;
		case 115:
			printf("Layer Two Tunneling Protocol");
			break;
		case 116:
			printf("D-II Data Exchange (DDX)");
			break;
		case 117:
			printf("Interactive Agent Transfer Protocol");
			break;
		case 118:
			printf("Schedule Transfer Protocol");
			break;
		case 119:
			printf("SpectraLink Radio Protocol");
			break;
		case 120:
			printf("UTI");
			break;
		case 121:
			printf("Simple Message Protocol");
			break;
		case 122:
			printf("SM");
			break;
		case 123:
			printf("Performance Transparency Protocol");
			break;
		case 124:
			printf("IS-IS sobre IPv4");
			break;
		case 125:
			printf("FIRE");
			break;
		case 126:
			printf("Combat Radio Transport Protocol");
			break;
		case 127:
			printf("Combat Radio User Datagram");
			break;
		case 128:
			printf("SSCOPMCE");
			break;
		case 129:
			printf("IPLT");
			break;
		case 130:
			printf("Secure Packet Shield");
			break;
		case 131:
			printf("Private IP Encapsulation within IP (Encapsulación Privada IP en IP)");
			break;
		case 132:
			printf("Stream Control Transmission Protocol");
			break;
		case 133:
			printf("Fibre Channel");
			break;
		case 134:
			printf("RSVP-E2E-IGNORE");
			break;
		case 135:
			printf("Cabecera de Movilidad");
			break;
		case 136:
			printf("UDP Lite");
			break;
		case 137:
			printf("MPLS-en-IP");
			break;
		case 138:
			printf("Protocolos MANET");
			break;
		case 139:
			printf("Host Identity Protocol");
			break;
		case 140:
			printf("Site Multihoming by IPv6 Intermediation");
			break;
		case 141:
		case 142:
		case 143:
		case 144:
		case 145:
		case 146:
		case 147:
		case 148:
		case 149:
		case 150:
		case 151:
		case 152:
		case 153:
		case 154:
		case 155:
		case 156:
		case 157:
		case 158:
		case 159:
		case 160:
		case 161:
		case 162:
		case 163:
		case 164:
		case 165:
		case 166:
		case 167:
		case 168:
		case 169:
		case 170:
		case 171:
		case 172:
		case 173:
		case 174:
		case 175:
		case 176:
		case 177:
		case 178:
		case 179:
		case 180:
		case 181:
		case 182:
		case 183:
		case 184:
		case 185:
		case 186:
		case 187:
		case 188:
		case 189:
		case 190:
		case 191:
		case 192:
		case 193:
		case 194:
		case 195:
		case 196:
		case 197:
		case 198:
		case 199:
		case 200:
		case 201:
		case 202:
		case 203:
		case 204:
		case 205:
		case 206:
		case 207:
		case 208:
		case 209:
		case 210:
		case 211:
		case 212:
		case 213:
		case 214:
		case 215:
		case 216:
		case 217:
		case 218:
		case 219:
		case 220:
		case 221:
		case 222:
		case 223:
		case 224:
		case 225:
		case 226:
		case 227:
		case 228:
		case 229:
		case 230:
		case 231:
		case 232:
		case 233:
		case 234:
		case 235:
		case 236:
		case 237:
		case 238:
		case 239:
		case 240:
		case 241:
		case 242:
		case 243:
		case 244:
		case 245:
		case 246:
		case 247:
		case 248:
		case 249:
		case 250:
		case 251:
		case 252:
			printf("Sin asignar");
			break;
		case 253:
		case 254:
			printf("Experimentacion y pruebas");
			break;
		case 255:
			printf("Reservado");
			break;
		default:
			printf("?");
			break;

	}
	//i=24
	printf("\n-CheckSum (decimal): %d\n",pkt_data[i++]*256+pkt_data[i++]);
	//i=26
	printf("-Direccion IP de origen:\n");
	int j;
	for(j=0;j!=4;j++){
	   printf("%02X",pkt_data[i++]);
	   if(j!=3)
	   	printf(":");
	}
	//i=30
	printf("\n-Direccion IP de destino:\n");
	for(j=0;j!=4;j++){
	   printf("%02X",pkt_data[i++]);
	   if(j!=3)
	   	printf(":");
	}
	//i=34
	printf("\n-Opciones:\n");
	for(i;i!=14+IHL*4;i++){
		printf("%02X ",pkt_data[i]);
		if(i%4==3)
			printf("\n");
	}
	
	printf("-Seccion del protocolo:_-_-_-_-_-_-_-_-_-_-_-\n");
	switch (protocolo){
		case 1:
			registrar(protocolo,1);
			ICMP(i, header,pkt_data);
			break;
		case 2:
			registrar(protocolo,1);
			IGMP(i, header,pkt_data);
			break;
		
		default:
			printf("+Protocolo no soportado");
			break;
	}
}

	void ICMP(unsigned short extra, const struct pcap_pkthdr *header,const u_char *pkt_data){
		int i=extra;
		printf("+Tipo:");
		switch (pkt_data[i++]){
			case 0:	
				printf("Respuesta de eco\n");
				printf("\tSin Codigo (0)");
				break;

			case 3:	
				printf("Destino inalcanzable\n");
				switch(pkt_data[i]){
					case 0:	
						printf("\tRed inalcanzable"); 
						break;
					case 1:	
						printf("\tHost inalcanzable"); 
						break;
					case 2:	
						printf("\tProtocolo inalcanzable"); 
						break;
					case 3:	
						printf("\tPuerto inalcanzable"); 
						break;
					case 4:	
						printf("\tSe necesita fragmentación y no Fragmento fue establecido"); 
						break;
					case 5:	
						printf("\tRuta de origen fallida"); 
						break;
					case 6:	
						printf("\tRed de destino desconocida"); 
						break;
					case 7:	
						printf("\tHost de destino desconocido"); 
						break;
					case 8:	
						printf("\tHost de origen aislado"); 
						break;
					case 9:	
						printf("\tComunicación con el destino La red está prohibida administrativamente"); 
						break;
					case 10:	
						printf("\tLa comunicación con el host de destino es Prohibido administrativamente"); 
						break;
					case 11:	
						printf("\tRed de destino inaccesible para el tipo de servicio"); 
						break;
					case 12:	
						printf("\tHost de destino inalcanzable para el tipo de Servicio"); 
						break;
					case 13:	
						printf("\tComunicación prohibida administrativamente"); 
						break;
					case 14:	
						printf("\tViolación de la precedencia del host"); 
						break;
					case 15:	
						printf("\tCorte de precedencia en efecto"); 
						break;
					default:
						printf("\tSin asignar");
						break;
				}
				break;

			case 4:	
				printf("Enfriamiento de fuente (obsoleto)\n");
				printf("\tSin Codigo (0)");
				break;
			case 5:	
				printf("Redirigir\n");
				switch (pkt_data[i]){
					case 0:	
						printf("\tRedirigir datagrama para la red (o subred)");
						break;
					case 1:	
						printf("\tRedirigir datagrama para el host");
						break;
					case 2:	
						printf("\tRedirigir datagrama para el tipo de servicio y red");
						break;
					case 3:	
						printf("\tRedirigir datagrama para el tipo de servicio y host");
						break;
					default:
						printf("\tSin asignar");
						break;
				}
				break;
			case 6:	
				printf("Dirección de host alternativa (obsoleta)\n");
				printf("\tDireccion alternativa para el anfitrion (0)");
				break;
			case 8:	
				printf("Eco\n");
				printf("\tSin Codigo (0)");
				break;
			case 9:	
				printf("Anuncio de enrutador\n");
				switch (pkt_data[i]){
					case 0: 	
						printf("\tAnuncio de enrutador normal"); 
						break;
					case 16: 	
						printf("\tNo enruta el tráfico común "); 
						break;
					default:
						printf("\tSin asignar");
						break;
				}
				break;
			case 10:	
				printf("Solicitud de enrutador\n");
				printf("\tSin Codigo (0)");
				break;
			case 11:	
				printf("Tiempo excedido\n");
				switch (pkt_data[i]){
					case 0: 	
						printf("\tTiempo de vida excedido en tránsito ");
						break;
					case 1: 	
						printf("\tSe excedió el tiempo de reensamblado del fragmento");
						break;
					default:
						printf("\tSin asignar");
						break;
				}
				break;
			case 12:	
				printf("Problema de parámetro\n");
				switch (pkt_data[i]){
					case 0:
						printf("\tEl puntero indica el error");
						break;
					case 1:
						printf("\tFalta una opción requerida");
						break;
					case 2:
						printf("\tMala longitud ");
						break;
					default:
						printf("\tSin asignar");
						break;
				}
				break;
			case 13:	
				printf("Marca de tiempo");
				printf("\n\tSin Codigo (0)");
				break;
			case 14:	
				printf("Respuesta de marca de tiempo");
				printf("\n\tSin Codigo (0)");
				break;
			case 15:	
				printf("Solicitud de información (obsoleta)");
				printf("\n\tSin Codigo (0)");
				break;
			case 16:	
				printf("Respuesta de información (obsoleta)");
				printf("\n\tSin Codigo (0)");
				break;
			case 17:	
				printf("Solicitud de máscara de dirección (obsoleta)");
				printf("\n\tSin Codigo (0)");
				break;
			case 18:	
				printf("Respuesta de máscara de dirección (obsoleta)");
				printf("\n\tSin Codigo (0)");
				break;
			case 19:	
				printf("Reservado (por seguridad)");
				printf("\n\tReservado");
				break;
			case 20:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 21:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 22:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 23:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 24:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 25:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 26:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 27:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 28:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 29:	
				printf("Reservado (para el experimento de robustez)");
				printf("\n\tReservado");
				break;
			case 30:	
				printf("Traceroute (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 31:	
				printf("Error de conversión de datagrama (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 32:	
				printf("Redirección de host móvil (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 33:	
				printf("IPv6 Where-Are-You (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 34:	
				printf("IPv6 Estoy aquí (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 35:	
				printf("Solicitud de registro móvil (obsoleta)");
				printf("\n\tSin registro");
				break;
			case 36:	
				printf("Respuesta de registro móvil (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 37:	
				printf("Solicitud de nombre de dominio (obsoleta)");
				printf("\n\tSin registro");
				break;
			case 38:	
				printf("Respuesta de nombre de dominio (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 39:	
				printf("SKIP (obsoleto)");
				printf("\n\tSin registro");
				break;
			case 40:	
				printf("Photuris");
				switch (pkt_data[i]){
					case 0: 	
						printf("\n\tSPI incorrecto");
						break;
					case 1: 	
						printf("\n\tAutenticación fallida");
						break;
					case 2: 	
						printf("\n\tFalló la descompresión");
						break;
					case 3: 	
						printf("\n\tFalló el descifrado");
						break;
					case 4: 	
						printf("\n\tNecesita autenticación");
						break;
					case 5: 	
						printf("\n\tNecesita autorización");
						break;
					default:
						printf("\n\tSin asignar");
						break;
				}
				break;
			case 41:	
				printf("Mensajes ICMP utilizados por protocolos de movilidad experimentales como Seamoby");
				printf("\n\tSin registro");
				break;
			case 42:	
				printf("Solicitud de eco extendida");
				if(pkt_data[i]==0)
					printf("\n\tNo error");
				else
					printf("\n\tSin asignar");
				break;
			case 43:	
				printf("Respuesta de eco extendida");
				switch (pkt_data[i]){
					case 0:
						printf("\n\tNo Error");
						break;
					case 1:
						printf("\n\tConsulta con formato incorrecto");
						break;
					case 2:
						printf("\n\tNo hay tal interfaz");
						break;
					case 3:
						printf("\n\tNo hay tal entrada de tabla");
						break;
					case 4:
						printf("\n\tMúltiples interfaces satisfacen la consulta");
						break;
					default:
						printf("\n\tSin asignar");
						break;
				}
				break;
			case 253:	
				printf("Experimento 1 al estilo RFC3692");
				printf("\n\tSin registro");
				break;
			case 254:	
				printf("Experimento 2 al estilo RFC3692");
				printf("\n\tSin registro");
				break;
			case 255:	
				printf("Reservado");
				printf("\n\tSin registro");
				break;
			default:
				printf("Sin asignar");
				break;
		}
		i++;
		printf("\n+Checksum (decimal):%d\n",pkt_data[i++]*256+pkt_data[i++]);
		printf("+Opciones:\n");
		while (i<header->len-4){
			printf("%02X ",pkt_data[i]);
			if(i++%4==3)
				printf("\n");
		}
	}

	void IGMP(unsigned short extra, const struct pcap_pkthdr *header,const u_char *pkt_data){
		printf("IGMP");
	}

void IPv6(unsigned short extra, const struct pcap_pkthdr *header,const u_char *pkt_data){
	printf("Es de tipo IPv6... Nada mas... jejeje...\n");
}

void LLC(unsigned short extra, const struct pcap_pkthdr *header,const u_char *pkt_data){
	int i=14;
	int tl=pkt_data[i++]+pkt_data[i++];
	
    printf("-DSAP:");intbin(pkt_data[i],8);
    	
	printf("\n\tDireccion destino:");intbin(pkt_data[i]>>1,7);
	int a=pkt_data[i++]&1;
	printf("\n\t\tI/G:%s(%d)",a? "Grupo":"Individual",a);
	
	printf("\n\tSSAP:");intbin(pkt_data[i],8);
	printf("\n\t\tDireccion:");intbin(pkt_data[i]>>7,8);
	a=pkt_data[i++]&1;
	printf("\n\t\tC/R:%s(%d)\n\t",a? "Respuesta":"Comando",a);   
	
	if(tl>3){//tomar 2 bytes de campo de control
		a=pkt_data[i]&1;
		switch(a){
			case 0://I
				printf("Trama I->");
				a=(pkt_data[i++]>>1);
				printf("\n\t\tNumero de secuencia de la trama enviada:");
				intbin(a,8);
				a=(pkt_data[i]>>1);
				printf("\n\t\tNumero de secuencia de la proxima trama esperada:");
				intbin(a,8);
				printf("\n\t\tP/F:");
				intbin(pkt_data[i]&1,8);
				break;
				
			case 1:
				switch((pkt_data[i]&2)>>1){
					case 0://S
						printf("Trama S->");
						a=(pkt_data[i++]>>2)&3;
						printf("\n\t\tCodigo:");
						intbin(a,8);
						a=(pkt_data[i]>>1);
						printf("\n\t\tNumero de secuencia de la proxima trama esperada:");
						intbin(a,8);
						printf("\n\t\tP/F:");
						intbin(pkt_data[i]&1,8);
						break;
				
					case 1://U
						printf("Trama U->");	
						a=pkt_data[i]>>2;
						a=((a&1)<<4)+((a&2)<<2)+((a&8)>>1)+((a&16)>>3)+((a&32)>>5);
						switch (a){
							case 1://SNRM
								printf("SNRM");
								break;
							case 27://SNRME
								printf("SNRME");
								break;
							case 28://SABM
								printf("SABM");
								break;
							case 30://SABME
								printf("SABME");
								break;
							case 0://UI
								printf("UI");
								break;
							case 6://-
								printf("-");
								break;
							case 2://DISC
								printf("DISC");
								break;
							case 16://SIM
								printf("SIM");
								break;
							case 4://UP
								printf("UP");
								break;
							case 25://RSET
								printf("RSET");
								break;
							case 29://XID
								printf("XID");
								break;
							case 17://FRMR
								printf("FRMR");
								break;
							default://?
								printf("?");
								break;
						}
						printf(":");
						intbin(a,8);

						break;
						
				}
				break;
		}

		i++;

		printf("\nInformacion:\n");
		for (i; (i < header->caplen-4 ) ; i++){
			printf("%.2x ", pkt_data[i]);
			if ( (i % 16) == 0) printf("\n");
		}
		
		printf("\nCRC:\n");
		for (i; (i < header->caplen ) ; i++){
			printf("%.2x ", pkt_data[i]);
			if ( (i % 16) == 0) printf("\n");
		}
	
	}

	else{//tomar 1 byte de vínculo lógico de control
		a=pkt_data[i]&1;
		switch(a){
			case 0://I
				printf("Trama I->");
				a=(pkt_data[i]>>1)&7;
				printf("\n\t\tNumero de secuencia de la trama enviada:");
				intbin(a,8);
				printf("\n\t\tNumero de secuencia de la proxima trama esperada:");
				a=(pkt_data[i]>>5)&7;
				intbin(a,8);
				break;
				
			case 1:
				switch((pkt_data[i]&2)>>1){
					case 0://S
						printf("Trama S->");
						a=(pkt_data[i]>>2)&3;
						printf("\n\t\tCodigo:");
						intbin(a,8);
						a=(pkt_data[i]>>5)&7;
						printf("\n\t\tNumero de secuencia de la proxima trama esperada:");
						intbin(a,8);
						break;
				
					case 1://U
						printf("Trama U->");	
						a=pkt_data[i]>>2;
						a=((a&1)<<4)+((a&2)<<2)+((a&8)>>1)+((a&16)>>3)+((a&32)>>5);
						switch (a){
							case 1://SNRM
								printf("SNRM");
								break;
							case 27://SNRME
								printf("SNRME");
								break;
							case 28://SABM
								printf("SABM");
								break;
							case 30://SABME
								printf("SABME");
								break;
							case 0://UI
								printf("UI");
								break;
							case 6://-
								printf("-");
								break;
							case 2://DISC
								printf("DISC");
								break;
							case 16://SIM
								printf("SIM");
								break;
							case 4://UP
								printf("UP");
								break;
							case 25://RSET
								printf("RSET");
								break;
							case 29://XID
								printf("XID");
								break;
							case 17://FRMR
								printf("FRMR");
								break;
							default://?
								printf("?");
								break;
						}
						printf(":");
						intbin(a,8);

						break;
						
				}
				break;
		}
		printf("\n\t\tP/F:%d",(a&4)>>2);
		i++;

		printf("\nInformacion:\n");
		for (i; (i < header->caplen-4 ) ; i++){
			printf("%.2x ", pkt_data[i]);
			if ( (i % 16) == 0) printf("\n");
		}
		
		printf("\nCRC:\n");
		for (i; (i < header->caplen ) ; i++){
			printf("%.2x ", pkt_data[i]);
			if ( (i % 16) == 0) printf("\n");
		}
	}
	
}

//Funciones de ayuda__________________________________________________________________________________________________________________________________
void intbin(int n,int max){
		int i,m=n;
	if(n!=0){
		int aux=1;
		i=0;
		while(n){ aux++; n>>=1;}	
		int arr[aux];
		n=m;
		while (n) {
			arr[aux-1-i++]=n & 1;
			n >>= 1;
		}
        for(i=0;i!=max-aux+1;i++)
            printf("0");
		for(i=1;i!=aux;i++)
			printf("%d",arr[i]);
	}
	else
		for(i=0;i!=max;i++) 
			printf("0");
	printf(" (%d)",m);
}

void registrar(int protocolo, int capa){
	if(estad_is_0) return;
	if (capa==0){
		switch (protocolo){
		case 1:
			stats->icmp++;
			break;
		case 2:
			stats->igmp++;
			break;
		
		default:
			break;
		}
	}
	else{
		switch (protocolo){
			case 2048://08 00 IPv4
				stats->ipv4++;
				break;

			case 34525://86 DD IPv6
				stats->ipv6++;
				break;
			case 2054://08 06 ARP
				stats->arp++;
				break;
		}
	}
}

