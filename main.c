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

	//Parametros no usados
	(VOID)(param);
	(VOID)(pkt_data);

	local_tv_sec = header->ts.tv_sec;

	//Analisis de encabezado Ethernet_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
		//Encabezado de Ethernet en crudo
		    printf("-Encabezado Ethernet completo:\n");
			int i;
			for(i=0;i!=14;i++){
				if(i%4==0)
					printf("\t");
				printf("%02X ",pkt_data[i]);
				if(i%4==3)
					printf("\n");
			}
		//Direccion MAC destino
			int j=0,k=0;
			printf("\n-MAC destino:\n");
			for(j=0;j<6;j++){
				printf("%02X",pkt_data[j]);
				if(j!=5)
					printf(":");   
			}
		
		//Direccion MAC origen
			printf("\n-MAC origen:\n");
			for(k=6;k<12;k++){
				printf("%02X",pkt_data[k]);
				if(k!=11)
					printf(":");  
			}
		//Tipo de protocolo
			unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
			printf("\n-Trama de tipo ");
			switch (tipo){
				case 2048://08 00 IPv4
					printf("IPv4\n");
					IPv4(tipo,header,pkt_data);
					break;

				case 2054://08 06 ARP
					printf("ARP\n");
					ARP(tipo,header,pkt_data);
					break;

				case 34525://86 DD IPv6
					printf("IPv6\n");
					IPv6(tipo,header,pkt_data);
					break;
				
				default:
					printf("Protocolo no soportado: %02X %02X (%d)",pkt_data[12],pkt_data[13],tipo);
					break;
			}
	printf("\n_______________________________________________________________________\n");
}



void IPv6(unsigned short tipo, const struct pcap_pkthdr *header,const u_char *pkt_data){
	printf("Es de tipo IPv6... Nada mas... jejeje...\n");
}


void ARP(unsigned short tipo, const struct pcap_pkthdr *header,const u_char *pkt_data){
    
	printf("-Tipo de hardware: %02X %02X\n",pkt_data[14],pkt_data[15]);
	
	unsigned short tipo_dos = (pkt_data[16]*256)+pkt_data[17];
	if(tipo_dos==2048)
		printf("-Tipo de protocolo: %d (Ethernet)   %02X %02X\n",tipo_dos,pkt_data[16],pkt_data[17]);
	
	printf("-Longitud de direccion de hardware: %02X (Por direccion MAC)\n",pkt_data[18]);
	printf("-Longitud de direccion segun el protocolo: %02X (Por direccion IP)\n",pkt_data[19]);
	
	printf("-Codigo de operacion: ");
	switch(pkt_data[21]){
		case 1:
			printf("%02X %02X  ARP Request (Solicitud a ARP)",pkt_data[20],pkt_data[21]);
			break;
		case 2:
			printf("%02X %02X  ARP Reply (Respuesta a ARP)",pkt_data[20],pkt_data[21]);
			break; 
		case 3:
			printf("%02X %02X  RARP Request (Solicitud a ARP inverso)",pkt_data[20],pkt_data[21]);
			break;
		case 4:
			printf("%02X %02X  RARP Reply (Respuesta a ARP inverso)",pkt_data[20],pkt_data[21]);
			break;
		default:
			printf("valor no identificado");
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


void IPv4(unsigned short tipo, const struct pcap_pkthdr *header,const u_char *pkt_data){
	int i=14;
	//i=14
	printf("\n-Version:%d\n",pkt_data[i]>>4);
	//i=14
	printf("-Tamanno de cabecera(IHL):%d\n",pkt_data[i++]&15);
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
	printf("-Protocolo:");
	switch (pkt_data[i++]){
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
	//i=58
	printf("\n-Direccion IP de destino:\n");
	for(j=0;j!=4;j++){
	   printf("%02X",pkt_data[i++]);
	   if(j!=3)
	   	printf(":");
	}
	//i=90
	printf("\n-Opciones:\n");
	for(i;i<header->len;i++){
		printf("%02X ",pkt_data[i]);
		if(i%4==3)
			printf("\n");
	}
}
