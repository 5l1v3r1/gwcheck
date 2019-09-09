/*	
	gwcheck.c
	written by poplix in a dark winter night of december 2007
  
	gwcheck is a simple program that checks if a host in an ethernet network is
	a gateway to internet.
	The check is done by sending a tcp syn to an internet host with the mac 
	address of the host to check. It can take a single ip address or a file 
	containing a list of addresses (one per line) that can be easly generated
	with nmap arp-ping scan.
	It may be considered a gateway scanner...
  
  
  
  	compile with: gcc -O2 gwcheck.c -o gwcheck -lpcap
	it runs on linux and BSD family and works with IPv4 and ethernet only 
  
  
	the same old story...
		This program is free software; you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation; either version 2 of the License, or
		(at your option) any later version. . . . 
		
	
	have fun
	
	-p
	http://px.dynalias.org
*/

#define VER "0.1"


#define _BSD_SOURCE 1
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>


#include <sys/ioctl.h>
#include <sys/param.h>//param.h defines BSD in bsd systems 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <netdb.h>

#ifdef BSD
#include <net/if_dl.h>
 #include <net/bpf.h>
#endif


#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <ifaddrs.h>

#include <pcap.h>

#ifdef BSD
#include <net/if_types.h>
#endif


#define __FAVOR_BSD 1
#include <netinet/ip.h>
#include <netinet/tcp.h>



#ifdef __linux__
#include <net/if_arp.h>
#include <linux/if_packet.h>
#endif






#ifndef DLT_EN10MB
#define DLT_EN10MB	1
#endif

#ifndef DLT_LOOP
#define DLT_LOOP	10
#endif

#ifndef DLT_PPP
#define DLT_PPP		9
#endif
      
#define ETHADDR_SIZE 6
#define ETHHDR_SIZE 14
#define ETHTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHARP_PKT_SIZE 42 


#define ERR_INIT  1
#define ERR_PARSE 2
#define ERR_LINK  3
#define ERR_WRITE 4
#define ERR_RT	  5


#define SMALLOC(x,y){x=(y*)malloc(sizeof(y));\
	if( x == NULL){fprintf(stderr,"ERROR: malloc out of memory\n");exit(ERR_RT);}\
}

#define SCALLOC(x,y,z){ x=(y*)calloc(z,sizeof(y));\
	if(x==NULL){fprintf(stderr,"ERROR: calloc out of memory\n");exit(ERR_RT);}\
}


#define SSTRNCPY(dst,src,len){strncpy(dst,src,len-1); dst[len-1]=0;}
#define SSTRNCAT(dst,src,len)strncat(dst,src, len - strlen(dst) - 1);


#define CKSUM_CARRY(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))






struct intf{
	char name[12];
	u_int index;
	int fd;
	u_int mtu;
	u_int type;
	
	u_int32_t ipaddr;
	u_int32_t netmask;
	
	u_char  l2addr[6];
	u_int	l2addr_size;
	u_int	l2hdr_size;

	pcap_t *pcap_hnd;
	
};




struct arphdr_eth {
    u_short	ar_hrd;			/* Format of hardware address.  */
    u_short	ar_pro;			/* Format of protocol address.  */
    u_char	ar_hln;			/* Length of hardware address.  */
    u_char	ar_pln;			/* Length of protocol address.  */
    u_short	ar_op;			/* ARP opcode (command).  */
    u_char	ar_sha[6];		/* Sender hardware address.  */
    u_char	ar_spa[4];		/* Sender IP address.  */
    u_char	ar_tha[6];		/* Target hardware address.  */
    u_char	ar_tpa[4];		/* Target IP address.  */
}__attribute__((packed));




struct ipnmac{
	u_int32_t ip;
	u_char 	  mac[ETHADDR_SIZE];
};





int in_cksum (u_short*,  int );
void compute_ip_cksum (struct ip*);
void compute_l4_cksum (u_char *);
#ifndef HAVE_PCAP_SETBLOCK
int setnonblock(int);
#endif
u_int ip_to_int (char *,int *);
int str_to_macaddr (char *, u_char *);
char *int_to_ip (u_int32_t);
char *macaddr_to_str (u_char *);
char *getfirstifname ();
int getifinfo (char *, struct intf *);
int write_link (struct intf *, u_char *, u_int);
int open_link (char *);
u_int32_t DNSresolve (char *);
int build_ether_hdr (u_char *, u_char *, u_short, u_char *);
int build_arp_hdr (u_char *, u_int32_t, u_char *, u_int32_t, u_short, u_char *);
int arp_request (u_int32_t, u_int32_t, u_char *);
void usage (char *);
void send_tcp_syn (u_int32_t, u_char *, u_short);
void tcp_callback (u_char *, const struct pcap_pkthdr *, const u_char *);
void arp_callback (u_char *, const struct pcap_pkthdr *, const u_char *);
int is_gateway (u_int32_t, u_short);




/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */





#define GWARR_SIZE 1024


struct intf out_intf;
u_int32_t internethost;
int arp_timeout, 
	tcp_timeout, 
	tothosts=0, 
	totonline=0, 
	totgw=0, 
	verbose=1;


#define DEF_INTERNET_HOST	"www.google.com"
#define DEF_TCP_PORT		80
#define DEF_ARP_TIMEOUT		10 // 1 second
#define DEF_TCP_TIMEOUT		20 // 2 seconds







//from libnet1.0
int in_cksum(u_short *addr, int len){
   int sum=0;
   int nleft=len;
   u_short ans=0;
   u_short *w=addr;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	
	if (nleft == 1) {
		*(u_char *)(&ans) = *(u_char *)w;
		sum += ans;
	}
	
	return (sum);
}





void compute_ip_cksum(struct ip* ip){

  int sum;
  	
  	ip->ip_sum=0;
  	sum=in_cksum( (u_short*) ip,  20 );
    ip->ip_sum= (u_short) CKSUM_CARRY(sum);
}





void compute_l4_cksum(u_char *buff){
   int cksum;
   int len;
   struct tcphdr *tcp=(struct tcphdr*)(buff+sizeof(struct ip));
   struct ip *ip=(struct ip*)buff;
	
      
	len=20;
	tcp->th_sum=0;
	cksum=in_cksum((u_short*) &(ip->ip_src.s_addr),8);
	cksum+=htons(IPPROTO_TCP+len);
	cksum+=in_cksum((u_short*) tcp, len);
	tcp->th_sum=CKSUM_CARRY(cksum);

}





#ifndef HAVE_PCAP_SETBLOCK
int setnonblock(int fd){
  int flags;
	
	if( (flags=fcntl(fd,F_GETFL,0)) < 0){
		fprintf(stderr,"fcntl error: %s\n",strerror(errno));
		exit(ERR_LINK);
	}
	flags |= O_NONBLOCK;
	if( fcntl(fd,F_SETFL,flags) <0){
		fprintf(stderr,"fcntl error: %s\n",strerror(errno));
		exit(ERR_LINK);
	}
	
	return 1;
}
#endif





u_int ip_to_int(char *ip,int *err){ 

	int a,
		c=0,
		pos=0,
		tmpint;
		
	char t[4],*inv;
	u_char  addr[4];
	
	for(a=0; pos<4; a++){	
		if(ip[a]=='.' || ip[a]==0){
		  	t[c]=0;
		  	tmpint=strtol(t, &inv, 10);
    		if(*inv != 0 || (tmpint<0 || tmpint>255) )goto bad;
    		addr[pos]=(u_char)tmpint;
			pos++;
			c=0;
		}else {
			if ( c > (sizeof(t)-1) ) goto bad;
			t[c]=ip[a];
			c++;
		}
	}
	
	if(pos!=4)goto bad;
	if(err!=NULL)*err=0;
	return *(u_int*)addr;
	
bad:
	if(err!=NULL)*err=1;
	return 0;
}





int str_to_macaddr(char *str, u_char *dst){
  char *inv,*s;
  int a;
  u_int tmp;
	
	if(str == NULL || strlen(str) < 11) return 0;
	s=str;
	for( a=0; a < ETHADDR_SIZE; a++){
  		tmp=strtoul(s,&inv,16);
  		if( (*inv != ':' && *inv!=0) || tmp < 0x00 || tmp > 0xff ) 
  			return 0;
  		
  		dst[a]=tmp;
  		s=++inv;
	}
	
	
	return 1;

}





char *int_to_ip(u_int32_t ip){
	u_char *tmp=(u_char *)&ip;
	static char ret[16];
	memset(ret,0,sizeof(ret));
	sprintf(ret,"%u.%u.%u.%u",tmp[0] & 0xff,tmp[1] & 0xff,tmp[2] & 0xff,tmp[3] & 0xff);
	return ret;
	
}





char *macaddr_to_str(u_char *mac){
	static char ret[18];
	memset(ret,0,sizeof(ret));
	sprintf(ret,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return ret;
	
}





#ifdef BSD

char *getfirstifname(){
  struct ifaddrs *ifap, *ifa;
  static char name[12];

	if(getifaddrs(&ifap) < 0) return NULL;
	if(!ifap) return NULL; 
	
	memset(name,0,sizeof(name));
	
	for(ifa = ifap; ifa; ifa = ifa->ifa_next){
	 	if(	ifa->ifa_addr->sa_family == AF_LINK && 
	 		((struct if_data*)ifa->ifa_data)->ifi_type == IFT_ETHER &&
	 		(ifa->ifa_flags & IFF_UP) ){
				SSTRNCPY(name,ifa->ifa_name,sizeof(name))
		 		return name;
		 }
	 }	

	return NULL;
	

 }





int getifinfo(char *name,struct intf *iface){
   struct ifaddrs *ifap, *ifa;
   int find=0;
	
   int mib[]={CTL_NET,AF_ROUTE,0,AF_LINK,NET_RT_IFLIST,0};
   size_t len;
   u_char *buff, *next, *end;
   struct if_msghdr *ifm;
   struct sockaddr_dl *sdl;



	// get the list 
	if(getifaddrs(&ifap) < 0) return 0;
	
	if(!ifap) return 0; 
	//nota che ogni inf compare due volte in lista, una volta come AF_LINK e una AF_INET
	for(ifa = ifap; ifa; ifa = ifa->ifa_next)
	 if((ifa->ifa_flags & IFF_UP)  && !strcmp(name,ifa->ifa_name)){
	 	//copy only the first time
	 	if(find==0){
	 		memset(iface->name,0,sizeof(iface->name));
	 		SSTRNCPY(iface->name,name,sizeof(iface->name))
	 	}
	 	find=1;
		if(ifa->ifa_addr->sa_family == AF_LINK){
			iface->mtu=((struct if_data*)ifa->ifa_data)->ifi_mtu;
			
			switch(((struct if_data*)ifa->ifa_data)->ifi_type){
				case IFT_ETHER:
					iface->type=DLT_EN10MB;
					iface->l2hdr_size=ETHHDR_SIZE;
					break;
				case IFT_GIF:
				case IFT_LOOP:
					iface->type=DLT_LOOP;
					iface->l2hdr_size=0;
					break;
				case IFT_PPP:
					iface->type = DLT_PPP;
				default:
					freeifaddrs(ifap);
					return 0;
			}
			
		}
		if(ifa->ifa_addr->sa_family == AF_INET){
			iface->ipaddr  = (u_int32_t) ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
			iface->netmask = (u_int32_t) ((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr;
		}
	  }
		
	freeifaddrs(ifap);
	
	//get hardware address
	if (sysctl(mib, ETHADDR_SIZE, NULL, &len, NULL, 0) == -1){
		fprintf(stderr,"error getting hardware address\n");
		exit(ERR_LINK);
	}

    SCALLOC(buff,u_char,len)
    if (sysctl(mib, ETHADDR_SIZE, buff, &len, NULL, 0) < 0){
        free(buff);
        fprintf(stderr,"error getting hardware address\n");
        exit(ERR_LINK);
    }
    end = buff + len;

    for (next = buff ; next < end ; next += ifm->ifm_msglen){
        ifm = (struct if_msghdr *)next;
        if (ifm->ifm_type == RTM_IFINFO){
            sdl = (struct sockaddr_dl *)(ifm + 1);
            if (strncmp(&sdl->sdl_data[0], iface->name, sdl->sdl_nlen) == 0){
                memcpy(iface->l2addr,LLADDR(sdl),ETHADDR_SIZE);
                break;
            }
        }
    }
    free(buff);

	iface->index=0; // dont care
	
	return find;
	

 }





int write_link(struct intf *iface,u_char *frame, u_int size){
    int c;
	
    if (iface->fd < 0){
    	fprintf(stderr,"unknown bpf error\n");
    	exit(ERR_LINK);
    }
    c = write(iface->fd, frame, size);
    
    if (c != size){
    	fprintf(stderr,"error writing to bpf,, written:%d bytes\n",c);
    	exit(ERR_WRITE);
    }

    return (c);
}





int open_link(char* ifname){
   int i, fd;
   char devname[12];
   struct ifreq ifr;
    
    for (i=0; i<100; i++){
        sprintf(devname, "/dev/bpf%u", i);
        fd = open(devname, O_RDWR);
        if (fd == -1 && errno == EBUSY)
            continue;
        else
        	break;
    }

    if (fd == -1){
        fprintf(stderr,"unable to open bpf\n");
        exit(ERR_LINK);
    }

    
	SSTRNCPY(ifr.ifr_name, ifname, sizeof(ifr.ifr_name))
    
    if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) == -1){
       fprintf(stderr,"error attaching interface to bpf\n");
       exit(ERR_LINK);
    }
    
    
    return (fd);
}

 
#endif
//end of BSD code





#ifdef __linux__


char * getfirstifname(){
   int fd;
   struct ifconf   ifc;
   struct ifreq    ibuf[16], ifr, *ifrp, *ifend;
   static char name[12];	
	
	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) return NULL;
	
	memset(ibuf, 0, sizeof(struct ifreq)*16);
	ifc.ifc_len = sizeof(ibuf);
	ifc.ifc_buf = (caddr_t) ibuf;
	
	/* gets interfaces list */
	if ( ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
		 ifc.ifc_len < sizeof(struct ifreq)         ) 
		 	goto bad;

	/* ifrp points to buffer and ifend points to buffer's end */
	ifrp = ibuf;
	ifend = (struct ifreq*) ((char*)ibuf + ifc.ifc_len);
	
	for (; ifrp < ifend; ifrp++) {

		SSTRNCPY(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name))
		if(ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1)goto bad;
		if ( !(ifr.ifr_flags & IFF_UP) )continue;
	
		if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1)goto bad;
		if (ifr.ifr_ifru.ifru_addr.sa_family == AF_INET) {
			//get link-type
			if(ioctl(fd, SIOCGIFHWADDR, (char*)&ifr) == -1)goto bad;
			if(ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
				SSTRNCPY(name,ifrp->ifr_name,sizeof(name))
				close(fd);
				return name;
			}
		}
			
	}
	
bad:
   close(fd);
   return NULL;
  }





 //fetifinfo sets:ifname, mtu, link-type,layer4 address,layer4 netmask, 
int getifinfo(char *name,struct intf *iface){
   int fd,find=0;
   struct ifconf   ifc;
   struct ifreq    ibuf[16], ifr, *ifrp, *ifend;
	
	
	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) return 0;
	
	*(iface->name) = 0;
	
	memset(ibuf, 0, sizeof(struct ifreq)*16);
	ifc.ifc_len = sizeof(ibuf);
	ifc.ifc_buf = (caddr_t) ibuf;
	
	/* gets interfaces list */
	if ( ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
		 ifc.ifc_len < sizeof(struct ifreq)         ) 
		 	goto bad;
	
	/* ifrp points to buffer and ifend points to buffer's end */
	ifrp = ibuf;
	ifend = (struct ifreq*) ((char*)ibuf + ifc.ifc_len);
	
	for (; ifrp < ifend; ifrp++) {
		if(strcmp(ifrp->ifr_name,name))continue;
		find=1;
		SSTRNCPY(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name))
		
		//get if flags
		if(ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1)
			goto bad;
			
		//if is down
		if ( !(ifr.ifr_flags & IFF_UP) )goto bad;
	
		SSTRNCPY(iface->name, ifr.ifr_name, sizeof(iface->name))
		
		//get l3 addr
		if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1)goto bad;
			
		if (ifr.ifr_ifru.ifru_addr.sa_family != AF_INET) goto bad;
		//save addr
		iface->ipaddr=((struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr)->sin_addr.s_addr;
		
		//get netmask
		if(ioctl(fd, SIOCGIFNETMASK, (char*)&ifr) == -1)goto bad;
		iface->netmask=((struct sockaddr_in *)&ifr.ifr_ifru.ifru_netmask)->sin_addr.s_addr;
		
		//get index
		if (ioctl(fd, SIOCGIFINDEX, (char*)&ifr) == -1)goto bad;
		iface->index=ifr.ifr_ifindex;
		
		//get link-type
		if(ioctl(fd, SIOCGIFHWADDR, (char*)&ifr) == -1)goto bad;
		switch (ifr.ifr_hwaddr.sa_family) {
			//__linux__ encaps loop in eth frames
			case ARPHRD_LOOPBACK:
			case ARPHRD_ETHER:
			case ARPHRD_METRICOM:
				iface->type = DLT_EN10MB;
				iface->l2hdr_size=ETHHDR_SIZE;
				if(ifr.ifr_hwaddr.sa_family != ARPHRD_LOOPBACK)
					memcpy(iface->l2addr,ifr.ifr_hwaddr.sa_data,ETHADDR_SIZE);
				break;
			case ARPHRD_PPP:
			default: 
				goto bad;
		}

		//get MTU
		if(ioctl(fd, SIOCGIFMTU, &ifr) == -1)goto bad;
		iface->mtu=ifr.ifr_mtu;               
	}
	
	close(fd);
	//intf name not found
	if(*(iface->name) == 0) return 0;
	return 1;
	
   bad:
   close(fd);
   fprintf(stderr,"error getting interface infos\n");
   exit(ERR_LINK);
  }





int write_link(struct intf *iface,u_char *frame, u_int size){
   int c;
   struct sockaddr_ll sa;
    
	memset(&sa, 0, sizeof (sa));
	
	sa.sll_family    = AF_PACKET;
	sa.sll_ifindex   = iface->index;
	sa.sll_protocol  = htons(ETH_P_ALL);
	
	c = sendto(iface->fd, frame, size, 0, (struct sockaddr *)&sa, sizeof (sa));
	
	if (c != size){
		fprintf(stderr,"error writing to bpf,, written:%d bytes\n",c);
		exit(ERR_WRITE);
	}
	return (c);
}





int open_link(char *ifname){
    struct ifreq ifr;
    int n = 1,fd;


    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd == -1){
    	fprintf(stderr,"error opening link %s\n",ifname);
    	exit(ERR_LINK);
    }

    memset(&ifr, 0, sizeof (ifr));
    
    SSTRNCPY(ifr.ifr_name,ifname,sizeof (ifr.ifr_name))
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ){
		fprintf(stderr,"error setting SIOCGIFHWADDR\n");
		exit(ERR_LINK);
	}


#ifdef SO_BROADCAST
/*
 * man 7 socket
 *
 * Set or get the broadcast flag. When  enabled,  datagram  sockets
 * receive packets sent to a broadcast address and they are allowed
 * to send packets to a broadcast  address.   This  option  has  no
 * effect on stream-oriented sockets.
 */
 	n=1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1){
    	fprintf(stderr,"error set sock opt: SO_BROADCAST\n");
    	exit(ERR_LINK);
    }
    
#endif  /*  SO_BROADCAST  */

    return fd;


}
  
#endif  //linux





u_int32_t DNSresolve (char *host) {
   struct in_addr in;
   struct hostent *he;
    
	if ((he = gethostbyname(host)) == NULL){
		fprintf(stderr,"unable to resolve %s\n",host);
		exit(ERR_INIT);
	}

	memcpy( (caddr_t) &in, he->h_addr, he->h_length);
    
	return(in.s_addr);
}





int build_ether_hdr(u_char *dst, u_char* src,u_short type,u_char* dstbuff){
  memcpy(dstbuff,dst,ETHADDR_SIZE);
  memcpy(dstbuff+ETHADDR_SIZE,src,ETHADDR_SIZE);
  
  *( (u_short*)(dstbuff+12) ) = htons(type);
  
  return 1;
	
}





int build_arp_hdr(u_char *hdst,u_int32_t pdst,u_char* hsrc,u_int32_t psrc,u_short arpop,u_char* dstbuff){
  struct arphdr* hdr= (struct arphdr*)dstbuff;
  u_int off;
  
	hdr->ar_hrd=htons(ARPHRD_ETHER);
  	hdr->ar_pro=htons(ETHTYPE_IP);
  	hdr->ar_hln=ETHADDR_SIZE;
  	hdr->ar_pln=4;
  	hdr->ar_op=htons(arpop);
  	
  	off=8;
  	
  	memcpy(dstbuff + off,hsrc,ETHADDR_SIZE);
	off+=ETHADDR_SIZE;
	
	memcpy(dstbuff + off,(u_char*)&psrc,4);
	off+=4,
	
  	memcpy(dstbuff + off,hdst,ETHADDR_SIZE);
  	off+=ETHADDR_SIZE;
  	
	memcpy(dstbuff + off,(u_char*)&pdst,4);
  	
  	return 1;
}





int arp_request(u_int32_t ripaddr,u_int32_t ipsrc,u_char *macsrc){
  u_char arpbuff[ETHARP_PKT_SIZE]; 

	if(macsrc==NULL)macsrc=out_intf.l2addr;
	if(ipsrc==0)ipsrc=out_intf.ipaddr;
	build_ether_hdr((u_char*)"\xff\xff\xff\xff\xff\xff",macsrc,ETHERTYPE_ARP,arpbuff);
	
	build_arp_hdr((u_char*)"\x0\x0\x0\x0\x0\x0",
					ripaddr,
					macsrc,
					ipsrc,
					ARPOP_REQUEST,
					arpbuff + ETHHDR_SIZE
					);
					
	write_link(&out_intf,arpbuff,sizeof(arpbuff));

	return 1;
}





void usage(char *pname){
 	printf(	"gwcheck v"VER" by poplix\x40papuasia.org"
  			"\ncheck if a given host is a gateway to internet\n\n"

			"usage:  %s [Options] <ip_addr OR filename>\n\n"
			"   <ip_addr> is the host to check.\n"
			"     If ip_addr is not in the standard IPv4 address format it will be\n"
			"     treated as the name of a file containing a hosts list (one per line)\n\n"
			" Options:\n"			
			"   -i    <interface> the network interface (def:the first available)\n"
			"   -I    <internet_host> address of an internet host (def:"DEF_INTERNET_HOST")\n"
			"   -p    <tcp_port> an unfiltered port on internet_host (def:%u)\n"
			"   -t    <arp_timeout> timeout for arp replies (def:%u = %0.1f secs)\n"
			"   -T    <tcp_timeout> timeout for tcp replies (def:%u = %0.1f secs)\n"
			"   -q    be quiet, show gateways only\n"
			
			"\n"
			" with nmap -sP -PR -oG nmap_file 10.0.0.* && \\\n"
			"       grep Host nmap_file | awk '{print $2}' > filename\n"
			" you can get a file with all arp-responding hosts on 10.0.0.0/24\n"
			"\n"
			,pname,DEF_TCP_PORT,DEF_ARP_TIMEOUT,((float)DEF_ARP_TIMEOUT/10),DEF_TCP_TIMEOUT,((float)DEF_TCP_TIMEOUT/10));
	exit(0);

}





void send_tcp_syn(u_int32_t dstip,u_char *dstmac, u_short port){
  u_char buff[20+20+14];
  struct ip *ip;
  struct tcphdr *tcp;
  	
  	srand(time(NULL));
  
  	ip=(struct ip*)(buff+ETHHDR_SIZE);
  	tcp=(struct tcphdr*)(buff + 20 + ETHHDR_SIZE);
  	
	ip->ip_v = 4;
	ip->ip_hl= 20 >> 2;
	ip->ip_tos = 0;
	ip->ip_len = htons(40);
	ip->ip_id = htons(4096 + (rand()*4) % 60000);
	ip->ip_off=0;
	ip->ip_ttl = 255;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src.s_addr=out_intf.ipaddr;
	ip->ip_dst.s_addr=dstip;
	
	tcp->th_sport=htons(2048 + (rand()*4) % 60000);
	tcp->th_dport=htons(port);
	tcp->th_seq=htonl(4096 + (rand()*4));  
	tcp->th_ack=0;  
	tcp->th_off=20 >> 2;
	tcp->th_flags=TH_SYN;	
	tcp->th_win=htons(65535);
	tcp->th_sum=0;
	tcp->th_urp=0;

	
  	build_ether_hdr(dstmac, out_intf.l2addr, ETHERTYPE_IP, buff);
  	
  	compute_ip_cksum(ip);
	compute_l4_cksum((u_char*)ip);
	
	write_link(&out_intf,buff,sizeof(buff));
}





void tcp_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
  struct ipnmac *ret = (struct ipnmac*)param;
  	ret->ip= ( (struct ip*)(pkt_data+ETHHDR_SIZE) )->ip_src.s_addr;
  	memcpy(ret->mac, pkt_data+6, 6);

}





void arp_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
  struct arphdr_eth *af;

	af=(struct arphdr_eth*)(pkt_data + ETHHDR_SIZE); 
	
	if(ntohs(af->ar_op) == ARPOP_REPLY)
		memcpy(param,af,sizeof(struct arphdr_eth));
	else 
		memset(param,0,sizeof(struct arphdr_eth));
	
}





int is_gateway(u_int32_t dstip,u_short port){
  struct ipnmac im;
  int cnt=0;
  u_char dstmac[ETHADDR_SIZE];
  struct arphdr_eth arpf;
  
	arp_request(dstip,out_intf.ipaddr,out_intf.l2addr);
		
	memset(dstmac,0,ETHADDR_SIZE);
	for(cnt=0;cnt < arp_timeout; cnt++){
		pcap_dispatch(out_intf.pcap_hnd,1,arp_callback,(u_char*)&arpf);
		if( *((u_int32_t*)arpf.ar_spa) == dstip){
			memcpy(dstmac, arpf.ar_sha, ETHADDR_SIZE);
			break;
		}
		usleep(100000);
	}
	if(!memcmp(dstmac,"\x00\x00\x00\x00\x00\x00",ETHADDR_SIZE)){
		if(verbose)printf("host %s is down\n",int_to_ip(dstip));
		return 0;
	}
	
	totonline++;	
	if(verbose){
		printf("checking %s (%s) ",int_to_ip(dstip),macaddr_to_str(dstmac));
		fflush(stdout);
	}
	
	send_tcp_syn(internethost, dstmac, port);
	for(cnt=0;cnt < tcp_timeout; cnt++){
		pcap_dispatch(out_intf.pcap_hnd,1,tcp_callback,(u_char*)&im);
		if(verbose && cnt%10 == 0){
			printf(". ");
			fflush(stdout);
		}
		if(im.ip == internethost && !memcmp(im.mac,dstmac,6) ){
			if(verbose)printf("Ok, it's a gateway\n");
			totgw++;
			return 1;
		}
		usleep(100000);
	}
	if(verbose)printf("\n");
	return 0;
}










int main(int argc, char **argv){

  int err,opt;
  u_int32_t dstip;
  u_short tcpport;
  bpf_u_int32 mask, net;
  struct bpf_program filter;
  char 	ifname[12],
  		filter_str[512],
  		ipstr[32],
  		p_errbuf[PCAP_ERRBUF_SIZE], 
  		*inv; 
  FILE *f;
  extern char *optarg;
  extern int optopt,optind;
  char internethost_name[128];
  u_int32_t gateways[GWARR_SIZE];
  	
  	if( getuid() != 0){
		fprintf(stderr,"ERROR: you MUST be root.. \n");
		exit(ERR_INIT);
	}
  	
	internethost=0;
	tcpport=DEF_TCP_PORT;
	arp_timeout=DEF_ARP_TIMEOUT;
	tcp_timeout=DEF_TCP_TIMEOUT;
	memset(internethost_name,0,sizeof(internethost_name));
	memset(ifname,0,sizeof(ifname));
	
     while ((opt = getopt(argc, argv, "t:T:i:I:p:q")) != -1) {
       switch(opt) {
         case 't':
         	arp_timeout=strtoul(optarg,&inv,10);
         	if(*inv != 0){	
         		fprintf(stderr,"error parsing arp timeout:%s\n",optarg);
         		exit(ERR_PARSE);
         	}
         	break;
         case 'T':
         	tcp_timeout=strtoul(optarg,&inv,10);
         	if(*inv != 0){	
         		fprintf(stderr,"error parsing tcp timeout :%s\n",optarg);
         		exit(ERR_PARSE);
         	}
         	break;
         case 'i':
         	SSTRNCPY(ifname,optarg,sizeof(ifname))
         	break;
         case 'I':
         	internethost=ip_to_int(optarg,&err);
			if(err)
				internethost=DNSresolve(optarg);
			SSTRNCPY(internethost_name,optarg,sizeof(internethost_name))
         	break;
         case 'p':
         	tcpport=strtoul(optarg,&inv,10);
         	if(*inv != 0){	
         		fprintf(stderr,"error parsing tcp port:%s\n",optarg);
         		exit(ERR_PARSE);
         	}
         	break;
         case 'q':
         	verbose=0;
         	break;
         case ':':
            fprintf(stderr,"error: argument for -%c is mandatory\n", optopt);
            exit(ERR_INIT);
         case '?':
            fprintf(stderr,"error: unknown option -%c\n", optopt);
            exit(ERR_INIT);
	  }
	}
  	
  	
	if( (argc-optind) < 1 )usage(argv[0]);
 	printf(	"gwcheck v"VER"%s", verbose?"\n":" started\n");

	if(*internethost_name == 0)
		SSTRNCPY(internethost_name, DEF_INTERNET_HOST, sizeof(internethost_name))
	
	if(*ifname == 0){
	  char *t = getfirstifname();
	  	if(t==NULL){
	  		fprintf(stderr,"unable to find as active interface\n");
	  		exit(ERR_LINK);
	  	}
		SSTRNCPY(ifname,t,sizeof(ifname))
	}
	
	if(!getifinfo(ifname,&out_intf)){
		fprintf(stderr,"error opening interface %s\n",ifname);
		exit(ERR_LINK);
	}
	
	
	pcap_lookupnet(out_intf.name, &net, &mask, p_errbuf);
	out_intf.pcap_hnd=pcap_open_live(out_intf.name, 128, 0, 0, p_errbuf);
	if(out_intf.pcap_hnd==NULL){
		fprintf(stderr,"pcap Error: %s\n",p_errbuf);
		exit(ERR_LINK);
	}
  	
#ifdef BSD
{
  int bsdimmediate=1;
	ioctl(pcap_fileno(out_intf.pcap_hnd), BIOCIMMEDIATE, &bsdimmediate);	
}
#endif
    

	sprintf(filter_str,"(arp or tcp) and not src host %s",int_to_ip(out_intf.ipaddr));	
	pcap_compile(out_intf.pcap_hnd, &filter, filter_str, 0,mask);
	pcap_setfilter(out_intf.pcap_hnd, &filter);

	
	out_intf.fd=open_link(out_intf.name);
	
	
	
#ifdef HAVE_PCAP_SETNONBLOCK
	pcap_setnonblock(out_intf.pcap_hnd,1,p_errbuf);
#else
	setnonblock(pcap_fileno(out_intf.pcap_hnd));
#endif
	


	if(internethost == 0)
		internethost=DNSresolve(DEF_INTERNET_HOST);
	
	
	if(verbose)printf(	"intf: %s, internet host: %s:%u, arp TO: %u, tcp TO: %u\n\n",
				ifname,internethost_name,tcpport,arp_timeout,tcp_timeout);	


	dstip=ip_to_int(argv[optind],&err);
	if(!err){
		tothosts++;
		if(is_gateway(dstip,tcpport)){
			if(!verbose)printf("%s is a gateway\n",int_to_ip(dstip));
			gateways[totgw-1] = dstip;
		}
		verbose = 0;
		goto end;
	}
	
	f=fopen(argv[optind],"r");
	if( f == NULL){
		fprintf(stderr,"unable to open file %s\n",argv[optind]);
		exit(ERR_INIT);
	}
	while(fgets(ipstr,sizeof(ipstr),f) != NULL){
	  char *lf;
	  
		lf=strchr(ipstr,'\r'); if(lf!=NULL)*lf=0;
		lf=strchr(ipstr,'\n'); if(lf!=NULL)*lf=0;
		
		if(strlen(ipstr) < 7)continue;
		
 		dstip=ip_to_int(ipstr,&err);
		if(err){
			if(verbose)printf("invalid ip address format: %s\n",ipstr);
			continue;
		}

		if( dstip == out_intf.ipaddr){
			if(verbose)printf("skipping myself (%s) . .\n",int_to_ip(dstip));
			continue;
		}
		
		tothosts++;
		if(is_gateway(dstip,tcpport)){
			if(!verbose)printf("%s is a gateway\n",int_to_ip(dstip));
			else {
				if(totgw > GWARR_SIZE){
					fprintf(stderr,"too many gateways (more than %u),\nuse -q option or modify GWARR_SIZE in the source and recompile\n",GWARR_SIZE);
					exit(ERR_RT);
				}
				gateways[totgw-1] = dstip;				
			}
		}
		
	}
	fclose(f);

end:
	close(out_intf.fd);
	
	if(verbose){
		if( totgw > 0 ){
		  int a;
  			printf("\ndiscovered gateway(s):");
			for(a=0; a<totgw; a++)
				printf(" %s",int_to_ip(gateways[a]));
		} else
			printf("\nsorry, no gateways have been found");
	} 
	

	
	printf("\n%u host(s) checked, %u online, %u gateway(s)\n",tothosts,totonline,totgw);

	exit(0);
}
