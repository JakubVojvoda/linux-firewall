/*
 * Simple netfilter firewall for Linux
 * by Jakub Vojvoda [vojvoda@swdeveloper.sk]
 * 
 * file: pdsfw.c
 * - implementation of kernel modul (version 3.13) using netfilter
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple netfilter firewall");
MODULE_AUTHOR("Jakub Vojvoda");

#define PROCF_SIZE 1024
#define PROCF_NAME "xvojvo00_pdsprocfile"

#define IPV4_MAX_SIZE 3
#define IPV4 4

#define ACTION_ALLOW 1
#define ACTION_DENY  2

#define PROTOCOL_TCP  1
#define PROTOCOL_UDP  2
#define PROTOCOL_ICMP 3
#define PROTOCOL_IP   4

#define PORT_ANY UINT_MAX

struct frule {
  
  unsigned int number;
  
  unsigned char action;
  unsigned char protocol;
  
  unsigned char srcip[IPV4];
  unsigned char dstip[IPV4];
  
  unsigned int srcport;
  unsigned int dstport;
  
  struct list_head list;
};

static struct frule firewall_policy;

static ssize_t procf_read(struct file *filp, char __user *buf, size_t count, loff_t *offp);
static ssize_t procf_write(struct file *filp, const char __user *buf, size_t count, loff_t *offp);

unsigned int io_hook_filter(const struct nf_hook_ops *ops, struct sk_buff *skb, 
                     const struct net_device *in, const struct net_device *out, 
                     int (*okfn)(struct sk_buff *));

static int add_rule(char *rule);
static void add_rule_to_list(struct frule *new);
static void delete_rule(char *rule);

static int check_packet(struct frule *packet, struct frule *rule);
static unsigned int decode_ip_part(char *str, int *index);
static int get_int_length(int number);

// proc subor a buffer
static struct proc_dir_entry *proc_file;
static char *proc_buffer;

// i/o hook
static struct nf_hook_ops nf_hook_in;
static struct nf_hook_ops nf_hook_out;

//////////////////////////////////////////////////////////////////////////////////////////////

/* init_module
 * 
 * - inicializacia modulu jadra
 */
int init_module()
{
  // definicia majitela a volanych funkcii 
  static const struct file_operations procf_ops = {

    .owner = THIS_MODULE,
    .read  = procf_read,
    .write = procf_write,
  }; 
  
  // vytvorenie proc suboru
  proc_file = proc_create(PROCF_NAME, 0666, NULL, &procf_ops);
  
  // vytvorenie pomocneho bufferu k zapisu do proc suboru
  proc_buffer = (char *) vmalloc(PROCF_SIZE * sizeof(char));
  memset(proc_buffer, 0, PROCF_SIZE );
  
  // neuspesne vytvorenie proc suboru
  if (proc_file == NULL || proc_buffer == NULL) {
    
      printk(KERN_INFO "pdsfw: could not initialize proc file (error)\n");
      return -ENOMEM;
  }
  
  // inicializacia zoznamu pravidiel
  INIT_LIST_HEAD(&(firewall_policy.list));
  
  // nastavenie vstupnej hook funkcie
  nf_hook_in.hook = io_hook_filter;
  nf_hook_in.hooknum = NF_INET_LOCAL_IN;
  nf_hook_in.pf = PF_INET;
  nf_hook_in.priority = NF_IP_PRI_FIRST;
  
  nf_register_hook(&nf_hook_in);
  
  // nastavenie vstupnej hook funkcie
  nf_hook_out.hook = io_hook_filter;
  nf_hook_out.hooknum = NF_INET_LOCAL_OUT;
  nf_hook_out.pf = PF_INET;
  nf_hook_out.priority = NF_IP_PRI_FIRST;
    
  nf_register_hook(&nf_hook_out);
  
  printk(KERN_INFO "pdsfw: initialize kernel module\n");
  
  return 0;
}

/* cleanup_module
 * 
 * - odstranenie modulu jadra
 */
void cleanup_module()
{
  struct list_head *p, *q;
  struct frule *rule;
  
  // odregistrovanie hook funkcii
  nf_unregister_hook(&nf_hook_in);
  nf_unregister_hook(&nf_hook_out);
  
  // uvolnenie pravidiel zo zoznamu
  list_for_each_safe(p, q, &firewall_policy.list) {
    
    rule = list_entry(p, struct frule, list);
    list_del(p);
    kfree(rule);
  }
  
  // odstranenie proc suboru a pomocneho bufferu
  remove_proc_entry(PROCF_NAME, NULL);
  vfree(proc_buffer);
  
  printk(KERN_INFO "pdsfw: clean up kernel module\n");
}   

//////////////////////////////////////////////////////////////////////////////////////////////

/* io_hook_filter
 * 
 * - filter vstupnej a vystupnej komunikacie vyuzivajuci netfilter
 * - funkcia implementuje filtracnu logiku firewallu 
 */
unsigned int io_hook_filter(const struct nf_hook_ops *ops, struct sk_buff *skb, 
                     const struct net_device *in, const struct net_device *out, 
                     int (*okfn)(struct sk_buff *)) 
{
  // ziskanie hlavicky ip protokolu
  struct iphdr   *ip_header = (struct iphdr *) skb_network_header(skb);
  struct tcphdr  *tcp_header;
  struct udphdr  *udp_header;
  struct icmphdr *icmp_header;
  
  struct list_head *p;
  
  struct frule *rule;
  struct frule *actual_packet;
  
  char sip[16], dip[16];
  int i, sidx, didx;
  
  // alokacia struktury pre aktualny paket
  actual_packet = kmalloc(sizeof(struct frule), GFP_KERNEL);
  
  // neuspesna alokacia
  if (actual_packet == NULL) {
    
    return -ENOMEM;
  } 
  
  // transportny protokol TCP
  if (ip_header->protocol == IPPROTO_TCP) {
    
    tcp_header = (struct tcphdr *)(skb_transport_header(skb));
    
    actual_packet->protocol = PROTOCOL_TCP;
    actual_packet->srcport = (unsigned int) ntohs(tcp_header->source);
    actual_packet->dstport = (unsigned int) ntohs(tcp_header->dest);
  }

  // transportny protokol UDP
  else if (ip_header->protocol == IPPROTO_UDP) {
    
    udp_header = (struct udphdr *)(skb_transport_header(skb));
    
    actual_packet->protocol = PROTOCOL_UDP;
    actual_packet->srcport = (unsigned int) ntohs(udp_header->source);
    actual_packet->dstport = (unsigned int) ntohs(udp_header->dest);
  }
  
  // transportny protokol ICMP
  else if (ip_header->protocol == IPPROTO_ICMP) {
    
    icmp_header = (struct icmphdr *)(skb_transport_header(skb));
    
    actual_packet->protocol = PROTOCOL_ICMP;
    actual_packet->srcport = PORT_ANY;
    actual_packet->dstport = PORT_ANY;
  }
  
  // sietovy protokol IPv4
  else if (ip_header->protocol == IPPROTO_IP) {
    
    actual_packet->protocol = PROTOCOL_IP;
    actual_packet->srcport = PORT_ANY;
    actual_packet->dstport = PORT_ANY;
  }
  
  // ostatne protokoly
  else {

    return NF_ACCEPT;
  }
  
  // prevod zdroj. a ciel. ip adresy na retazec
  sprintf(sip, "%pI4 ", &ip_header->saddr);
  sprintf(dip, "%pI4 ", &ip_header->daddr);
  
  // dekodovanie ip adries
  for (sidx = 0, didx = 0, i = 0; i < IPV4; i++) {
    
    actual_packet->srcip[i] = decode_ip_part(sip, &sidx);
    actual_packet->dstip[i] = decode_ip_part(dip, &didx);    
  }
  
  // prijatie/zahodenie paketu na zaklade filtracnej logiky
  list_for_each(p, &firewall_policy.list) {
    
    rule = list_entry(p, struct frule, list);

    if (check_packet(actual_packet, rule) == 0) {
      
      kfree(actual_packet);
      return (rule->action == ACTION_ALLOW) ? NF_ACCEPT : NF_DROP;
    }
  }
  
  // uvolnenie aktualneho paketu
  kfree(actual_packet);
  return NF_ACCEPT;
}

//////////////////////////////////////////////////////////////////////////////////////////////

/* procf_read
 * 
 * - funkcia volana pred citanim z proc suboru
 * - zapisany obsah do suboru je formatovany pre pouzitie v userspace aplikacii bez uprav  
 */
static ssize_t procf_read(struct file *filp, char __user *buf, size_t count, loff_t *offp)
{
  struct frule *rule;
  
  char *number;
  int number_len;
  
  char *ip_part;
  int i, ip_len;
  
  char *port;
  int port_len;
  
  unsigned long proc_buffer_pos = 0;
  
  if (*offp > 0) {
      
    return 0;
  }
  
  // vymazanie obsahu pomocneho buffera
  memset(proc_buffer, 0, PROCF_SIZE);
  
  // naplnenie pomocneho buffera retazcom na zaklade
  // pravidiel vo filtracnom zozname
  list_for_each_entry(rule, &firewall_policy.list, list) {
    
    number_len = get_int_length(rule->number);
    number = (char *) kmalloc(number_len * sizeof(char), GFP_KERNEL);
    sprintf(number, "%d", rule->number);
    memcpy(proc_buffer + proc_buffer_pos, number, number_len);
    proc_buffer_pos += number_len;
    kfree(number);
    
    // definovana akcia
    if (rule->action == ACTION_ALLOW) {
    
      memcpy(proc_buffer + proc_buffer_pos, "\tallow\t", 7);
      proc_buffer_pos += 7;
    }
    
    else {
      
      memcpy(proc_buffer + proc_buffer_pos, "\tdeny\t", 6);
      proc_buffer_pos += 6;
    }
    
    // zapis zdrojovej ip adresy
    if (rule->srcip[0] == 0 && rule->srcip[1] == 0 && rule->srcip[2] == 0 && rule->srcip[3] == 0) {
      
      memcpy(proc_buffer + proc_buffer_pos, "*\t", 2);
      proc_buffer_pos += 2;
    }
    
    else {
      
      for (i = 0; i < IPV4; i++) {
        
        ip_len = get_int_length(rule->srcip[i]);
        ip_part = (char *) kmalloc(ip_len * sizeof(char), GFP_KERNEL);
        sprintf(ip_part, "%d", rule->srcip[i]);
        memcpy(proc_buffer + proc_buffer_pos, ip_part, ip_len);
        proc_buffer_pos += ip_len;
        
        if (i == (IPV4 - 1)) {
          
          memcpy(proc_buffer + proc_buffer_pos, "\t", 1);
        }
        
        else {

          memcpy(proc_buffer + proc_buffer_pos, ".", 1);          
        }

        proc_buffer_pos += 1;
        kfree(ip_part);
      } 
    }
    
    // zapis zdrojoveho portu
    if (rule->srcport == PORT_ANY) {
      
      memcpy(proc_buffer + proc_buffer_pos, "*", 1);
      proc_buffer_pos += 1;
    }
    
    else {
      
      port_len = get_int_length(rule->srcport);
      port = (char *) kmalloc(port_len * sizeof(char), GFP_KERNEL);
      sprintf(port, "%d", rule->srcport);
      memcpy(proc_buffer + proc_buffer_pos, port, port_len);
      proc_buffer_pos += port_len;
      kfree(port);
    }
    
    memcpy(proc_buffer + proc_buffer_pos, "\t", 1);
    proc_buffer_pos += 1;
    
    // zapis cielovej adresy
    if (rule->dstip[0] == 0 && rule->dstip[1] == 0 && rule->dstip[2] == 0 && rule->dstip[3] == 0) {
      
      memcpy(proc_buffer + proc_buffer_pos, "*\t", 2);
      proc_buffer_pos += 2;
    }
    
    else {
      
      for (i = 0; i < IPV4; i++) {
        
        ip_len = get_int_length(rule->dstip[i]);
        ip_part = (char *) kmalloc(ip_len * sizeof(char), GFP_KERNEL);
        sprintf(ip_part, "%d", rule->dstip[i]);
        memcpy(proc_buffer + proc_buffer_pos, ip_part, ip_len);
        proc_buffer_pos += ip_len;
        
        if (i == (IPV4 - 1)) {
          
          memcpy(proc_buffer + proc_buffer_pos, "\t", 1);
        }
        
        else {

          memcpy(proc_buffer + proc_buffer_pos, ".", 1);          
        }

        proc_buffer_pos += 1;
        kfree(ip_part);
      } 
    }
    
    // zapis cieloveho portu
    if (rule->dstport == PORT_ANY) {
      
      memcpy(proc_buffer + proc_buffer_pos, "*", 1);
      proc_buffer_pos += 1;
    }
    
    else {
      
      port_len = get_int_length(rule->dstport);
      port = (char *) kmalloc(port_len * sizeof(char), GFP_KERNEL);
      sprintf(port, "%d", rule->dstport);
      memcpy(proc_buffer + proc_buffer_pos, port, port_len);
      proc_buffer_pos += port_len;
      kfree(port);
    }
    
    memcpy(proc_buffer + proc_buffer_pos, "\t", 1);
    proc_buffer_pos += 1;
    
    // protokol
    if (rule->protocol == PROTOCOL_TCP) {

      memcpy(proc_buffer + proc_buffer_pos, "tcp", 3);
      proc_buffer_pos += 3;
    }
    
    else if (rule->protocol == PROTOCOL_UDP) {

      memcpy(proc_buffer + proc_buffer_pos, "udp", 3);
      proc_buffer_pos += 3;      
    }
    
    else if (rule->protocol == PROTOCOL_ICMP) {
      
      memcpy(proc_buffer + proc_buffer_pos, "icmp", 4);
      proc_buffer_pos += 4;
    }
    
    else {
      
      memcpy(proc_buffer + proc_buffer_pos, "ip", 2);
      proc_buffer_pos += 2;
    }
    
    memcpy(proc_buffer + proc_buffer_pos, "\n", 1);
    proc_buffer_pos += 1;
  }

  // zapis obsahu buffera do proc suboru
  copy_to_user(buf, proc_buffer, proc_buffer_pos);
  *offp = proc_buffer_pos;
  
  // velkost zapisaneho obsahu
  return proc_buffer_pos;
}

/* procf_read
 * 
 * - funkcia volana po zapise do proc suboru
 * - na zaklade prveho znaku spravy je definovana odpovedajuca akcia
 *   (a - pridat pravidlo do modulu, d - vymazat pravidlo z modulu) 
 */
ssize_t procf_write(struct file *filp, const char __user *buf, size_t count, loff_t *offp)
{ 
  int stat, sep;
  int i;
  
  char *rule_str;  
  
  if (count > PROCF_SIZE) {
    
    count = PROCF_SIZE;
  }
  
  // nacitanie obsahu proc suboru do buffera
  copy_from_user(proc_buffer, buf, count);
  
  if (proc_buffer == NULL || count < 3) {
    
      memset(proc_buffer, 0, PROCF_SIZE);
      return count;
  }
  
  // alokacia retazca reprezentujuceho pravidlo
  rule_str = (char *) kmalloc((count - 1) * sizeof(char), GFP_KERNEL);
  
  i = 0;
  
  // kopirovanie upraveneho obsahu buffera do retazca 
  while (i < count - 2) {
    
    rule_str[i] = proc_buffer[i+2];
    i++;
  }
  
  rule_str[i] = '\0';
  
  // ziskanie typu spravy z buffera
  stat = proc_buffer[0];
  sep  = proc_buffer[1];
  
  // pridanie pravidla do zoznamu
  if (stat == 'a' && sep == '#') {
    
    add_rule(rule_str);
  }
  
  // odstranenie pravidla zo zoznamu
  else if (stat == 'd' && sep == '#') {
    
    delete_rule(rule_str);
  }
  
  // neznamy prikaz (typ spravy)
  else {
    
    printk(KERN_INFO "pdsfw: wrong proc file format (error)\n");
  }
  
  kfree(rule_str);
  memset(proc_buffer, 0, PROCF_SIZE);
  
  return count;
}

//////////////////////////////////////////////////////////////////////////////////////////////

/* add_rule
 * 
 * - vytvorenie a pridanie novej struktury do zoznamu pravidiel
 */
static int add_rule(char *rule) 
{
  int idx, i;
  
  // vytvorenie novej struktury
  struct frule *new_rule;
  new_rule = kmalloc(sizeof(struct frule), GFP_KERNEL);
  
  // neuspesna alokacia
  if (new_rule == NULL) {
    
    printk(KERN_INFO "pdsfw: memory allocation failed (error)\n");
    return -ENOMEM;
  }
  
  // cislo pravidla
  idx = 0;
  new_rule->number = 0;
  
  while (rule[idx] != ' ') {
    new_rule->number = new_rule->number * 10 + (rule[idx] - '0');
    idx++;
  }
  
  idx += 1; 
  
  // akcia firewallu
  if (rule[idx] == 'a') {
    
    new_rule->action = ACTION_ALLOW;
    idx += 6;
  }
  
  else {
    
    new_rule->action = ACTION_DENY;
    idx += 5;
  }
  
  // protokol
  if (rule[idx] == 't') {
    
    new_rule->protocol = PROTOCOL_TCP;
    idx += 4; 
  }
  
  else if (rule[idx] == 'u') {
    
    new_rule->protocol = PROTOCOL_UDP;
    idx += 4;     
  }
  
  else if (rule[idx+1] == 'c') {
    
    new_rule->protocol = PROTOCOL_ICMP;
    idx += 5; 
  }
  
  else {
    
    new_rule->protocol = PROTOCOL_IP;
    idx += 3; 
  }
  
  // zdrojova a cielova ip adresa
  for (i = 0; i < IPV4; i++) {
    
    new_rule->srcip[i] = 0;
    new_rule->dstip[i] = 0;
  }
  
  if (rule[idx] != 'a') {
    
      for (i = 0; i < IPV4; i++) 
        new_rule->srcip[i] = decode_ip_part(rule, &idx);
  }
  
  else {
    
    idx += 4;
  }
  
  if (rule[idx] != 'a') {
   
    for (i = 0; i < IPV4; i++)
        new_rule->dstip[i] = decode_ip_part(rule, &idx);
  }
  
  else {
    
    idx += 4;
  }
  
  // zdrojovy a cielovy port
  if (rule[idx] == '-') {
    
    new_rule->srcport = PORT_ANY;
    idx += 2;
  }
  
  else {
    
    new_rule->srcport = 0;
    
    while (rule[idx] != ' ') {
      
      new_rule->srcport = new_rule->srcport * 10 + (rule[idx] - '0');
      idx++;
    } 
    
    idx += 1;
  }
  
  
  if (rule[idx] == '-') {
    
    new_rule->dstport = PORT_ANY;
    idx += 2;
  }
  
  else {
    
    new_rule->dstport = 0;
    
    while (rule[idx] != '\0') {
      
      new_rule->dstport = new_rule->dstport * 10 + (rule[idx] - '0');
      idx++;
    }     
  }
  
  // pridanie noveho pravidla do zoznamu
  INIT_LIST_HEAD(&(new_rule->list));
  add_rule_to_list(new_rule);
  
  return 0;
}

/* add_rule_to_list
 * 
 * - zaradenie pravidla do zoznamu uz existujucich pravidiel
 * - pravidla su radene zostupne na zaklade ich cisla 
 * - v pripade pridavania pravidla s duplicitnym cislom je existujuce 
 *   pravidlo prepisane pravidlom novym
 */
static void add_rule_to_list(struct frule *new)
{
  struct list_head *p, *q, *head;
  struct frule *actual, *next;
  
  // ukazovatel na zaciatok zoznamu
  head = &firewall_policy.list;
  
  // pridanie pravidla na zaklade jeho cisla
  list_for_each_safe(p, q, head) {
    
    // aktualne prechadzane a nasledujuce pravidlo
    actual = list_entry(p, struct frule, list);
    next = list_entry(p->next, struct frule, list);
    
    // pridanie pravidla na zaciatok zoznamu
    if (new->number < actual->number) {  
      
      list_add_tail(&(new->list), p);
      return;
    }   
    
    // nahradenie existujuceho pravidla s rovnaky cislom
    else if (new->number == actual->number) {

      list_add(&(new->list), p);      
      
      list_del(p);
      kfree(actual);
      return;
    }
    
    // zaradenie pravidla medzi existujuce pravidla
    else if (new->number > actual->number && new->number < next->number) {
      
      list_add(&(new->list), p);
      return;
    }
    
  }
  
  // pridanie pravidla na koniec zoznamu
  list_add_tail(&(new->list), head);
  return;
}

/* delete_rule
 * 
 * - odstranenie pravidla zo zoznamu pravidiel
 * - v pripade neexistencie previdla zostava zoznam bez zmeny 
 */
static void delete_rule(char *rule)
{
  long int id = 0;
  
  // v pripade uspesneho prevodu retazca na cislo odstranenie pravidla
  if (kstrtol(rule, 10, &id) == 0) {
    
    struct list_head *p, *q;
    struct frule *rule;
    
    // linearny prechod zoznamom pravidiel
    list_for_each_safe(p, q, &firewall_policy.list) {
      
      rule = list_entry(p, struct frule, list);
      
      if (id == rule->number) {
        
        list_del(p);
        kfree(rule);
        break;
      }
      
    }
  }
  
}

/* is_same_ip
 * 
 * - porovnanie ipv4 adries reprezentovanych ako char[4]
 */
static int is_same_ip(char *ip1, char *ip2)
{
  int i;
  int sum1 = 0, sum2 = 0;
  
  // zistenie, ci sa nejedna o adresu 0.0.0.0
  for (i = 0; i < IPV4; i++) {
      
    sum1 += ip1[i];
    sum2 += ip2[i];
  }
  
  if (sum1 == 0 || sum2 == 0)
    return 0;
  
  // porovanie ip adries
  for (i = 0; i < IPV4; i++) {
    
    if (ip1[i] != ip2[i]) 
      return 1;
  }
  
  return 0;
}

/* check_packet
 * 
 * - filtracna logika firewallu
 */
static int check_packet(struct frule *packet, struct frule *rule)
{
  // kontrola protokolu
  if (rule->protocol != packet->protocol && rule->protocol != PROTOCOL_IP)
    return 1;
  
  // kontrola zdrojovej adresy
  if (is_same_ip(rule->srcip, packet->srcip) != 0)
    return 1;
  
  // kontrola cielovej adresy
  if (is_same_ip(rule->dstip, packet->dstip) != 0)
    return 1;
  
  // overenie portov len v ramci protokolov TCP a UDP
  if (packet->protocol == PROTOCOL_TCP || packet->protocol == PROTOCOL_UDP) {
    
    // kontrola zdrojoveho portu
    if (rule->srcport != PORT_ANY && rule->srcport != packet->srcport)
      return 1;
   
    // kontrola cieloveho portu
    if (rule->dstport != PORT_ANY && rule->dstport != packet->dstport)
      return 1;
  }
  
  return 0;
}

/* decode_ip_part
 * 
 * - prevod casti ip adresy reprezentovanej ako retazec
 *   na unsigned char
 */
static unsigned int decode_ip_part(char *str, int *index) 
{
  unsigned int part = 0;
  
  while (str[*index] != '.' && str[*index] != ' ') {
    
    part = part * 10 + (str[*index] - '0');
    (*index)++;
  }
  
  (*index) += 1;
  
  return part;
}

/* get_int_length
 * 
 * - zistenie poctu cislic
 */
static int get_int_length(int number)
{
  int len = 1;
  
  while (number > 9) {
    
    number /= 10; 
    len++;
  } 
  
  return len;
}


