/*
 * Simple netfilter firewall for Linux
 * by Jakub Vojvoda [vojvoda@swdeveloper.sk]
 * 
 * file: pdscli.c
 * - implementation of userspace application for communication with kernel module
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#define YY_CURRENT_BUFFER 0

#define PROCF_NAME "/proc/xvojvo00_pdsprocfile"
#define CHAR_SEPARATORS 8

typedef struct {
    
    char *number;
    
    char *action;
    char *protocol;

    char *srcip;
    char *dstip;
    
    char *srcport;
    char *dstport;
    
} firewall_rule;

typedef struct yy_buffer_state* YY_BUFFER_STATE;
extern int yyparse();

int parse_string(char *str);
int get_rule_size(firewall_rule rule);
char *encode_rule(firewall_rule rule);
firewall_rule decode_rule(char *str);

void print_rules();
int write_to_procf(char *str);


int main(int argc, char **argv) 
{   
    int option;
    int errval = 0;
    
    while ((option = getopt(argc, argv, "f:pa:d:")) != -1) {

        // nacitanie pravidiel zo vstupneho suboru 
        // jedno pravidlo na riadku
        if (option == 'f') {
            
            // otvorenie suboru
            FILE *input = fopen(optarg, "r");
            
            char *line = NULL;
            size_t length = 0;
            ssize_t chars;
            
            if (input == NULL) {
                
                fprintf(stderr, "%s: cannot open file %s\n", argv[0], optarg);
                return 1;
            }
            
            // citanie suboru riadok po riadku
            while ((chars = getline(&line, &length, input)) != -1) {
                
                if (line[chars - 1] == '\n')
                    line[chars - 1] = '\0';
                
                // overenie syntaktickej spravnosti pravidla
                int accept = parse_string(line);
                
                // dekodovanie a pridanie pravidla do modulu
                if (accept == 0) {
                  
                    firewall_rule rule = decode_rule(line);
                    
                    char *er = encode_rule(rule);
                    write_to_procf(er);
                    free(er);
                }
                
                else {
                  
                    fprintf(stderr, "%s: invalid format of line '%s'\n", argv[0], line);
                    errval = 1;
                }
            }
        }
        
        // vypis aktualnych pravidiel v module
        else if (option == 'p') {
            
            print_rules();
        }
        
        // pridanie pravidla do modulu
        else if (option == 'a') {
            
            // overenie syntaktickej spravnosti pravidla
            int accept = parse_string(optarg);
            
            // pridanie pravidla
            if (accept == 0) {
                
                firewall_rule rule = decode_rule(optarg);
                
                char *er = encode_rule(rule);
                write_to_procf(er);
                free(er);
            }
            
            else {
              
                fprintf(stderr, "%s: invalid format of argument '%s'\n", argv[0], optarg);
                errval = 1; 
            }
        }
        
        // odstranenie pravidla z modulu
        else if (option == 'd') {
            
            char *endptr;
            
            long int rule_number = strtol(optarg, &endptr, 10); 
            
            if (*endptr == '\0') {
                
                int len = strlen(optarg) + 3;
                
                char *stat = (char *) malloc(len * sizeof(char));
                
                if (stat == NULL) {
                    
                    fprintf(stderr, "%s: memory allocation error\n", argv[0]);
                    return 1;
                }
                
                // typ spravy a cislo pravidla
                strcpy(stat, "d#");
                strcat(stat, optarg);
                stat[len - 1] = '\0';
                
                // zapis do proc suboru
                write_to_procf(stat);
                free(stat);
            }
            
            else {
                
                fprintf(stderr, "%s: invalid option -d argument\n", argv[0]);
                errval = 1;
            }
        }
        
        else {
            
            return 2;
        }
        
    } 
    
    return errval;
}

/* get_rule_size
 * 
 * - zistenie potrebneho poctu znakov pre spravu
 */
int get_rule_size(firewall_rule rule)
{
    int length = strlen(rule.number);
    
    length += strlen(rule.action);
    length += strlen(rule.protocol);
    
    length += strlen(rule.srcip);
    length += strlen(rule.dstip);
    
    length += strlen(rule.srcport);
    length += strlen(rule.dstport);
    
    return length + CHAR_SEPARATORS + 1;
}

/* encode_rule
 * 
 * - zakodovanie pravidla do formatu urceneho
 *   k zapisu do proc suboru
 */
char *encode_rule(firewall_rule rule) 
{
    int length = get_rule_size(rule);
    
    // typ spravy
    char *str = (char *) malloc(length * sizeof(char));   
    strcpy(str, "a#");
    
    // cislo pravidla
    strcat(str, rule.number);
    strcat(str, " ");

    // akcia a protokol
    strcat(str, rule.action);
    strcat(str, " ");
    strcat(str, rule.protocol);
    strcat(str, " ");
    
    // zdrojova a cielova ip adresa
    strcat(str, rule.srcip);
    strcat(str, " ");
    strcat(str, rule.dstip);
    strcat(str, " ");
    
    // zdrojovy a cielovy port
    strcat(str, rule.srcport);
    strcat(str, " ");
    strcat(str, rule.dstport);
    strcat(str, "\0");
    
    return str;
}

/* decode_rule
 * 
 * - dekodovanie pravidla pre vypis na standard. vystup
 */
firewall_rule decode_rule(char *str) 
{    
    char *item;
    firewall_rule rule;
    
    // cislo pravidla
    rule.number = strtok(str, " ");
    
    // akcia a protokol
    rule.action = strtok(NULL, " ");
    rule.protocol = strtok(NULL, " ");
    
    // zdrojova a cielova ip adresa
    strtok(NULL, " ");
    rule.srcip = strtok(NULL, " ");
    strtok(NULL, " ");
    rule.dstip = strtok(NULL, " ");
    
    // zdrojovy a cielovy port
    item = strtok(NULL, " ");
    rule.srcport = "-";
    rule.dstport = "-";
    
    if (item != NULL && strcmp(item, "src-port") == 0) {

        rule.srcport = strtok(NULL, " ");
        item = strtok(NULL, " ");
    }
    
    if (item != NULL && strcmp(item, "dst-port") == 0) {

        rule.dstport = strtok(NULL, " ");
    }
        
    return rule;
}

/* parse_string
 * 
 * - lexikalna a syntakticka analyza retazca
 *   reprezentujuceho pravidlo
 */
int parse_string(char *str)
{
    yy_scan_string(str);
    int parsing = yyparse();
    yy_delete_buffer(YY_CURRENT_BUFFER);
    
    return parsing;
}

/* print_rules
 * 
 * - vypis pravidiel z proc suboru na standardny vystup
 */
void print_rules()
{
    FILE *procf = fopen(PROCF_NAME, "r");
    
    if (procf == NULL) {
        
        fprintf(stderr, "pdscli: cannot open proc file\n");
        return;
    }
    
    fprintf(stdout, "id\taction\tsrcip\tsrcport\tdstip\tdstport\tprotocol\n");
    
    char c;
    
    while ((c = fgetc(procf)) != EOF) {
      
      fprintf(stdout, "%c", (char) c);
    }
    
    fclose(procf);
}

/* write_to_procf
 * 
 * - zapis retazca do proc suboru
 */
int write_to_procf(char *str)
{
    FILE *procf = fopen(PROCF_NAME, "w");
  
    if (procf == NULL) {
        
        fprintf(stderr, "pdscli: cannot open proc file\n");
        return 1;
    }
  
    fprintf(procf, "%s", str);
    
    fclose(procf);
    return 0;
}

