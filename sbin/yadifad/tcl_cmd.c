/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
* The YADIFA TM software product is provided under the BSD 3-clause license:
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions
* are met:
*
*        * Redistributions of source code must retain the above copyright 
*          notice, this list of conditions and the following disclaimer.
*        * Redistributions in binary form must reproduce the above copyright 
*          notice, this list of conditions and the following disclaimer in the 
*          documentation and/or other materials provided with the distribution.
*        * Neither the name of EURid nor the names of its contributors may be 
*          used to endorse or promote products derived from this software 
*          without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*------------------------------------------------------------------------------
*
* DOCUMENTATION */
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 *  Implementation of routines for ...
 *   - ...
 *   - ...
 *   - ...
 *    -# ...
 *    -# ...
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "confs.h"

#include <dnscore/sys_get_cpu_count.h>

#include <dnsdb/dnssec.h>
#include <dnsdb/nsec3.h>
#include <dnsdb/zdb_zone.h>

#include "tcl_cmd.h"


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern server_context_t *server_context;

/*------------------------------------------------------------------------------
 * Consts  */

static const char* ERROR_CODE_HEX_DEC = "Error %08x = %d\n";

static const char* WRONG_NUMBER_OF_ARGUMENTS = "Wrong number of arguments given to %s";
static const char* WRONG_FDN = "%s: Wrong dns name '%s'";
static const char* WRONG_CLASS = "%s: Wrong class/type '%s'";
static const char* WRONG_TYPE = "%s: Wrong type '%s'";

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * ARGV TOOLS FUNCTIONS */

const char*
next_arg(char* argv[], int argc, int* argi)
{
    int idx = *argi;

    if(idx >= argc)
    {
	fprintf(stdout, "Not enough arguments"); /* DO NOT TOUCH PRINTF IN THIS FILE */
	fflush(stdout);

	return NULL;
    }

    *argi = idx + 1;

    return argv[idx];
}

ya_result
read_classtype(char* argv[], int argc, int* argi, u16* qclass, u16* qtype)
{
    const char* name = next_arg(argv, argc, argi);

    if(name == NULL)
    {
	return COMMAND_ARGUMENT_EXPECTED;
    }

    if(FAIL(get_class_from_name(name, qclass)))
    {
	*qclass = CLASS_IN;

	if(FAIL(get_type_from_name(name, qtype)))
	{
	    fprintf(stdout, "Wrong class '%s'\n", name);
	    fflush(stdout);
	    return ERROR - 2;
	}
    }
    else
    {
	const char* name = next_arg(argv, argc, argi);

	if(name == NULL)
	{
	    return ERROR - 4;
	}

	if(FAIL(get_type_from_name((const u_char*)name, qtype)))
	{
	    fprintf(stdout, "Wrong type '%s'\n", name);
	    fflush(stdout);
	    return ERROR - 5;
	}
    }

    return OK;
}

ya_result
read_string(char* argv[], int argc, int* argi, char** txt)
{
    const char* name = next_arg(argv, argc, argi);

    if(name == NULL)
    {
	return COMMAND_ARGUMENT_EXPECTED;
    }

    *txt = name;

    return OK;
}

ya_result
read_fdn(char* argv[], int argc, int* argi, u8* fdn_buffer)
{
    const char* name = next_arg(argv, argc, argi);

    if(name == NULL)
    {
	return ERROR - 1;
    }

    if(FAIL(cstr_to_dnsname(name, fdn_buffer)))
    {
	fprintf(stdout, "Invalid FDN '%s'\n", name);
	fflush(stdout);

	return ERROR - 2;
    }

    return OK;
}

ya_result
read_u32(char* argv[], int argc, int* argi, u32* val)
{
    const char* name = next_arg(argv, argc, argi);

    if(name == NULL)
    {
	return COMMAND_ARGUMENT_EXPECTED;
    }

    return parse_u32_range(name, val, 0, MAX_U32, BASE_10);
}

ya_result
read_u16(char* argv[], int argc, int* argi, u16* val16)
{
    const char* name = next_arg(argv, argc, argi);
    ya_result return_code;
    u32 val;

    if(name == NULL)
    {
	return COMMAND_ARGUMENT_EXPECTED;
    }

    if(FAIL(return_code = parse_u32_range(name, &val, 0, MAX_U16, BASE_10)))
    {
	val16 = (u16)val;
    }

    return return_code;
}

ya_result
read_zone(char* argv[], int argc, int* argi, zdb_zone** zone)
{
    const char* name = next_arg(argv, argc, argi);

    if(name == NULL)
    {
	return COMMAND_ARGUMENT_EXPECTED;
    }

    if(NULL == (*zone = zdb_zone_find_from_name(&server_context->db_zdb, name, CLASS_IN)))
    {
	fprintf(stdout, "Zone not found '%s'\n", name);
	fflush(stdout);

	return ERROR - 2;
    }

    return OK;
}

ya_result
read_remaining(char* argv[], int argc, int* argi, char** concat)
{
    char* txt;
    size_t len = 0;
    int idx = *argi;
    int i;

    *concat = NULL; /* So the caller can safely free it */

    for(i = idx; i < argc; i++)
    {
	len += strlen(argv[i]) + 1; /* +1 : space or \0 */
    }

    txt = (char*)malloc(len);
    *concat = txt;

    for(i = idx; i < argc; i++)
    {
	len = strlen(argv[i]);
	MEMCOPY(txt, argv[i], len);
	txt += len;
	*txt++ = ' ';
    }

    txt--;
    *txt = '\0';

    return len - 1;
}

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */


int
Tcl_AppInit(Tcl_Interp *interp)
{
    char *prompt1 = malloc((strlen(PACKAGE_VERSION) + strlen(YA_TCLPROMPT) + 1) * sizeof (char));
    sprintf(prompt1, YA_TCLPROMPT, PACKAGE_VERSION);
    /*  Tcl_Init reads init.tcl from the Tcl script library. */
    if(Tcl_Init(interp) == TCL_ERROR)
	return TCL_ERROR;

    /* Add our own commands to the Tcl interpreter. */
    if(TclCommandsInit(interp) == TCL_ERROR)
	return TCL_ERROR;

    Tcl_SetVar(interp, "tcl_prompt1", prompt1, TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "tcl_rcFileName", YA_TCLRCFILE, TCL_GLOBAL_ONLY);
    free(prompt1);

    return TCL_OK;
}

int
tcl_tcltest(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    if(argc != 1)
    {
	sprintf(interp->result, WRONG_NUMBER_OF_ARGUMENTS, argv[0]);
	return TCL_OK;
    }
    else
    {
	sprintf(interp->result, "It works!");
	return TCL_OK;
    }


    return TCL_OK;
}

static int
tcl_loaddb(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    if(argc != 1)
    {
	sprintf(interp->result, WRONG_NUMBER_OF_ARGUMENTS, argv[0]);
	return TCL_OK;
    }
    else
    {
	ya_result return_code;

	config_data *config = NULL;
	/* Initialise configuration file */
	if(FAIL(config_init(S_CONFIGDIR, &config)))
	{
	    return EXIT_FAILURE;
	}

	/* Read configuration file */
	if(FAIL(config_read("main", &config)))
	{
	    return EXIT_FAILURE;
	}

	/* Read configuration file */
	if(FAIL(config_read("zone", &config)))
	{
	    return EXIT_FAILURE;
	}

	if(FAIL(return_code = database_load(&server_context->db_zdb, config->data_path, config->zones)))
	{
	    OSDEBUG(termout, "error: %r\n", return_code);
	    
	    return return_code;
	}

	sprintf(interp->result, "done");

	return TCL_OK;
    }


    return TCL_OK;
}

static int
tcl_printdb(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    if(argc != 1)
    {
        sprintf(interp->result, WRONG_NUMBER_OF_ARGUMENTS, argv[0]);
        return TCL_OK;
    }
    else
    {
        zdb* db = &server_context->db_zdb;

        zdb_print(db);

        fflush(stdout);

        sprintf(interp->result, "done");

        return TCL_OK;
    }

    return TCL_OK;
}

static int
tcl_addnsec3param(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    ya_result return_code;
    zdb_zone* zone;

    int argi = 1;

    if(FAIL(read_zone(argv, argc, &argi, &zone)))
    {
        return -1;
    }

    return_code = nsec3_add_nsec3param(zone, 1, 0, 1, 0, NULL);

    if(FAIL(return_code))
    {
        fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
        fflush(stdout);

        return -1;
    }

    return TCL_OK;
}

static int
tcl_updatensec3(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    ya_result return_code;
    zdb_zone* zone;

    int argi = 1;

    if(FAIL(read_zone(argv, argc, &argi, &zone)))
    {
        return -1;
    }

    nsec3_update_zone(zone);

    if(FAIL(return_code))
    {
        fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
        fflush(stdout);

        return -1;
    }

    return TCL_OK;
}

static int
tcl_updatesigs(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    ya_result return_code;
    zdb_zone* zone;
    int argi = 1;

    if(FAIL(read_zone(argv, argc, &argi, &zone)))
    {
        return -1;
    }

    zdb_update_zone_signatures(zone, FALSE);

    if(FAIL(return_code))
    {
        fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
        fflush(stdout);

        return -1;
    }


    return TCL_OK;
}

static int
tcl_addkey(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    ya_result return_code;
    zdb_zone* zone;
    dnssec_key* key;
    u32 key_size;
    int argi = 1;
    u16 key_flags;

    if(FAIL(read_zone(argv, argc, &argi, &zone)))
    {
	return -1;
    }

    if(FAIL(read_u32(argv, argc, &argi, &key_size)))
    {
	return -2;
    }

    if(FAIL(read_u16(argv, argc, &argi, &key_flags)))
    {
	return -3;
    }

    /* argv[1] is always the origin */

    key = dnssec_key_createnew(DNSKEY_ALGORITHM_RSASHA1_NSEC3, key_size, key_flags, argv[1]);

    if(key == NULL)
    {
	fprintf(stdout, "Key generation error\n");
	fflush(stdout);
	return -4;
    }

    return_code = dnssec_key_store_private(key);

    if(FAIL(return_code))
    {
	fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
	fflush(stdout);

	dnssec_key_free(key);

	return -5;
    }

    return_code = dnssec_key_store_dnskey(key);

    if(FAIL(return_code))
    {
	fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
	fflush(stdout);

	dnssec_key_free(key);

	return -6;
    }

    dnssec_key_addrecord(zone, key);

    return TCL_OK;
}

static int
tcl_writezone(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    ya_result return_code;
    zdb_zone* zone;
    char* path;

    int argi = 1;

    if(FAIL(read_zone(argv, argc, &argi, &zone)))
    {
	return -1;
    }

    if(FAIL(read_string(argv, argc, &argi, &path)))
    {
	return -2;
    }

    if(FAIL(return_code = zdb_zone_write_text(zone, path)))
    {
	fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
	fflush(stdout);

	return -3;
    }

    return TCL_OK;
}

static int
tcl_query(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    u8 qname[MAX_DOMAIN_LENGTH];
    zdb_query_ex_answer answer;

    ya_result return_code;
    u16 qclass;
    u16 qtype;

    int argi = 1;

    if(FAIL(read_fdn(argv, argc, &argi, qname)))
    {
        return -1;
    }

    if(FAIL(read_classtype(argv, argc, &argi, &qclass, &qtype)))
    {
        return -2;
    }

    print_question((u8*)qname, qclass, qtype);

    zdb_query_ex_answer_create(&answer);
    
    if(FAIL(return_code = zdb_query_ex(&server_context->db_zdb, qname, qclass, qtype, &answer)))
    {
        fprintf(stdout, ERROR_CODE_HEX_DEC, return_code, return_code);
        fflush(stdout);

        return -3;
    }

    print_query_ex(&answer);

    zdb_query_ex_answer_destroy(&answer);

    fflush(stdout);

    return TCL_OK;
}

/* add & del */
static int
tcl_update(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    u8 qorigin[MAX_DOMAIN_LENGTH];
    u8 qname[MAX_DOMAIN_LENGTH];

    u_char* rdata;
    ya_result return_code;
    u32 ttl;
    int argi;
    u16 qclass;
    u16 qtype;
    u16 rdata_len;
    bool mode_add;

    mode_add = (clientData == 0);

    argi = 1;

    if(FAIL(read_fdn(argv, argc, &argi, qorigin)))
    {
	return -1;
    }

    if(FAIL(read_fdn(argv, argc, &argi, qname)))
    {
	return -2;
    }

    if(FAIL(read_u32(argv, argc, &argi, &ttl)))
    {
	return -3;
    }

    if(FAIL(read_classtype(argv, argc, &argi, &qclass, &qtype)))
    {
	return -4;
    }

    if(FAIL(rdata_len = read_remaining(argv, argc, &argi, (char**) & rdata)))
    {
	return -5;
    }

    /* The origin is ALWAYS in argv[1] */

    if(FAIL(rr_convert_rdata(&rdata, &rdata_len, qtype, (u_char*)argv[1])))
    {
	fprintf(stdout, "Invalid rdata for type %i\n", qtype);
	fflush(stdout);

	free(rdata);

	return -6;
    }

    if(mode_add)
    {
	return_code = zdb_add(&server_context->db_zdb, qorigin, qname, qclass, qtype, ttl, rdata_len, rdata);
    }
    else
    {
	return_code = zdb_delete(&server_context->db_zdb, qorigin, qname, qclass, qtype, ttl, rdata_len, rdata);
    }

    free(rdata);

    if(FAIL(return_code))
    {
	fprintf(stdout, "%s: Add returned %08x = %d\n", argv[0], return_code, return_code);
	fflush(stdout);

	return -7;
    }

    return TCL_OK;
}

static int
tcl_meminfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    u64 heap_size_total = 0;
    u64 heap_avail_total = 0;

    int i;

#if ZDB_ZALLOC_STATISTICS!=0
    fprintf(stdout, "Total used memory: %lld\n", zdb_mused());
#endif

    fprintf(stdout, "\n------------- HEAP SIZE - USED SIZE - FREE SIZE - HEAP SLOT - USED SLOT - FREE SLOT -\n");

    for(i = 0; i < ZDB_ALLOC_PG_SIZE_COUNT; i++)
    {
	u64 size = ((i + 1) << 3);
	u64 heap_size = zdb_mheap(i) * size;
	u64 heap_avail = zdb_mavail(i) * size;
	u64 heap_size_lines = zdb_mheap(i);
	u64 heap_avail_lines = zdb_mavail(i);

	heap_size_total += heap_size;
	heap_avail_total += heap_avail;

	fprintf(stdout,
		"[%3i..%3i] : %10llu  %10llu  %10llu  %10llu  %10llu  %10llu\n",
		(i << 3) + 1, ((i + 1) << 3),
		heap_size, heap_size - heap_avail, heap_avail,
		heap_size_lines, heap_size_lines - heap_avail_lines, heap_avail_lines);
    }

    fprintf(stdout, "             %10llu  %10llu  %10llu\n", heap_size_total, heap_size_total - heap_avail_total, heap_avail_total);

    fflush(stdout);
    return TCL_OK;
}

static int
tcl_cpucount(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    ya_result count = sys_get_cpu_count();

    if(ISOK(count))
    {
	fprintf(stdout, "Detected cpu count : %i\n", count);
    }
    else
    {
	fprintf(stdout, "Assumed cpu count : %i\n", DEFAULT_ASSUMED_CPU_COUNT);
    }

    fflush(stdout);

    return TCL_OK;
}

typedef struct tcl_help_struct tcl_help_struct;

struct tcl_help_struct
{
    const char* command;
    const char* info;
    const char* args;
};

static tcl_help_struct tcl_help_commands[] ={
    {"help", "Prints this help", "[command]"},
    {"?", "Prints this help", "[command]"},

    {"tcltest", "Prints \"It works!\"", ""},

    {"loaddb", "loads the database defined in the configuration file", ""},
    {"printdb", "prints the database on stdout", ""},

    {"addnsec3param", "Adds the default nsec3param to the zone", "origin"},
    {"updatensec3", "Updates all the NSEC3 records for all the NSEC3PARAM records of the zone", "origin"},
    {"updatesigs", "Updates all the signatures of the zone", "origin"},
    {"addkey", "Adds an NSEC3RSASHA1 key of the given size (bits) and flags to the zone", "origin size flags"},

    {"writezone", "Writes the zone file", "origin"},

    {"query", "DNS query", "fdn [class] type"},
    {"add", "Adds a record to the database. NOTE: The server MUST be disabled", "origin relative-name ttl [class] type rdata"},
    {"del", "Deletes a record from the database. NOTE: The server MUST be disabled", "origin relative-name ttl [class] type rdata"},

    {"meminfo", "Prints the database proprietary memory information", ""},
    {"cpucount", "Prints the number of cpu cores that will be used for multi-threaded tasks", ""},

    {NULL, NULL, NULL}
};

static int
tcl_help(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
    if(argc == 1)
    {
	tcl_help_struct* cmd = tcl_help_commands;

	fprintf(stdout, "\n");

	while(cmd->command != NULL)
	{
	    fprintf(stdout, "%-16s : %s\n", cmd->command, cmd->info);

	    cmd++;
	}

	fprintf(stdout, "\n");
    }
    else
    {
	char* command = argv[1];

	tcl_help_struct* cmd = tcl_help_commands;

	while(cmd->command != NULL)
	{
	    if(strcmp(command, cmd->command) == 0)
	    {
		fprintf(stdout,
			"\n"
			"%-16s : %s\n\n"
			"Usage: %s %s\n\n",
			cmd->command, cmd->info,
			cmd->command, cmd->args);
		break;
	    }

	    cmd++;
	}
    }

    fflush(stdout);

    return TCL_OK;

}

int
TclCommandsInit(Tcl_Interp *interp)
{
    /*Load libdatarouter TCL commands    ldr_tclcommandsinit(interp);*/

    /*Load libdatarouternetwork TCL commands*/
    /** @todo what ?*/
    /*DRH Plugin Commands*/
    Tcl_CreateCommand(interp, "tcltest", (Tcl_CmdProc *)tcl_tcltest, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "loaddb", (Tcl_CmdProc *)tcl_loaddb, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "printdb", (Tcl_CmdProc *)tcl_printdb, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    /* Nsec commands */
    Tcl_CreateCommand(interp, "addnsec3param", (Tcl_CmdProc *)tcl_addnsec3param, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "updatensec3", (Tcl_CmdProc *)tcl_updatensec3, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "updatesigs", (Tcl_CmdProc *)tcl_updatesigs, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "addkey", (Tcl_CmdProc *)tcl_addkey, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "writezone", (Tcl_CmdProc *)tcl_writezone, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "query", (Tcl_CmdProc *)tcl_query, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "add", (Tcl_CmdProc *)tcl_update, (ClientData)0, (Tcl_CmdDeleteProc *)NULL); /*  0 = add */
    Tcl_CreateCommand(interp, "del", (Tcl_CmdProc *)tcl_update, (ClientData)1, (Tcl_CmdDeleteProc *)NULL); /* !0 = del */
    Tcl_CreateCommand(interp, "meminfo", (Tcl_CmdProc *)tcl_meminfo, (ClientData)0, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "cpucount", (Tcl_CmdProc *)tcl_cpucount, (ClientData)0, (Tcl_CmdDeleteProc *)NULL);

    Tcl_CreateCommand(interp, "help", (Tcl_CmdProc *)tcl_help, (ClientData)0, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateCommand(interp, "?", (Tcl_CmdProc *)tcl_help, (ClientData)0, (Tcl_CmdDeleteProc *)NULL);

    return TCL_OK;

}


/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

