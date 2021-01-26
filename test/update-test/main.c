/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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
 */

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 *
 * skeleton test program, will not be installed with a "make install"
 *
 * To create a new test based on the skeleton:
 *
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/base64.h>
#include <dnscore/tsig.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/message.h>
#include <dnscore/config_settings.h>
#include <dnscore/random.h>
#include <dnscore/packet_reader.h>
#include <dnscore/packet_writer.h>
#include <dnscore/nsec3-hash.h>
#include <dnscore/base32hex.h>
#include <dnscore/xfr_input_stream.h>
#include <dnscore/timems.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>

/**
 * The program will query for the NSEC3PARAM of the zone
 * From it, it will compute and sort the hashes for a list of names
 * Then it will do various insertions deletions meant to cover various cases
 * of updates of the NSEC3 chain.
 *
 * If there is no NSEC3PARAM record, it will do the same but use NSEC record order
 * instead of NSEC3 digest order.
 */

#define VERBOSE 1
#define TIMEOUT 30 // seconds
#define LOADFIRST 0

#define MODE_AUTO 0
#define MODE_NSEC 1
#define MODE_NSEC3 2
#define MODE_STATE 3

#define NAME_BUFFER_SIZE 0x1000000

/**
 * global "no cleanup" flag
 * each test is supposed to remove what it has added
 * if this flag is set to true, it will not make that effort
 */

struct nsec3param_record
{
    u8 alg;
    u8 flags;
    u16 iterations;
    u8 salt_size;
    u8 salt[255];
};

typedef struct nsec3param_record nsec3param_record;

struct zone_chain
{
    nsec3param_record n3;
};

struct nsec3_domain
{
    int index;
    bool deleted;
    u8 fqdn[256];
    u8 digest[64];
};

typedef struct nsec3_domain nsec3_domain;

static int nsec3_domain_compare_digests(const void* a_, const void* b_)
{
    nsec3_domain *a = (nsec3_domain*)a_;
    nsec3_domain *b = (nsec3_domain*)b_;

    return memcmp(a->digest, b->digest, a->digest[0] + 1);
}

struct nsec_domain
{
    int index;
    bool deleted;
    u8 fqdn[256];
    u8 inverse[256];
};

typedef struct nsec_domain nsec_domain;

struct fqdn_type
{
    const u8* fqdn;
    u16 rtype;
};

typedef struct fqdn_type fqdn_type;


static int nsec_domain_compare_inverse(const void* a_, const void* b_)
{
    nsec_domain *a = (nsec_domain*)a_;
    nsec_domain *b = (nsec_domain*)b_;

    return dnsname_compare(a->inverse, b->inverse);
}

#define NSEC3PARAM_RECORD_MAX 8

static int verbose = VERBOSE;
static int g_queryback = FALSE;
static int g_tcp = FALSE;

static int g_spa = TRUE;
static int g_spa_mix = TRUE;
static int g_sp = TRUE;
static int g_sp_mix = TRUE;
static int g_sp_delall = TRUE;

static int list_of_names_size;
static const char *list_of_names[] =
{
//"thequickbrownfoxjumpsoverthelazydog-0123456789abcdefghijklmnop",
"aardvark",
"aardwolf","african-buffalo","african-elephant","african-leopard", "albatross",
"alligator","alpaca", "amphibian","anaconda","angelfish","anglerfish","ant","anteater",
"antelope","antlion","ape","aphid","arabian-leopard","arctic-fox","arctic-wolf",
"armadillo","arrow-crab","asp","baboon","badger","bald-eagle","bali-cattle","bandicoot",
"barnacle","barracuda","basilisk","bass","bat","beaked-whale","bear","beaver",
"bedbug","bee","beetle","bird","bison","black-panther","black-widow-spider","blackbird",
"blue-bird","blue-jay","blue-whale","boa","boar","bobcat","bobolink","bonobo",
"booby","bovid","box-jellyfish","buffalo","bug","butterfly","buzzard","camel",
"canid","canidae","cape-buffalo","capybara","cardinal","caribou","carp","cat",
"caterpillar","catfish","catshark","cattle","centipede","cephalopod","chameleon",
"cheetah","chickadee","chicken","chicken-breeds","chimpanzee","chinchilla",
"chipmunk","cicada","clam","clownfish","cobra","cockroach","cod","condor",
"constrictor","coral","cougar","cow","coyote","crab","crane","crane-fly","crawdad",
"crayfish","cricket","crocodile","crow","cuckoo","damselfly","deer","dingo",
"dinosaur","dog","dolphin","donkey","dormouse","dove","dragon","dragonfly","duck",
"dung-beetle","eagle","earthworm","earwig","echidna","eel","egret","elephant",
"elephant-seal","elk","emu","ermine","falcon""felidae","ferret","finch","firefly",
"fish","flamingo","flea","fly","flyingfish","fowl","fox","frog","fruit-bat","galliform",
"gamefowl","gayal","gazelle","gecko","gerbil","giant-panda","giant-squid","gibbon",

"gila-monster","giraffe","goat","goldfish","goose","gopher","gorilla","grasshopper",
"great-blue-heron","great-white-shark","grizzly-bear","ground-shark","ground-sloth",
"grouse","guan","guanaco","guinea-pig","guineafowl","gull","guppy","haddock",
"halibut","hammerhead-shark","hamster","hare","harrier","hawk","hedgehog","hermit-crab",
"heron","herring","hippopotamus","hookworm","hornet","horse","hoverfly","hummingbird",
"humpback-whale","hyena","iguana","impala","irukandji-jellyfish","jackal","jaguar",
"jay","jellyfish","junglefowl","kangaroo","kangaroo-mouse","kangaroo-rat",
"kingfisher","kite","kiwi","koala","koi","komodo-dragon","krill","lab-rat",
"ladybug","lamprey","land-snail","landfowl","lark","leech","lemming","lemur",
"leopard","leopon","limpet","lion","list","lizard","llama","lobster","locust",
"loon","louse","lungfish","lynx","macaw","mackerel","magpie","mammal","manatee",
"mandrill","manta-ray","marlin","marmoset","marmot","marsupial","marten","mastodon",
"meadowlark","meerkat","mink","minnow","mite","mockingbird","mole","mollusk",
"mongoose","monitor-lizard","monkey","moose","mosquito","moth","mountain-goat",
"mouse","mule","muskox","narwhal","new-world-quail","newt","nightingale","ocelot",
"octopus","old-world-quail","opossum","orangutan","orca","ostrich","otter",
"owl","ox","panda","panther","panthera-hybrid","parakeet","parrot","parrotfish",
"partridge","peacock","peafowl","pelican","penguin","perch","peregrine-falcon",
"pheasant","pig","pigeon","pigeon-breeds","pike","pilot-whale","pinniped",
"piranha","planarian","platypus","polar-bear","pony","porcupine","porpoise",
"possum","prairie-dog","prawn","praying-mantis","primate","ptarmigan","puffin",
"puma","python","quail","quelea","quokka","rabbit","raccoon","rainbow-trout","rat",
"rattlesnake","raven","ray","red-panda","reindeer","reptile","rhinoceros","right-whale",
"ringneck-dove","roadrunner","rodent","rook","rooster","roundworm","saber-toothed-cat",
"sailfish","salamander","salmon","sawfish","scale-insect","scallop","scorpion",
"sea-lion","sea-slug","sea-snail","seahorse","shark","sheep","sheep-breeds",
"shrew","shrimp","siamese-fighting-fish","silkworm","silverfish","skink",
"skunk","sloth","slug","smelt","snail","snake","snipe","snow-leopard","society-finch",
"sockeye-salmon","sole","sparrow","sperm-whale","spider","spider-monkey","spoonbill",
"squid","squirrel","star-nosed-mole","starfish","steelhead-trout","stingray",
"stoat","stork","sturgeon","sugar-glider","swallow","swan","swift","swordfish",
"swordtail","tahr","takin","tapir","tarantula","tarsier","tasmanian-devil","termite",
"tern","thrush","tick","tiger","tiger-shark","tiglon","toad","tortoise","toucan",
"trapdoor-spider","tree-frog","trout","tuna","turkey","turkey-breeds","turtle",
"tyrannosaurus","urial","vampire-bat","vampire-squid","vicuna","viper","vole",
"vulture","wallaby","walrus","warbler","wasp","water-boa","water-buffalo","water-buffalo-breeds",
"weasel","whale","whippet","whitefish","whooping-crane","wildcat","wildebeest",
"wildfowl","wolf","wolverine","wombat","woodpecker","worm","wren","x-ray-fish",
"xerinae","yak","yellow-perch","zebra","zebra-finch",

NULL
};

static const char *alternate_names[1]=
{
    "hydra"
};

static bool g_interactive = FALSE;

/**
 * This is a copy of update_test_nsec_inverse_name FROM DNSDB (I was not about to link the lib for this)
 */

static u32
update_test_nsec_inverse_name(u8 *inverse_name, const u8 *name)
{
    dnslabel_vector labels;

    s32 vtop = dnsname_to_dnslabel_vector(name, labels);
    u32 ret = dnslabel_stack_to_dnsname(labels, vtop, inverse_name);
    return ret;
}

#define QUERY_BACK_QUERY_MODE_ADD 0 // add
#define QUERY_BACK_QUERY_MODE_DEL 1 // del

static void
update_test_send_domains_update_query(const host_address *ip, message_data *mesg, random_ctx rndctx, const u8 *fqdn, u16 rtype, int mode)
{
    ya_result ret;
    u16 id;

    formatln("query: %{dnsname} %{dnstype}", fqdn, &rtype);
    id = (u16)random_next(rndctx);
    message_make_query_ex(mesg, id, fqdn, rtype, CLASS_IN, 0);
    ret = message_query(mesg, ip);
    formatln("answer: %{dnsname} %{dnstype}: %r", fqdn, &rtype, ret);

    message_map map;
    message_map_init(&map, mesg);
    message_map_reorder(&map);
    message_map_print(&map, termout);
    message_map_finalize(&map);

    //message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, 0);

    if(message_isanswer(mesg))
    {
        if(mode == QUERY_BACK_QUERY_MODE_ADD)
        {
            if(message_get_rcode(mesg) != RCODE_NOERROR)
            {
                formatln("query: %{dnsname} %{dnstype}: ERROR: expected-noerror", fqdn, &rtype);
            }
        }
        else
        {
            if(message_get_rcode(mesg) != RCODE_NXDOMAIN)
            {
                formatln("query: %{dnsname} %{dnstype}: ERROR: expected-nxdomain", fqdn, &rtype);
            }
        }
    }
    else
    {
        formatln("query: %{dnsname} %{dnstype}: ERROR: not-an-answer", fqdn, &rtype);
    }

    formatln("query: %{dnsname} %{dnstype} +dnssec", fqdn, &rtype);
    id = (u16)random_next(rndctx);
    message_make_query_ex(mesg, id, fqdn, rtype, CLASS_IN, MESSAGE_EDNS0_DNSSEC);
    ret = message_query(mesg, ip);
    formatln("answer: %{dnsname} %{dnstype} +dnssec: %r", fqdn, &rtype, ret);

    message_map_init(&map, mesg);
    message_map_reorder(&map);
    message_map_print(&map, termout);
    message_map_finalize(&map);

    //message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, 0);

    if(message_isanswer(mesg))
    {
        if(mode == QUERY_BACK_QUERY_MODE_ADD)
        {
            if(message_get_rcode(mesg) != RCODE_NOERROR)
            {
                formatln("answer: %{dnsname} %{dnstype}: ERROR: expected-noerror", fqdn, &rtype);
            }
            else
            {
                formatln("answer: %{dnsname} %{dnstype}: SUCCESS: as-expected", fqdn, &rtype);
            }
        }
        else
        {
            if(message_get_rcode(mesg) != RCODE_NXDOMAIN)
            {
                formatln("answer: %{dnsname} %{dnstype}: ERROR: expected-nxdomain", fqdn, &rtype);
            }
            else
            {
                formatln("answer: %{dnsname} %{dnstype}: SUCCESS: as-expected", fqdn, &rtype);
            }
        }
    }
    else
    {
        formatln("answer: %{dnsname} %{dnstype}: ERROR: not-an-answer", fqdn, &rtype);
    }
}

static void
update_test_send_domains_update_query_all(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
        const ptr_vector* domains_add,
        const ptr_vector* domains_del, bool with_ds)
{
    u8 fqdn[256];
    char tmp[256];

    formatln("update_test_send_domains_update_query_all(%{hostaddr}, %{dnsname}, mesg, rndctx, add %i, del %i, with_ds=%i)",
             ip, zone, ptr_vector_size(domains_add), ptr_vector_size(domains_del), with_ds);

    formatln("query-back: %{hostaddr} %{dnsname} with_ds=%i", ip, zone, with_ds?1:0);

    for(int i = 0; i < ptr_vector_size(domains_add); ++i)
    {
        nsec3_domain *d = (nsec3_domain*)ptr_vector_get(domains_add, i);

        formatln("zone: %{dnsname} query added: %{dnsname}", zone, d->fqdn);
        println("============================================================");

        snformat(tmp, sizeof(tmp), "%{dnsname}", d->fqdn);  // written for uniformity, not for beauty nor speed
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_ADD);

        snformat(tmp, sizeof(tmp), "ns1.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_ADD);

        snformat(tmp, sizeof(tmp), "ns2.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_ADD);

        snformat(tmp, sizeof(tmp), "brol.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_ADD);

        snformat(tmp, sizeof(tmp), "truc.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_ADD);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_ADD);
    }

    for(int i = 0; i < ptr_vector_size(domains_del); ++i)
    {
        nsec3_domain *d = (nsec3_domain*)ptr_vector_get(domains_del, i);

        formatln("zone: %{dnsname} query deleted: %{dnsname}", zone, d->fqdn);
        println("============================================================");

        snformat(tmp, sizeof(tmp), "%{dnsname}", d->fqdn);  // written for uniformity, not for beauty nor speed
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_DEL);

        snformat(tmp, sizeof(tmp), "ns1.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_DEL);

        snformat(tmp, sizeof(tmp), "ns2.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_DEL);

        snformat(tmp, sizeof(tmp), "brol.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_DEL);

        snformat(tmp, sizeof(tmp), "truc.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);

        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_DS, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_A, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_TXT, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_NSEC, QUERY_BACK_QUERY_MODE_DEL);
        update_test_send_domains_update_query(ip, mesg, rndctx, fqdn, TYPE_RRSIG, QUERY_BACK_QUERY_MODE_DEL);
    }
}

static ya_result
update_test_send_domains_update_ex(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
        const ptr_vector* domains_add,
        const ptr_vector* domains_del, bool with_ds)
{
    formatln("update_test_send_domains_update_ex(%{hostaddr}, %{dnsname}, mesg, rndctx, add %i, del %i, with_ds=%i)",
             ip, zone, ptr_vector_size(domains_add), ptr_vector_size(domains_del), with_ds);
    println("BEGIN ------------------------------------------------------------------------");

    message_map map;
    input_stream xfris;
    ya_result ret;
    int soa_rdata_size = -1;

    u16 id;
    u8 fqdn[256];
    char tmp[256];
    u8 soa_rdata[1024];
    struct packet_writer pw;

    // query for the current SOA

    id = (u16)random_next(rndctx);

    message_make_query(mesg, id, zone, TYPE_SOA, CLASS_IN);

    if(FAIL(ret = message_query(mesg, ip)))
    {
        formatln("ERROR: failed to obtain zone %{dnsname} serial from %{hostaddr}: %r", zone, ip, ret);
        return ret;
    }

    message_map_init(&map, mesg);
    int soa_index = message_map_get_next_record_from_section(&map, 1, 0, TYPE_SOA);
    if(soa_index >= 0)
    {
        soa_index += message_map_get_section_base(&map, 1);
        soa_rdata_size = message_map_get_rdata(&map, soa_index, soa_rdata, sizeof(soa_rdata));
    }
    message_map_finalize(&map);

    // prepare and send the update query

    id = (u16)random_next(rndctx);
    message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

    for(int i = 0; i < ptr_vector_size(domains_add); ++i)
    {
        nsec3_domain *d = (nsec3_domain*)ptr_vector_get(domains_add, i);
        snformat(tmp, sizeof(tmp), "ns1.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);
        message_make_dnsupdate_add_record(mesg, &pw, d->fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(fqdn), fqdn);
        snformat(tmp, sizeof(tmp), "ns2.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);
        message_make_dnsupdate_add_record(mesg, &pw, d->fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(fqdn), fqdn);
        if(with_ds)
        {
            snformat(tmp, sizeof(tmp), "%{dnsname}", d->fqdn);
            cstr_to_dnsname(fqdn, tmp);
            tmp[0] = 9;
            tmp[1] = 62;
            tmp[2] = 8;
            tmp[3] = 2;
            for(int i = 0; i < 32; ++i)
            {
                tmp[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
            }

            message_make_dnsupdate_add_record(mesg, &pw, d->fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, (const u8*)tmp);
        }
    }

    for(int i = 0; i < ptr_vector_size(domains_del); ++i)
    {
        nsec3_domain *d = (nsec3_domain*)ptr_vector_get(domains_del, i);
        snformat(tmp, sizeof(tmp), "ns1.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);
        message_make_dnsupdate_delete_record(mesg, &pw, d->fqdn, TYPE_NS, dnsname_len(fqdn), fqdn);
        snformat(tmp, sizeof(tmp), "ns2.%{dnsname}", d->fqdn);
        cstr_to_dnsname(fqdn, tmp);
        message_make_dnsupdate_delete_record(mesg, &pw, d->fqdn, TYPE_NS, dnsname_len(fqdn), fqdn);
        if(with_ds)
        {
            snformat(tmp, sizeof(tmp), "%{dnsname}", d->fqdn);
            cstr_to_dnsname(fqdn, tmp);
            tmp[0] = 9;
            tmp[1] = 62;
            tmp[2] = 8;
            tmp[3] = 2;
            for(int i = 0; i < 32; ++i)
            {
                tmp[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
            }

            message_make_dnsupdate_delete_record(mesg, &pw, d->fqdn, TYPE_DS, 4 + 32, (const u8*)tmp);
        }
    }

    message_make_dnsupdate_finalize(mesg, &pw);

    if(verbose || g_interactive)
    {
        message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, -1);

        flushout();

        if(g_interactive)
        {
            formatln("press a key to send ...");
            flushout();
            getchar();
        }
    }

    s64 query_start = timeus();

    for(int tries = 0;; ++tries)
    {
        if(!g_tcp)
        {
            formatln("update_test_send_domains_update_ex: TCP: %i bytes to %{hostaddr}", message_get_size(mesg), ip);
            ret = message_query_udp_with_timeout(mesg, ip, TIMEOUT, 0);
        }
        else
        {
            formatln("update_test_send_domains_update_ex: UDP %i bytes to %{hostaddr}", message_get_size(mesg), ip);
            ret = message_query_tcp_with_timeout(mesg, ip, TIMEOUT);
        }

        if(FAIL(ret))
        {
            if(ret == MAKE_ERRNO_ERROR(EAGAIN))
            {
                formatln("... tries: %i", tries);
                continue;
            }

            if(ret == MAKE_ERRNO_ERROR(EINTR))
            {
                formatln("... interrupted: %i", tries);
                continue;
            }

            formatln("error: %{dnsname}: sending %i bytes to %{hostaddr} using UDP failed with: %r", zone, message_get_size(mesg), ip, ret);
            flushout();

            //sleep(1);
            //continue;
        }

        if(verbose)
        {
            s64 query_stop = timeus();

            s64 duration = (query_start < query_stop)?(query_stop - query_start):0;
            duration /= 1000;

            message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, duration);

            if(g_interactive)
            {
                formatln("press a key to proceed ...");
                flushout();
                getchar();
            }
        }

        break;
    }

    if(ISOK(ret) && g_queryback)
    {
        if(soa_rdata_size >= 0)
        {
            if(ISOK(ret = xfr_input_stream_init_with_query(&xfris, ip, zone, 86400, soa_rdata, soa_rdata_size, XFR_ALLOW_IXFR)))
            {
                dns_resource_record rr;
                dns_resource_record_init(&rr);

                int soa_count = 0;

                for(;;)
                {
                    if((ret = dns_resource_record_read(&rr, &xfris)) <= 0)
                    {
			            println("IXFR: end of the stream");
                        break;
                    }

                    if(rr.tctr.qtype == TYPE_SOA)
                    {
                        ++soa_count;
                    }

                    formatln("IXFR: %c %{dnsrr}", "+-"[soa_count], &rr);
                }

                dns_resource_record_clear(&rr);

                input_stream_close(&xfris);
            }
            else
            {
                formatln("IXFR: failed to open stream on %{hostaddr} for %{dnsname}", ip, zone);
            }
        }

        if(ISOK(ret))
        {
            update_test_send_domains_update_query_all(ip, zone, mesg, rndctx, domains_add, domains_del, with_ds);
        }
        else
        {
            formatln("query-back: %{hostaddr} %{dnsname} with_ds=%i will not be done because an error occurred (%r)", ip, zone, with_ds?1:0, ret);
        }
    }

    println("END --------------------------------------------------------------------------");

    return ret;
}

static int update_test_send_message_and_check_count = 0;

static ya_result
update_test_send_message_and_check(const host_address *ip, const u8 *zone, message_data *mesg, const u8 *soa_rdata, int soa_rdata_size)
{
    formatln("Sending update_test_send_message_and_check %i\n", update_test_send_message_and_check_count);
/*
    if(update_test_send_message_and_check_count == 485)
    {
        println("Now ?");
        getchar();
    }
*/
    flushout();
    ++update_test_send_message_and_check_count;

    ya_result ret;
    input_stream xfris;

    if(verbose || g_interactive)
    {
        message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, -1);

        flushout();

        if(g_interactive)
        {
            formatln("press a key to send ...");
            flushout();
            getchar();
        }
    }

    s64 query_start = timeus();

    for(int tries = 0;; ++tries)
    {
        if(!g_tcp)
        {
            ret = message_query_udp_with_timeout(mesg, ip, TIMEOUT, 0);
        }
        else
        {
            ret = message_query_tcp_with_timeout(mesg, ip, TIMEOUT);
        }

        if(FAIL(ret))
        {
            if(ret == MAKE_ERRNO_ERROR(EAGAIN))
            {
                formatln("... tries: %i", tries);
                continue;
            }

            if(ret == MAKE_ERRNO_ERROR(EINTR))
            {
                formatln("... interrupted: %i", tries);
                continue;
            }

            formatln("error: %{dnsname}: sending %i bytes to %{hostaddr} using UDP failed with: %r", zone, message_get_size(mesg), ip, ret);
            flushout();

            //return ret;
        }

        if(verbose)
        {
            s64 query_stop = timeus();

            s64 duration = (query_start < query_stop)?(query_stop - query_start):0;
            duration /= 1000;

            message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, duration);

            if(g_interactive)
            {
                formatln("press a key to proceed ...");
                flushout();
                getchar();
            }
        }

        break;
    }

    if(ISOK(ret) && g_queryback)
    {
        if(soa_rdata_size >= 0)
        {
            if(ISOK(ret = xfr_input_stream_init_with_query(&xfris, ip, zone, 86400, soa_rdata, soa_rdata_size, XFR_ALLOW_IXFR)))
            {
                dns_resource_record rr;
                dns_resource_record_init(&rr);

                int soa_count = 0;

                for(;;)
                {
                    if((ret = dns_resource_record_read(&rr, &xfris)) <= 0)
                    {
                        println("IXFR: end of the stream");
                        break;
                    }

                    if(rr.tctr.qtype == TYPE_SOA)
                    {
                        ++soa_count;
                    }

                    formatln("IXFR: %c %{dnsrr}", "+-"[soa_count], &rr);
                }

                dns_resource_record_clear(&rr);

                input_stream_close(&xfris);
            }
            else
            {
                formatln("IXFR: failed to open stream on %{hostaddr} for %{dnsname}", ip, zone);
                flushout();
                flusherr();
                exit(1);
            }
        }
    }

    return ret;
}

static ya_result
update_test_send_domains_update_subdelegation_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
                                   const ptr_vector* domains_add,
                                   const ptr_vector* domains_del)
{
    formatln("update_test_send_domains_update_subdelegation_pattern(%{hostaddr}, %{dnsname}, mesg, rndctx, add %i, del %i)",
             ip, zone, ptr_vector_size(domains_add), ptr_vector_size(domains_del));
    println("BEGIN ------------------------------------------------------------------------");

    message_map map;

    ya_result ret;
    int soa_rdata_size = -1;

    u16 id;
    char tmp[256];
    u8 ns_fqdn[256];
    u8 ns2_fqdn[256];
    u8 a_fqdn[256];
    u8 a2_fqdn[256];
    u8 ds_rdata[256];
    u8 soa_rdata[1024];
    u8 a_ip[4];

    struct packet_writer pw;

    // query for the current SOA

    id = (u16)random_next(rndctx);

    message_make_query(mesg, id, zone, TYPE_SOA, CLASS_IN);

    if(FAIL(ret = message_query(mesg, ip)))
    {
        formatln("ERROR: failed to obtain zone %{dnsname} serial from %{hostaddr}: %r", zone, ip, ret);
        return ret;
    }

    message_map_init(&map, mesg);
    int soa_index = message_map_get_next_record_from_section(&map, 1, 0, TYPE_SOA);
    if(soa_index >= 0)
    {
        soa_index += message_map_get_section_base(&map, 1);
        soa_rdata_size = message_map_get_rdata(&map, soa_index, soa_rdata, sizeof(soa_rdata));
    }
    message_map_finalize(&map);

    for(u8 pattern = 0; pattern < 64; ++pattern)
    {
        formatln("pattern: %08x", pattern);

        // prepare and send the update query

        if(ptr_vector_size(domains_add) > 0)
        {
            bool with_ns = pattern & 1;
            bool with_ns2 = pattern & 2;
            bool with_ds = pattern & 4;
            bool with_ds2 = pattern & 8;
            bool with_a = pattern & 16;
            bool with_a2 = pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }

        if(ptr_vector_size(domains_add) > 0)
        {
            bool with_ns = ~pattern & 1;
            bool with_ns2 = ~pattern & 2;
            bool with_ds = ~pattern & 4;
            bool with_ds2 = ~pattern & 8;
            bool with_a = ~pattern & 16;
            bool with_a2 = ~pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }
    }

    for(u8 pattern = 0; pattern < 64; ++pattern)
    {
        formatln("pattern: %08x", pattern);

        // prepare and send the update query

        if(ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = pattern & 1;
            bool with_ns2 = pattern & 2;
            bool with_ds = pattern & 4;
            bool with_ds2 = pattern & 8;
            bool with_a = pattern & 16;
            bool with_a2 = pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_NS, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_NS, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_record(mesg, &pw, a_fqdn, TYPE_A, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_record(mesg, &pw, a2_fqdn, TYPE_A, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }

        if(ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = ~pattern & 1;
            bool with_ns2 = ~pattern & 2;
            bool with_ds = ~pattern & 4;
            bool with_ds2 = ~pattern & 8;
            bool with_a = ~pattern & 16;
            bool with_a2 = ~pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_NS, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_NS, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_record(mesg, &pw, a_fqdn, TYPE_A, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_record(mesg, &pw, a2_fqdn, TYPE_A, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }
    }

    println("END --------------------------------------------------------------------------");

    return ret;
}

static ya_result
update_test_send_domains_update_subdelegation_mix_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
                                                          const ptr_vector* domains_add,
                                                          const ptr_vector* domains_del)
{
    formatln("update_test_send_domains_update_subdelegation_mix_pattern(%{hostaddr}, %{dnsname}, mesg, rndctx, add %i, del %i)",
             ip, zone, ptr_vector_size(domains_add), ptr_vector_size(domains_del));
    println("BEGIN ------------------------------------------------------------------------");

    message_map map;

    ya_result ret;
    int soa_rdata_size = -1;

    u16 id;
    char tmp[256];
    u8 ns_fqdn[256];
    u8 ns2_fqdn[256];
    u8 a_fqdn[256];
    u8 a2_fqdn[256];
    u8 ds_rdata[256];
    u8 soa_rdata[1024];
    u8 a_ip[4];

    struct packet_writer pw;

    // query for the current SOA

    id = (u16)random_next(rndctx);

    message_make_query(mesg, id, zone, TYPE_SOA, CLASS_IN);

    if(FAIL(ret = message_query(mesg, ip)))
    {
        formatln("ERROR: failed to obtain zone %{dnsname} serial from %{hostaddr}: %r", zone, ip, ret);
        return ret;
    }

    message_map_init(&map, mesg);
    int soa_index = message_map_get_next_record_from_section(&map, 1, 0, TYPE_SOA);
    if(soa_index >= 0)
    {
        soa_index += message_map_get_section_base(&map, 1);
        soa_rdata_size = message_map_get_rdata(&map, soa_index, soa_rdata, sizeof(soa_rdata));
    }
    message_map_finalize(&map);

    for(u8 pattern = 0; pattern < 64; ++pattern)
    {
        formatln("pattern: %08x", pattern);

        // prepare and send the update query

        if(ptr_vector_size(domains_add) + ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = pattern & 1;
            bool with_ns2 = pattern & 2;
            bool with_ds = pattern & 4;
            bool with_ds2 = pattern & 8;
            bool with_a = pattern & 16;
            bool with_a2 = pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_NS, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_NS, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_record(mesg, &pw, a_fqdn, TYPE_A, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_record(mesg, &pw, a2_fqdn, TYPE_A, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }

        if(ptr_vector_size(domains_add) + ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = ~pattern & 1;
            bool with_ns2 = ~pattern & 2;
            bool with_ds = ~pattern & 4;
            bool with_ds2 = ~pattern & 8;
            bool with_a = ~pattern & 16;
            bool with_a2 = ~pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_NS, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_NS, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_record(mesg, &pw, ns2_fqdn, TYPE_DS, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_record(mesg, &pw, a_fqdn, TYPE_A, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_record(mesg, &pw, a2_fqdn, TYPE_A, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }
    }

    println("END --------------------------------------------------------------------------");

    return ret;
}


static ya_result
update_test_send_domains_update_del_domains(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
                                                      const ptr_vector* domains_del)
{
    formatln("update_test_send_domains_update_del_domains(%{hostaddr}, %{dnsname}, mesg, rndctx, del %i)",
             ip, zone, ptr_vector_size(domains_del));
    println("BEGIN ------------------------------------------------------------------------");

    message_map map;

    ya_result ret;
    int soa_rdata_size = -1;

    u16 id;
    char tmp[256];
    u8 ns_fqdn[256];
    u8 ns2_fqdn[256];
    u8 a_fqdn[256];
    u8 a2_fqdn[256];
    u8 soa_rdata[1024];

    struct packet_writer pw;

    // query for the current SOA

    id = (u16)random_next(rndctx);

    message_make_query(mesg, id, zone, TYPE_SOA, CLASS_IN);

    if(FAIL(ret = message_query(mesg, ip)))
    {
        formatln("ERROR: failed to obtain zone %{dnsname} serial from %{hostaddr}: %r", zone, ip, ret);
        return ret;
    }

    message_map_init(&map, mesg);
    int soa_index = message_map_get_next_record_from_section(&map, 1, 0, TYPE_SOA);
    if(soa_index >= 0)
    {
        soa_index += message_map_get_section_base(&map, 1);
        soa_rdata_size = message_map_get_rdata(&map, soa_index, soa_rdata, sizeof(soa_rdata));
    }
    message_map_finalize(&map);

    int pattern = 0;

    id = (u16)random_next(rndctx);
    message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

    for(int i = 0; i < ptr_vector_size(domains_del); ++i)
    {
        pattern &= 15;

        const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

        snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(ns_fqdn, tmp);

        snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(ns2_fqdn, tmp);

        snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(a_fqdn, tmp);

        snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(a2_fqdn, tmp);

        if(pattern & 1)
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, ns_fqdn);
        if(pattern & 2)
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, ns2_fqdn);
        if(pattern & 4)
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, a_fqdn);
        if(pattern & 8)
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, a2_fqdn);

        if(pw.packet_offset >= 0x8000)
        {
            break;
        }

        ++pattern;
    }

    message_make_dnsupdate_finalize(mesg, &pw);

    ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

    if(FAIL(ret))
    {
        return ret;
    }

    id = (u16)random_next(rndctx);
    message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

    for(int i = 0; i < ptr_vector_size(domains_del); ++i)
    {
        pattern &= 15;

        const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

        snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(ns_fqdn, tmp);

        snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(ns2_fqdn, tmp);

        snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(a_fqdn, tmp);

        snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
        cstr_to_dnsname(a2_fqdn, tmp);

        if(!(pattern & 1))
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, ns_fqdn);
        if(!(pattern & 2))
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, ns2_fqdn);
        if(!(pattern & 4))
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, a_fqdn);
        if(!(pattern & 8))
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, a2_fqdn);

        if(pw.packet_offset >= 0x8000)
        {
            break;
        }

        ++pattern;
    }

    message_make_dnsupdate_finalize(mesg, &pw);

    ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

    println("END --------------------------------------------------------------------------");

    return ret;
}


static ya_result
update_test_send_domains_update_subdelegation_delany_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
                                                      const ptr_vector* domains_add,
                                                      const ptr_vector* domains_del)
{
    formatln("update_test_send_domains_update_subdelegation_delany_pattern(%{hostaddr}, %{dnsname}, mesg, rndctx, add %i, del %i)",
            ip, zone, ptr_vector_size(domains_add), ptr_vector_size(domains_del));
    println("BEGIN ------------------------------------------------------------------------");

    message_map map;

    ya_result ret;
    int soa_rdata_size = -1;

    u16 id;
    char tmp[256];
    u8 ns_fqdn[256];
    u8 ns2_fqdn[256];
    u8 a_fqdn[256];
    u8 a2_fqdn[256];
    u8 ds_rdata[256];
    u8 soa_rdata[1024];
    u8 a_ip[4];

    struct packet_writer pw;

    // query for the current SOA

    id = (u16)random_next(rndctx);

    message_make_query(mesg, id, zone, TYPE_SOA, CLASS_IN);

    if(FAIL(ret = message_query(mesg, ip)))
    {
        formatln("ERROR: failed to obtain zone %{dnsname} serial from %{hostaddr}: %r", zone, ip, ret);
        return ret;
    }

    message_map_init(&map, mesg);
    int soa_index = message_map_get_next_record_from_section(&map, 1, 0, TYPE_SOA);
    if(soa_index >= 0)
    {
        soa_index += message_map_get_section_base(&map, 1);
        soa_rdata_size = message_map_get_rdata(&map, soa_index, soa_rdata, sizeof(soa_rdata));
    }
    message_map_finalize(&map);

    for(u8 pattern = 0; pattern < 64; ++pattern)
    {
        formatln("pattern: %08x", pattern);

        // prepare and send the update query

        if(ptr_vector_size(domains_add) > 0)
        {
            bool with_ns = pattern & 1;
            bool with_ns2 = pattern & 2;
            bool with_ds = pattern & 4;
            bool with_ds2 = pattern & 8;
            bool with_a = pattern & 16;
            bool with_a2 = pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }

        if(ptr_vector_size(domains_add) > 0)
        {
            bool with_ns = ~pattern & 1;
            bool with_ns2 = ~pattern & 2;
            bool with_ds = ~pattern & 4;
            bool with_ds2 = ~pattern & 8;
            bool with_a = ~pattern & 16;
            bool with_a2 = ~pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }
    }

    for(u8 pattern = 0; pattern < 64; ++pattern)
    {
        formatln("pattern: %08x", pattern);

        // prepare and send the update query

        if(ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = pattern & 1;
            bool with_ns2 = pattern & 2;
            bool with_ds = pattern & 4;
            bool with_ds2 = pattern & 8;
            bool with_a = pattern & 16;
            bool with_a2 = pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a_fqdn, TYPE_ANY);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_record(mesg, &pw, a2_fqdn, TYPE_A, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }

        if(ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = ~pattern & 1;
            bool with_ns2 = ~pattern & 2;
            bool with_ds = ~pattern & 4;
            bool with_ds2 = ~pattern & 8;
            bool with_a = ~pattern & 16;
            bool with_a2 = ~pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a_fqdn, TYPE_ANY);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a2_fqdn, TYPE_ANY);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }
    }

    println("END --------------------------------------------------------------------------");

    return ret;
}

static ya_result
update_test_send_domains_update_subdelegation_delany_mix_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
                                                          const ptr_vector* domains_add,
                                                          const ptr_vector* domains_del)
{
    /*
    for(int i = 0; i <= ptr_vector_last_index(domains_add); ++i)
    {
        assert(dnsname_verify_charspace((u8*)ptr_vector_get(domains_add, i)));
    }
    for(int i = 0; i <= ptr_vector_last_index(domains_del); ++i)
    {
        assert(dnsname_verify_charspace((u8*)ptr_vector_get(domains_del, i)));
    }
    */
    formatln("update_test_send_domains_update_subdelegation_delany_mix_pattern(%{hostaddr}, %{dnsname}, mesg, rndctx, add %i, del %i)",
             ip, zone, ptr_vector_size(domains_add), ptr_vector_size(domains_del));
    println("BEGIN ------------------------------------------------------------------------");

    message_map map;

    ya_result ret;
    int soa_rdata_size = -1;

    u16 id;
    char tmp[256];
    u8 ns_fqdn[256];
    u8 ns2_fqdn[256];
    u8 a_fqdn[256];
    u8 a2_fqdn[256];
    u8 ds_rdata[256];
    u8 soa_rdata[1024];
    u8 a_ip[4];

    struct packet_writer pw;

    // query for the current SOA

    id = (u16)random_next(rndctx);

    message_make_query(mesg, id, zone, TYPE_SOA, CLASS_IN);

    if(FAIL(ret = message_query(mesg, ip)))
    {
        formatln("ERROR: failed to obtain zone %{dnsname} serial from %{hostaddr}: %r", zone, ip, ret);
        return ret;
    }

    message_map_init(&map, mesg);
    int soa_index = message_map_get_next_record_from_section(&map, 1, 0, TYPE_SOA);
    if(soa_index >= 0)
    {
        soa_index += message_map_get_section_base(&map, 1);
        soa_rdata_size = message_map_get_rdata(&map, soa_index, soa_rdata, sizeof(soa_rdata));
    }
    message_map_finalize(&map);

    for(u8 pattern = 0; pattern < 64; ++pattern)
    {
        formatln("pattern: %08x", pattern);

        // prepare and send the update query

        if(ptr_vector_size(domains_add) + ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = pattern & 1;
            bool with_ns2 = pattern & 2;
            bool with_ds = pattern & 4;
            bool with_ds2 = pattern & 8;
            bool with_a = pattern & 16;
            bool with_a2 = pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a_fqdn, TYPE_ANY);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a2_fqdn, TYPE_ANY);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }

        if(ptr_vector_size(domains_add) + ptr_vector_size(domains_del) > 0)
        {
            bool with_ns = ~pattern & 1;
            bool with_ns2 = ~pattern & 2;
            bool with_ds = ~pattern & 4;
            bool with_ds2 = ~pattern & 8;
            bool with_a = ~pattern & 16;
            bool with_a2 = ~pattern & 32;

            id = (u16)random_next(rndctx);
            message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

            for(int i = 0; i < ptr_vector_size(domains_add); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_add, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_fqdn), a_fqdn);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a2_fqdn), a2_fqdn);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_add_record(mesg, &pw, ns2_fqdn, TYPE_DS, CLASS_IN, 86400, 4 + 32, ds_rdata);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_add_record(mesg, &pw, a_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_add_record(mesg, &pw, a2_fqdn, TYPE_A, CLASS_IN, 86400, 4, a_ip);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            for(int i = 0; i < ptr_vector_size(domains_del); ++i)
            {
                const u8 *d_fqdn = (const u8*)ptr_vector_get(domains_del, i);

                snformat(tmp, sizeof(tmp), "a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(ns2_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "z.y.x.a.b.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a_fqdn, tmp);

                snformat(tmp, sizeof(tmp), "w.v.u.c.d.e.%{dnsname}", d_fqdn);
                cstr_to_dnsname(a2_fqdn, tmp);

                if(with_ns)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ns2)
                {
                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_ds)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 73 * i * i + 43 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns_fqdn, TYPE_ANY);
                }

                if(with_ds2)
                {
                    ds_rdata[0] = 9;
                    ds_rdata[1] = 62;
                    ds_rdata[2] = 8;
                    ds_rdata[3] = 2;
                    for(int i = 0; i < 32; ++i)
                    {
                        ds_rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
                    }

                    message_make_dnsupdate_delete_rrset(mesg, &pw, ns2_fqdn, TYPE_ANY);
                }

                if(with_a)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 31;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a_fqdn, TYPE_ANY);
                }

                if(with_a2)
                {
                    a_ip[0] = 127;
                    a_ip[1] = 0;
                    a_ip[2] = 0;
                    a_ip[3] = i + 63;
                    message_make_dnsupdate_delete_rrset(mesg, &pw, a2_fqdn, TYPE_ANY);
                }

                if(pw.packet_offset >= 0x8000)
                {
                    break;
                }
            }

            message_make_dnsupdate_finalize(mesg, &pw);

            ret = update_test_send_message_and_check(ip, zone, mesg, soa_rdata, soa_rdata_size);

            if(FAIL(ret))
            {
                break;
            }
        }
    }

    println("END --------------------------------------------------------------------------");

    return ret;
}


static ya_result
update_test_send_domains_update(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
        const ptr_vector* domains_add,
        const ptr_vector* domains_del)
{
    return update_test_send_domains_update_ex(ip, zone, mesg, rndctx, domains_add, domains_del, TRUE);
}

static ya_result
update_test_domain(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx,
        const ptr_vector* records_add,
        const ptr_vector* records_del)
{
    struct packet_writer pw;
    ya_result ret;

    u16 id = (u16)random_next(rndctx);
    message_make_dnsupdate_init(mesg, id, zone, CLASS_IN, message_get_buffer_size_max(mesg), &pw);

    for(int i = 0; i < ptr_vector_size(records_add); ++i)
    {
        message_make_dnsupdate_add_dns_resource_record(mesg, &pw, (dns_resource_record*)ptr_vector_get(records_add, i));
    }

    for(int i = 0; i < ptr_vector_size(records_del); ++i)
    {
        dns_resource_record* rr = (dns_resource_record*)ptr_vector_get(records_del, i);
        if(rr->tctr.qclass != CLASS_ANY)
        {
            message_make_dnsupdate_delete_dns_resource_record(mesg, &pw, rr);
        }
        else if(rr->tctr.qtype != TYPE_ANY)
        {
            message_make_dnsupdate_delete_rrset(mesg, &pw, rr->name, rr->tctr.qtype);
        }
        else
        {
            message_make_dnsupdate_delete_all_rrsets(mesg, &pw, rr->name);
        }
    }

    message_make_dnsupdate_finalize(mesg, &pw);

    if(verbose || g_interactive)
    {
        message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, -1);
        flushout();

        if(g_interactive)
        {
            formatln("press a key to send ...");
            flushout();
            getchar();
        }
    }

    s64 query_start = timeus();

    for(int tries = 0;; ++tries)
    {
        if(FAIL(ret = message_query_udp_with_timeout(mesg, ip, TIMEOUT, 3)))
        {
            if(ret == MAKE_ERRNO_ERROR(EAGAIN))
            {
                formatln("... tries: %i", tries);
                continue;
            }

            if(ret == MAKE_ERRNO_ERROR(EINTR))
            {
                formatln("... interrupted: %i", tries);
                continue;
            }

            formatln("error: %{dnsname} network failed with: %r", zone, ret);
            flushout();

            //sleep(1);
            //continue;
        }

        if(verbose)
        {
            s64 query_stop = timeus();

            s64 duration = (query_start < query_stop)?(query_stop - query_start):0;
            duration /= 1000;

            message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, duration);

            if(g_interactive)
            {
                formatln("press a key to proceed ...");
                flushout();
                getchar();
            }
        }

        break;
    }

    return ret;
}

/**
 * Returns the index of a consecutive run of 'n' unused labels
 * All the labels covered from the first to the nth are marked as being used.
 */

static int
update_test_nsec3_get_consecutive(nsec3_domain *domains, int n)
{
    for(int i = 0; i < list_of_names_size; ++i)
    {
        if(domains[i].index < 0)
        {
            int j;
            for(j = i + 1; j < i + n; ++j)
            {
                if(domains[j].index >= 0)
                {
                    j = i;
                    break;
                }
            }
            if(j - i == n)
            {
                // mark them

                for(j = i; j < i + n; ++j)
                {
                    domains[j].index = list_of_names_size;
                }
                return i;
            }
        }
    }

    return -1;
}

static ya_result
udpate_test_subdelegation_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    ptr_vector domains = PTR_VECTOR_EMPTY;
    ptr_vector empty = PTR_VECTOR_EMPTY;
    u8 *domains_buffer;
    ya_result ret;
    char tmp[256];
    MALLOC_OBJECT_ARRAY(domains_buffer, u8, NAME_BUFFER_SIZE, GENERIC_TAG);
    u8* d = domains_buffer;
    for(int i = 1; list_of_names[i] != NULL; ++i)
    {
        snformat(tmp, sizeof(tmp), "%s-sp.%{dnsname}", list_of_names[i], zone);
        u8* prev = d;
        d += cstr_to_dnsname(d, tmp);
        assert(dnsname_locase_verify_charspace(prev));
        ptr_vector_append(&domains, prev);
    }

    ret = update_test_send_domains_update_subdelegation_pattern(ip, zone, mesg, rndctx,
                                                          &domains,
                                                          &empty);
    if(ISOK(ret))
    {
        if(!nocleanup)
        {
            ret = update_test_send_domains_update_subdelegation_pattern(ip, zone, mesg, rndctx,
                                                                  &empty,
                                                                  &domains);
        }
    }

    free(domains_buffer);
    ptr_vector_destroy(&domains);

    return ret;
}

static ya_result
udpate_test_subdelegation_pattern_clean_dels_all_rrsets(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    ptr_vector domains = PTR_VECTOR_EMPTY;
    ptr_vector empty = PTR_VECTOR_EMPTY;
    u8 *domains_buffer;
    ya_result ret;
    char tmp[256];
    MALLOC_OBJECT_ARRAY(domains_buffer, u8, NAME_BUFFER_SIZE, GENERIC_TAG);
    u8* d = domains_buffer;
    for(int i = 1; list_of_names[i] != NULL; ++i)
    {
        snformat(tmp, sizeof(tmp), "%s-spcar.%{dnsname}", list_of_names[i], zone);
        u8* prev = d;
        d += cstr_to_dnsname(d, tmp);
        assert(dnsname_locase_verify_charspace(prev));
        ptr_vector_append(&domains, prev);
    }

    ret = update_test_send_domains_update_subdelegation_pattern(ip, zone, mesg, rndctx,
                                                                &domains,
                                                                &empty);
    if(ISOK(ret))
    {
        if(!nocleanup)
        {
            ret = update_test_send_domains_update_del_domains(ip,zone, mesg, rndctx, &domains);
        }
    }

    free(domains_buffer);
    ptr_vector_destroy(&domains);

    return ret;
}


static ya_result
udpate_test_subdelegation_mix_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    ptr_vector domains_add = PTR_VECTOR_EMPTY;
    ptr_vector domains_del = PTR_VECTOR_EMPTY;
    ptr_vector empty = PTR_VECTOR_EMPTY;
    u8 *domains_buffer;
    ya_result ret;
    char tmp[256];
    MALLOC_OBJECT_ARRAY(domains_buffer, u8, NAME_BUFFER_SIZE, GENERIC_TAG);
    u8* d = domains_buffer;
    int i;

    for(i = 1; (i < 8) && (list_of_names[i] != NULL); ++i)
    {
        snformat(tmp, sizeof(tmp), "%s-sp2.%{dnsname}", list_of_names[i], zone);
        u8* prev = d;
        d += cstr_to_dnsname(d, tmp);
        assert(dnsname_locase_verify_charspace(prev));
        ptr_vector_append(&domains_add, prev);
    }

    ret = update_test_send_domains_update_subdelegation_mix_pattern(ip, zone, mesg, rndctx,
                                                                &domains_add,
                                                                &empty);

    while(ISOK(ret) && (list_of_names[i] != NULL))
    {
        ptr_vector_clear(&domains_del);
        ptr_vector_append_vector(&domains_del, &domains_add);
        ptr_vector_clear(&domains_add);

        int j = i + 8;

        for(; (i < j) && (list_of_names[i] != NULL); ++i)
        {
            snformat(tmp, sizeof(tmp), "%s-sp2.%{dnsname}", list_of_names[i], zone);
            u8* prev = d;
            d += cstr_to_dnsname(d, tmp);
            assert(dnsname_locase_verify_charspace(prev));
            ptr_vector_append(&domains_add, prev);
        }

        ret = update_test_send_domains_update_subdelegation_mix_pattern(ip, zone, mesg, rndctx,
                                                                    &domains_add,
                                                                    &domains_del);
    }

    if(ISOK(ret))
    {
        if(!nocleanup)
        {
            ret = update_test_send_domains_update_subdelegation_mix_pattern(ip, zone, mesg, rndctx,
                                                                            &empty,
                                                                            &domains_add);
        }
    }

    free(domains_buffer);
    ptr_vector_destroy(&domains_del);
    ptr_vector_destroy(&domains_add);

    return ret;
}

static ya_result
udpate_test_subdelegation_delany_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    ptr_vector domains = PTR_VECTOR_EMPTY;
    ptr_vector empty = PTR_VECTOR_EMPTY;
    u8 *domains_buffer;
    ya_result ret;
    char tmp[256];
    MALLOC_OBJECT_ARRAY(domains_buffer, u8, NAME_BUFFER_SIZE, GENERIC_TAG);
    u8* d = domains_buffer;
    for(int i = 1; list_of_names[i] != NULL; ++i)
    {
        snformat(tmp, sizeof(tmp), "%s-spa.%{dnsname}", list_of_names[i], zone);
        u8* prev = d;
        d += cstr_to_dnsname(d, tmp);
        assert(dnsname_locase_verify_charspace(prev));
        ptr_vector_append(&domains, prev);
    }

    ret = update_test_send_domains_update_subdelegation_delany_pattern(ip, zone, mesg, rndctx,
                                                                &domains,
                                                                &empty);
    if(ISOK(ret))
    {
        if(!nocleanup)
        {
            ret = update_test_send_domains_update_subdelegation_delany_pattern(ip, zone, mesg, rndctx,
                                                                        &empty,
                                                                        &domains);
        }
    }

    free(domains_buffer);
    ptr_vector_destroy(&domains);

    return ret;
}

static ya_result
udpate_test_subdelegation_delany_mix_pattern(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    ptr_vector domains_add = PTR_VECTOR_EMPTY;
    ptr_vector domains_del = PTR_VECTOR_EMPTY;
    ptr_vector empty = PTR_VECTOR_EMPTY;
    u8 *domains_buffer;
    ya_result ret;
    char tmp[256];
    MALLOC_OBJECT_ARRAY(domains_buffer, u8, NAME_BUFFER_SIZE, GENERIC_TAG);
    u8* d = domains_buffer;
    int i;

    for(i = 0; (i < 8) && (list_of_names[i] != NULL); ++i)
    {
        snformat(tmp, sizeof(tmp), "%s-spa2.%{dnsname}", list_of_names[i], zone);
        u8* prev = d;
        d += cstr_to_dnsname(d, tmp);
        assert(dnsname_locase_verify_charspace(prev));
        ptr_vector_append(&domains_add, prev);
    }

    ret = update_test_send_domains_update_subdelegation_delany_mix_pattern(ip, zone, mesg, rndctx,
                                                                    &domains_add,
                                                                    &empty);

    while(ISOK(ret) && (list_of_names[i] != NULL))
    {
/*
        for(int i = 0; i <= ptr_vector_last_index(&domains_add); ++i)
        {
            assert(dnsname_verify_charspace((u8*)ptr_vector_get(&domains_add, i)));
        }
        for(int i = 0; i <= ptr_vector_last_index(&domains_del); ++i)
        {
            assert(dnsname_verify_charspace((u8*)ptr_vector_get(&domains_del, i)));
        }
*/
        ptr_vector_clear(&domains_del);
/*
        for(int i = 0; i <= ptr_vector_last_index(&domains_del); ++i)
        {
            assert(dnsname_verify_charspace((u8*)ptr_vector_get(&domains_del, i)));
        }
*/
        ptr_vector_append_vector(&domains_del, &domains_add);
/*
        for(int i = 0; i <= ptr_vector_last_index(&domains_del); ++i)
        {
            assert(dnsname_verify_charspace((u8*)ptr_vector_get(&domains_del, i)));
        }

        for(int i = 0; i <= ptr_vector_last_index(&domains_add); ++i)
        {
            assert(dnsname_verify_charspace((u8*)ptr_vector_get(&domains_add, i)));
        }
*/
        ptr_vector_clear(&domains_add);
/*
        for(int i = 0; i <= ptr_vector_last_index(&domains_del); ++i)
        {
            assert(dnsname_verify_charspace((u8*)ptr_vector_get(&domains_del, i)));
        }
*/
        int j = i + 8;

        for(; (i < j) && (list_of_names[i] != NULL); ++i)
        {
            snformat(tmp, sizeof(tmp), "%s-spa2.%{dnsname}", list_of_names[i], zone);
            u8* prev = d;
            d += cstr_to_dnsname(d, tmp);
            assert(dnsname_locase_verify_charspace(prev));
            ptr_vector_append(&domains_add, prev);
        }

        ret = update_test_send_domains_update_subdelegation_delany_mix_pattern(ip, zone, mesg, rndctx,
                                                                        &domains_add,
                                                                        &domains_del);
    }

    if(ISOK(ret))
    {
        if(!nocleanup)
        {
            ret = update_test_send_domains_update_subdelegation_delany_mix_pattern(ip, zone, mesg, rndctx,
                                                                            &empty,
                                                                            &domains_add);
        }
    }

    free(domains_buffer);
    ptr_vector_destroy(&domains_del);
    ptr_vector_destroy(&domains_add);

    return ret;
}


static ya_result
udpate_test_nsec3(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    packet_unpack_reader_data pr;
    nsec3_domain *domains = NULL;
    int zone_nsec3_index;
    ya_result ret = SUCCESS;
    u8 nsec3param_count = 0;
    u8 zone_digest[64];
    u8 buffer[2048];
    struct zone_chain zone_chain[NSEC3PARAM_RECORD_MAX];

    ZEROMEMORY(zone_chain, sizeof(zone_chain));

    packet_reader_init_from_message(&pr, mesg);

    int n = message_get_query_count(mesg);

    while(n-- > 0)
    {
        packet_reader_skip_fqdn(&pr);
        packet_reader_skip(&pr, 4);
    }

    n = message_get_answer_count(mesg);

    while(n-- > 0)
    {
        if(FAIL(ret = packet_reader_read_record(&pr, buffer, sizeof(buffer))))
        {
            goto update_test_nsec3_cleanup;
        }

        u8 *p = buffer + dnsname_len(buffer);
        u16 rtype = GET_U16_AT(*p);
        if(rtype == TYPE_NSEC3PARAM)
        {
            // got one

            p += 2 + 2 + 4;
            //u16 rdata_size = GET_U16_AT_P(p);
            p += 2;

            zone_chain[nsec3param_count].n3.alg = *p++;
            zone_chain[nsec3param_count].n3.flags = *p++;
            zone_chain[nsec3param_count].n3.iterations = ntohs(GET_U16_AT_P(p));
            p += 2;
            zone_chain[nsec3param_count].n3.salt_size = *p++;
            memcpy(zone_chain[nsec3param_count].n3.salt, p, zone_chain[nsec3param_count].n3.salt_size);
            if(++nsec3param_count == NSEC3PARAM_RECORD_MAX)
            {
                break;
            }
        }
    }

    if(nsec3param_count == 0)
    {
        formatln("error: %{dnsname} no NSEC3PARAM found in zone", zone);
        ret = ERROR;
        goto update_test_nsec3_cleanup;
    }

    MALLOC_OBJECT_ARRAY_OR_DIE(domains, nsec3_domain, list_of_names_size, GENERIC_TAG);

    ptr_vector nsec3_domains_add = PTR_VECTOR_EMPTY;
    ptr_vector nsec3_domains_del = PTR_VECTOR_EMPTY;

    int current_index;

    for(int nsec3param_index = 0; nsec3param_index < nsec3param_count; ++nsec3param_index)
    {
        for(int i = 0; i < list_of_names_size; ++i)
        {
            domains[i].index = -1;
            domains[i].deleted = FALSE;
        }

        nsec3param_record *nsec3param = &zone_chain[nsec3param_index].n3;
        nsec3_hash_function* const digestfunction = nsec3_hash_get_function(nsec3param->alg);
        current_index = 0;

        zone_digest[0] = 20;
        digestfunction(zone, dnsname_len(zone), nsec3param->salt, nsec3param->salt_size, nsec3param->iterations, &zone_digest[1], FALSE);

        if(verbose)
        {
            format("[%i] NSEC3PARAM %i %i %i ", nsec3param_index, nsec3param->alg, nsec3param->flags, nsec3param->iterations);
            osprint_dump(termout, nsec3param->salt, nsec3param->salt_size, 20, OSPRINT_DUMP_BASE16);
            println("");
        }

        for(int i = 0; i < list_of_names_size; ++i)
        {
            u8 *name;
            u8 *digest;
            domains[i].index = -1;
            domains[i].deleted = FALSE;
            name = domains[i].fqdn;
            digest = domains[i].digest;
            name[0] = strlen(list_of_names[i]);
            memcpy(&name[1], list_of_names[i], name[0]);
            memcpy(&name[name[0] + 1], zone, dnsname_len(zone));
            digest[0] = 20;
            digestfunction(name, dnsname_len(name), nsec3param->salt, nsec3param->salt_size, nsec3param->iterations, &digest[1], FALSE);
            formatln("%{dnsname} : %{digest32h}", name, digest);
        }

        // got the digests

        // now, choose the order of operations

        qsort(domains, list_of_names_size, sizeof(nsec3_domain), nsec3_domain_compare_digests);

        // find the position of the zone fqdn's NSEC3

        for(zone_nsec3_index = 0; zone_nsec3_index < list_of_names_size; ++zone_nsec3_index)
        {
            if(memcmp(zone_digest, domains[zone_nsec3_index].digest, zone_digest[0] + 1) <= 0)
            {
                break;
            }
        }

        // domain at position zone_nsec3_index is before the zone nsec3
        // domain at position zone_nsec3_index + 1 is after the zone nsec3

        int middle_right = (list_of_names_size + zone_nsec3_index) / 2;
        int middle_left = zone_nsec3_index / 2;

        // delete 1 middle right (that should not work)
        // delete 1 middle left (that should not work)

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_del, &domains[middle_right]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[middle_right].index = current_index++;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_del, &domains[middle_left]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[middle_right].index = current_index++;

        // insert 1 middle right
        // insert 1 middle left

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[middle_right]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[middle_right].index = current_index++;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[middle_left]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[middle_right].index = current_index++;

        // insert 2 middle right
        // insert 2 extreme right
        // insert 2 extreme left

        int middle2_right = (zone_nsec3_index + middle_right) / 2;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[middle2_right]);
        ptr_vector_append(&nsec3_domains_add, &domains[middle2_right + 1]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[middle2_right].index = current_index++;
        domains[middle2_right + 1].index = current_index++;

        int extreme2_right = (list_of_names_size + middle_right) / 2;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme2_right]);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme2_right + 1]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[extreme2_right].index = current_index++;
        domains[extreme2_right + 1].index = current_index++;

        int extreme2_left = middle_left / 2;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme2_left]);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme2_left + 1]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[extreme2_left].index = current_index++;
        domains[extreme2_left + 1].index = current_index++;

        // insert 3 middle right
        // insert 3 extreme right
        // insert 3 extreme left

        int middle3_right = (zone_nsec3_index + middle2_right) / 2;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[middle3_right]);
        ptr_vector_append(&nsec3_domains_add, &domains[middle3_right + 1]);
        ptr_vector_append(&nsec3_domains_add, &domains[middle3_right + 2]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[middle3_right].index = current_index++;
        domains[middle3_right + 1].index = current_index++;
        domains[middle3_right + 2].index = current_index++;

        int extreme3_right = (list_of_names_size + middle3_right) / 2;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme3_right]);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme3_right + 1]);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme3_right + 2]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[extreme3_right].index = current_index++;
        domains[extreme3_right + 1].index = current_index++;
        domains[extreme3_right + 2].index = current_index++;

        int extreme3_left = extreme2_left / 2;

        ptr_vector_clear(&nsec3_domains_add);
        ptr_vector_clear(&nsec3_domains_del);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme3_left]);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme3_left + 1]);
        ptr_vector_append(&nsec3_domains_add, &domains[extreme3_left + 2]);
        if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
        domains[extreme3_left].index = current_index++;
        domains[extreme3_left + 1].index = current_index++;
        domains[extreme3_left + 2].index = current_index++;

        // add 3 (ada), remove the one in the middle
        // add 3 (dad), remove the ones on the side
        // add 6 (aaddaa)
        // add 6 (ddaadd)
        // add 9 (aaadddaaa)
        // add 9 (dddaaaddd)
        // add 5 (adada), remove the one in the middle
        // add 5 (dadad), remove the ones on the side
        // add 10 (aaddaaddaa)
        // add 10 (ddaaddaadd)
        // add 15 (aaadddaaadddaaa)
        // add 15 (dddaaadddaaaddd)

        int ada_indexes[2 * 3 * 2];
        int ada_index = 0;

        // prepare

        int send_index = 0;

        for(int blocks = 3; blocks <= 5; blocks += 2) // 2
        {
            for(int runlen = 1; runlen <= 3; ++runlen) // 3
            {
                for(int negative = 0; negative <= 1; ++negative) // 2
                {
                    int br = blocks * runlen;
                    int index = update_test_nsec3_get_consecutive(domains, br);

                    if((index < 0) || (index > list_of_names_size))
                    {
                        formatln("could not find %i consecutive names", br);
                        goto update_test_nsec3_cleanup;
                    }

                    ptr_vector_clear(&nsec3_domains_add);
                    ptr_vector_clear(&nsec3_domains_del);

                    bool with_ds = (send_index % 10) == 0;

                    for(int d_index = negative * runlen; d_index < br; d_index += runlen * 2)
                    {
                        for(int r_index = 0; r_index < runlen; ++r_index)
                        {
                            ptr_vector_append(&nsec3_domains_add, &domains[index + d_index + r_index]);
                            domains[index + d_index + r_index].index = current_index++;
                        }
                    }

                    // 10% of the domains will have a DS record attached

                    ret = update_test_send_domains_update_ex(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del, with_ds);

                    if(FAIL(ret))
                    {
                        return ret;
                    }

                    ++send_index;

                    ada_indexes[ada_index++] = index;
                }
            }
        }

        // execute

        ada_index = 0;

        send_index = 0;

        for(int blocks = 3; blocks <= 5; blocks += 2) // 2
        {
            for(int runlen = 1; runlen <= 3; ++runlen) // 3
            {
                for(int negative = 0; negative <= 1; ++negative) // 2
                {
                    int br = blocks * runlen;
                    int index = ada_indexes[ada_index++];

                    ptr_vector_clear(&nsec3_domains_add);
                    ptr_vector_clear(&nsec3_domains_del);

                    bool with_ds = (send_index % 10) == 0;

                    for(int d_index = negative * runlen; d_index < br; d_index += runlen * 2)
                    {
                        for(int r_index = 0; r_index < runlen; ++r_index)
                        {
                            ptr_vector_append(&nsec3_domains_del, &domains[index + d_index + r_index]);
                            domains[index + d_index + r_index].deleted = TRUE;
                        }
                    }

                    for(int d_index = (1 - negative) * runlen; d_index < br; d_index += runlen * 2)
                    {
                        for(int r_index = 0; r_index < runlen; ++r_index)
                        {
                            ptr_vector_append(&nsec3_domains_add, &domains[index + d_index + r_index]);
                            domains[index + d_index + r_index].index = current_index++;
                        }
                    }

                    ret = update_test_send_domains_update_ex(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del, with_ds);

                    if(FAIL(ret))
                    {
                        return ret;
                    }

                    ++send_index;
                }
            }
        }

        for(int i = 0; i < list_of_names_size; ++i)
        {
            if(domains[i].index < 0)
            {
                ptr_vector_clear(&nsec3_domains_add);
                ptr_vector_clear(&nsec3_domains_del);

                bool with_ds = (i % 10) == 0;

                ptr_vector_append(&nsec3_domains_add, &domains[i]);

                ret = update_test_send_domains_update_ex(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del, with_ds);

                if(FAIL(ret))
                {
                    return ret;
                }

                domains[i].index = current_index++;
            }
        }

        if(!nocleanup)
        {
            for(int i = 0; i < list_of_names_size; ++i)
            {
                if(!domains[i].deleted)
                {
                    ptr_vector_clear(&nsec3_domains_add);
                    ptr_vector_clear(&nsec3_domains_del);

                    ptr_vector_append(&nsec3_domains_del, &domains[i]);

                    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec3_domains_add, &nsec3_domains_del))) return ret;
                }
            }
        }
    }

update_test_nsec3_cleanup:

    ptr_vector_destroy(&nsec3_domains_del);
    ptr_vector_destroy(&nsec3_domains_add);
    free(domains);

    return ret;
}

#define UPDATE_TEST_UPDATE_PERMUT_COUNT 6
/*
struct update_test_update_permut_state
{
    const host_address *ip;
    ptr_vector add;
    ptr_vector del;
    dns_resource_record* rr[UPDATE_TEST_UPDATE_PERMUT_COUNT];
    u8 state[UPDATE_TEST_UPDATE_PERMUT_COUNT];
};
*/
static ya_result
update_test_domain_state_change(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    (void)nocleanup;

    ptr_vector add;
    ptr_vector del;

    ptr_vector_init_ex(&add, UPDATE_TEST_UPDATE_PERMUT_COUNT);
    ptr_vector_init_ex(&del, UPDATE_TEST_UPDATE_PERMUT_COUNT);

    u8 fqdn[256];
    u8 rdata[256];
    char tmp[256];

    const char *label = alternate_names[0];
    s32 ttl = 86400;

    dns_resource_record fqdn_ns1;
    dns_resource_record ns1_fqdn_a;
    snformat(tmp, sizeof(tmp), "%s.%{dnsname}", label, zone);
    cstr_to_dnsname(fqdn, tmp);
    snformat(tmp, sizeof(tmp), "ns1.%s.%{dnsname}", label, zone);
    cstr_to_dnsname(rdata, tmp);
    dns_resource_record_init_record(&fqdn_ns1, fqdn, TYPE_NS, CLASS_IN, ttl, dnsname_len(rdata), rdata);
    snformat(tmp, sizeof(tmp), "ns1.%s.%{dnsname}", label, zone);
    cstr_to_dnsname(fqdn, tmp);
    rdata[0] = 127;
    rdata[1] = 0;
    rdata[2] = 0;
    rdata[3] = 1;
    dns_resource_record_init_record(&ns1_fqdn_a, fqdn, TYPE_A, CLASS_IN, ttl, 4, rdata);

    dns_resource_record fqdn_ns2;
    dns_resource_record ns2_fqdn_a;
    snformat(tmp, sizeof(tmp), "%s.%{dnsname}", label, zone);
    cstr_to_dnsname(fqdn, tmp);
    snformat(tmp, sizeof(tmp), "ns2.%s.%{dnsname}", label, zone);
    cstr_to_dnsname(rdata, tmp);
    dns_resource_record_init_record(&fqdn_ns2, fqdn, TYPE_NS, CLASS_IN, ttl, dnsname_len(rdata), rdata);
    snformat(tmp, sizeof(tmp), "ns2.%s.%{dnsname}", label, zone);
    cstr_to_dnsname(fqdn, tmp);
    rdata[0] = 127;
    rdata[1] = 0;
    rdata[2] = 0;
    rdata[3] = 2;
    dns_resource_record_init_record(&ns2_fqdn_a, fqdn, TYPE_A, CLASS_IN, ttl, 4, rdata);

    dns_resource_record fqdn_ns3;
    snformat(tmp, sizeof(tmp), "%s.%{dnsname}", label, zone);
    cstr_to_dnsname(fqdn, tmp);
    snformat(tmp, sizeof(tmp), "ns3.%s.%{dnsname}.com.", label, zone);
    cstr_to_dnsname(rdata, tmp);
    dns_resource_record_init_record(&fqdn_ns3, fqdn, TYPE_NS, CLASS_IN, ttl, dnsname_len(rdata), rdata);

    dns_resource_record fqdn_ds;
    snformat(tmp, sizeof(tmp), "%s.%{dnsname}", label, zone);
    cstr_to_dnsname(fqdn, tmp);
    rdata[0] = 209;
    rdata[1] = 162;
    rdata[2] = 8;
    rdata[3] = 2;
    for(int i = 0; i < 32; ++i)
    {
        rdata[4 + i] = (u8)(17 + 43 * i * i + 73 * i);
    }
    dns_resource_record_init_record(&fqdn_ds, fqdn, TYPE_DS, CLASS_IN, ttl, 4 + 32, rdata);

    // 6 records, to be added and removed in various combinaisons

    // all added

    ptr_vector_append(&add, &fqdn_ns1);
    ptr_vector_append(&add, &ns1_fqdn_a);
    ptr_vector_append(&add, &fqdn_ns2);
    ptr_vector_append(&add, &ns2_fqdn_a);
    ptr_vector_append(&add, &fqdn_ns3);
    ptr_vector_append(&add, &fqdn_ds);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&add);
    ptr_vector_clear(&del);

    // all removed

    ptr_vector_append(&del, &fqdn_ns1);
    ptr_vector_append(&del, &ns1_fqdn_a);
    ptr_vector_append(&del, &fqdn_ns2);
    ptr_vector_append(&del, &ns2_fqdn_a);
    ptr_vector_append(&del, &fqdn_ns3);
    ptr_vector_append(&del, &fqdn_ds);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&add);
    ptr_vector_clear(&del);

    // add the glues first

    ptr_vector_append(&add, &ns1_fqdn_a);
    ptr_vector_append(&add, &ns2_fqdn_a);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&add);

    // then add what makes them glues

    ptr_vector_append(&add, &fqdn_ns1);
    ptr_vector_append(&add, &fqdn_ns2);
    ptr_vector_append(&add, &fqdn_ns3);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&add);

    // then add what puts the domain in the NSEC3 chain, if the zone is NSEC3-optout (else it's already in)

    ptr_vector_append(&add, &fqdn_ds);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&add);

    // then remove the above to see that the domain is not in the chain anymore

    ptr_vector_append(&del, &fqdn_ds);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&del);

    // then remove what makes it a delegation

    ptr_vector_append(&del, &fqdn_ns1);
    ptr_vector_append(&del, &fqdn_ns2);
    ptr_vector_append(&del, &fqdn_ns3);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&del);

    // then remove the remaining glues

    ptr_vector_append(&del, &ns1_fqdn_a);
    ptr_vector_append(&del, &ns2_fqdn_a);
    update_test_domain(ip, zone, mesg, rndctx, &add, &del);
    ptr_vector_clear(&del);

    return SUCCESS;
}

static int
update_test_nsec_get_consecutive(nsec_domain *domains, int n)
{
    for(int i = 0; i < list_of_names_size; ++i)
    {
        if(domains[i].index < 0)
        {
            int j;
            for(j = i + 1; j < i + n; ++j)
            {
                if(domains[j].index >= 0)
                {
                    j = i;
                    break;
                }
            }
            if(j - i == n)
            {
                // mark them

                for(j = i; j < i + n; ++j)
                {
                    domains[j].index = list_of_names_size;
                }
                return i;
            }
        }
    }

    return -1;
}

static ya_result
udpate_test_nsec(const host_address *ip, const u8 *zone, message_data *mesg, random_ctx rndctx, bool nocleanup)
{
    nsec_domain *domains = NULL;

    ya_result ret = SUCCESS;

    MALLOC_OBJECT_ARRAY_OR_DIE(domains, nsec_domain, list_of_names_size, GENERIC_TAG);

    ptr_vector nsec_domains_add = PTR_VECTOR_EMPTY;
    ptr_vector nsec_domains_del = PTR_VECTOR_EMPTY;

    int current_index = 0;

    for(int i = 0; i < list_of_names_size; ++i)
    {
        domains[i].index = -1;
        domains[i].deleted = FALSE;
    }

    for(int i = 0; i < list_of_names_size; ++i)
    {
        u8 *name;

        domains[i].index = -1;
        domains[i].deleted = FALSE;
        name = domains[i].fqdn;

        name[0] = strlen(list_of_names[i]);
        memcpy(&name[1], list_of_names[i], name[0]);
        memcpy(&name[name[0] + 1], zone, dnsname_len(zone));

        update_test_nsec_inverse_name(domains[i].inverse, domains[i].fqdn);
    }

    // got the digests

    // now, choose the order of operations

    qsort(domains, list_of_names_size, sizeof(nsec_domain), nsec_domain_compare_inverse);

    // the zone's fqdn is always first (NSEC)

    /*
     * This test is slightly more complicated in NSEC than NSEC3.
     * It should be the same but for NSEC3, with a big enough amount of labels,
     * we can have enough of them at the left of the apex (without guarantee but
     * it's a test and it has only to work on our data set, which it does).
     *
     * On NSEC the apex is at index 0 so we have to work 'modulo'.
     *
     * The math basically do not change for the right, but they do for the left
     */

    int middle_right = list_of_names_size / 4;
    int middle_left = (3 * list_of_names_size) / 4;

    // delete 1 middle right (that should not work)
    // delete 1 middle left (that should not work)

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_del, &domains[middle_right]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[middle_right].index = current_index++;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_del, &domains[middle_left]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[middle_right].index = current_index++;

    // insert 1 middle right
    // insert 1 middle left

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[middle_right]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[middle_right].index = current_index++;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[middle_left]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[middle_right].index = current_index++;

    // insert 2 middle right
    // insert 2 extreme right
    // insert 2 extreme left

    int middle2_right = (1 * list_of_names_size) / 8;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[middle2_right]);
    ptr_vector_append(&nsec_domains_add, &domains[middle2_right + 1]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[middle2_right].index = current_index++;
    domains[middle2_right + 1].index = current_index++;

    int extreme2_right = (3 * list_of_names_size) / 8;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[extreme2_right]);
    ptr_vector_append(&nsec_domains_add, &domains[extreme2_right + 1]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[extreme2_right].index = current_index++;
    domains[extreme2_right + 1].index = current_index++;

    int extreme2_left = (5 * list_of_names_size) / 8;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[extreme2_left]);
    ptr_vector_append(&nsec_domains_add, &domains[extreme2_left + 1]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[extreme2_left].index = current_index++;
    domains[extreme2_left + 1].index = current_index++;

    // insert 3 middle right
    // insert 3 extreme right
    // insert 3 extreme left

    int middle3_right = (1 * list_of_names_size) / 16;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[middle3_right]);
    ptr_vector_append(&nsec_domains_add, &domains[middle3_right + 1]);
    ptr_vector_append(&nsec_domains_add, &domains[middle3_right + 2]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[middle3_right].index = current_index++;
    domains[middle3_right + 1].index = current_index++;
    domains[middle3_right + 2].index = current_index++;

    int extreme3_right = (7 * list_of_names_size) / 16;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[extreme3_right]);
    ptr_vector_append(&nsec_domains_add, &domains[extreme3_right + 1]);
    ptr_vector_append(&nsec_domains_add, &domains[extreme3_right + 2]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[extreme3_right].index = current_index++;
    domains[extreme3_right + 1].index = current_index++;
    domains[extreme3_right + 2].index = current_index++;

    int extreme3_left = (15 * list_of_names_size) / 16;

    ptr_vector_clear(&nsec_domains_add);
    ptr_vector_clear(&nsec_domains_del);
    ptr_vector_append(&nsec_domains_add, &domains[extreme3_left]);
    ptr_vector_append(&nsec_domains_add, &domains[extreme3_left + 1]);
    ptr_vector_append(&nsec_domains_add, &domains[extreme3_left + 2]);
    if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
    domains[extreme3_left].index = current_index++;
    domains[extreme3_left + 1].index = current_index++;
    domains[extreme3_left + 2].index = current_index++;

    // add 3 (ada), remove the one in the middle
    // add 3 (dad), remove the ones on the side
    // add 6 (aaddaa)
    // add 6 (ddaadd)
    // add 9 (aaadddaaa)
    // add 9 (dddaaaddd)
    // add 5 (adada), remove the one in the middle
    // add 5 (dadad), remove the ones on the side
    // add 10 (aaddaaddaa)
    // add 10 (ddaaddaadd)
    // add 15 (aaadddaaadddaaa)
    // add 15 (dddaaadddaaaddd)

    int ada_indexes[2 * 3 * 2];
    int ada_index = 0;

    // prepare

    for(int blocks = 3; blocks <= 5; blocks += 2) // 2
    {
        for(int runlen = 1; runlen <= 3; ++runlen) // 3
        {
            for(int negative = 0; negative <= 1; ++negative) // 2
            {
                int br = blocks * runlen;
                int index = update_test_nsec_get_consecutive(domains, br);

                if((index < 0) || (index > list_of_names_size))
                {
                    formatln("could not find %i consecutive names", br);
                    goto update_test_nsec_cleanup;
                }

                ptr_vector_clear(&nsec_domains_add);
                ptr_vector_clear(&nsec_domains_del);

                for(int d_index = negative * runlen; d_index < br; d_index += runlen * 2)
                {
                    for(int r_index = 0; r_index < runlen; ++r_index)
                    {
                        ptr_vector_append(&nsec_domains_add, &domains[index + d_index + r_index]);
                        domains[index + d_index + r_index].index = current_index++;
                    }
                }

                if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;

                ada_indexes[ada_index++] = index;
            }
        }
    }

    // execute

    ada_index = 0;

    for(int blocks = 3; blocks <= 5; blocks += 2) // 2
    {
        for(int runlen = 1; runlen <= 3; ++runlen) // 3
        {
            for(int negative = 0; negative <= 1; ++negative) // 2
            {
                int br = blocks * runlen;
                int index = ada_indexes[ada_index++];

                ptr_vector_clear(&nsec_domains_add);
                ptr_vector_clear(&nsec_domains_del);

                for(int d_index = negative * runlen; d_index < br; d_index += runlen * 2)
                {
                    for(int r_index = 0; r_index < runlen; ++r_index)
                    {
                        ptr_vector_append(&nsec_domains_del, &domains[index + d_index + r_index]);
                        domains[index + d_index + r_index].deleted = TRUE;
                    }
                }

                for(int d_index = (1 - negative) * runlen; d_index < br; d_index += runlen * 2)
                {
                    for(int r_index = 0; r_index < runlen; ++r_index)
                    {
                        ptr_vector_append(&nsec_domains_add, &domains[index + d_index + r_index]);
                        domains[index + d_index + r_index].index = current_index++;
                    }
                }

                if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
            }
        }
    }

    for(int i = 0; i < list_of_names_size; ++i)
    {
        if(domains[i].index < 0)
        {
            ptr_vector_clear(&nsec_domains_add);
            ptr_vector_clear(&nsec_domains_del);

            ptr_vector_append(&nsec_domains_add, &domains[i]);

            if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;

            domains[i].index = current_index++;
        }
    }

    if(!nocleanup)
    {
        for(int i = 0; i < list_of_names_size; ++i)
        {
            if(!domains[i].deleted)
            {
                ptr_vector_clear(&nsec_domains_add);
                ptr_vector_clear(&nsec_domains_del);

                ptr_vector_append(&nsec_domains_del, &domains[i]);

                if(FAIL(ret = update_test_send_domains_update(ip, zone, mesg, rndctx, &nsec_domains_add, &nsec_domains_del))) return ret;
            }
        }
    }

update_test_nsec_cleanup:

    ptr_vector_destroy(&nsec_domains_del);
    ptr_vector_destroy(&nsec_domains_add);
    free(domains);

    return ret;
}

static ya_result
update_test(const host_address *ip, const u8 *zone, int mode, bool nocleanup)
{
    random_ctx rndctx = random_init_auto();
    message_data* mesg = message_new_instance();
    ya_result ret;

    message_edns0_setmaxsize(4096);

    s64 query_start = timeus();

    for(int tries = 0;; ++tries)
    {
        u16 id = (u16)random_next(rndctx);
        message_make_query_ex(mesg, id, zone, TYPE_NSEC3PARAM, CLASS_IN, MESSAGE_EDNS0_DNSSEC);
        if(FAIL(ret = message_query_udp_with_timeout(mesg, ip, TIMEOUT,0)))
        {
            if(ret == MAKE_ERRNO_ERROR(EAGAIN))
            {
                formatln("... tries: %i", tries);
                continue;
            }

            if(ret == MAKE_ERRNO_ERROR(EINTR))
            {
                formatln("... interrupted: %i", tries);
                continue;
            }

            formatln("error: %{dnsname} NSEC3PARAM network failed with: %r %i", zone, ret, ret);
            goto update_test_cleanup;
        }

        break;
    }

    if(verbose)
    {
        s64 query_stop = timeus();

        s64 duration = (query_start < query_stop)?(query_stop - query_start):0;
        duration /= 1000;

        message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, duration);
    }

    if((message_get_rcode(mesg) != RCODE_NOERROR) && (message_get_rcode(mesg) != RCODE_NXDOMAIN))
    {
        ret = RCODE_ERROR_CODE(message_get_rcode(mesg));
        formatln("error: %{dnsname} NSEC3PARAM: query failed with: %r", zone, ret);
        goto update_test_cleanup;
    }

    switch(mode)
    {
        case MODE_AUTO:
        default:
        {
            if(message_get_answer_count(mesg) > 0)
            {
                // for each NSEC3PARAM, compute the digests
                ret = udpate_test_nsec3(ip, zone, mesg, rndctx, nocleanup);
            }
            else
            {
                ret = udpate_test_nsec(ip, zone, mesg, rndctx, nocleanup);
            }

            break;
        }
        case MODE_NSEC:
        {
            ret = udpate_test_nsec(ip, zone, mesg, rndctx, nocleanup);

            break;
        }
        case MODE_NSEC3:
        {
            if(message_get_answer_count(mesg) > 0)
            {
                // for each NSEC3PARAM, compute the digests
                ret = udpate_test_nsec3(ip, zone, mesg, rndctx, nocleanup);
            }
            else
            {
                ret = ERROR;
                formatln("error: %{dnsname}: no NSEC3PARAM means no NSEC3 mode", zone);
            }

            break;
        }
        case MODE_STATE: // only do the state change
        {
            ret = SUCCESS;
            break;
        }
    }

    if(ISOK(ret) && g_spa)
    {
        ret = udpate_test_subdelegation_delany_pattern(ip, zone, mesg, rndctx, nocleanup);
    }

    if(ISOK(ret) && g_spa_mix)
    {
        ret = udpate_test_subdelegation_delany_mix_pattern(ip, zone, mesg, rndctx, nocleanup);
    }

    if(ISOK(ret) && g_sp)
    {
        ret = udpate_test_subdelegation_pattern(ip, zone, mesg, rndctx, nocleanup);
    }

    if(ISOK(ret) && g_sp_mix)
    {
        ret = udpate_test_subdelegation_mix_pattern(ip, zone, mesg, rndctx, nocleanup);
    }

    if(ISOK(ret) && g_sp_delall)
    {
        ret = udpate_test_subdelegation_pattern_clean_dels_all_rrsets(ip, zone, mesg, rndctx, nocleanup);
    }


    if(ISOK(ret))
    {
        update_test_domain_state_change(ip, zone, mesg, rndctx, nocleanup);
    }

update_test_cleanup:
    message_free(mesg);
    random_finalize(rndctx);

    return ret;
}

static void help()
{
    println("parameters: server-ip zone [nocleanup|auto|nsec|nsec3|stateonly] [no-sp] [no-spa] [no-sp-mix] [no-spa-mix] [no-sp-delall] [interactive] [queryback]");
    println("\n\tnode: default mode is nsec3\n");
    flushout();
}

int
main(int argc, char *argv[])
{
    host_address *ip = NULL;
    ya_result ret;
    u8 zone[256];

    /* initializes the core library */

    dnscore_init();

    if(argc < 3)
    {
        help();
        return EXIT_FAILURE;
    }

    anytype defaults = {._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,1,0,0,0,0,0,0}};
    if(FAIL(ret = config_set_host_list(argv[1], &ip, defaults)))
    {
        formatln("%s is an invalid ip: %r", argv[1], ret);
        help();
        return EXIT_FAILURE;
    }

    if(ip->port == 0)
    {
        ip->port = NU16(53);
    }

    if(FAIL(ret = cstr_to_dnsname_with_check(zone, argv[2])))
    {
        formatln("%s is an invalid zone: %r", argv[2], ret);
        help();
        return EXIT_FAILURE;
    }

    for(list_of_names_size = 0; list_of_names[list_of_names_size]!= NULL; ++list_of_names_size) {}

    int mode = MODE_AUTO;
    bool nocleanup = FALSE;

    for(int i = 3; i < argc; ++i)
    {
        if(strcmp(argv[i], "nocleanup") == 0)
        {
            nocleanup = TRUE;
        }
        else if(strcmp(argv[i], "auto") == 0)
        {
            mode = MODE_AUTO;
        }
        else if(strcmp(argv[i], "nsec") == 0)
        {
            mode = MODE_NSEC;
        }
        else if(strcmp(argv[i], "nsec3") == 0)
        {
            mode = MODE_NSEC3;
        }
        else if(strcmp(argv[i], "stateonly") == 0)
        {
            mode = MODE_STATE;
        }
        else if(strcmp(argv[i], "interactive") == 0)
        {
            println("interactive mode enabled");
            g_interactive = TRUE;
        }
        else if(strcmp(argv[i], "queryback") == 0)
        {
            println("queryback mode enabled");
            g_queryback = TRUE;
        }
        else if(strcmp(argv[i], "tcp") == 0)
        {
            println("tcp mode enabled");
            g_tcp = TRUE;
        }
        else if(strcmp(argv[i], "no-spa") == 0)
        {
            println("subdelegation delete by rrset: disabled");
            g_spa = FALSE;
        }
        else if(strcmp(argv[i], "no-spa-mix") == 0)
        {
            println("subdelegation delete by rrset, add/del mixed: disabled");
            g_spa_mix = FALSE;
        }
        else if(strcmp(argv[i], "no-sp") == 0)
        {
            println("subdelegation delete by record: disabled");
            g_sp = FALSE;
        }
        else if(strcmp(argv[i], "no-sp-mix") == 0)
        {
            println("subdelegation delete by record, add/del mixed: disabled");
            g_sp_mix = FALSE;
        }
        else if(strcmp(argv[i], "no-sp-delall") == 0)
        {
            println("subdelegation delete all rrsets: disabled");
            g_sp_delall = FALSE;
        }
        else
        {
            help();
            return EXIT_FAILURE;
        }
    }

    if(ISOK(ret = update_test(ip, zone, mode, nocleanup)))
    {
        formatln("all tests succeeded (%08x)", ret);
    }
    else
    {
        formatln("some test has failed (%p)", ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
