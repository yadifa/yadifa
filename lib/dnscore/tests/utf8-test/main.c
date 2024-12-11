/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

#include "yatest.h"
#include "dnscore/bytearray_input_stream.h"
#include <dnscore/dnscore.h>
#include <dnscore/utf8.h>

// sample taken from: https://www.kermitproject.org/utf8.html
// I've added the "clé de sol" to cover the high range of the UTF-8 character set too.

static const uint8_t utf8_multilingual_sample[] =
    "English: The quick brown fox jumps over the lazy dog.\n"
    "Jamaican: Chruu, a kwik di kwik brong fox a jomp huova di liezi daag de, yu no siit?\n"
    "Irish: \"An ḃfuil do ċroí ag bualaḋ ó ḟaitíos an ġrá a ṁeall lena ṗóg éada ó ṡlí do leasa ṫú?\" \"D'ḟuascail Íosa "
    "Úrṁac na hÓiġe Beannaiṫe pór Éava agus Áḋaiṁ.\"\n"
    "Dutch: Pa's wĳze lynx bezag vroom het fikse aquaduct.\n"
    "German: Falsches Üben von Xylophonmusik quält jeden größeren Zwerg. (1)\n"
    "German: Im finſteren Jagdſchloß am offenen Felsquellwaſſer patzte der affig-flatterhafte kauzig-höf\u200Cliche "
    "Bäcker über ſeinem verſifften kniffligen C-Xylophon. (2)\n"
    "Norwegian: Blåbærsyltetøy (\"blueberry jam\", includes every extra letter used in Norwegian).\n"
    "Swedish: Flygande bäckasiner söka strax hwila på mjuka tuvor.\n"
    "Icelandic: Sævör grét áðan því úlpan var ónýt.\n"
    "Finnish: (5) Törkylempijävongahdus (This is a perfect pangram, every letter appears only once. Translating it is "
    "an art on its own, but I'll say \"rude lover's yelp\". :-D)\n"
    "Finnish: (5) Albert osti fagotin ja töräytti puhkuvan melodian. (Albert bought a bassoon and hooted an impressive "
    "melody.)\n"
    "Finnish: (5) On sangen hauskaa, että polkupyörä on maanteiden jokapäiväinen ilmiö. (It's pleasantly amusing, that "
    "the bicycle is an everyday sight on the roads.)\n"
    "Polish: Pchnąć w tę łódź jeża lub osiem skrzyń fig.\n"
    "Czech: Příliš žluťoučký kůň úpěl ďábelské ódy.\n"
    "Slovak: Starý kôň na hŕbe kníh žuje tíško povädnuté ruže, na stĺpe sa ďateľ učí kvákať novú ódu o živote.\n"
    "Slovenian: Šerif bo za domačo vajo spet kuhal žgance.\n"
    "Greek (monotonic): ξεσκεπάζω την ψυχοφθόρα βδελυγμία\n"
    "Greek (polytonic): ξεσκεπάζω τὴν ψυχοφθόρα βδελυγμία\n"
    "Russian: Съешь же ещё этих мягких французских булок да выпей чаю.\n"
    "Russian: В чащах юга жил-был цитрус? Да, но фальшивый экземпляр! ёъ.\n"
    "Bulgarian: Жълтата дюля беше щастлива, че пухът, който цъфна, замръзна като гьон.\n"
    "Sami (Northern): Vuol Ruoŧa geđggiid leat máŋga luosa ja čuovžža.\n"
    "Hungarian: Árvíztűrő tükörfúrógép.\n"
    "Spanish: El pingüino Wenceslao hizo kilómetros bajo exhaustiva lluvia y frío, añoraba a su querido cachorro.\n"
    "Spanish: Volé cigüeña que jamás cruzó París, exhibe flor de kiwi y atún.\n"
    "Portuguese: O próximo vôo à noite sobre o Atlântico, põe freqüentemente o único médico. (3)\n"
    "French: Les naïfs ægithales hâtifs pondant à Noël où il gèle sont sûrs d'être déçus en voyant leurs drôles d'œufs "
    "abîmés.\n"
    "Esperanto: Eĥoŝanĝo ĉiuĵaŭde\n"
    "Esperanto: Laŭ Ludoviko Zamenhof bongustas freŝa ĉeĥa manĝaĵo kun spicoj.\n"
    "Hebrew: זה כיף סתם לשמוע איך תנצח קרפד עץ טוב בגן.\n"
    "Japanese (Hiragana):\n"
    "いろはにほへど　ちりぬるを\n"
    "わがよたれぞ　つねならむ\n"
    "うゐのおくやま　けふこえて\n"
    "あさきゆめみじ　ゑひもせず\n"
    "\360\235\204\236\n"; // = f09d849e = clé de sol

static int utf8_next_uchar_test()
{
    dnscore_init();
    const uint8_t *text = utf8_multilingual_sample;
    uint8_t        tmp_text[32];
    while(*text != '\0')
    {
        uchar_t chr = 0;
        int     chr_len = utf8_next_uchar(text, &chr);
        if(chr_len <= 0)
        {
            yatest_err("utf8_next_uchar <= 0 (%i)", chr_len);
            return 1;
        }
        if(chr_len > 4)
        {
            yatest_err("utf8_next_uchar > 4 (%i)", chr_len);
            return 1;
        }

        //

        uchar_t chr_nocheck = 0;
        int     chr_nocheck_len = utf8_next_char32_nocheck(text, &chr_nocheck);

        if(chr_len != chr_nocheck_len)
        {
            yatest_err("utf8_next_char32 and utf8_next_char32_nocheck are disagreeing for %08x", chr);
            return 1;
        }

        //

        uint16_t chr16 = 0;
        int      chr16_len = utf8_next_char16(text, &chr16);
        if(chr <= UINT16_MAX)
        {
            if(chr_len != chr16_len)
            {
                yatest_err("utf8_next_char32 and utf8_next_char16 are disagreeing for %08x", chr);
                return 1;
            }

            //

            uint16_t chr16_nocheck = 0;
            int      chr16_nocheck_len = utf8_next_char16_nocheck(text, &chr16_nocheck);
            if(chr16_len != chr16_nocheck_len)
            {
                utf8_next_char16_nocheck(text, &chr16_nocheck);
                yatest_err("utf8_next_char16 and utf8_next_char16_nocheck are disagreeing for %08x (%i vs %i) = %04x = %04x", chr, chr16_len, chr16_nocheck_len, chr16, chr16_nocheck);
                yatest_hexdump_err(text, text + chr_len);
                return 1;
            }
        }
        else
        {
            if(chr16_len != 0)
            {
                yatest_err("utf8_next_char16 should have returned 0 for %08x", chr);
                return 1;
            }
        }

        //

        text += chr_len;

        // encode

        int chr_expected_encoded_len = utf8_encode_char32_len(chr);
        if(chr_expected_encoded_len == 0)
        {
            yatest_err("utf8_encode_char32_len %08x failed", chr);
            return 1;
        }

        int chr_encoded_len = utf8_encode_char32(chr, tmp_text);
        if(chr_encoded_len == 0)
        {
            yatest_err("utf8_encode_char32 %08x failed", chr);
            return 1;
        }

        if(chr_encoded_len != chr_expected_encoded_len)
        {
            yatest_err("expected encoded len %i, encoded len %i", chr, chr_expected_encoded_len, chr_encoded_len);
            return 1;
        }

        fwrite(tmp_text, chr_encoded_len, 1, stdout);
        fflush(stdout);
    }
    dnscore_finalize();
    return 0;
}

static int utf8_read_line_test()
{
    int     ret;
    uchar_t line_buffer[1024];
    dnscore_init();
    input_stream_t bais;
    bytearray_input_stream_init(&bais, utf8_multilingual_sample, sizeof(utf8_multilingual_sample) - 1, false);
    for(;;)
    {
        ret = utf8_read_line(&bais, line_buffer, sizeof(line_buffer));
        if(ret < 0)
        {
            yatest_err("utf8_read_line failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        if(ret == 0)
        {
            break;
        }
        ret = utf8_write_unicode(termout, line_buffer, ret);
        if(ret < 0)
        {
            yatest_err("utf8_write_unicode failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
    }
    dnscore_finalize();
    return 0;
}

static int utf8_strchr_test()
{
    dnscore_init();
    const uint8_t *text = utf8_multilingual_sample + 189;
    while(*text != '\0')
    {
        const uint8_t *letterp;
        const uint8_t *src;
        uchar_t        chr = 0;
        int            chr_len = utf8_next_uchar(text, &chr);
        src = utf8_multilingual_sample;
        for(;;)
        {
            letterp = utf8_strchr(src, chr);
            if(letterp == NULL)
            {
                if(chr <= 127)
                {
                    yatest_err("char %08x=%c from text[%lli] got unexpected NULL", chr, chr, text - utf8_multilingual_sample);
                }
                else
                {
                    yatest_err("char %08x from text[%lli] got unexpected NULL", chr, text - utf8_multilingual_sample);
                }
                return 1;
            }
            if(letterp < text)
            {
                src = letterp + chr_len;
                continue;
            }
            break;
        }
        if(letterp != text)
        {
            if(chr <= 127)
            {
                yatest_err("char %08x=%c from text[%lli] not found", chr, chr, text - utf8_multilingual_sample);
            }
            else
            {
                yatest_err("char %08x from text[%lli] not found", chr, text - utf8_multilingual_sample);
            }
            return 1;
        }

        fwrite(text, chr_len, 1, stdout);
        fflush(stdout);

        text += chr_len;
    }
    dnscore_finalize();
    return 0;
}

static int utf8_strcmp_test()
{
    dnscore_init();
    if(utf8_strcmp(utf8_multilingual_sample, utf8_multilingual_sample) != 0)
    {
        yatest_err("unexpected 0");
        return 1;
    }
    if(utf8_strcmp(utf8_multilingual_sample, utf8_multilingual_sample + 1) == 0)
    {
        yatest_err("unexpected != 0");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int utf8_memcmp_test()
{
    dnscore_init();
    if(utf8_memcmp(utf8_multilingual_sample, sizeof(utf8_multilingual_sample), utf8_multilingual_sample, sizeof(utf8_multilingual_sample)) != 0)
    {
        yatest_err("unexpected 0");
        return 1;
    }
    if(utf8_memcmp(utf8_multilingual_sample, sizeof(utf8_multilingual_sample), utf8_multilingual_sample + 1, sizeof(utf8_multilingual_sample) - 1) == 0)
    {
        yatest_err("unexpected != 0");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(utf8_next_uchar_test)
YATEST(utf8_read_line_test)
YATEST(utf8_strchr_test)
YATEST(utf8_strcmp_test)
YATEST(utf8_memcmp_test)
YATEST_TABLE_END
