// This is a part of rust-encoding.
// Copyright (c) 2013, Kang Seonghoon.
// See README.md and LICENSE.txt for details.

/*!
 * An alternative API compatible to WHATWG Encoding standard. 
 *
 * WHATWG Encoding standard, compared to the native interface provided by rust-encoding, requires
 * both intentionally different naming of encodings (for example, "EUC-KR" in the standard is
 * actually Windows code page 949) and that the decoder error only consumes one byte. While
 * rust-encoding itself does not implement the exact algorithm specified by the Encoding standard,
 * it is trivial to support the WHATWG Encoding interface for the sake of completeness.
 *
 * That said, why does rust-encoding implements its own standard? The main reason is that
 * rust-encoding provides much wider options for error recovery, and having as many bytes in
 * the problem as possible is beneficial in this regard. Rust-encoding still does *not* return every
 * byte in the problem to limit the memory consumption, and its definition of the error range is
 * at best arbitrary (it is not wrong though).
 */

use std::util::swap;
use all;
use types;

mod whatwg_encodings {
    use all;
    use types::*;
    use codec::singlebyte::SingleByteEncoding;

    /// Replacement encoding used to solve a particular attack vector due to mismatching server and
    /// client supports for encodings. It is rarely useful outside.
    #[deriving(Clone)]
    struct ReplacementEncoding;

    impl Encoding for ReplacementEncoding {
        pub fn name(&self) -> ~str { ~"replacement" }
        pub fn encoder(&self) -> ~Encoder { all::UTF_8.encoder() }
        pub fn decoder(&self) -> ~Decoder { all::ERROR.decoder() }
        pub fn preferred_replacement_seq(&self) -> ~[u8] { ~[0x3f] /* "?" */ }
    }

    pub static REPLACEMENT: &'static ReplacementEncoding = &ReplacementEncoding;

    #[inline]
    fn x_user_defined_forward(code: u8) -> u16 {
        0xf780 + (code as u16)
    }

    #[inline]
    fn x_user_defined_backward(code: u16) -> u8 {
        if 0xf780 <= code && code <= 0xf7ff {(code - 0xf780) as u8} else {0xff}
    }

    pub static X_USER_DEFINED: &'static SingleByteEncoding = &SingleByteEncoding {
        name: "x-user-defined",
        index_forward: x_user_defined_forward,
        index_backward: x_user_defined_backward,
    };
}

/// Returns an encoding and canonical name from given label if any. Follows WHATWG Encoding
/// Standard "get an encoding" algorithm.
pub fn get_encoding(label: &str) -> Option<(&'static types::Encoding, &'static str)> {
    match label.trim().to_ascii().to_lower().to_str_ascii() {
        ~"unicode-1-1-utf-8" |
        ~"utf-8" |
        ~"utf8" =>
            Some((all::UTF_8 as &'static types::Encoding, "utf-8")),
        ~"866" |
        ~"cp866" |
        ~"csibm866" |
        ~"ibm866" =>
            Some((all::IBM866 as &'static types::Encoding, "ibm866")),
        ~"csisolatin2" |
        ~"iso-8859-2" |
        ~"iso-ir-101" |
        ~"iso8859-2" |
        ~"iso88592" |
        ~"iso_8859-2" |
        ~"iso_8859-2:1987" |
        ~"l2" |
        ~"latin2" =>
            Some((all::ISO_8859_2 as &'static types::Encoding, "iso-8859-2")),
        ~"csisolatin3" |
        ~"iso-8859-3" |
        ~"iso-ir-109" |
        ~"iso8859-3" |
        ~"iso88593" |
        ~"iso_8859-3" |
        ~"iso_8859-3:1988" |
        ~"l3" |
        ~"latin3" =>
            Some((all::ISO_8859_3 as &'static types::Encoding, "iso-8859-3")),
        ~"csisolatin4" |
        ~"iso-8859-4" |
        ~"iso-ir-110" |
        ~"iso8859-4" |
        ~"iso88594" |
        ~"iso_8859-4" |
        ~"iso_8859-4:1988" |
        ~"l4" |
        ~"latin4" =>
            Some((all::ISO_8859_4 as &'static types::Encoding, "iso-8859-4")),
        ~"csisolatincyrillic" |
        ~"cyrillic" |
        ~"iso-8859-5" |
        ~"iso-ir-144" |
        ~"iso8859-5" |
        ~"iso88595" |
        ~"iso_8859-5" |
        ~"iso_8859-5:1988" =>
            Some((all::ISO_8859_5 as &'static types::Encoding, "iso-8859-5")),
        ~"arabic" |
        ~"asmo-708" |
        ~"csiso88596e" |
        ~"csiso88596i" |
        ~"csisolatinarabic" |
        ~"ecma-114" |
        ~"iso-8859-6" |
        ~"iso-8859-6-e" |
        ~"iso-8859-6-i" |
        ~"iso-ir-127" |
        ~"iso8859-6" |
        ~"iso88596" |
        ~"iso_8859-6" |
        ~"iso_8859-6:1987" =>
            Some((all::ISO_8859_6 as &'static types::Encoding, "iso-8859-6")),
        ~"csisolatingreek" |
        ~"ecma-118" |
        ~"elot_928" |
        ~"greek" |
        ~"greek8" |
        ~"iso-8859-7" |
        ~"iso-ir-126" |
        ~"iso8859-7" |
        ~"iso88597" |
        ~"iso_8859-7" |
        ~"iso_8859-7:1987" |
        ~"sun_eu_greek" =>
            Some((all::ISO_8859_7 as &'static types::Encoding, "iso-8859-7")),
        ~"csiso88598e" |
        ~"csisolatinhebrew" |
        ~"hebrew" |
        ~"iso-8859-8" |
        ~"iso-8859-8-e" |
        ~"iso-ir-138" |
        ~"iso8859-8" |
        ~"iso88598" |
        ~"iso_8859-8" |
        ~"iso_8859-8:1988" |
        ~"visual" =>
            Some((all::ISO_8859_8 as &'static types::Encoding, "iso-8859-8")),
        ~"csiso88598i" |
        ~"iso-8859-8-i" |
        ~"logical" =>
            Some((all::ISO_8859_8 as &'static types::Encoding, "iso-8859-8-i")),
        ~"csisolatin6" |
        ~"iso-8859-10" |
        ~"iso-ir-157" |
        ~"iso8859-10" |
        ~"iso885910" |
        ~"l6" |
        ~"latin6" =>
            Some((all::ISO_8859_10 as &'static types::Encoding, "iso-8859-10")),
        ~"iso-8859-13" |
        ~"iso8859-13" |
        ~"iso885913" =>
            Some((all::ISO_8859_13 as &'static types::Encoding, "iso-8859-13")),
        ~"iso-8859-14" |
        ~"iso8859-14" |
        ~"iso885914" =>
            Some((all::ISO_8859_14 as &'static types::Encoding, "iso-8859-14")),
        ~"csisolatin9" |
        ~"iso-8859-15" |
        ~"iso8859-15" |
        ~"iso885915" |
        ~"iso_8859-15" |
        ~"l9" =>
            Some((all::ISO_8859_15 as &'static types::Encoding, "iso-8859-15")),
        ~"iso-8859-16" =>
            Some((all::ISO_8859_16 as &'static types::Encoding, "iso-8859-16")),
        ~"cskoi8r" |
        ~"koi" |
        ~"koi8" |
        ~"koi8-r" |
        ~"koi8_r" =>
            Some((all::KOI8_R as &'static types::Encoding, "koi8-r")),
        ~"koi8-u" =>
            Some((all::KOI8_U as &'static types::Encoding, "koi8-u")),
        ~"csmacintosh" |
        ~"mac" |
        ~"macintosh" |
        ~"x-mac-roman" =>
            Some((all::MACINTOSH as &'static types::Encoding, "macintosh")),
        ~"dos-874" |
        ~"iso-8859-11" |
        ~"iso8859-11" |
        ~"iso885911" |
        ~"tis-620" |
        ~"windows-874" =>
            Some((all::WINDOWS_874 as &'static types::Encoding, "windows-874")),
        ~"cp1250" |
        ~"windows-1250" |
        ~"x-cp1250" =>
            Some((all::WINDOWS_1250 as &'static types::Encoding, "windows-1250")),
        ~"cp1251" |
        ~"windows-1251" |
        ~"x-cp1251" =>
            Some((all::WINDOWS_1251 as &'static types::Encoding, "windows-1251")),
        ~"ansi_x3.4-1968" |
        ~"ascii" |
        ~"cp1252" |
        ~"cp819" |
        ~"csisolatin1" |
        ~"ibm819" |
        ~"iso-8859-1" |
        ~"iso-ir-100" |
        ~"iso8859-1" |
        ~"iso88591" |
        ~"iso_8859-1" |
        ~"iso_8859-1:1987" |
        ~"l1" |
        ~"latin1" |
        ~"us-ascii" |
        ~"windows-1252" |
        ~"x-cp1252" =>
            Some((all::WINDOWS_1252 as &'static types::Encoding, "windows-1252")),
        ~"cp1253" |
        ~"windows-1253" |
        ~"x-cp1253" =>
            Some((all::WINDOWS_1253 as &'static types::Encoding, "windows-1253")),
        ~"cp1254" |
        ~"csisolatin5" |
        ~"iso-8859-9" |
        ~"iso-ir-148" |
        ~"iso8859-9" |
        ~"iso88599" |
        ~"iso_8859-9" |
        ~"iso_8859-9:1989" |
        ~"l5" |
        ~"latin5" |
        ~"windows-1254" |
        ~"x-cp1254" =>
            Some((all::WINDOWS_1254 as &'static types::Encoding, "windows-1254")),
        ~"cp1255" |
        ~"windows-1255" |
        ~"x-cp1255" =>
            Some((all::WINDOWS_1255 as &'static types::Encoding, "windows-1255")),
        ~"cp1256" |
        ~"windows-1256" |
        ~"x-cp1256" =>
            Some((all::WINDOWS_1256 as &'static types::Encoding, "windows-1256")),
        ~"cp1257" |
        ~"windows-1257" |
        ~"x-cp1257" =>
            Some((all::WINDOWS_1257 as &'static types::Encoding, "windows-1257")),
        ~"cp1258" |
        ~"windows-1258" |
        ~"x-cp1258" =>
            Some((all::WINDOWS_1258 as &'static types::Encoding, "windows-1258")),
        ~"x-mac-cyrillic" |
        ~"x-mac-ukrainian" =>
            Some((all::X_MAC_CYRILLIC as &'static types::Encoding, "x-mac-cyrillic")),
        /*
        ~"chinese" |
        ~"csgb2312" |
        ~"csiso58gb231280" |
        ~"gb2312" |
        ~"gb_2312" |
        ~"gb_2312-80" |
        ~"gbk" |
        ~"iso-ir-58" |
        ~"x-gbk" =>
            Some((all::GBK as &'static types::Encoding, "gbk")),
        ~"gb18030" =>
            Some((all::GB18030 as &'static types::Encoding, "gb18030")),
        ~"hz-gb-2312" =>
            Some((all::HZ_GB_2312 as &'static types::Encoding, "hz-gb-2312")),
        ~"big5" |
        ~"big5-hkscs" |
        ~"cn-big5" |
        ~"csbig5" |
        ~"x-x-big5" =>
            Some((all::BIG5 as &'static types::Encoding, "big5")),
        */
        ~"cseucpkdfmtjapanese" |
        ~"euc-jp" |
        ~"x-euc-jp" =>
            Some((all::EUC_JP as &'static types::Encoding, "euc-jp")),
        /*
        ~"csiso2022jp" |
        ~"iso-2022-jp" =>
            Some((all::ISO_2022_JP as &'static types::Encoding, "iso-2022-jp")),
        */
        ~"csshiftjis" |
        ~"ms_kanji" |
        ~"shift-jis" |
        ~"shift_jis" |
        ~"sjis" |
        ~"windows-31j" |
        ~"x-sjis" =>
            Some((all::SHIFT_JIS as &'static types::Encoding, "shift_jis")),
        ~"cseuckr" |
        ~"csksc56011987" |
        ~"euc-kr" |
        ~"iso-ir-149" |
        ~"korean" |
        ~"ks_c_5601-1987" |
        ~"ks_c_5601-1989" |
        ~"ksc5601" |
        ~"ksc_5601" |
        ~"windows-949" =>
            Some((all::WINDOWS_949 as &'static types::Encoding, "euc-kr")),
        /*
        ~"csiso2022kr" |
        ~"iso-2022-kr" =>
            Some((all::ISO_2022_KR as &'static types::Encoding, "iso-2022-kr")),
        */
        ~"iso-2022-cn" |
        ~"iso-2022-cn-ext" =>
            Some((whatwg_encodings::REPLACEMENT as &'static types::Encoding, "replacement")),
        /*
        ~"utf-16be" =>
            Some((all::UTF_16BE as &'static types::Encoding, "utf-16be")),
        ~"utf-16" |
        ~"utf-16le" =>
            Some((all::UTF_16LE as &'static types::Encoding, "utf-16le")),
        */
        ~"x-user-defined" =>
            Some((whatwg_encodings::X_USER_DEFINED as &'static types::Encoding, "x-user-defined")),
        _ => None
    }
}
