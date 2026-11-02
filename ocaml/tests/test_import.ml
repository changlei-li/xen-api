(*
 * Copyright (c) Cloud Software Group, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

(* Tests for [Import.with_open_archive], which opens the tar stream of a VM
   metadata / XVA import off a socket, hands the caller the [ova.xml] entry, and
   (with [~drain]) consumes the rest of the request body so the connection can
   be closed cleanly.

   The cases feed an in-memory archive, in both ustar and pax form, followed by
   trailing sentinel bytes:
   - the [ova.xml] content must round-trip, for ustar and for pax (whose real
     header is preceded by an extra extended-header record that the tar reader
     consumes transparently);
   - without [~drain] the end-of-archive markers are left on the socket;
   - with [~drain] exactly Content-Length is consumed, so the sentinel is left
     untouched. For pax this is the CA-432853 regression: the old drain did not
     count the extended-header record, over-read, and blocked on
     PUT /import_metadata. *)

module Direct = struct
  type 'a t = 'a

  let ( >>= ) x f = f x

  let return x = x
end

module Buffer_writer = struct
  type out_channel = Buffer.t

  type 'a t = 'a

  let really_write buf cs = Buffer.add_string buf (Cstruct.to_string cs)
end

module Header_writer = Tar.HeaderWriter (Direct) (Buffer_writer)

let empty_extended =
  Tar.Header.Extended.
    {
      access_time= None
    ; charset= None
    ; comment= None
    ; group_id= None
    ; gname= None
    ; header_charset= None
    ; link_path= None
    ; mod_time= None
    ; path= None
    ; file_size= None
    ; user_id= None
    ; uname= None
    }

(* Build an in-memory tar archive holding a single [ova.xml] entry. When [pax]
   is set the entry carries a pax extended header. *)
let make_archive ~pax content =
  let buf = Buffer.create 4096 in
  let size = Int64.of_int (String.length content) in
  let base = Tar.Header.make Xapi_globs.ova_xml_filename size in
  let hdr =
    if pax then
      {
        base with
        Tar.Header.extended= Some {empty_extended with mod_time= Some 1L}
      }
    else
      base
  in
  Header_writer.write hdr buf ;
  Buffer.add_string buf content ;
  Buffer.add_string buf (Cstruct.to_string (Tar.Header.zero_padding hdr)) ;
  (* two zero blocks mark the end of the archive *)
  Buffer.add_string buf (String.make (2 * Tar.Header.length) '\000') ;
  Buffer.contents buf

let read_all fd =
  let bufsz = 4096 in
  let b = Bytes.create bufsz in
  let out = Buffer.create bufsz in
  let rec loop () =
    let n = Unix.read fd b 0 bufsz in
    if n > 0 then (
      Buffer.add_subbytes out b 0 n ;
      loop ()
    )
  in
  loop () ; Buffer.contents out

let content = "<value>regression-test-ova-xml</value>"

(* Feed [make_archive ~pax content] plus a trailing sentinel through
   [with_open_archive ~drain], returning the ova.xml it handed back and the
   number of bytes still unread on the socket afterwards. *)
let run ~pax ~drain =
  let archive = make_archive ~pax content in
  (* Trailing bytes a correct drain must leave untouched. *)
  let sentinel = String.make 4096 'S' in
  let rd, wr = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Xapi_stdext_unix.Unixext.really_write_string wr (archive ^ sentinel) ;
  let xml =
    Import.with_open_archive rd
      ~length:(Int64.of_int (String.length archive))
      ~drain
      (fun xml _fd -> xml)
  in
  Unix.close wr ;
  let leftover = read_all rd in
  Unix.close rd ;
  (xml, String.length sentinel, String.length leftover)

let test_read ~pax () =
  let xml, sentinel_len, leftover_len = run ~pax ~drain:false in
  Alcotest.(check string) "ova.xml content round-trips" content xml ;
  (* Without [~drain] the end-of-archive markers stay on the socket. *)
  Alcotest.(check int)
    "no draining without ~drain"
    ((2 * Tar.Header.length) + sentinel_len)
    leftover_len

let test_drain ~pax () =
  let xml, sentinel_len, leftover_len = run ~pax ~drain:true in
  Alcotest.(check string) "ova.xml content round-trips" content xml ;
  Alcotest.(check int)
    "drain consumes exactly Content-Length, sentinel intact" sentinel_len
    leftover_len

let test =
  [
    Alcotest.test_case "with_open_archive reads ustar ova.xml" `Quick
      (test_read ~pax:false)
  ; Alcotest.test_case "with_open_archive reads pax ova.xml" `Quick
      (test_read ~pax:true)
  ; Alcotest.test_case "with_open_archive ~drain drains ustar to Content-Length"
      `Quick (test_drain ~pax:false)
  ; Alcotest.test_case
      "with_open_archive ~drain drains pax to Content-Length (CA-432853)" `Quick
      (test_drain ~pax:true)
  ]
