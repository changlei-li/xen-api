(*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
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

module Mutex = struct
  include Mutex

  (** execute the function f with the mutex hold *)
  let execute lock f =
    Mutex.lock lock ;
    let r = try f () with exn -> Mutex.unlock lock ; raise exn in
    Mutex.unlock lock ; r
end

let get_thread_id () = try Thread.id (Thread.self ()) with _ -> -1

module IntMap = Map.Make (Int)

module ThreadLocalTable = struct
  (* The map values behave like stacks here, with shadowing as in Hashtbl.
     A Hashtbl is not used here, in order to avoid taking the lock in `find`. *)
  type 'a t = {mutable tbl: 'a list IntMap.t; m: Mutex.t}

  let make () =
    let tbl = IntMap.empty in
    let m = Mutex.create () in
    {tbl; m}

  let add t v =
    let id = get_thread_id () in
    Mutex.execute t.m (fun () ->
        t.tbl <-
          IntMap.update id
            (function Some v' -> Some (v :: v') | None -> Some [v])
            t.tbl
    )

  let remove t =
    let id = get_thread_id () in
    Mutex.execute t.m (fun () ->
        t.tbl <-
          IntMap.update id
            (function
              | Some [_] ->
                  None
              | Some (_hd :: tl) ->
                  Some tl
              | Some [] | None ->
                  None
              )
            t.tbl
    )

  let find t =
    let id = get_thread_id () in
    IntMap.find_opt id t.tbl
    |> Option.fold ~none:None ~some:(function v :: _ -> Some v | [] -> None)
end

type task = {desc: string; client: string option}

let tasks : task ThreadLocalTable.t = ThreadLocalTable.make ()

let names : string ThreadLocalTable.t = ThreadLocalTable.make ()

let gettimestring () =
  let time = Unix.gettimeofday () in
  let tm = Unix.gmtime time in
  let msec = time -. floor time in
  Printf.sprintf "%d%.2d%.2dT%.2d:%.2d:%.2d.%.3dZ|" (1900 + tm.Unix.tm_year)
    (tm.Unix.tm_mon + 1) tm.Unix.tm_mday tm.Unix.tm_hour tm.Unix.tm_min
    tm.Unix.tm_sec
    (int_of_float (1000.0 *. msec))

(** [escape str] efficiently escapes non-printable characters and in addition
    the backslash character. The function is efficient in the sense that it will
    allocate a new string only when necessary *)
let escape = Astring.String.Ascii.escape

let format include_time brand priority message =
  let id = get_thread_id () in
  let task, name =
    (* if the task's client is known, attach it to the task's name *)
    let name =
      match ThreadLocalTable.find names with Some x -> x | None -> ""
    in
    match ThreadLocalTable.find tasks with
    | None ->
        ("", name)
    | Some {desc; client= None} ->
        (desc, name)
    | Some {desc; client= Some client} ->
        (desc, Printf.sprintf "%s->%s" client name)
  in
  Printf.sprintf "[%s%5s||%d %s|%s|%s] %s"
    (if include_time then gettimestring () else "")
    priority id name task brand message

let print_debug = ref false

let log_to_stdout () = print_debug := true

module BrandLevelPair = struct
  type t = string * Syslog.level

  let compare = Stdlib.compare
end

module BrandLevelPairSet = Set.Make (BrandLevelPair)

let loglevel_m = Mutex.create ()

let logging_disabled_for = ref BrandLevelPairSet.empty

let default_loglevel = Syslog.Debug

let loglevel = ref default_loglevel

let disabled_modules () = BrandLevelPairSet.elements !logging_disabled_for

let is_disabled brand level =
  Syslog.is_masked ~threshold:!loglevel level
  || BrandLevelPairSet.mem (brand, level) !logging_disabled_for

let facility = ref Syslog.Daemon

let set_facility f = facility := f

let get_facility () = !facility

let output_log brand level priority s =
  if not (is_disabled brand level) then (
    let msg = format false brand priority s in
    if !print_debug then
      Printf.printf "%s\n%!" (format true brand priority s) ;
    Syslog.log (get_facility ()) level (escape msg)
  )

let logs_reporter =
  (* We convert Logs level to our own type to allow output_log to correctly
     filter logs coming from libraries using Logs *)
  let logs_to_syslog_level = function
    (* In practice we only care about Syslog.Debug,Warning,Info,Err, because
       these are the ones we use in the log functions in Debug.Make *)
    | Logs.Debug ->
        Syslog.Debug
    | Logs.Info ->
        Syslog.Info
    | Logs.Warning ->
        Syslog.Warning
    | Logs.Error ->
        Syslog.Err
    (* This is used by applications, not libraries - we should not get this in
       practice *)
    | Logs.App ->
        Syslog.Info
  in
  (* Ensure that logs from libraries will be displayed with the correct priority *)
  let logs_level_to_priority = function
    (* These string match the ones used by the logging functions in Debug.Make *)
    | Logs.Debug ->
        "debug"
    | Logs.Info ->
        "info"
    | Logs.Warning ->
        "warn"
    | Logs.Error ->
        "error"
    (* This is used by applications, not libraries - we should not get this in
       practice *)
    | Logs.App ->
        "app"
  in
  let report src level ~over k msgf =
    let formatter ?header ?tags fmt =
      ignore header ;
      ignore tags ;
      let buf = Buffer.create 80 in
      let buf_fmt = Format.formatter_of_buffer buf in
      let k _ =
        Format.pp_print_flush buf_fmt () ;
        let msg = Buffer.contents buf in
        (* We map the Logs source name to the "brand", so we have to use the
           name of the Logs source when enabling/disabling it *)
        let brand = Logs.Src.name src in
        output_log brand
          (logs_to_syslog_level level)
          (logs_level_to_priority level)
          msg ;
        over () ;
        k ()
      in
      Format.kfprintf k buf_fmt fmt
    in
    msgf formatter
  in
  {Logs.report}

let init_logs () =
  Logs.set_reporter logs_reporter ;
  (* [output_log] will do the actual filtering based on levels, but we only
     consider messages of level warning and above from libraries, to avoid
     calling [output_log] too often. *)
  Logs.set_level (Some Logs.Warning)

let rec split_c c str =
  try
    let i = String.index str c in
    String.sub str 0 i
    :: split_c c (String.sub str (i + 1) (String.length str - i - 1))
  with Not_found -> [str]

let log_backtrace_exn ?(level = Syslog.Err) ?(msg = "error") exn bt =
  (* We already got the backtrace in the `bt` argument when called from with_thread_associated.
     Log that, and remove `exn` from the backtraces table.
     If with_backtraces was not nested then looking at `bt` is the only way to get
     a proper backtrace, otherwise exiting from `with_backtraces` would've removed the backtrace
     from the thread-local backtraces table, and we'd always just log a message complaining about
     with_backtraces not being called, which is not true because it was.
  *)
  let bt' = Backtrace.remove exn in
  (* bt could be empty, but bt' would contain a non-empty warning, so compare 'bt' here *)
  let bt = if bt = Backtrace.empty then bt' else bt in
  let all = split_c '\n' Backtrace.(to_string_hum bt) in
  (* Write to the log line at a time *)
  output_log "backtrace" level msg
    (Printf.sprintf "Raised %s" (Printexc.to_string exn)) ;
  List.iter (output_log "backtrace" level msg) all

let log_backtrace_internal ?level ?msg e _bt =
  Backtrace.is_important e ;
  log_backtrace_exn ?level ?msg e (Backtrace.remove e)

let log_backtrace e bt = log_backtrace_internal e bt

let with_thread_associated ?client ?(quiet = false) desc f x =
  ThreadLocalTable.add tasks {desc; client} ;
  let result =
    Backtrace.with_backtraces (fun () ->
        try f x with e -> Backtrace.is_important e ; raise e
    )
  in
  ThreadLocalTable.remove tasks ;
  match result with
  | `Ok result ->
      result
  | `Error (exn, bt) ->
      (* This function is a top-level exception handler typically used on fresh
         threads. This is the last chance to do something with the backtrace *)
      if not quiet then (
        (* It would seem that a Backtrace.is_important would be missing here.
           But in fact it has actually been called in [let result] above,
           so calling it again is not necessary.
        *)
        output_log "backtrace" Syslog.Err "error"
          (Printf.sprintf "%s failed with exception %s" desc
             (Printexc.to_string exn)
          ) ;
        log_backtrace_exn exn bt
      ) ;
      raise exn

let with_thread_named name f x =
  ThreadLocalTable.add names name ;
  try
    let result = f x in
    ThreadLocalTable.remove names ;
    result
  with e ->
    Backtrace.is_important e ;
    ThreadLocalTable.remove names ;
    raise e

module type BRAND = sig
  val name : string
end

let all_levels =
  [Syslog.Debug; Syslog.Info; Syslog.Warning; Syslog.Err; Syslog.Crit]

let add_to_stoplist brand level =
  logging_disabled_for :=
    BrandLevelPairSet.add (brand, level) !logging_disabled_for

let disable ?level brand =
  let levels = match level with None -> all_levels | Some l -> [l] in
  Mutex.execute loglevel_m (fun () -> List.iter (add_to_stoplist brand) levels)

let set_level level = Mutex.execute loglevel_m (fun () -> loglevel := level)

module type DEBUG = sig
  val debug : ('a, unit, string, unit) format4 -> 'a

  val warn : ('a, unit, string, unit) format4 -> 'a

  val info : ('a, unit, string, unit) format4 -> 'a

  val error : ('a, unit, string, unit) format4 -> 'a

  val critical : ('a, unit, string, unit) format4 -> 'a

  val audit : ?raw:bool -> ('a, unit, string, string) format4 -> 'a

  val log_backtrace : exn -> unit

  val log_and_ignore_exn : (unit -> unit) -> unit
end

module Make =
functor
  (Brand : BRAND)
  ->
  struct
    let output level priority (fmt : ('a, unit, string, 'b) format4) =
      Printf.ksprintf
        (fun s ->
          if not (is_disabled Brand.name level) then
            output_log Brand.name level priority s
        )
        fmt

    let debug fmt = output Syslog.Debug "debug" fmt

    let warn fmt = output Syslog.Warning "warn" fmt

    let info fmt = output Syslog.Info "info" fmt

    let error fmt = output Syslog.Err "error" fmt

    let critical fmt = output Syslog.Crit "critical" fmt

    let audit ?(raw = false) (fmt : ('a, unit, string, 'b) format4) =
      Printf.ksprintf
        (fun s ->
          let msg = if raw then s else format true Brand.name "audit" s in
          Syslog.log Syslog.Local6 Syslog.Info (escape msg) ;
          msg
        )
        fmt

    let log_backtrace exn =
      let level = Syslog.Debug in
      if not (is_disabled Brand.name level) then
        log_backtrace_internal ~level exn ()

    let log_and_ignore_exn f =
      try f ()
      with e -> log_backtrace_internal ~level:Syslog.Debug ~msg:"debug" e ()
  end

module Pp = struct
  let mtime_span () = Fmt.to_to_string Mtime.Span.pp

  let signal () = Fmt.(to_to_string Dump.signal)
end
