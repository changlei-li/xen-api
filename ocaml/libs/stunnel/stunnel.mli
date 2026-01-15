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

(** Thrown if we can't find the stunnel binary in the prescribed location *)
exception Stunnel_binary_missing

exception Stunnel_error of string

exception Stunnel_verify_error of string list

val crl_path : string

val timeoutidle : int option ref

type pid =
  | StdFork of int  (** we forked and exec'ed. This is the pid *)
  | FEFork of Forkhelpers.pidty  (** the forkhelpers module did it for us. *)
  | Nopid

val getpid : pid -> int

val debug_conf_of_bool : bool -> string

val debug_conf_of_env : unit -> string

type verify = VerifyPeer | CheckHost

type verification_config = {
    sni: string option
  ; verify: verify
  ; cert_bundle_path: string
}

(** Represents an active stunnel connection *)
type t = {
    mutable pid: pid
  ; fd: Safe_resources.Unixfd.t
  ; host: string
  ; port: int
  ; connected_time: float
        (** time when the connection opened, for 'early retirement' *)
  ; unique_id: int option
  ; mutable logfile: string
  ; verified: verification_config option
}

type stunnel_error =
  | Certificate_verify of string list
  | Stunnel of string
  | Unknown of string

module UnixSocketProxy : sig
  (** Handle for a long-running stunnel proxy that exposes TLS connection
      via a UNIX socket file *)
  type t

  val socket_path : t -> string
  (** Get the UNIX socket file path for connecting to the proxy.
      Use this path with HTTP clients (curl, urllib, etc.) to send traffic
      through the TLS tunnel. *)

  val start :
       verify_cert:verification_config option
    -> remote_host:string
    -> remote_port:int
    -> ?unix_socket_path:string
    -> unit
    -> (t, stunnel_error) result
  (** Start a long-running stunnel proxy listening on a UNIX socket.
      Returns Ok handle that must be explicitly stopped with [stop].
      The stunnel process will continue running until stopped, allowing
      multiple clients to connect to the UNIX socket over time.
      Returns Error if stunnel fails to start or initialize.
      
      If [unix_socket_path] is not provided, a unique path will be generated
      automatically in /var/run with the format:
      stunnel-proxy-{host}-{port}-{uuid}.sock
      
      Note: This only starts the proxy - it does NOT verify the certificate.
      The TLS connection and certificate verification happen when a client
      actually connects through the socket. Use the standalone [check_cert] 
      function to verify the remote server's certificate before starting the 
      proxy if needed. *)

  val stop : t -> unit
  (** Stop a running stunnel proxy and clean up resources.
      This kills the stunnel process and removes the socket and log files. *)

  val diagnose : t -> (unit, stunnel_error) result
  (** Diagnose the status of a running stunnel proxy by checking its logfile.
      Returns Ok () if no errors found, Error with details otherwise. *)

  val with_proxy :
       verify_cert:verification_config option
    -> remote_host:string
    -> remote_port:int
    -> ?unix_socket_path:string
    -> (t -> ('a, stunnel_error) result)
    -> ('a, stunnel_error) result
  (** Start a proxy, execute a function with it, and automatically stop it.
      The proxy is guaranteed to be stopped even if the function raises an exception.
      If [unix_socket_path] is not provided, a unique path will be generated.
      This is the preferred way to use the proxy for most use cases. *)
end

val fetch_server_cert : remote_host:string -> remote_port:int -> string option
(** Fetch the server certificate from a remote host.
    Uses openssl s_client to connect and retrieve the certificate in PEM format.
    This is useful for TOFU (Trust-On-First-Use) scenarios. *)

val check_cert :
     verify_cert:verification_config option
  -> remote_host:string
  -> remote_port:int
  -> (unit, stunnel_error) result
(** Check certificate verification using a temporary stunnel connection.
    Returns [Ok ()] if the certificate is valid according to the verification
    policy (VerifyPeer or CheckHost), or [Error] with details if verification fails.

    This creates an isolated, temporary stunnel connection solely for certificate 
    verification. The connection is automatically cleaned up after the check.

    This is useful for pre-flight certificate validation before starting a 
    long-running proxy, or for periodic re-validation of certificates. *)

val appliance : verification_config

val pool : verification_config

val external_host : string -> verification_config

val with_connect :
     ?unique_id:int
  -> ?use_fork_exec_helper:bool
  -> ?write_to_log:(string -> unit)
  -> verify_cert:verification_config option
  -> ?extended_diagnosis:bool
  -> string
  -> int
  -> (t -> 'b)
  -> 'b
(** Connects via stunnel (optionally via an external 'fork/exec' helper) to
    a host and port.
    NOTE: this does not guarantee the connection to the remote server actually works.
    For server-side connections, use Xmlrpcclient.get_reusable_stunnel instead.
*)

val disconnect : ?wait:bool -> ?force:bool -> t -> unit
(** Disconnects from stunnel and cleans up *)

val diagnose_failure : t -> unit

val test : string -> int -> unit

val move_out_exn : t -> t

val with_moved_exn : t -> (t -> 'd) -> 'd

val safe_release : t -> unit

val with_client_proxy_systemd_service :
     verify_cert:verification_config option
  -> remote_host:string
  -> remote_port:int
  -> local_host:string
  -> local_port:int
  -> service:string
  -> (unit -> 'a)
  -> 'a

val with_client_proxy_unix_socket :
     verify_cert:verification_config option
  -> remote_host:string
  -> remote_port:int
  -> unix_socket_path:string
  -> (diagnose_stunnel:(unit -> (unit, stunnel_error) result) -> 'a)
  -> 'a
(** Establish a connection to the specified [remote_host] and [remote_port]
    via a stunnel process, using a UNIX socket file at [unix_socket_path] to
    accept non-TLS traffic. The provided function (last parameter) can send
    traffic through the [unix_socket_path] to the [remote_host] and [remote_port]
    and check the stunnel error by invoking [diagnose_stunnel ()]. *)
