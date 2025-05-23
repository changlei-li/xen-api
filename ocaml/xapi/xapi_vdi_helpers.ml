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
(**
 * @group Storage
*)

open Client
open Xapi_database.Db_cache_types
module Redo_log = Xapi_database.Redo_log

let with_lock = Xapi_stdext_threads.Threadext.Mutex.execute

module Unixext = Xapi_stdext_unix.Unixext

module D = Debug.Make (struct let name = "xapi_vdi_helpers" end)

open D

let all_ops = API.vdi_operations__all

(* CA-26514: Block operations on 'unmanaged' VDIs *)
let assert_managed ~__context ~vdi =
  if not (Db.VDI.get_managed ~__context ~self:vdi) then
    raise
      (Api_errors.Server_error (Api_errors.vdi_not_managed, [Ref.string_of vdi]))

(* Database replication to metadata VDIs. *)
let redo_log_lifecycle_mutex = Mutex.create ()

let metadata_replication :
    (API.ref_VDI, API.ref_VBD * [`RW] Redo_log.redo_log) Hashtbl.t =
  Hashtbl.create Xapi_globs.redo_log_max_instances

let get_master_dom0 ~__context =
  let master = Helpers.get_master ~__context in
  Db.Host.get_control_domain ~__context ~self:master

(* Unplug and destroy any existing VBDs owned by the VDI. *)
let destroy_all_vbds ~__context ~vdi =
  let existing_vbds = Db.VDI.get_VBDs ~__context ~self:vdi in
  Helpers.call_api_functions ~__context (fun rpc session_id ->
      List.iter
        (fun vbd ->
          ( if Client.VBD.get_currently_attached ~session_id ~rpc ~self:vbd then
              try
                (* In the case of HA failover, attempting to unplug the previous master's VBD will timeout as the host is uncontactable. *)
                Attach_helpers.safe_unplug rpc session_id vbd
              with
              | Api_errors.Server_error (code, _)
              when code = Api_errors.cannot_contact_host
              ->
                debug
                  "VBD.unplug attempt on metadata VDI %s timed out - assuming \
                   that this is an HA failover and that the previous master is \
                   now dead."
                  (Db.VDI.get_uuid ~__context ~self:vdi)
          ) ;
          (* Meanwhile, HA should mark the previous master as dead and set the VBD as detached. *)
          (* If the VBD is not detached by now, VBD.destroy will fail and we will give up. *)
          Client.VBD.destroy ~rpc ~session_id ~self:vbd
        )
        existing_vbds
  )

(* Create and plug a VBD from the VDI, then create a redo log and point it at the block device. *)
let enable_database_replication ~__context ~get_vdi_callback =
  with_lock redo_log_lifecycle_mutex (fun () ->
      (* Check that the number of metadata redo_logs isn't already at the limit. *)
      (* There should never actually be more redo_logs than the limit! *)
      if
        Hashtbl.length metadata_replication >= Xapi_globs.redo_log_max_instances
      then
        raise
          (Api_errors.Server_error (Api_errors.no_more_redo_logs_allowed, [])) ;
      let vdi = get_vdi_callback () in
      let vdi_uuid = Db.VDI.get_uuid ~__context ~self:vdi in
      if Hashtbl.mem metadata_replication vdi then
        debug "Metadata is already being replicated to VDI %s" vdi_uuid
      else (
        debug "Attempting to enable metadata replication to VDI %s" vdi_uuid ;
        let dom0 = get_master_dom0 ~__context in
        (* We've established that metadata is not being replicated to this VDI, so it should be safe to do this. *)
        destroy_all_vbds ~__context ~vdi ;
        (* Create and plug vbd *)
        let vbd =
          Helpers.call_api_functions ~__context (fun rpc session_id ->
              let vbd =
                Client.VBD.create ~rpc ~session_id ~vM:dom0 ~empty:false
                  ~vDI:vdi ~userdevice:"autodetect" ~bootable:false ~mode:`RW
                  ~_type:`Disk ~unpluggable:true ~qos_algorithm_type:""
                  ~qos_algorithm_params:[] ~other_config:[] ~device:""
                  ~currently_attached:false
              in
              Client.VBD.plug ~rpc ~session_id ~self:vbd ;
              vbd
          )
        in
        (* This needs to be done in a thread, otherwise the redo_log will hang when attempting the DB write. *)
        let state_change_callback =
          Some
            (fun new_state ->
              ignore
                (Thread.create
                   (fun () ->
                     Db.VDI.set_metadata_latest ~__context ~self:vdi
                       ~value:new_state
                   )
                   ()
                )
            )
        in
        (* Enable redo_log and point it at the new device *)
        let log_name = Printf.sprintf "DR redo log for VDI %s" vdi_uuid in
        let log = Redo_log.create_rw ~name:log_name ~state_change_callback in
        let device = Db.VBD.get_device ~__context ~self:vbd in
        try
          Redo_log.enable_block_and_flush
            (Context.database_of __context |> Xapi_database.Db_ref.get_database)
            log ("/dev/" ^ device) ;
          Hashtbl.add metadata_replication vdi (vbd, log) ;
          let vbd_uuid = Db.VBD.get_uuid ~__context ~self:vbd in
          Db.VDI.set_metadata_latest ~__context ~self:vdi ~value:true ;
          debug "Redo log started on VBD %s" vbd_uuid
        with e ->
          Redo_log.shutdown log ;
          Redo_log.delete log ;
          Helpers.call_api_functions ~__context (fun rpc session_id ->
              Client.VBD.unplug ~rpc ~session_id ~self:vbd
          ) ;
          raise
            (Api_errors.Server_error
               (Api_errors.cannot_enable_redo_log, [Printexc.to_string e])
            )
      )
  )

(* Shut down the redo log, then unplug and destroy the VBD. *)
let disable_database_replication ~__context ~vdi =
  with_lock redo_log_lifecycle_mutex (fun () ->
      debug "Attempting to disable metadata replication on VDI [%s:%s]."
        (Db.VDI.get_name_label ~__context ~self:vdi)
        (Db.VDI.get_uuid ~__context ~self:vdi) ;
      match Hashtbl.find_opt metadata_replication vdi with
      | None ->
          debug "Metadata is not being replicated to this VDI."
      | Some (vbd, log) ->
          Redo_log.shutdown log ;
          Redo_log.disable log ;
          (* Check the recorded VBD still exists before trying to unplug and destroy it. *)
          if Db.is_valid_ref __context vbd then
            Helpers.call_api_functions ~__context (fun rpc session_id ->
                try
                  Attach_helpers.safe_unplug rpc session_id vbd ;
                  Client.VBD.destroy ~rpc ~session_id ~self:vbd
                with e ->
                  debug "Caught %s while trying to dispose of VBD %s."
                    (Printexc.to_string e) (Ref.string_of vbd)
            ) ;
          Hashtbl.remove metadata_replication vdi ;
          Redo_log.delete log ;
          Db.VDI.set_metadata_latest ~__context ~self:vdi ~value:false
  )

let database_open_mutex = Mutex.create ()

(* Extract a database from a VDI. *)
let database_ref_of_vdi ~__context ~vdi =
  let database_ref_of_device device =
    let log =
      Redo_log.create_ro ~name:"Foreign database redo log"
        ~state_change_callback:None
    in
    debug "Enabling redo_log with device reason [%s]" device ;
    Redo_log.enable_block_existing log device ;
    let db = Database.make (Datamodel_schema.of_datamodel ()) in
    let db_ref = Xapi_database.Db_ref.in_memory (Atomic.make db) in
    Redo_log_usage.read_from_redo_log log Xapi_globs.foreign_metadata_db db_ref ;
    Redo_log.delete log ;
    (* Upgrade database to the local schema. *)
    (* Reindex database to make sure is_valid_ref works. *)
    let ( ++ ) f g x = f (g x) in
    Xapi_database.(
      Db_ref.update_database db_ref
        (Db_upgrade.generic_database_upgrade
        ++ Database.reindex
        ++ Db_backend.blow_away_non_persistent_fields
             (Datamodel_schema.of_datamodel ())
        )
    ) ;
    db_ref
  in
  with_lock database_open_mutex (fun () ->
      Helpers.call_api_functions ~__context (fun rpc session_id ->
          Sm_fs_ops.with_block_attached_device __context rpc session_id vdi `RW
            database_ref_of_device
      )
  )

module VDI_CStruct = struct
  let magic_number = 0x7ada7adal

  let magic_number_offset = 0

  let version = 1l

  let version_offset = 4

  let length_offset = 8

  let data_offset = 12

  let vdi_format_length = 12 (* VDI format takes 12bytes *)

  let vdi_size = 4194304 (* 4MiB *)

  let default_offset = 0

  (* Set the magic number *)
  let set_magic_number cstruct =
    Cstruct.BE.set_uint32 cstruct magic_number_offset magic_number

  (* Get the magic number *)
  let get_magic_number cstruct =
    Cstruct.BE.get_uint32 cstruct magic_number_offset

  (* Set the version *)
  let set_version cstruct = Cstruct.BE.set_uint32 cstruct version_offset version

  (* Set the data length *)
  let set_data_length cstruct len =
    Cstruct.BE.set_uint32 cstruct length_offset len

  (* Get the data length *)
  let get_data_length cstruct = Cstruct.BE.get_uint32 cstruct length_offset

  (* Write the string to the cstruct *)
  let write cstruct text text_len =
    Cstruct.blit_from_string text default_offset cstruct data_offset text_len ;
    set_data_length cstruct (Int32.of_int text_len)

  (* Read the string from the cstruct *)
  let read cstruct =
    let curr_len = Int32.to_int (get_data_length cstruct) in
    let curr_text = Bytes.make curr_len '\000' in
    Cstruct.blit_to_bytes cstruct data_offset curr_text default_offset curr_len ;
    Bytes.unsafe_to_string curr_text

  (* Format the cstruct for the first time *)
  let format cstruct = set_magic_number cstruct ; set_version cstruct
end

let write_raw ~__context ~vdi ~text =
  ( if String.length text >= VDI_CStruct.(vdi_size - vdi_format_length) then
      let error_msg =
        Printf.sprintf "Cannot write %d bytes to raw VDI. Capacity = %d bytes"
          (String.length text)
          VDI_CStruct.(vdi_size - vdi_format_length)
      in
      failwith error_msg
  ) ;
  Helpers.call_api_functions ~__context (fun rpc session_id ->
      Sm_fs_ops.with_open_block_attached_device __context rpc session_id vdi `RW
        (fun fd ->
          let contents = Unixext.really_read_string fd VDI_CStruct.vdi_size in
          let cstruct = Cstruct.of_string contents in
          if VDI_CStruct.get_magic_number cstruct <> VDI_CStruct.magic_number
          then
            VDI_CStruct.format cstruct ;
          VDI_CStruct.write cstruct text (String.length text) ;
          Unix.ftruncate fd 0 ;
          ignore (Unixext.seek_to fd 0 : int) ;
          Unixext.really_write_string fd (VDI_CStruct.read cstruct)
      )
  )

let read_raw ~__context ~vdi =
  Helpers.call_api_functions ~__context (fun rpc session_id ->
      Sm_fs_ops.with_open_block_attached_device __context rpc session_id vdi `RW
        (fun fd ->
          let contents = Unixext.really_read_string fd VDI_CStruct.vdi_size in
          let cstruct = Cstruct.of_string contents in
          if VDI_CStruct.get_magic_number cstruct <> VDI_CStruct.magic_number
          then (
            debug
              "Attempted read from raw VDI but VDI not formatted: returning \
               None" ;
            None
          ) else
            Some (VDI_CStruct.read cstruct)
      )
  )
