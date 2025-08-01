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
 * @group API Messaging
*)

let finally = Xapi_stdext_pervasives.Pervasiveext.finally

open Client

module D = Debug.Make (struct let name = "message_forwarding" end)

open D

module Audit = Debug.Make (struct let name = "audit" end)

let info = Audit.debug

module PBDSet = Set.Make (struct
  type t = API.ref_PBD

  let compare = Stdlib.compare
end)

(**************************************************************************************)

(* WARNING: using persistent+cached connections with retries doesn't work for all messages.
   Examples:
   1. The callback in Pool.hello will fail with an emergency mode error
   2. The no-other masters check will take /ages/ if a host is offline
   So we have two rpc functions: one with retrying and one without.

   When doing "normal" calls where the host is expected to be live, we use the retry fn.
   When doing "unusual" calls (like pool hellos) where the host may well be down or
   marked as down, we use the basic non-retry kind.
*)

(* Use HTTP 1.0, don't use the connection cache and don't pre-verify the connection *)
let remote_rpc_no_retry _context hostname (task_opt : API.ref_task option) xml =
  let open Xmlrpc_client in
  let transport =
    SSL
      ( SSL.make ~verify_cert:(Stunnel_client.pool ())
          ?task_id:(Option.map Ref.string_of task_opt)
          ()
      , hostname
      , !Constants.https_port
      )
  in
  let tracing = Context.set_client_span _context in
  let http =
    xmlrpc ?task_id:(Option.map Ref.string_of task_opt) ~version:"1.0" "/"
    |> Helpers.TraceHelper.inject_span_into_req tracing
  in
  XMLRPC_protocol.rpc ~srcstr:"xapi" ~dststr:"dst_xapi" ~transport ~http xml

(* Use HTTP 1.1, use the stunnel cache and pre-verify the connection *)
let remote_rpc_retry _context hostname (task_opt : API.ref_task option) xml =
  let open Xmlrpc_client in
  let transport =
    SSL
      ( SSL.make ~verify_cert:(Stunnel_client.pool ()) ~use_stunnel_cache:true
          ?task_id:(Option.map Ref.string_of task_opt)
          ()
      , hostname
      , !Constants.https_port
      )
  in
  let tracing = Context.set_client_span _context in
  let http =
    xmlrpc ?task_id:(Option.map Ref.string_of task_opt) ~version:"1.1" "/"
    |> Helpers.TraceHelper.inject_span_into_req tracing
  in
  XMLRPC_protocol.rpc ~srcstr:"xapi" ~dststr:"dst_xapi" ~transport ~http xml

let call_slave_with_session remote_rpc_fn __context host
    (task_opt : API.ref_task option) f =
  let hostname = Db.Host.get_address ~__context ~self:host in
  let session_id =
    Xapi_session.login_no_password ~__context ~uname:None ~host ~pool:true
      ~is_local_superuser:true ~subject:Ref.null ~auth_user_sid:""
      ~auth_user_name:"" ~rbac_permissions:[]
  in
  finally
    (fun () -> f ~rpc:(remote_rpc_fn __context hostname task_opt) ~session_id)
    (fun () -> Xapi_session.destroy_db_session ~__context ~self:session_id)

let call_slave_with_local_session remote_rpc_fn __context host
    (task_opt : API.ref_task option) f =
  let hostname = Db.Host.get_address ~__context ~self:host in
  let session_id =
    Client.Session.slave_local_login
      ~rpc:(remote_rpc_fn __context hostname None)
      ~psecret:(Xapi_globs.pool_secret ())
  in
  finally
    (fun () -> f ~rpc:(remote_rpc_fn __context hostname task_opt) ~session_id)
    (fun () ->
      Client.Session.local_logout
        ~rpc:(remote_rpc_fn __context hostname None)
        ~session_id
    )

(* set the fields on the task record to indicate that forwarding has taken place and
   creates a task id for the slave to use *)
let set_forwarding_on_task ~__context ~host =
  if Context.task_in_database __context then (
    let rt = Context.get_task_id __context in
    Db.Task.set_forwarded ~__context ~self:rt ~value:true ;
    Db.Task.set_forwarded_to ~__context ~self:rt ~value:host ;
    Db.Task.set_resident_on ~__context ~self:rt ~value:host ;
    Some rt (* slave uses this task for progress/status etc. *)
  ) else
    None

let check_live ~__context h =
  (* assume that localhost is always live *)
  if
    true
    && Helpers.get_localhost ~__context <> h
    && not (Xapi_vm_helpers.is_host_live ~__context h)
  then
    raise (Api_errors.Server_error (Api_errors.host_offline, [Ref.string_of h]))

(* Forward op to one of the specified hosts if host is not localhost *)
let do_op_on_common ~local_fn ~__context ~host ~remote_fn f =
  try
    let localhost = Helpers.get_localhost ~__context in
    if localhost = host then
      local_fn ~__context
    else
      let task_opt = set_forwarding_on_task ~__context ~host in
      f __context host task_opt remote_fn
  with
  | ( Xmlrpc_client.Connection_reset
    | Http_client.Http_request_rejected _
    | Xmlrpc_client.Stunnel_connection_failed ) as e
  ->
    error
      "%s: Caught %s when contacting host %s; converting into \
       CANNOT_CONTACT_HOST"
      __FUNCTION__ (Printexc.to_string e) (Ref.string_of host) ;
    raise Api_errors.(Server_error (cannot_contact_host, [Ref.string_of host]))

(* regular forwarding fn, with session and live-check. Used by most calls, will
   use the connection cache. *)
(* we don't check "host.enabled" here, because for most messages we want to be able to forward
   them even when the host is disabled; vm.start_on and resume_on do their own check for enabled *)
let do_op_on ~local_fn ~__context ~host ~remote_fn =
  check_live ~__context host ;
  do_op_on_common ~local_fn ~__context ~host ~remote_fn
    (call_slave_with_session remote_rpc_retry)

(* with session but no live check. Used by the Pool.hello calling back ONLY
   Don't use the connection cache or retry logic. *)
let do_op_on_nolivecheck_no_retry ~local_fn ~__context ~host ~remote_fn =
  do_op_on_common ~local_fn ~__context ~host ~remote_fn
    (call_slave_with_session remote_rpc_no_retry)

(* with a local session and no checking. This is used for forwarding messages to hosts that
   we don't know are alive/dead -- e.g. the pool_emergency_* messages.
   Don't use the connection cache or retry logic. *)
let do_op_on_localsession_nolivecheck ~local_fn ~__context ~host ~remote_fn =
  do_op_on_common ~local_fn ~__context ~host ~remote_fn
    (call_slave_with_local_session remote_rpc_no_retry)

(* Map a function across a list, remove elements which throw an exception *)
let map_with_drop ?(doc = "performing unknown operation") f xs =
  let one x =
    try [f x]
    with e ->
      debug "Caught exception while %s in message forwarder: %s" doc
        (ExnHelper.string_of_exn e) ;
      []
  in
  List.concat_map one xs

(* Iterate a function across a list, ignoring applications which throw an exception *)
let iter_with_drop ?(doc = "performing unknown operation") f xs =
  let one x =
    try f x
    with e ->
      debug "Caught exception while %s in message forwarder: %s" doc
        (ExnHelper.string_of_exn e)
  in
  List.iter one xs

let log_exn ?(doc = "performing unknown operation") f x =
  try f x
  with e ->
    debug "Caught exception while %s in message forwarder: %s" doc
      (ExnHelper.string_of_exn e) ;
    raise e

let log_exn_ignore ?(doc = "performing unknown operation") f x =
  try f x
  with e ->
    debug "Ignoring exception while %s in message forwarder: %s" doc
      (ExnHelper.string_of_exn e)

(**************************************************************************************)

(* Given an SR, return a PBD to use for some storage operation. *)
(* In the case of SR.destroy and forget we need to be able to forward the SR
   operation when all PBDs are unplugged. This is the reason for the
   consider_unplugged_pbds argument below. All other SR ops only
   consider plugged PBDs. *)
let choose_pbds_for_sr ~consider_unplugged_pbds ~__context ~self () =
  let module R = Stdlib.Result in
  let all_pbds = Db.SR.get_PBDs ~__context ~self in
  let plugged_pbds =
    List.filter
      (fun self -> Db.PBD.get_currently_attached ~__context ~self)
      all_pbds
  in
  let pbds_to_consider =
    if consider_unplugged_pbds then all_pbds else plugged_pbds
  in
  let pbds = PBDSet.of_list pbds_to_consider in
  let pbd_candidates =
    if Helpers.is_sr_shared ~__context ~self then
      let master = Helpers.get_master ~__context in
      let master_pbds =
        PBDSet.of_list (Db.Host.get_PBDs ~__context ~self:master)
      in
      (* Operation run on shared SRs depend on the first pbd of the list to be
         on the master. *)
      let sr_master_pbds, rest_pbds =
        PBDSet.partition (fun pbd -> PBDSet.mem pbd master_pbds) pbds
      in
      if PBDSet.is_empty sr_master_pbds then
        Error `Sr_no_pbds
      else
        Ok
          (List.rev_append
             (PBDSet.elements sr_master_pbds)
             (PBDSet.elements rest_pbds)
          )
    else
      Ok pbds_to_consider
  in
  R.bind pbd_candidates (function [] -> Error `Sr_no_pbds | pbds -> Ok pbds)

let choose_pbd_for_sr ~consider_unplugged_pbds ~__context ~self () =
  match choose_pbds_for_sr ~consider_unplugged_pbds ~__context ~self () with
  | Ok (x :: _) ->
      x
  | Ok [] ->
      failwith "expected 'choose_pbds_for_sr' to return a non-empty list"
  | Error `Sr_no_pbds ->
      raise
        (Api_errors.Server_error (Api_errors.sr_no_pbds, [Ref.string_of self]))

let loadbalance_host_operation ~__context ~hosts ~doc ~op
    (f : API.ref_host -> unit) =
  let task_id = Ref.string_of (Context.get_task_id __context) in
  let choice =
    Helpers.retry_with_global_lock ~__context ~doc (fun () ->
        let possibilities =
          List.filter
            (fun self ->
              try
                Xapi_host_helpers.assert_operation_valid ~__context ~self ~op ;
                true
              with _ -> false
            )
            hosts
        in
        if possibilities = [] then
          raise
            (Api_errors.Server_error
               ( Api_errors.other_operation_in_progress
               , ["host"; Ref.string_of (List.hd hosts)]
               )
            ) ;
        let choice =
          List.nth possibilities (Random.int (List.length possibilities))
        in
        Xapi_host_helpers.assert_operation_valid ~__context ~self:choice ~op ;
        Db.Host.add_to_current_operations ~__context ~self:choice ~key:task_id
          ~value:op ;
        Xapi_host_helpers.update_allowed_operations ~__context ~self:choice ;
        choice
    )
  in
  (* Then do the action with the lock released *)
  finally
    (fun () -> f choice)
    (* Make sure to clean up at the end *)
      (fun () ->
      try
        Db.Host.remove_from_current_operations ~__context ~self:choice
          ~key:task_id ;
        Xapi_host_helpers.update_allowed_operations ~__context ~self:choice ;
        Helpers.Early_wakeup.broadcast
          (Datamodel_common._host, Ref.string_of choice)
      with _ -> ()
    )

module Forward =
functor
  (Local : Custom_actions.CUSTOM_ACTIONS)
  ->
  struct
    (* During certain operations that are executed on a pool slave, the slave management can reconfigure
     * its management interface, we can lose connection with the slave.
     * This function catches any "host cannot be contacted" exceptions during such calls and polls
     * periodically to see whether the operation has completed on the slave. *)
    let tolerate_connection_loss fn success timeout =
      try fn ()
      with
      | Api_errors.Server_error (ercode, params)
      when ercode = Api_errors.cannot_contact_host
      ->
        debug
          "Lost connection with slave during call (expected). Waiting for \
           slave to come up again." ;
        let time_between_retries = 1. (* seconds *) in
        let num_retries = int_of_float (timeout /. time_between_retries) in
        let rec poll i =
          match i with
          | 0 ->
              raise (Api_errors.Server_error (ercode, params))
              (* give up and re-raise exn *)
          | i -> (
            match success () with
            | Some result ->
                debug "Slave is back and has completed the operation!" ;
                result (* success *)
            | None ->
                Thread.delay time_between_retries ;
                poll (i - 1)
          )
        in
        poll num_retries

    let add_brackets s =
      if s = "" then
        ""
      else
        Printf.sprintf " (%s)" s

    let pool_uuid ~__context pool =
      try
        if Pool_role.is_master () then
          let name = Db.Pool.get_name_label ~__context ~self:pool in
          Printf.sprintf "%s%s"
            (Db.Pool.get_uuid ~__context ~self:pool)
            (add_brackets name)
        else
          Ref.string_of pool
      with _ -> "invalid"

    let current_pool_uuid ~__context =
      if Pool_role.is_master () then
        let _, pool = List.hd (Db.Pool.get_all_records ~__context) in
        Printf.sprintf "%s%s" pool.API.pool_uuid
          (add_brackets pool.API.pool_name_label)
      else
        "invalid"

    let host_uuid ~__context host =
      try
        if Pool_role.is_master () then
          let name = Db.Host.get_name_label ~__context ~self:host in
          Printf.sprintf "%s%s"
            (Db.Host.get_uuid ~__context ~self:host)
            (add_brackets name)
        else
          Ref.string_of host
      with _ -> "invalid"

    let vm_uuid ~__context vm =
      try
        if Pool_role.is_master () then
          let name = Db.VM.get_name_label ~__context ~self:vm in
          Printf.sprintf "%s%s"
            (Db.VM.get_uuid ~__context ~self:vm)
            (add_brackets name)
        else
          Ref.string_of vm
      with _ -> "invalid"

    let vm_appliance_uuid ~__context vm_appliance =
      try
        if Pool_role.is_master () then
          let name =
            Db.VM_appliance.get_name_label ~__context ~self:vm_appliance
          in
          Printf.sprintf "%s%s"
            (Db.VM_appliance.get_uuid ~__context ~self:vm_appliance)
            (add_brackets name)
        else
          Ref.string_of vm_appliance
      with _ -> "invalid"

    let vm_group_uuid ~__context vm_group =
      try
        if Pool_role.is_master () then
          let name = Db.VM_group.get_name_label ~__context ~self:vm_group in
          Printf.sprintf "%s%s"
            (Db.VM_group.get_uuid ~__context ~self:vm_group)
            (add_brackets name)
        else
          Ref.string_of vm_group
      with _ -> "invalid"

    let sr_uuid ~__context sr =
      try
        if Pool_role.is_master () then
          let name = Db.SR.get_name_label ~__context ~self:sr in
          Printf.sprintf "%s%s"
            (Db.SR.get_uuid ~__context ~self:sr)
            (add_brackets name)
        else
          Ref.string_of sr
      with _ -> "invalid"

    let vdi_uuid ~__context vdi =
      try
        if Pool_role.is_master () then
          Db.VDI.get_uuid ~__context ~self:vdi
        else
          Ref.string_of vdi
      with _ -> "invalid"

    let vif_uuid ~__context vif =
      try
        if Pool_role.is_master () then
          Db.VIF.get_uuid ~__context ~self:vif
        else
          Ref.string_of vif
      with _ -> "invalid"

    let vlan_uuid ~__context vlan =
      try
        if Pool_role.is_master () then
          Db.VLAN.get_uuid ~__context ~self:vlan
        else
          Ref.string_of vlan
      with _ -> "invalid"

    let tunnel_uuid ~__context tunnel =
      try
        if Pool_role.is_master () then
          Db.Tunnel.get_uuid ~__context ~self:tunnel
        else
          Ref.string_of tunnel
      with _ -> "invalid"

    let bond_uuid ~__context bond =
      try
        if Pool_role.is_master () then
          Db.Bond.get_uuid ~__context ~self:bond
        else
          Ref.string_of bond
      with _ -> "invalid"

    let network_sriov_uuid ~__context sriov =
      try
        if Pool_role.is_master () then
          Db.Network_sriov.get_uuid ~__context ~self:sriov
        else
          Ref.string_of sriov
      with _ -> "invalid"

    let pif_uuid ~__context pif =
      try
        if Pool_role.is_master () then
          Db.PIF.get_uuid ~__context ~self:pif
        else
          Ref.string_of pif
      with _ -> "invalid"

    let vbd_uuid ~__context vbd =
      try
        if Pool_role.is_master () then
          Db.VBD.get_uuid ~__context ~self:vbd
        else
          Ref.string_of vbd
      with _ -> "invalid"

    let pbd_uuid ~__context pbd =
      try
        if Pool_role.is_master () then
          Db.PBD.get_uuid ~__context ~self:pbd
        else
          Ref.string_of pbd
      with _ -> "invalid"

    let task_uuid ~__context task =
      try
        if Pool_role.is_master () then
          Db.Task.get_uuid ~__context ~self:task
        else
          Ref.string_of task
      with _ -> "invalid"

    let crashdump_uuid ~__context cd =
      try
        if Pool_role.is_master () then
          Db.Crashdump.get_uuid ~__context ~self:cd
        else
          Ref.string_of cd
      with _ -> "invalid"

    let host_crashdump_uuid ~__context hcd =
      try
        if Pool_role.is_master () then
          Db.Host_crashdump.get_uuid ~__context ~self:hcd
        else
          Ref.string_of hcd
      with _ -> "invalid"

    let network_uuid ~__context network =
      try
        if Pool_role.is_master () then
          Db.Network.get_uuid ~__context ~self:network
        else
          Ref.string_of network
      with _ -> "invalid"

    let host_patch_uuid ~__context patch =
      try
        if Pool_role.is_master () then
          Db.Host_patch.get_uuid ~__context ~self:patch
        else
          Ref.string_of patch
      with _ -> "invalid"

    let pool_patch_uuid ~__context patch =
      try
        if Pool_role.is_master () then
          Db.Pool_patch.get_uuid ~__context ~self:patch
        else
          Ref.string_of patch
      with _ -> "invalid"

    let pool_update_uuid ~__context update =
      try
        if Pool_role.is_master () then
          Db.Pool_update.get_uuid ~__context ~self:update
        else
          Ref.string_of update
      with _ -> "invalid"

    let pci_uuid ~__context pci =
      try
        if Pool_role.is_master () then
          Db.PCI.get_uuid ~__context ~self:pci
        else
          Ref.string_of pci
      with _ -> "invalid"

    let pgpu_uuid ~__context pgpu =
      try
        if Pool_role.is_master () then
          Db.PGPU.get_uuid ~__context ~self:pgpu
        else
          Ref.string_of pgpu
      with _ -> "invalid"

    let gpu_group_uuid ~__context gpu_group =
      try
        if Pool_role.is_master () then
          Db.GPU_group.get_uuid ~__context ~self:gpu_group
        else
          Ref.string_of gpu_group
      with _ -> "invalid"

    let vgpu_uuid ~__context vgpu =
      try
        if Pool_role.is_master () then
          Db.VGPU.get_uuid ~__context ~self:vgpu
        else
          Ref.string_of vgpu
      with _ -> "invalid"

    let vgpu_type_uuid ~__context vgpu_type =
      try
        if Pool_role.is_master () then
          Db.VGPU_type.get_uuid ~__context ~self:vgpu_type
        else
          Ref.string_of vgpu_type
      with _ -> "invalid"

    let sdn_controller_uuid ~__context sdn_controller =
      try
        if Pool_role.is_master () then
          Db.SDN_controller.get_uuid ~__context ~self:sdn_controller
        else
          Ref.string_of sdn_controller
      with _ -> "invalid"

    let pusb_uuid ~__context pusb =
      try
        if Pool_role.is_master () then
          Db.PUSB.get_uuid ~__context ~self:pusb
        else
          Ref.string_of pusb
      with _ -> "invalid"

    let usb_group_uuid ~__context usb_group =
      try
        if Pool_role.is_master () then
          Db.USB_group.get_uuid ~__context ~self:usb_group
        else
          Ref.string_of usb_group
      with _ -> "invalid"

    let vusb_uuid ~__context vusb =
      try
        if Pool_role.is_master () then
          Db.VUSB.get_uuid ~__context ~self:vusb
        else
          Ref.string_of vusb
      with _ -> "invalid"

    let repository_uuid ~__context repository =
      try
        if Pool_role.is_master () then
          Db.Repository.get_uuid ~__context ~self:repository
        else
          Ref.string_of repository
      with _ -> "invalid"

    let observer_uuid ~__context observer =
      try
        if Pool_role.is_master () then
          Db.Observer.get_uuid ~__context ~self:observer
        else
          Ref.string_of observer
      with _ -> "invalid"

    module Session = struct
      include Local.Session

      let login_with_password ~__context ~uname ~pwd ~version ~originator =
        Xapi_session.record_login_failure ~__context ~uname:(Some uname)
          ~originator:(Some originator) ~record:`log_and_alert (fun () ->
            Local.Session.login_with_password ~__context ~uname ~pwd ~version
              ~originator
        )

      let slave_login ~__context ~host ~psecret =
        Xapi_session.record_login_failure ~__context ~uname:None
          ~record:`log_and_alert ~originator:None (fun () ->
            Local.Session.slave_login ~__context ~host ~psecret
        )

      let change_password ~__context ~old_pwd ~new_pwd =
        Xapi_session.record_login_failure ~__context ~uname:None
          ~originator:None ~record:`log_and_alert (fun () ->
            Local.Session.change_password ~__context ~old_pwd ~new_pwd
        )

      (* for emergency local logins, we just log - we only bother with alerts on the master *)

      let slave_local_login ~__context ~psecret =
        Xapi_session.record_login_failure ~__context ~uname:None
          ~originator:(Some "localhost") ~record:`log_only (fun () ->
            Local.Session.slave_local_login ~__context ~psecret
        )

      let slave_local_login_with_password ~__context ~uname ~pwd =
        Xapi_session.record_login_failure ~__context ~uname:(Some uname)
          ~originator:(Some "localhost") ~record:`log_only (fun () ->
            Local.Session.slave_local_login_with_password ~__context ~uname ~pwd
        )
    end

    module Auth = Local.Auth
    module Subject = Local.Subject
    module Role = Local.Role

    module Task = struct
      include Local.Task

      let cancel ~__context ~task =
        Context.with_tracing ~__context __FUNCTION__ @@ fun __context ->
        TaskHelper.assert_op_valid ~__context task ;
        let local_fn = cancel ~task in
        let remote_fn = Client.Task.cancel ~task in
        let forwarded_to = Db.Task.get_forwarded_to ~__context ~self:task in
        if Db.is_valid_ref __context forwarded_to then
          do_op_on ~local_fn ~__context
            ~host:(Db.Task.get_forwarded_to ~__context ~self:task)
            ~remote_fn
        else
          local_fn ~__context
    end

    module Event = Local.Event
    module VMPP = Local.VMPP
    module VMSS = Local.VMSS

    module VM_appliance = struct
      include Local.VM_appliance

      (* Add to the VM_appliance's current operations, call a function and then remove from the *)
      (* current operations. Ensure the allowed_operations are kept up to date. *)
      let with_vm_appliance_operation ~__context ~self ~doc ~op f =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            Xapi_vm_appliance.assert_operation_valid ~__context ~self ~op ;
            Db.VM_appliance.add_to_current_operations ~__context ~self
              ~key:task_id ~value:op ;
            Xapi_vm_appliance.update_allowed_operations ~__context ~self
        ) ;
        (* Then do the action with the lock released *)
        finally f (* Make sure to clean up at the end *) (fun () ->
            try
              Db.VM_appliance.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vm_appliance.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vm_appliance, Ref.string_of self)
            with _ -> ()
        )

      let start ~__context ~self ~paused =
        info "VM_appliance.start: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        Pool_features.assert_enabled ~__context ~f:Features.VM_appliance_start ;
        with_vm_appliance_operation ~__context ~self ~doc:"VM_appliance.start"
          ~op:`start (fun () ->
            Local.VM_appliance.start ~__context ~self ~paused
        )

      let clean_shutdown ~__context ~self =
        info "VM_appliance.clean_shutdown: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        with_vm_appliance_operation ~__context ~self
          ~doc:"VM_appliance.clean_shutdown" ~op:`clean_shutdown (fun () ->
            Local.VM_appliance.clean_shutdown ~__context ~self
        )

      let hard_shutdown ~__context ~self =
        info "VM_appliance.hard_shutdown: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        with_vm_appliance_operation ~__context ~self
          ~doc:"VM_appliance.hard_shutdown" ~op:`hard_shutdown (fun () ->
            Local.VM_appliance.hard_shutdown ~__context ~self
        )

      let shutdown ~__context ~self =
        info "VM_appliance.shutdown: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        with_vm_appliance_operation ~__context ~self
          ~doc:"VM_appliance.shutdown" ~op:`shutdown (fun () ->
            Local.VM_appliance.shutdown ~__context ~self
        )

      let assert_can_be_recovered ~__context ~self ~session_to =
        info "VM_appliance.assert_can_be_recovered: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        Local.VM_appliance.assert_can_be_recovered ~__context ~self ~session_to

      let get_SRs_required_for_recovery ~__context ~self ~session_to =
        info "VM_appliance.get_SRs_required_for_recovery: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        Local.VM_appliance.get_SRs_required_for_recovery ~__context ~self
          ~session_to

      let recover ~__context ~self ~session_to ~force =
        info "VM_appliance.recover: VM_appliance = '%s'"
          (vm_appliance_uuid ~__context self) ;
        Local.VM_appliance.recover ~__context ~self ~session_to ~force
    end

    module DR_task = Local.DR_task

    (* module Alert = Local.Alert *)

    module Pool = struct
      include Local.Pool

      let eject ~__context ~host =
        info "Pool.eject: pool = '%s'; host = '%s'"
          (current_pool_uuid ~__context)
          (host_uuid ~__context host) ;
        let pool = Helpers.get_pool ~__context in
        Xapi_pool_helpers.with_pool_operation ~__context ~doc:"Pool.eject"
          ~self:pool ~op:`eject
        @@ fun () ->
        let master = Helpers.get_master ~__context in
        let local_fn = Local.Pool.eject ~host in
        let remote_fn = Client.Pool.eject ~host in
        let other =
          Db.Host.get_all ~__context
          |> List.filter (fun h -> h <> host && h <> master)
        in
        (* eject host but don't remove it from DB yet *)
        do_op_on ~local_fn ~__context ~host ~remote_fn ;
        (* perform cleanup on remaining pool members
         * this must be best effort - once an eject has begun we cannot rollback *)
        other
        |> List.iter (fun h ->
               try do_op_on ~local_fn ~__context ~host:h ~remote_fn
               with e ->
                 D.warn
                   "Pool.eject: while ejecting host=%s, we failed to clean up \
                    on host=%s. ignoring error: %s"
                   (Ref.short_string_of host) (Ref.short_string_of h)
                   (Printexc.to_string e)
           ) ;
        (* finally clean up on master *)
        do_op_on ~local_fn ~__context ~host:master ~remote_fn

      let designate_new_master ~__context ~host =
        info "Pool.designate_new_master: pool = '%s'; host = '%s'"
          (current_pool_uuid ~__context)
          (host_uuid ~__context host) ;
        Xapi_pool_helpers.with_pool_operation ~__context
          ~self:(Helpers.get_pool ~__context)
          ~doc:"Pool.designate_new_master" ~op:`designate_new_master (fun () ->
            (* Sync the RRDs from localhost to new master *)
            Xapi_sync.sync_host ~__context host ;
            let local_fn = Local.Pool.designate_new_master ~host in
            let remote_fn = Client.Pool.designate_new_master ~host in
            do_op_on ~local_fn ~__context ~host ~remote_fn
        )

      let management_reconfigure ~__context ~network =
        info "Pool.management_reconfigure: pool = '%s'; network = '%s'"
          (current_pool_uuid ~__context)
          (network_uuid ~__context network) ;
        Local.Pool.management_reconfigure ~__context ~network

      let enable_ha ~__context ~heartbeat_srs ~configuration =
        info
          "Pool.enable_ha: pool = '%s'; heartbeat_srs = [ %s ]; configuration \
           = [ %s ]"
          (current_pool_uuid ~__context)
          (String.concat ", " (List.map Ref.string_of heartbeat_srs))
          (String.concat "; "
             (List.map (fun (k, v) -> k ^ "=" ^ v) configuration)
          ) ;
        let pool = Helpers.get_pool ~__context in
        Xapi_pool_helpers.with_pool_operation ~__context ~doc:"Pool.ha_enable"
          ~self:pool ~op:`ha_enable (fun () ->
            Local.Pool.enable_ha ~__context ~heartbeat_srs ~configuration
        )

      let disable_ha ~__context =
        info "Pool.disable_ha: pool = '%s'" (current_pool_uuid ~__context) ;
        let pool = Helpers.get_pool ~__context in
        Xapi_pool_helpers.with_pool_operation ~__context ~doc:"Pool.ha_disable"
          ~self:pool ~op:`ha_disable (fun () -> Local.Pool.disable_ha ~__context
        )

      let ha_prevent_restarts_for ~__context ~seconds =
        info "Pool.ha_prevent_restarts_for: pool = '%s'; seconds = %Ld"
          (current_pool_uuid ~__context)
          seconds ;
        Local.Pool.ha_prevent_restarts_for ~__context ~seconds

      let ha_failover_plan_exists ~__context ~n =
        info "Pool.ha_failover_plan_exists: pool = '%s'; n = %Ld"
          (current_pool_uuid ~__context)
          n ;
        Local.Pool.ha_failover_plan_exists ~__context ~n

      let ha_compute_max_host_failures_to_tolerate ~__context =
        Xapi_clustering.with_clustering_lock_if_cluster_exists ~__context
          __LOC__ (fun () ->
            info "Pool.ha_compute_max_host_failures_to_tolerate: pool = '%s'"
              (current_pool_uuid ~__context) ;
            Local.Pool.ha_compute_max_host_failures_to_tolerate ~__context
        )

      let ha_compute_hypothetical_max_host_failures_to_tolerate ~__context
          ~configuration =
        Xapi_clustering.with_clustering_lock_if_cluster_exists ~__context
          __LOC__ (fun () ->
            info
              "Pool.ha_compute_hypothetical_max_host_failures_to_tolerate: \
               pool = '%s'; configuration = [ %s ]"
              (current_pool_uuid ~__context)
              (String.concat "; "
                 (List.map
                    (fun (vm, p) -> Ref.string_of vm ^ " " ^ p)
                    configuration
                 )
              ) ;
            Local.Pool.ha_compute_hypothetical_max_host_failures_to_tolerate
              ~__context ~configuration
        )

      let ha_compute_vm_failover_plan ~__context ~failed_hosts ~failed_vms =
        info
          "Pool.ha_compute_vm_failover_plan: pool = '%s'; failed_hosts = [ %s \
           ]; failed_vms = [ %s ]"
          (current_pool_uuid ~__context)
          (String.concat "; " (List.map Ref.string_of failed_hosts))
          (String.concat "; " (List.map Ref.string_of failed_vms)) ;
        Local.Pool.ha_compute_vm_failover_plan ~__context ~failed_hosts
          ~failed_vms

      let set_ha_host_failures_to_tolerate ~__context ~self ~value =
        Xapi_clustering.with_clustering_lock_if_cluster_exists ~__context
          __LOC__ (fun () ->
            info
              "Pool.set_ha_host_failures_to_tolerate: pool = '%s'; value = %Ld"
              (pool_uuid ~__context self)
              value ;
            Local.Pool.set_ha_host_failures_to_tolerate ~__context ~self ~value
        )

      let ha_schedule_plan_recomputation ~__context =
        info "Pool.ha_schedule_plan_recomputation: pool = '%s'"
          (current_pool_uuid ~__context) ;
        Local.Pool.ha_schedule_plan_recomputation ~__context

      let enable_external_auth ~__context ~pool ~config ~service_name ~auth_type
          =
        info
          "Pool.enable_external_auth: pool = '%s'; service name = '%s'; \
           auth_type = '%s'"
          (pool_uuid ~__context pool)
          service_name auth_type ;
        Local.Pool.enable_external_auth ~__context ~pool ~config ~service_name
          ~auth_type

      let disable_external_auth ~__context ~pool =
        info "Pool.disable_external_auth: pool = '%s'"
          (pool_uuid ~__context pool) ;
        Local.Pool.disable_external_auth ~__context ~pool

      let enable_redo_log ~__context ~sr =
        info "Pool.enable_redo_log: pool = '%s'; sr_uuid = '%s'"
          (current_pool_uuid ~__context)
          (sr_uuid ~__context sr) ;
        Local.Pool.enable_redo_log ~__context ~sr

      let disable_redo_log ~__context =
        info "Pool.disable_redo_log: pool = '%s'" (current_pool_uuid ~__context) ;
        Local.Pool.disable_redo_log ~__context

      let set_vswitch_controller ~__context ~address =
        info "Pool.set_vswitch_controller: pool = '%s'; address = '%s'"
          (current_pool_uuid ~__context)
          address ;
        Local.Pool.set_vswitch_controller ~__context ~address

      let get_license_state ~__context ~self =
        info "Pool.get_license_state: pool = '%s'" (pool_uuid ~__context self) ;
        Local.Pool.get_license_state ~__context ~self

      let apply_edition ~__context ~self ~edition =
        info "Pool.apply_edition: pool = '%s'; edition = '%s'"
          (pool_uuid ~__context self)
          edition ;
        Local.Pool.apply_edition ~__context ~self ~edition

      let disable_ssl_legacy ~__context ~self =
        info "Pool.disable_ssl_legacy: pool = '%s'" (pool_uuid ~__context self) ;
        Local.Pool.disable_ssl_legacy ~__context ~self

      let set_igmp_snooping_enabled ~__context ~self ~value =
        info "Pool.set_igmp_snooping_enabled: Pool = '%s', value = %b"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_igmp_snooping_enabled ~__context ~self ~value

      let has_extension ~__context ~self ~name =
        info "Pool.has_extension: pool = '%s'; name = '%s'"
          (pool_uuid ~__context self)
          name ;
        Local.Pool.has_extension ~__context ~self ~name

      let add_to_guest_agent_config ~__context ~self ~key ~value =
        info
          "Pool.add_to_guest_agent_config: pool = '%s'; key = '%s'; value = \
           '%s'"
          (pool_uuid ~__context self)
          key value ;
        Local.Pool.add_to_guest_agent_config ~__context ~self ~key ~value

      let remove_from_guest_agent_config ~__context ~self ~key =
        info "Pool.remove_from_guest_agent_config: pool = '%s'; key = '%s'"
          (pool_uuid ~__context self)
          key ;
        Local.Pool.remove_from_guest_agent_config ~__context ~self ~key

      let rotate_secret ~__context =
        info "Pool.rotate_secret: pool = '%s'" (current_pool_uuid ~__context) ;
        Local.Pool.rotate_secret ~__context

      (* this ought to be
         (a) idempotent
         (b) capable of re-enabling verification on hosts who have had verification emergency disabled *)
      let enable_tls_verification ~__context =
        info "Pool.enable_tls_verification: pool = '%s'"
          (current_pool_uuid ~__context) ;
        let self = Helpers.get_pool ~__context in
        let local_fn = Local.Pool.enable_tls_verification in
        let remote_fn = Client.Pool.enable_tls_verification in
        let all_hosts = Xapi_pool_helpers.get_master_slaves_list ~__context in

        Xapi_pool_helpers.with_pool_operation ~__context
          ~doc:"Pool.enable_tls_verification" ~self ~op:`tls_verification_enable
          (fun () ->
            debug "Pool.enable_tls_verification start ... (1/2)" ;
            Cert_distrib.exchange_certificates_in_pool ~__context ;
            while Xapi_fist.pause_after_cert_exchange () do
              debug "Pool.enable_tls_verification sleeping on fistpoint" ;
              Thread.delay 5.0
            done ;
            all_hosts
            |> List.iter (fun host ->
                   do_op_on ~local_fn ~__context ~host ~remote_fn ;
                   debug "Pool.enable_tls_verification enabling on host %s"
                     (Ref.string_of host)
               ) ;
            Db.Pool.set_tls_verification_enabled ~__context ~self ~value:true ;
            debug "Enabling TLS verification for Work Load Balancing (WLB)" ;
            Db.Pool.set_wlb_verify_cert ~__context ~self ~value:true ;
            debug "Pool.enable_tls_verification completed (2/2)"
        )

      let set_repositories ~__context ~self ~value =
        info "Pool.set_repositories : pool = '%s'; value = [ %s ]"
          (pool_uuid ~__context self)
          (String.concat "; " (List.map (repository_uuid ~__context) value)) ;
        Local.Pool.set_repositories ~__context ~self ~value

      let add_repository ~__context ~self ~value =
        info "Pool.add_repository : pool = '%s'; repo_uuid = %s"
          (pool_uuid ~__context self)
          (repository_uuid ~__context value) ;
        Local.Pool.add_repository ~__context ~self ~value

      let remove_repository ~__context ~self ~value =
        info "Pool.remove_repository : pool = '%s'; repo_uuid = %s"
          (pool_uuid ~__context self)
          (repository_uuid ~__context value) ;
        Local.Pool.remove_repository ~__context ~self ~value

      let sync_updates ~__context ~self ~force ~token ~token_id =
        info
          "Pool.sync_updates: pool = '%s'; force = %s; token = %s; token_id = \
           %s"
          (pool_uuid ~__context self)
          (string_of_bool force)
          (if token = "" then "" else "(token filtered)")
          token_id ;
        Local.Pool.sync_updates ~__context ~self ~force ~token ~token_id

      let check_update_readiness ~__context ~self ~requires_reboot =
        info "Pool.check_update_readiness: pool = '%s'; requires_reboot = %s"
          (pool_uuid ~__context self)
          (string_of_bool requires_reboot) ;
        Local.Pool.check_update_readiness ~__context ~self ~requires_reboot

      let enable_client_certificate_auth ~__context ~self ~name =
        info "Pool.enable_client_certificate_auth: pool = '%s'; name = '%s'"
          (pool_uuid ~__context self)
          name ;
        Local.Pool.enable_client_certificate_auth ~__context ~self ~name

      let disable_client_certificate_auth ~__context ~self =
        info "Pool.disable_client_certificate_auth: pool = '%s'"
          (pool_uuid ~__context self) ;
        Local.Pool.disable_client_certificate_auth ~__context ~self

      let configure_repository_proxy ~__context ~self ~url ~username ~password =
        info
          "Pool.configure_repository_proxy: pool = '%s'; url = %s; username = \
           %s; password = %s"
          (pool_uuid ~__context self)
          url
          (if username = "" then "" else "(username filtered)")
          (if password = "" then "" else "(password filtered)") ;
        Local.Pool.configure_repository_proxy ~__context ~self ~url ~username
          ~password

      let disable_repository_proxy ~__context ~self =
        info "Pool.disable_repository_proxy: pool = '%s'"
          (pool_uuid ~__context self) ;
        Local.Pool.disable_repository_proxy ~__context ~self

      let set_uefi_certificates ~__context ~self ~value =
        info "Pool.set_uefi_certificates: pool='%s' value='%s'"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_uefi_certificates ~__context ~self ~value

      let set_custom_uefi_certificates ~__context ~self ~value =
        info "Pool.set_custom_uefi_certificates: pool='%s' value='%s'"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_custom_uefi_certificates ~__context ~self ~value

      let set_https_only ~__context ~self ~value =
        info "Pool.set_https_only: pool='%s' value='%B'"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_https_only ~__context ~self ~value

      let set_telemetry_next_collection ~__context ~self ~value =
        info "%s: pool='%s' value='%s'" __FUNCTION__
          (pool_uuid ~__context self)
          (Clock.Date.to_rfc3339 value) ;
        Local.Pool.set_telemetry_next_collection ~__context ~self ~value

      let reset_telemetry_uuid ~__context ~self =
        info "%s: pool='%s'" __FUNCTION__ (pool_uuid ~__context self) ;
        Local.Pool.reset_telemetry_uuid ~__context ~self

      let configure_update_sync ~__context ~self ~update_sync_frequency
          ~update_sync_day =
        info "%s: pool='%s' update_sync_frequency='%s' update_sync_day=%Ld"
          __FUNCTION__
          (pool_uuid ~__context self)
          (Record_util.update_sync_frequency_to_string update_sync_frequency)
          update_sync_day ;
        Local.Pool.configure_update_sync ~__context ~self ~update_sync_frequency
          ~update_sync_day

      let set_update_sync_enabled ~__context ~self ~value =
        info "%s: pool='%s' value='%B'" __FUNCTION__
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_update_sync_enabled ~__context ~self ~value

      let set_local_auth_max_threads ~__context ~self ~value =
        info "%s: pool='%s' value='%Ld'" __FUNCTION__
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_local_auth_max_threads ~__context ~self ~value

      let set_ext_auth_max_threads ~__context ~self ~value =
        info "%s: pool='%s' value='%Ld'" __FUNCTION__
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_ext_auth_max_threads ~__context ~self ~value

      let set_ext_auth_cache_enabled ~__context ~self ~value =
        info "%s: pool='%s' value='%b'" __FUNCTION__
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_ext_auth_cache_enabled ~__context ~self ~value

      let set_ext_auth_cache_size ~__context ~self ~value =
        info "%s: pool='%s' value='%Ld'" __FUNCTION__
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_ext_auth_cache_size ~__context ~self ~value

      let set_ext_auth_cache_expiry ~__context ~self ~value =
        info "%s: pool='%s' value='%Ld'" __FUNCTION__
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_ext_auth_cache_expiry ~__context ~self ~value

      let get_guest_secureboot_readiness ~__context ~self =
        info "%s: pool='%s'" __FUNCTION__ (pool_uuid ~__context self) ;
        Local.Pool.get_guest_secureboot_readiness ~__context ~self

      let enable_ssh ~__context ~self =
        info "%s: pool = '%s'" __FUNCTION__ (pool_uuid ~__context self) ;
        Local.Pool.enable_ssh ~__context ~self

      let disable_ssh ~__context ~self =
        info "%s: pool = '%s'" __FUNCTION__ (pool_uuid ~__context self) ;
        Local.Pool.disable_ssh ~__context ~self

      let set_ssh_enabled_timeout ~__context ~self ~value =
        info "Pool.set_ssh_enabled_timeout: pool='%s' value='%Ld'"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_ssh_enabled_timeout ~__context ~self ~value

      let set_console_idle_timeout ~__context ~self ~value =
        info "Pool.set_console_idle_timeout: pool='%s' value='%Ld'"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_console_idle_timeout ~__context ~self ~value

      let set_ssh_auto_mode ~__context ~self ~value =
        info "Pool.set_ssh_auto_mode: pool='%s' value='%b'"
          (pool_uuid ~__context self)
          value ;
        Local.Pool.set_ssh_auto_mode ~__context ~self ~value
    end

    module VM = struct
      (* Defined in Xapi_vm_helpers so it can be used from elsewhere without circular dependency. *)
      let with_vm_operation = Xapi_vm_helpers.with_vm_operation

      (* Nb, we're not using the snapshots returned in 'Event.from' here because
       * the tasks might get deleted. The standard mechanism for dealing with
       * deleted events assumes you have a full database replica locally, and
       * deletions are handled by checking your valid_ref_counts table against
       * your local database. In this case, we're only interested in a subset of
       * events, so this mechanism doesn't work. There will only be a few outstanding
       * tasks anyway, so we're safe to just iterate through the references when an
       * event happens - ie, we use the event API simply to wake us up when something
       * interesting has happened. *)

      let wait_for_tasks = Helpers.Task.wait_for

      let create_vm_message ~__context ~vm ~message_body ~message =
        let name, priority = message in
        try
          ignore
            (Xapi_message.create ~__context ~name ~priority ~cls:`VM
               ~obj_uuid:(Db.VM.get_uuid ~__context ~self:vm)
               ~body:message_body
            )
        with _ -> ()

      let cancel ~__context ~vm ~ops =
        Context.with_tracing ~__context __FUNCTION__ @@ fun __context ->
        let cancelled =
          List.filter_map
            (fun (task, op) ->
              if List.mem op ops then (
                info "Cancelling VM.%s for VM.hard_shutdown/reboot"
                  (Record_util.vm_operation_to_string op) ;
                Helpers.call_api_functions ~__context (fun rpc session_id ->
                    try
                      Client.Task.cancel ~rpc ~session_id
                        ~task:(Ref.of_string task)
                    with _ -> ()
                ) ;
                Some (Ref.of_string task)
              ) else
                None
            )
            (Db.VM.get_current_operations ~__context ~self:vm)
        in
        wait_for_tasks ~__context ~tasks:cancelled

      let unmark_vbds ~__context ~vbds ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        iter_with_drop
          ~doc:("unmarking VBDs after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.VBD.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vbd_helpers.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vbd, Ref.string_of self)
            )
          )
          vbds

      let mark_vbds ~__context ~vm ~doc ~op : API.ref_VBD list =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        let vbds = Db.VM.get_VBDs ~__context ~self:vm in
        let marked = ref [] in
        (* CA-26575: paper over transient VBD glitches caused by SR.lvhd_stop_the_world by throwing the
           first OTHER_OPERATION_IN_PROGRESS (or whatever) we encounter and let the caller deal with it *)
        try
          List.iter
            (fun vbd ->
              Xapi_vbd_helpers.assert_operation_valid ~__context ~self:vbd ~op ;
              Db.VBD.add_to_current_operations ~__context ~self:vbd ~key:task_id
                ~value:op ;
              Xapi_vbd_helpers.update_allowed_operations ~__context ~self:vbd ;
              marked := vbd :: !marked
            )
            vbds ;
          vbds
        with e ->
          debug "Caught exception marking VBD for %s on VM %s: %s" doc
            (Ref.string_of vm)
            (ExnHelper.string_of_exn e) ;
          unmark_vbds ~__context ~vbds:!marked ~doc ~op ;
          raise e

      let with_vbds_marked ~__context ~vm ~doc ~op f =
        (* CA-26575: paper over transient VBD glitches caused by SR.lvhd_stop_the_world *)
        let vbds =
          Helpers.retry_with_global_lock ~__context ~doc
            ~policy:Helpers.Policy.fail_quickly (fun () ->
              mark_vbds ~__context ~vm ~doc ~op
          )
        in
        finally
          (fun () -> f vbds)
          (fun () ->
            Helpers.with_global_lock (fun () ->
                unmark_vbds ~__context ~vbds ~doc ~op
            )
          )

      let unmark_vifs ~__context ~vifs ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        iter_with_drop
          ~doc:("unmarking VIFs after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.VIF.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vif_helpers.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vif, Ref.string_of self)
            )
          )
          vifs

      let mark_vifs ~__context ~vm ~doc ~op : API.ref_VIF list =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        let vifs = Db.VM.get_VIFs ~__context ~self:vm in
        let marked =
          map_with_drop
            ~doc:("marking VIFs for " ^ doc)
            (fun vif ->
              Xapi_vif_helpers.assert_operation_valid ~__context ~self:vif ~op ;
              Db.VIF.add_to_current_operations ~__context ~self:vif ~key:task_id
                ~value:op ;
              Xapi_vif_helpers.update_allowed_operations ~__context ~self:vif ;
              vif
            )
            vifs
        in
        (* Did we mark them all? *)
        if List.length marked <> List.length vifs then (
          unmark_vifs ~__context ~vifs:marked ~doc ~op ;
          raise
            (Api_errors.Server_error
               (Api_errors.operation_not_allowed, ["Failed to lock all VIFs"])
            )
        ) else
          marked

      let with_vifs_marked ~__context ~vm ~doc ~op f =
        let vifs =
          Helpers.retry_with_global_lock ~__context ~doc (fun () ->
              mark_vifs ~__context ~vm ~doc ~op
          )
        in
        finally
          (fun () -> f vifs)
          (fun () ->
            Helpers.with_global_lock (fun () ->
                unmark_vifs ~__context ~vifs ~doc ~op
            )
          )

      (* Some VM operations have side-effects on VBD allowed_operations but don't actually
         lock the VBDs themselves (eg suspend) *)
      let update_vbd_operations ~__context ~vm =
        Helpers.with_global_lock (fun () ->
            List.iter
              (fun self ->
                Xapi_vbd_helpers.update_allowed_operations ~__context ~self ;
                try
                  let vdi = Db.VBD.get_VDI ~__context ~self in
                  Xapi_vdi.update_allowed_operations ~__context ~self:vdi
                with _ -> ()
              )
              (Db.VM.get_VBDs ~__context ~self:vm)
        )

      let update_vif_operations ~__context ~vm =
        Helpers.with_global_lock (fun () ->
            List.iter
              (fun self ->
                Xapi_vif_helpers.update_allowed_operations ~__context ~self
              )
              (Db.VM.get_VIFs ~__context ~self:vm)
        )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      (* Read resisdent-on field from vm to determine who to forward to  *)
      let forward_vm_op ~local_fn ~__context ~vm ~remote_fn =
        let power_state = Db.VM.get_power_state ~__context ~self:vm in
        if List.mem power_state [`Running; `Paused] then
          do_op_on ~local_fn ~__context
            ~host:(Db.VM.get_resident_on ~__context ~self:vm)
            ~remote_fn
        else
          local_fn ~__context

      let clear_vif_reservations ~__context ~vm =
        debug "%s VM=%s" __FUNCTION__ (Ref.string_of vm) ;
        Db.VM.get_VIFs ~__context ~self:vm
        |> List.iter (fun vif ->
               let vf = Db.VIF.get_reserved_pci ~__context ~self:vif in
               Db.VIF.set_reserved_pci ~__context ~self:vif ~value:Ref.null ;
               if Db.is_valid_ref __context vf then
                 Db.PCI.set_scheduled_to_be_attached_to ~__context ~self:vf
                   ~value:Ref.null
           )

      let clear_reservations ~__context ~vm =
        debug "%s VM=%s" __FUNCTION__ (Ref.string_of vm) ;
        (* host *)
        Db.VM.set_scheduled_to_be_resident_on ~__context ~self:vm
          ~value:Ref.null ;
        (* vgpu *)
        Db.VM.get_VGPUs ~__context ~self:vm
        |> List.iter (fun vgpu ->
               Db.VGPU.set_scheduled_to_be_resident_on ~__context ~self:vgpu
                 ~value:Ref.null
           ) ;
        (* pcis *)
        Db.PCI.get_refs_where ~__context
          ~expr:
            (Eq (Field "scheduled_to_be_attached_to", Literal (Ref.string_of vm))
            )
        |> List.iter (function
             | pci when pci <> Ref.null ->
                 debug "%s: clearing reservation of PCI %s for VM %s"
                   __FUNCTION__ (Ref.string_of pci) (Ref.string_of vm) ;
                 Db.PCI.set_scheduled_to_be_attached_to ~__context ~self:pci
                   ~value:Ref.null
             | _ ->
                 ()
             )

      (* Notes on memory checking/reservation logic:
         When computing the hosts free memory we consider all VMs resident_on (ie running
         and consuming resources NOW) and scheduled_to_be_resident_on (ie those which are
         starting/resuming/migrating, whose memory has been reserved but may not all be being
         used atm).
         We generally call 'assert_can_boot_here' with the master forwarding lock held,
         which verifies that a host has enough free memory to support the VM and then we
         set 'scheduled_to_be_resident_on' which prevents concurrent competing attempts to
         use the same resources from succeeding. *)

      (* Reserves the resources for a VM by setting it as 'scheduled_to_be_resident_on' a host *)
      let allocate_vm_to_host ~__context ~vm ~host ~snapshot ?host_op () =
        info "Reserve resources for VM %s on host %s" (Ref.string_of vm)
          (Ref.string_of host) ;
        Xapi_vm_helpers.assert_no_legacy_hardware ~__context ~vm ;
        ( match host_op with
        | Some x ->
            let task_id = Ref.string_of (Context.get_task_id __context) in
            Xapi_host_helpers.assert_operation_valid ~__context ~self:host ~op:x ;
            Db.Host.add_to_current_operations ~__context ~self:host ~key:task_id
              ~value:x ;
            Xapi_host_helpers.update_allowed_operations ~__context ~self:host
        | None ->
            ()
        ) ;
        (* Once this is set concurrent VM.start calls will start checking the memory used by this VM *)
        Db.VM.set_scheduled_to_be_resident_on ~__context ~self:vm ~value:host ;
        try
          Vgpuops.create_vgpus ~__context host (vm, snapshot)
            (Helpers.will_have_qemu ~__context ~self:vm) ;
          Xapi_network_sriov_helpers.reserve_sriov_vfs ~__context ~host ~vm
        with e ->
          clear_vif_reservations ~__context ~vm ;
          clear_reservations ~__context ~vm ;
          raise e

      (* For start/start_on/resume/resume_on/migrate *)
      let finally_clear_host_operation ~__context ~host ?host_op () =
        match host_op with
        | Some _ ->
            let task_id = Ref.string_of (Context.get_task_id __context) in
            Db.Host.remove_from_current_operations ~__context ~self:host
              ~key:task_id ;
            Xapi_host_helpers.update_allowed_operations ~__context ~self:host ;
            Helpers.Early_wakeup.broadcast
              (Datamodel_common._host, Ref.string_of host)
        | None ->
            ()

      let check_vm_preserves_ha_plan ~__context ~vm ~snapshot ~host =
        if
          true
          && snapshot.API.vM_ha_restart_priority = Constants.ha_restart
          && not snapshot.API.vM_ha_always_run
        then
          Xapi_ha_vm_failover.assert_new_vm_preserves_ha_plan ~__context vm
        else
          Xapi_ha_vm_failover.assert_vm_placement_preserves_ha_plan ~__context
            ~arriving:[(host, (vm, snapshot))]
            ()

      (* README: Note on locking -- forward_to_suitable_host and reserve_memory_for_vm are only
         called in a context where the current_operations field for the VM object contains the
         operation we're considering. Thus the global_lock in this context is _not_ used to cover
         the period where current_operations are set, but is used to ensure that (i) choose_host_for_vm
         is executed under mutual exclusion with other incoming operations; and (ii) that scheduled_to_be_resident_on
         (which must not change whilst someone is calling choose_host_for_vm) only executes in exclusion with
         choose_host_for_vm.
      *)

      (* Used by VM.start and VM.resume to choose a host with enough resource and to
         'allocate_vm_to_host' (ie set the 'scheduled_to_be_resident_on' field) *)
      let forward_to_suitable_host ~local_fn ~__context ~vm ~snapshot ~remote_fn
          ?host_op () =
        let suitable_host =
          Helpers.with_global_lock (fun () ->
              let host =
                Db.VM.get_scheduled_to_be_resident_on ~__context ~self:vm
              in
              if host <> Ref.null then
                host
              else
                let host =
                  Xapi_vm_helpers.choose_host_for_vm ~__context ~vm ~snapshot
                in
                (* HA overcommit protection: we can either perform 'n' HA plans by including this in
                   the 'choose_host_for_vm' function or we can be cheapskates by doing it here: *)
                check_vm_preserves_ha_plan ~__context ~vm ~snapshot ~host ;
                allocate_vm_to_host ~__context ~vm ~host ~snapshot ?host_op () ;
                host
          )
        in
        finally
          (fun () ->
            ( do_op_on ~local_fn ~__context ~host:suitable_host ~remote_fn
            , suitable_host
            )
          )
          (fun () ->
            Helpers.with_global_lock (fun () ->
                finally_clear_host_operation ~__context ~host:suitable_host
                  ?host_op () ;
                (* In certain cases, VM might have been destroyed as a consequence of operation *)
                if Db.is_valid_ref __context vm then
                  clear_reservations ~__context ~vm
            )
          )

      (* Used by VM.start_on, VM.resume_on, VM.migrate to verify a host has enough resource and to
         'allocate_vm_to_host' (ie set the 'scheduled_to_be_resident_on' field) *)
      let reserve_memory_for_vm ~__context ~vm ~snapshot ~host ?host_op f =
        Helpers.with_global_lock (fun () ->
            Xapi_vm_helpers.assert_can_boot_here ~__context ~self:vm ~host
              ~snapshot ~do_cpuid_check:false () ;
            (* NB in the case of migrate although we are about to increase free memory on the sending host
               we ignore this because if a failure happens while a VM is in-flight it will still be considered
               on both hosts, potentially breaking the failover plan. *)
            check_vm_preserves_ha_plan ~__context ~vm ~snapshot ~host ;
            allocate_vm_to_host ~__context ~vm ~host ~snapshot ?host_op ()
        ) ;
        finally f (fun () ->
            Helpers.with_global_lock (fun () ->
                finally_clear_host_operation ~__context ~host ?host_op () ;
                clear_reservations ~__context ~vm
            )
        )

      (**
      Used by VM.set_memory_dynamic_range to reserve enough memory for
      increasing dynamic_min. Although a VM may actually be technically
      outside the range [dynamic_min, dynamic_max] we still ensure that *if*
      all VMs are obeying our commands and ballooning to dynamic_min if we ask
      *then* the sum of the dynamic_mins will fit on the host.
     *)
      let reserve_memory_for_dynamic_change ~__context ~vm new_dynamic_min
          new_dynamic_max f =
        let host = Db.VM.get_resident_on ~__context ~self:vm in
        let old_dynamic_min =
          Db.VM.get_memory_dynamic_min ~__context ~self:vm
        in
        let old_dynamic_max =
          Db.VM.get_memory_dynamic_max ~__context ~self:vm
        in
        let restore_old_values_on_error = ref false in
        Helpers.with_global_lock (fun () ->
            let host_mem_available =
              Memory_check.host_compute_free_memory_with_maximum_compression
                ~__context ~host None
            in
            let dynamic_min_change =
              Int64.sub old_dynamic_min new_dynamic_min
            in
            let new_host_mem_available =
              Int64.add host_mem_available dynamic_min_change
            in
            if new_host_mem_available < 0L then
              raise
                (Api_errors.Server_error
                   ( Api_errors.host_not_enough_free_memory
                   , [
                       Int64.to_string
                         (Int64.div (Int64.sub 0L dynamic_min_change) 1024L)
                     ; Int64.to_string (Int64.div host_mem_available 1024L)
                     ]
                   )
                ) ;
            if dynamic_min_change < 0L then (
              restore_old_values_on_error := true ;
              Db.VM.set_memory_dynamic_min ~__context ~self:vm
                ~value:new_dynamic_min ;
              Db.VM.set_memory_dynamic_max ~__context ~self:vm
                ~value:new_dynamic_max
            )
        ) ;
        try f ()
        with exn ->
          if !restore_old_values_on_error then (
            Db.VM.set_memory_dynamic_min ~__context ~self:vm
              ~value:old_dynamic_min ;
            Db.VM.set_memory_dynamic_max ~__context ~self:vm
              ~value:old_dynamic_max
          ) ;
          raise exn

      let forward_to_access_srs ~local_fn ~__context ~vm ~remote_fn =
        let suitable_host =
          Xapi_vm_helpers.choose_host ~__context ~vm
            ~choose_fn:(Xapi_vm_helpers.assert_can_see_SRs ~__context ~self:vm)
            ()
        in
        do_op_on ~local_fn ~__context ~host:suitable_host ~remote_fn

      (* Used for the VM.copy when an SR is specified *)
      let forward_to_access_srs_and ~local_fn ~__context ~remote_fn ?vm
          ?extra_sr () =
        let choose_fn ~host =
          ( match vm with
          | Some vm ->
              Xapi_vm_helpers.assert_can_see_SRs ~__context ~self:vm ~host
          | _ ->
              ()
          ) ;
          match extra_sr with
          | Some extra_sr ->
              Xapi_vm_helpers.assert_can_see_specified_SRs ~__context
                ~reqd_srs:[extra_sr] ~host
          | _ ->
              ()
        in
        let suitable_host =
          Xapi_vm_helpers.choose_host ~__context ?vm ~choose_fn ()
        in
        do_op_on ~local_fn ~__context ~host:suitable_host ~remote_fn

      (* -------------------------------------------------------------------------- *)

      (* don't forward create. this just makes a db record *)
      let create ~__context ~name_label ~name_description =
        info "VM.create: name_label = '%s' name_description = '%s'" name_label
          name_description ;
        (* Partial application: return a function which will take the dozens of remaining params *)
        Local.VM.create ~__context ~name_label ~name_description

      (* don't forward destroy. this just deletes db record *)
      let destroy ~__context ~self =
        info "VM.destroy: VM = '%s'" (vm_uuid ~__context self) ;
        with_vm_operation ~__context ~self ~doc:"VM.destroy" ~op:`destroy
          (fun () -> Local.VM.destroy ~__context ~self
        )

      let set_actions_after_crash ~__context ~self ~value =
        info "VM.set_actions_after_crash: VM = '%s'" (vm_uuid ~__context self) ;
        Local.VM.set_actions_after_crash ~__context ~self ~value

      let set_ha_always_run ~__context ~self ~value =
        info "VM.set_ha_always_run: VM = '%s'; value = '%b'"
          (vm_uuid ~__context self) value ;
        Local.VM.set_ha_always_run ~__context ~self ~value ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self

      let set_ha_restart_priority ~__context ~self ~value =
        info "VM.set_ha_restart_priority: VM = '%s'; value = '%s'"
          (vm_uuid ~__context self) value ;
        Local.VM.set_ha_restart_priority ~__context ~self ~value ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self

      let set_is_a_template ~__context ~self ~value =
        if value then
          with_vm_operation ~__context ~self ~doc:"VM.set_is_a_template"
            ~op:`make_into_template (fun () ->
              Local.VM.set_is_a_template ~__context ~self ~value:true
          )
        else
          Local.VM.set_is_a_template ~__context ~self ~value

      (*
      else raise (Api_errors.Server_error(Api_errors.operation_not_allowed, [ "Must use VM.provision" ]))
     *)

      (* CA-234494: make sure that the allowed operations are updated for default templates *)
      let set_is_default_template ~__context ~vm ~value =
        info "VM.set_is_default_template: VM = %s; value = '%s'"
          (vm_uuid ~__context vm) (string_of_bool value) ;
        (* if the vm is already a template we cannot use with_vm_operation because
         * we would not be allowed to set the field on a template *)
        let is_a_template = Db.VM.get_is_a_template ~__context ~self:vm in
        if value && not is_a_template then
          with_vm_operation ~__context ~self:vm
            ~doc:"VM.set_is_default_template" ~op:`make_into_template (fun () ->
              Local.VM.set_is_default_template ~__context ~vm ~value:true
          )
        else (
          Local.VM.set_is_default_template ~__context ~vm ~value ;
          Xapi_vm_lifecycle.update_allowed_operations ~__context ~self:vm
        )

      let maximise_memory ~__context ~self ~total ~approximate =
        info "VM.maximise_memory: VM = '%s'; total = '%Ld'; approximate = '%b'"
          (vm_uuid ~__context self) total approximate ;
        Local.VM.maximise_memory ~__context ~self ~total ~approximate

      let clone ~__context ~vm ~new_name =
        info "VM.clone: VM = '%s'; new_name = '%s'" (vm_uuid ~__context vm)
          new_name ;
        let local_fn = Local.VM.clone ~vm ~new_name in
        let remote_fn = Client.VM.clone ~vm ~new_name in
        (* We mark the VM as cloning. We don't mark the disks; the implementation of the clone
           uses the API to clone and lock the individual VDIs. We don't give any atomicity
           guarantees here but we do prevent disk corruption. *)
        with_vm_operation ~__context ~self:vm ~doc:"VM.clone" ~op:`clone
          (fun () -> forward_to_access_srs ~local_fn ~__context ~vm ~remote_fn
        )

      let update_snapshot_metadata ~__context ~vm ~snapshot_of ~snapshot_time
          ~transportable_snapshot_id =
        Db.VM.set_is_a_snapshot ~__context ~self:vm ~value:true ;
        Db.VM.set_snapshot_time ~__context ~self:vm ~value:snapshot_time ;
        Db.VM.set_snapshot_of ~__context ~self:vm ~value:snapshot_of ;
        Db.VM.set_transportable_snapshot_id ~__context ~self:vm
          ~value:transportable_snapshot_id

      (* almost a copy of the clone function *)
      let snapshot ~__context ~vm ~new_name ~ignore_vdis =
        info "VM.snapshot: VM = '%s'; new_name = '%s'" (vm_uuid ~__context vm)
          new_name ;
        let local_fn = Local.VM.snapshot ~vm ~new_name ~ignore_vdis in
        let remote_fn = Client.VM.snapshot ~vm ~new_name ~ignore_vdis in
        (* We mark the VM as snapshoting. We don't mark the disks; the implementation of the snapshot uses the API   *)
        (* to snapshot and lock the individual VDIs. We don't give any atomicity guarantees here but we do prevent   *)
        (* disk corruption.                                                                                          *)
        let result =
          with_vm_operation ~__context ~self:vm ~doc:"VM.snapshot" ~op:`snapshot
            (fun () -> forward_to_access_srs ~local_fn ~__context ~vm ~remote_fn
          )
        in
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) snapshotted, snapshot name: %s"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            new_name
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_snapshotted ;
        result

      let checkpoint ~__context ~vm ~new_name =
        info "VM.checkpoint: VM = '%s'; new_name=' %s'" (vm_uuid ~__context vm)
          new_name ;
        let local_fn = Local.VM.checkpoint ~vm ~new_name in
        let remote_fn = Client.VM.checkpoint ~vm ~new_name in
        let result =
          with_vm_operation ~__context ~self:vm ~doc:"VM.checkpoint"
            ~op:`checkpoint (fun () ->
              if Db.VM.get_power_state ~__context ~self:vm = `Running then
                forward_vm_op ~local_fn ~__context ~vm ~remote_fn
              else
                forward_to_access_srs ~local_fn ~__context ~vm ~remote_fn
          )
        in
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) checkpointed, snapshot name: %s"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            new_name
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_checkpointed ;
        result

      let copy ~__context ~vm ~new_name ~sr =
        info "VM.copy: VM = '%s'; new_name = '%s'; SR = '%s'"
          (vm_uuid ~__context vm) new_name (sr_uuid ~__context sr) ;
        (* We mark the VM as cloning. We don't mark the disks; the implementation of the clone
           			   uses the API to clone and lock the individual VDIs. We don't give any atomicity
           			   guarantees here but we do prevent disk corruption.
           			   VM.copy is always run on the master - the VDI.copy subtask(s) will be
           			   forwarded to suitable hosts. *)
        with_vm_operation ~__context ~self:vm ~doc:"VM.copy" ~op:`copy
          (fun () -> Local.VM.copy ~__context ~vm ~new_name ~sr
        )

      exception Ambigious_provision_spec

      exception Not_forwarding

      let provision ~__context ~vm =
        info "VM.provision: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.provision ~vm in
        let remote_fn = Client.VM.provision ~vm in
        let localhost = Helpers.get_localhost ~__context in
        with_vm_operation ~__context ~self:vm ~doc:"VM.provision" ~op:`provision
          (fun () ->
            let template =
              Helpers.call_api_functions ~__context (fun rpc session_id ->
                  Xapi_templates.get_template_record rpc session_id vm
              )
            in
            (* Compute the set of hosts which can see the SRs mentioned in the provision spec *)
            let possible_hosts =
              try
                let srs_in_provision_spec =
                  match template with
                  | None ->
                      []
                  | Some template ->
                      let srs =
                        List.map
                          (fun d -> d.Xapi_templates.sr)
                          template.Xapi_templates.disks
                      in
                      let srs =
                        List.map
                          (fun sr ->
                            try Db.SR.get_by_uuid ~__context ~uuid:sr
                            with
                            | Db_exn.Read_missing_uuid (_, _, _)
                            | Db_exn.Too_many_values (_, _, _)
                            -> (
                              match
                                Db.SR.get_by_name_label ~__context ~label:sr
                              with
                              | [] ->
                                  raise Not_forwarding
                                  (* couldn't find it. Do it locally and will report correct error *)
                              | [x] ->
                                  info "VM.provision: VM = '%s'; SR = '%s'"
                                    (vm_uuid ~__context vm)
                                    (sr_uuid ~__context x) ;
                                  x
                              | _ ->
                                  raise Ambigious_provision_spec
                            )
                          )
                          srs
                      in
                      srs
                in
                Xapi_vm_helpers.possible_hosts ~__context ~vm
                  ~choose_fn:
                    (Xapi_vm_helpers.assert_can_see_specified_SRs ~__context
                       ~reqd_srs:srs_in_provision_spec
                    )
                  ()
              with
              | Not_forwarding ->
                  []
              | Api_errors.Server_error (code, _)
                when code = Api_errors.no_hosts_available ->
                  []
            in
            let hosts =
              if possible_hosts = [] then [localhost] else possible_hosts
            in
            loadbalance_host_operation ~__context ~hosts ~doc:"VM.provision"
              ~op:`provision (fun host ->
                do_op_on ~local_fn ~__context ~host ~remote_fn
            )
        )

      let query_services ~__context ~self =
        info "VM.query_services: VM = '%s'" (vm_uuid ~__context self) ;
        with_vm_operation ~__context ~self ~doc:"VM.query_services"
          ~op:`query_services (fun () ->
            Local.VM.query_services ~__context ~self
        )

      let start ~__context ~vm ~start_paused ~force =
        info "VM.start: VM = '%s'" (vm_uuid ~__context vm) ;
        Pool_features.assert_enabled ~__context ~f:Features.VM_start ;
        Xapi_vm_helpers.assert_no_legacy_hardware ~__context ~vm ;
        let local_fn = Local.VM.start ~vm ~start_paused ~force in
        let remote_fn = Client.VM.start ~vm ~start_paused ~force in
        let host =
          with_vm_operation ~__context ~self:vm ~doc:"VM.start" ~op:`start
            (fun () ->
              with_vbds_marked ~__context ~vm ~doc:"VM.start" ~op:`attach
                (fun _vbds ->
                  with_vifs_marked ~__context ~vm ~doc:"VM.start" ~op:`attach
                    (fun _vifs ->
                      Xapi_vm_helpers.ensure_domain_type_is_specified ~__context
                        ~self:vm ;
                      (* The start operation makes use of the cached memory overhead *)
                      (* value when reserving memory. It's important to recalculate  *)
                      (* the cached value before performing the start since there's  *)
                      (* no guarantee that the cached value is valid. In particular, *)
                      (* we must recalculate the value BEFORE creating the snapshot. *)
                      Xapi_vm_helpers.update_memory_overhead ~__context ~vm ;
                      Xapi_vm_helpers.consider_generic_bios_strings ~__context
                        ~vm ;
                      let snapshot = Db.VM.get_record ~__context ~self:vm in
                      let (), host =
                        forward_to_suitable_host ~local_fn ~__context ~vm
                          ~snapshot ~host_op:`vm_start ~remote_fn ()
                      in
                      host
                  )
              )
          )
        in
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm ;
        let uuid = Db.VM.get_uuid ~__context ~self:vm in
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) started on host: %s (uuid: %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.Host.get_name_label ~__context ~self:host)
            (Db.Host.get_uuid ~__context ~self:host)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_started ;
        Rrdd_proxy.push_rrd ~__context ~vm_uuid:uuid

      let start_on ~__context ~vm ~host ~start_paused ~force =
        if Helpers.rolling_upgrade_in_progress ~__context then
          Helpers.assert_host_has_highest_version_in_pool ~__context ~host ;
        Pool_features.assert_enabled ~__context ~f:Features.VM_start ;
        Xapi_vm_helpers.assert_matches_control_domain_affinity ~__context
          ~self:vm ~host ;
        (* Prevent VM start on a host that is evacuating *)
        List.iter
          (fun op ->
            match op with
            | _, `evacuate ->
                raise
                  (Api_errors.Server_error
                     (Api_errors.host_evacuate_in_progress, [Ref.string_of host])
                  )
            | _ ->
                ()
          )
          (Db.Host.get_current_operations ~__context ~self:host) ;
        info "VM.start_on: VM = '%s'; host '%s'" (vm_uuid ~__context vm)
          (host_uuid ~__context host) ;
        let local_fn = Local.VM.start_on ~vm ~host ~start_paused ~force in
        let remote_fn = Client.VM.start ~vm ~start_paused ~force in
        with_vm_operation ~__context ~self:vm ~doc:"VM.start_on" ~op:`start_on
          (fun () ->
            with_vbds_marked ~__context ~vm ~doc:"VM.start_on" ~op:`attach
              (fun _vbds ->
                with_vifs_marked ~__context ~vm ~doc:"VM.start_on" ~op:`attach
                  (fun _vifs ->
                    Xapi_vm_helpers.ensure_domain_type_is_specified ~__context
                      ~self:vm ;
                    (* The start operation makes use of the cached memory overhead *)
                    (* value when reserving memory. It's important to recalculate  *)
                    (* the cached value before performing the start since there's  *)
                    (* no guarantee that the cached value is valid. In particular, *)
                    (* we must recalculate the value BEFORE creating the snapshot. *)
                    Xapi_vm_helpers.update_memory_overhead ~__context ~vm ;
                    Xapi_vm_helpers.consider_generic_bios_strings ~__context ~vm ;
                    let snapshot = Db.VM.get_record ~__context ~self:vm in
                    reserve_memory_for_vm ~__context ~vm ~host ~snapshot
                      ~host_op:`vm_start (fun () ->
                        do_op_on ~local_fn ~__context ~host ~remote_fn
                    ) ;
                    Xapi_vm_helpers.start_delay ~__context ~vm
                )
            )
        ) ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm ;
        let _ (* uuid *) = Db.VM.get_uuid ~__context ~self:vm in
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) started on host: %s (uuid: %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.Host.get_name_label ~__context ~self:host)
            (Db.Host.get_uuid ~__context ~self:host)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_started ;
        Rrdd_proxy.push_rrd ~__context
          ~vm_uuid:(Db.VM.get_uuid ~__context ~self:vm)

      let pause ~__context ~vm =
        info "VM.pause: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.pause ~vm in
        let remote_fn = Client.VM.pause ~vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.pause" ~op:`pause
          (fun () -> forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) paused"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_paused ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let unpause ~__context ~vm =
        info "VM.unpause: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.unpause ~vm in
        let remote_fn = Client.VM.unpause ~vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.unpause" ~op:`unpause
          (fun () -> forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) unpaused"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_unpaused ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let call_plugin ~__context ~vm ~plugin ~fn ~args =
        info
          "VM.call_plugin: VM = '%s'; plugin = '%s'; fn = '%s'; args = [ \
           'hidden' ]"
          (vm_uuid ~__context vm) plugin fn ;
        let local_fn = Local.VM.call_plugin ~vm ~plugin ~fn ~args in
        let remote_fn = Client.VM.call_plugin ~vm ~plugin ~fn ~args in
        with_vm_operation ~__context ~self:vm ~doc:"VM.call_plugin"
          ~op:`call_plugin ~policy:Helpers.Policy.fail_immediately (fun () ->
            forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        )

      let call_host_plugin ~__context ~vm ~plugin ~fn ~args =
        info
          "VM.call_host_plugin: VM = '%s'; plugin = '%s'; fn = '%s'; args = [ \
           'hidden' ]"
          (vm_uuid ~__context vm) plugin fn ;
        let local_fn = Local.VM.call_host_plugin ~vm ~plugin ~fn ~args in
        let remote_fn = Client.VM.call_host_plugin ~vm ~plugin ~fn ~args in
        let power_state = Db.VM.get_power_state ~__context ~self:vm in
        (* Insisting on running to make sure xenstore and domain exist
           and the VM can react to xenstore events. Permitting Paused in
           addition could be an option *)
        if power_state <> `Running then
          raise
            Api_errors.(
              Server_error
                ( vm_bad_power_state
                , [
                    Ref.string_of vm
                  ; Record_util.vm_power_state_to_string `Running
                  ; Record_util.vm_power_state_to_string power_state
                  ]
                )
            ) ;
        with_vm_operation ~__context ~self:vm ~doc:"VM.call_host_plugin"
          ~op:`call_plugin ~policy:Helpers.Policy.fail_immediately (fun () ->
            forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        )

      let set_has_vendor_device ~__context ~self ~value =
        info "VM.set_has_vendor_device: VM = '%s' to %b"
          (vm_uuid ~__context self) value ;
        Local.VM.set_has_vendor_device ~__context ~self ~value

      let set_xenstore_data ~__context ~self ~value =
        info "VM.set_xenstore_data: VM = '%s'" (vm_uuid ~__context self) ;
        Db.VM.set_xenstore_data ~__context ~self ~value ;
        let power_state = Db.VM.get_power_state ~__context ~self in
        if power_state = `Running then
          let local_fn = Local.VM.set_xenstore_data ~self ~value in
          let remote_fn = Client.VM.set_xenstore_data ~self ~value in
          forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn

      let clean_shutdown ~__context ~vm =
        info "VM.clean_shutdown: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.clean_shutdown ~vm in
        let remote_fn = Client.VM.clean_shutdown ~vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.clean_shutdown"
          ~op:`clean_shutdown (fun () ->
            forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) shutdown"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_shutdown ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let shutdown ~__context ~vm =
        info "VM.shutdown: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.shutdown ~vm in
        let remote_fn = Client.VM.shutdown ~vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.shutdown" ~op:`shutdown
          (fun () ->
            if Db.VM.get_power_state ~__context ~self:vm = `Suspended then (
              debug
                "VM '%s' is suspended. Shutdown will just delete suspend VDI"
                (Ref.string_of vm) ;
              let all_vm_srs =
                Xapi_vm_helpers
                .compute_required_SRs_for_shutting_down_suspended_domains
                  ~__context ~vm
              in
              let suitable_host =
                Xapi_vm_helpers.choose_host ~__context ~vm
                  ~choose_fn:
                    (Xapi_vm_helpers.assert_can_see_specified_SRs ~__context
                       ~reqd_srs:all_vm_srs
                    )
                  ()
              in
              do_op_on ~__context
                ~local_fn:(Local.VM.hard_shutdown ~vm)
                ~host:suitable_host
                ~remote_fn:(Client.VM.hard_shutdown ~vm)
            ) else
              forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        ) ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) shutdown"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_shutdown

      let clean_reboot ~__context ~vm =
        info "VM.clean_reboot: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.clean_reboot ~vm in
        let remote_fn = Client.VM.clean_reboot ~vm in
        (* Mark all the VBDs to prevent someone nicking one of the VDIs (or attaching
           			   a conflicting VBD) while the devices are detached *)
        with_vm_operation ~__context ~self:vm ~doc:"VM.clean_reboot"
          ~op:`clean_reboot (fun () ->
            with_vbds_marked ~__context ~vm ~doc:"VM.clean_reboot" ~op:`attach
              (fun _vbds ->
                with_vifs_marked ~__context ~vm ~doc:"VM.clean_reboot"
                  ~op:`attach (fun _vifs ->
                    (* CA-31903: we don't need to reserve memory for reboot
                       because the memory settings can't change across reboot. *)
                    forward_vm_op ~local_fn ~__context ~vm ~remote_fn
                )
            )
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) rebooted cleanly"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_rebooted ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      (* don't forward power_state_reset; the whole point is that this can be performed when a host is down *)
      let power_state_reset ~__context ~vm =
        info "VM.power_state_reset: VM = '%s'" (vm_uuid ~__context vm) ;
        Local.VM.power_state_reset ~__context ~vm

      let hard_shutdown ~__context ~vm =
        info "VM.hard_shutdown: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.hard_shutdown ~vm in
        let remote_fn = Client.VM.hard_shutdown ~vm in
        let host = Db.VM.get_resident_on ~__context ~self:vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.hard_shutdown"
          ~op:`hard_shutdown (fun () ->
            cancel ~__context ~vm
              ~ops:
                [
                  `clean_shutdown
                ; `clean_reboot
                ; `hard_reboot
                ; `pool_migrate
                ; `call_plugin
                ; `shutdown
                ; `suspend
                ] ;
            (* If VM is actually suspended and we ask to hard_shutdown, we need to
               					   forward to any host that can see the VDIs *)
            let policy =
              if Db.VM.get_power_state ~__context ~self:vm = `Suspended then (
                debug
                  "VM '%s' is suspended. Shutdown will just delete suspend VDI"
                  (Ref.string_of vm) ;
                (* this expression evaluates to a fn that forwards to a host that can see all vdis: *)
                let all_vm_srs =
                  Xapi_vm_helpers
                  .compute_required_SRs_for_shutting_down_suspended_domains
                    ~__context ~vm
                in
                let suitable_host =
                  Xapi_vm_helpers.choose_host ~__context ~vm
                    ~choose_fn:
                      (Xapi_vm_helpers.assert_can_see_specified_SRs ~__context
                         ~reqd_srs:all_vm_srs
                      )
                    ()
                in
                do_op_on ~host:suitable_host
              ) else
                (* if we're nt suspended then just forward to host that has vm running on it: *)
                do_op_on ~host
            in
            policy ~local_fn ~__context ~remote_fn
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) shutdown forcibly"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_shutdown ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let hard_reboot ~__context ~vm =
        info "VM.hard_reboot: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.hard_reboot ~vm in
        let remote_fn = Client.VM.hard_reboot ~vm in
        let host = Db.VM.get_resident_on ~__context ~self:vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.hard_reboot"
          ~op:`hard_reboot (fun () ->
            cancel ~__context ~vm
              ~ops:
                [
                  `clean_shutdown
                ; `clean_reboot
                ; `pool_migrate
                ; `call_plugin
                ; `suspend
                ] ;
            with_vbds_marked ~__context ~vm ~doc:"VM.hard_reboot" ~op:`attach
              (fun _vbds ->
                with_vifs_marked ~__context ~vm ~doc:"VM.hard_reboot"
                  ~op:`attach (fun _vifs ->
                    (* CA-31903: we don't need to reserve memory for reboot
                       because the memory settings can't change across reboot. *)
                    do_op_on ~host ~local_fn ~__context ~remote_fn
                )
            )
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) rebooted forcibly"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_rebooted ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let hard_reboot_internal ~__context ~vm =
        info "VM.hard_reboot_internal: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.hard_reboot_internal ~vm in
        let remote_fn = Client.VM.hard_reboot_internal ~vm in
        (* no VM operation: we assume the VM is still Running *)
        with_vbds_marked ~__context ~vm ~doc:"VM.hard_reboot" ~op:`attach
          (fun _vbds ->
            with_vifs_marked ~__context ~vm ~doc:"VM.hard_reboot" ~op:`attach
              (fun _vifs ->
                (* CA-31903: we don't need to reserve memory for reboot because the memory settings can't
                   							   change across reboot. *)
                forward_vm_op ~local_fn ~__context ~vm ~remote_fn
            )
        ) ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let suspend ~__context ~vm =
        info "VM.suspend: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.suspend ~vm in
        let remote_fn = Client.VM.suspend ~vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.suspend" ~op:`suspend
          (fun () -> forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        ) ;
        (* debug "placeholder for retrieving the current value of memory-actual";*)
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) suspended"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_suspended ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let revert ~__context ~snapshot =
        info "VM.revert: snapshot = '%s'" (vm_uuid ~__context snapshot) ;
        let vm = Db.VM.get_snapshot_of ~__context ~self:snapshot in
        let vm =
          if Db.is_valid_ref __context vm then
            vm
          else
            Xapi_vm_snapshot.create_vm_from_snapshot ~__context ~snapshot
        in
        let local_fn = Local.VM.revert ~snapshot in
        let remote_fn ~rpc:_ ~session_id:_ =
          Local.VM.revert ~__context ~snapshot
        in
        with_vm_operation ~__context ~self:snapshot ~doc:"VM.revert" ~op:`revert
          (fun () ->
            with_vm_operation ~__context ~self:vm ~doc:"VM.reverting"
              ~op:`reverting (fun () ->
                (* We need to do a best-effort check that any suspend_VDI referenced by
                   the snapshot (not the current VM) is currently accessible. This is because
                   the revert code first clears space by deleting current VDIs before cloning
                   the suspend VDI: we want to minimise the probability that the operation fails
                   part-way through. *)
                ( if Db.VM.get_power_state ~__context ~self:snapshot = `Suspended
                  then
                    let suspend_VDI =
                      Db.VM.get_suspend_VDI ~__context ~self:snapshot
                    in
                    let sr = Db.VDI.get_SR ~__context ~self:suspend_VDI in
                    let pbd =
                      choose_pbd_for_sr ~consider_unplugged_pbds:false
                        ~__context ~self:sr ()
                    in
                    let host = Db.PBD.get_host ~__context ~self:pbd in
                    let metrics = Db.Host.get_metrics ~__context ~self:host in
                    let live =
                      Db.is_valid_ref __context metrics
                      && Db.Host_metrics.get_live ~__context ~self:metrics
                    in
                    if not live then
                      raise
                        (Api_errors.Server_error
                           (Api_errors.host_not_live, [Ref.string_of host])
                        )
                ) ;
                (* first of all, destroy the domain if needed. *)
                if Db.VM.get_power_state ~__context ~self:vm <> `Halted then (
                  debug
                    "VM %s (domid %Ld) which is reverted is not halted: \
                     shutting it down first"
                    (Db.VM.get_uuid ~__context ~self:vm)
                    (Db.VM.get_domid ~__context ~self:vm) ;
                  Helpers.call_api_functions ~__context (fun rpc session_id ->
                      Client.VM.hard_shutdown ~rpc ~session_id ~vm
                  )
                ) ;
                Xapi_vm_snapshot.revert_vm_fields ~__context ~snapshot ~vm ;
                if Db.VM.get_power_state ~__context ~self:vm = `Running then
                  forward_vm_op ~local_fn ~__context ~vm ~remote_fn
                else
                  forward_to_access_srs ~local_fn ~__context ~vm ~remote_fn
            )
        ) ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) reverted to snapshot: %s (uuid %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.VM.get_name_label ~__context ~self:snapshot)
            (Db.VM.get_uuid ~__context ~self:snapshot)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_snapshot_reverted

      (* same forwarding logic as clone *)
      let csvm ~__context ~vm =
        info "VM.csvm: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.csvm ~vm in
        let remote_fn = Client.VM.csvm ~vm in
        (* We mark the VM as cloning. We don't mark the disks; the implementation of the clone
           			   uses the API to clone and lock the individual VDIs. We don't give any atomicity
           			   guarantees here but we do prevent disk corruption. *)
        let suspend_sr =
          Db.VDI.get_SR ~__context
            ~self:(Db.VM.get_suspend_VDI ~__context ~self:vm)
        in
        let result =
          with_vm_operation ~__context ~self:vm ~doc:"VM.csvm" ~op:`csvm
            (fun () ->
              forward_to_access_srs_and ~extra_sr:suspend_sr ~local_fn
                ~__context ~vm ~remote_fn ()
          )
        in
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) cloned (new uuid: %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:result)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_cloned ;
        result

      (* Like start.. resume on any suitable host *)
      let resume ~__context ~vm ~start_paused ~force =
        info "VM.resume: VM = '%s'" (vm_uuid ~__context vm) ;
        Xapi_vm_helpers.assert_no_legacy_hardware ~__context ~vm ;
        let local_fn = Local.VM.resume ~vm ~start_paused ~force in

        let remote_fn = Client.VM.resume ~vm ~start_paused ~force in
        let host =
          with_vm_operation ~__context ~self:vm ~doc:"VM.resume" ~op:`resume
            (fun () ->
              with_vbds_marked ~__context ~vm ~doc:"VM.resume" ~op:`attach
                (fun _vbds ->
                  Xapi_vm_helpers.ensure_domain_type_is_specified ~__context
                    ~self:vm ;
                  let snapshot = Db.VM.get_record ~__context ~self:vm in
                  let (), host =
                    forward_to_suitable_host ~local_fn ~__context ~vm ~snapshot
                      ~host_op:`vm_resume ~remote_fn ()
                  in
                  host
              )
          )
        in
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) resumed on host: %s (uuid: %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.Host.get_name_label ~__context ~self:host)
            (Db.Host.get_uuid ~__context ~self:host)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_resumed ;
        Rrdd_proxy.push_rrd ~__context
          ~vm_uuid:(Db.VM.get_uuid ~__context ~self:vm)

      let resume_on ~__context ~vm ~host ~start_paused ~force =
        if Helpers.rolling_upgrade_in_progress ~__context then
          Helpers.assert_host_has_highest_version_in_pool ~__context ~host ;
        info "VM.resume_on: VM = '%s'; host = '%s'" (vm_uuid ~__context vm)
          (host_uuid ~__context host) ;
        let local_fn = Local.VM.resume_on ~vm ~host ~start_paused ~force in
        let remote_fn = Client.VM.resume_on ~vm ~host ~start_paused ~force in
        Xapi_vm_helpers.assert_no_legacy_hardware ~__context ~vm ;
        with_vm_operation ~__context ~self:vm ~doc:"VM.resume_on" ~op:`resume_on
          (fun () ->
            with_vbds_marked ~__context ~vm ~doc:"VM.resume_on" ~op:`attach
              (fun _vbds ->
                Xapi_vm_helpers.ensure_domain_type_is_specified ~__context
                  ~self:vm ;
                let snapshot = Db.VM.get_record ~__context ~self:vm in
                reserve_memory_for_vm ~__context ~vm ~host ~snapshot
                  ~host_op:`vm_resume (fun () ->
                    do_op_on ~local_fn ~__context ~host ~remote_fn
                )
            )
        ) ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm ;
        let message_body =
          Printf.sprintf "VM '%s' (uuid: %s) resumed on host: %s (uuid: %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.Host.get_name_label ~__context ~self:host)
            (Db.Host.get_uuid ~__context ~self:host)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_resumed ;
        Rrdd_proxy.push_rrd ~__context
          ~vm_uuid:(Db.VM.get_uuid ~__context ~self:vm)

      let pool_migrate_complete ~__context ~vm ~host =
        info "VM.pool_migrate_complete: VM = '%s'; host = '%s'"
          (vm_uuid ~__context vm)
          (host_uuid ~__context host) ;
        let local_fn = Local.VM.pool_migrate_complete ~vm ~host in
        let remote_fn = Client.VM.pool_migrate_complete ~vm ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let pool_migrate ~__context ~vm ~host ~options =
        info "VM.pool_migrate: VM = '%s'; host = '%s'" (vm_uuid ~__context vm)
          (host_uuid ~__context host) ;
        let local_fn = Local.VM.pool_migrate ~vm ~host ~options in
        let remote_fn = Client.VM.pool_migrate ~vm ~host ~options in
        (* Check that the VM is compatible with the host it is being migrated to. *)
        let force =
          try bool_of_string (List.assoc "force" options) with _ -> false
        in
        if not force then
          Cpuid_helpers.assert_vm_is_compatible ~__context ~vm:(`db vm) ~host ;
        let source_host = Db.VM.get_resident_on ~__context ~self:vm in
        with_vm_operation ~__context ~self:vm ~doc:"VM.pool_migrate"
          ~op:`pool_migrate ~strict:(not force) (fun () ->
            let to_equal_or_greater_version =
              Helpers.host_versions_not_decreasing ~__context
                ~host_from:(Helpers.LocalObject source_host)
                ~host_to:(Helpers.LocalObject host)
            in
            if
              Helpers.rolling_upgrade_in_progress ~__context
              && not to_equal_or_greater_version
            then
              raise
                (Api_errors.Server_error
                   (Api_errors.not_supported_during_upgrade, [])
                ) ;
            (* Make sure the target has enough memory to receive the VM *)
            let snapshot = Db.VM.get_record ~__context ~self:vm in
            reserve_memory_for_vm ~__context ~vm ~host ~snapshot
              ~host_op:`vm_migrate (fun () ->
                forward_vm_op ~local_fn ~__context ~vm ~remote_fn
            )
        ) ;
        let message_body =
          Printf.sprintf
            "VM '%s' (uuid: %s) migrated from host '%s' (uuid: %s) to host \
             '%s' (uuid: %s)"
            (Db.VM.get_name_label ~__context ~self:vm)
            (Db.VM.get_uuid ~__context ~self:vm)
            (Db.Host.get_name_label ~__context ~self:source_host)
            (Db.Host.get_uuid ~__context ~self:source_host)
            (Db.Host.get_name_label ~__context ~self:host)
            (Db.Host.get_uuid ~__context ~self:host)
        in
        create_vm_message ~__context ~vm ~message_body
          ~message:Api_messages.vm_migrated ;
        update_vbd_operations ~__context ~vm ;
        update_vif_operations ~__context ~vm

      let assert_can_migrate_sender ~__context ~vm ~dest ~live ~vdi_map ~vif_map
          ~vgpu_map ~options =
        info "VM.assert_can_migrate_sender: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn =
          Local.VM.assert_can_migrate_sender ~vm ~dest ~live ~vdi_map ~vif_map
            ~vgpu_map ~options
        in
        let remote_fn =
          Client.VM.assert_can_migrate_sender ~vm ~dest ~live ~vdi_map ~vif_map
            ~vgpu_map ~options
        in
        try forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        with
        | Api_errors.Server_error (code, _)
        when code = Api_errors.message_method_unknown
        ->
          warn
            "VM.assert_can_migrate_sender is not known by destination, \
             assuming it can ignore this check."

      let assert_can_migrate ~__context ~vm ~dest ~live ~vdi_map ~vif_map
          ~options ~vgpu_map =
        info "VM.assert_can_migrate: VM = '%s'" (vm_uuid ~__context vm) ;
        (* Run the checks that can be done using just the DB directly on the master *)
        Local.VM.assert_can_migrate ~__context ~vm ~dest ~live ~vdi_map ~vif_map
          ~vgpu_map ~options ;
        (* Run further checks on the sending host *)
        assert_can_migrate_sender ~__context ~vm ~dest ~live ~vdi_map ~vif_map
          ~vgpu_map ~options

      let migrate_send ~__context ~vm ~dest ~live ~vdi_map ~vif_map ~options
          ~vgpu_map =
        info "VM.migrate_send: VM = '%s'" (vm_uuid ~__context vm) ;
        let source_host = Db.VM.get_resident_on ~__context ~self:vm in
        let local_fn =
          Local.VM.migrate_send ~vm ~dest ~live ~vdi_map ~vif_map ~vgpu_map
            ~options
        in
        let remote_fn =
          Client.VM.migrate_send ~vm ~dest ~live ~vdi_map ~vif_map ~options
            ~vgpu_map
        in
        let migration_type =
          if Xapi_vm_lifecycle_helpers.is_live ~__context ~self:vm then
            let host = List.assoc Xapi_vm_migrate._host dest |> Ref.of_string in
            if Db.is_valid_ref __context host then
              `Live_intrapool host
            else
              `Live_interpool
          else
            `Non_live
        in
        let forward_migrate_send () =
          let forward_internal_async () =
            forward_vm_op ~local_fn ~__context ~vm
              ~remote_fn:(fun ~rpc ~session_id ->
                (* try InternalAsync.VM.migrate_send first to avoid long running idle stunnel connection
                   * fall back on Async.VM.migrate_send if slave doesn't support InternalAsync *)
                Helpers.try_internal_async ~__context API.ref_VM_of_rpc
                  (fun () ->
                    Client.InternalAsync.VM.migrate_send ~rpc ~session_id ~vm
                      ~dest ~live ~vdi_map ~vif_map ~options ~vgpu_map
                  )
                  (fun () -> remote_fn ~session_id ~rpc)
            )
          in
          match migration_type with
          | `Live_interpool ->
              forward_internal_async ()
              (* resources on the destination will be reserved separately *)
          | `Non_live ->
              let snapshot = Db.VM.get_record ~__context ~self:vm in
              fst
                (forward_to_suitable_host ~local_fn ~__context ~vm ~snapshot
                   ~host_op:`vm_migrate ~remote_fn ()
                )
          | `Live_intrapool host ->
              (* reserve resources on the destination host, then forward the call to the source. *)
              let snapshot = Db.VM.get_record ~__context ~self:vm in
              let clear_migrate_op () =
                Helpers.with_global_lock (fun () ->
                    finally_clear_host_operation ~__context ~host
                      ~host_op:`vm_migrate () ;
                    clear_reservations ~__context ~vm
                )
              in
              finally
                (fun () ->
                  allocate_vm_to_host ~__context ~vm ~host ~snapshot
                    ~host_op:`vm_migrate () ;
                  forward_internal_async ()
                )
                clear_migrate_op
        in
        let result =
          with_vm_operation ~__context ~self:vm ~doc:"VM.migrate_send"
            ~op:`migrate_send (fun () ->
              Server_helpers.exec_with_subtask ~__context
                "VM.assert_can_migrate" (fun ~__context ->
                  assert_can_migrate ~__context ~vm ~dest ~live ~vdi_map
                    ~vif_map ~vgpu_map ~options
              ) ;
              forward_migrate_send ()
          )
        in
        ( match migration_type with
        | `Live_intrapool host ->
            let message_body =
              Printf.sprintf
                "VM '%s' (uuid: %s) migrated from host '%s' (uuid: %s) to host \
                 '%s' (uuid: %s)"
                (Db.VM.get_name_label ~__context ~self:vm)
                (Db.VM.get_uuid ~__context ~self:vm)
                (Db.Host.get_name_label ~__context ~self:source_host)
                (Db.Host.get_uuid ~__context ~self:source_host)
                (Db.Host.get_name_label ~__context ~self:host)
                (Db.Host.get_uuid ~__context ~self:host)
            in
            create_vm_message ~__context ~vm ~message_body
              ~message:Api_messages.vm_migrated
        | _ ->
            ()
        ) ;
        result

      let send_trigger ~__context ~vm ~trigger =
        info "VM.send_trigger: VM = '%s'; trigger = '%s'"
          (vm_uuid ~__context vm) trigger ;
        let local_fn = Local.VM.send_trigger ~vm ~trigger in
        let remote_fn = Client.VM.send_trigger ~vm ~trigger in
        with_vm_operation ~__context ~self:vm ~doc:"VM.send_trigger"
          ~op:`send_trigger (fun () ->
            forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        )

      let send_sysrq ~__context ~vm ~key =
        info "VM.send_sysrq: VM = '%s'; sysrq = '%s'" (vm_uuid ~__context vm)
          key ;
        let local_fn = Local.VM.send_sysrq ~vm ~key in
        let remote_fn = Client.VM.send_sysrq ~vm ~key in
        with_vm_operation ~__context ~self:vm ~doc:"VM.send_sysrq"
          ~op:`send_sysrq (fun () ->
            forward_vm_op ~local_fn ~__context ~vm ~remote_fn
        )

      let set_VCPUs_number_live ~__context ~self ~nvcpu =
        info "VM.set_VCPUs_number_live: VM = '%s'; number_of_VCPU = %Ld"
          (vm_uuid ~__context self) nvcpu ;
        let local_fn = Local.VM.set_VCPUs_number_live ~self ~nvcpu in
        let remote_fn = Client.VM.set_VCPUs_number_live ~self ~nvcpu in
        with_vm_operation ~__context ~self ~doc:"VM.set_VCPUs_number_live"
          ~op:`changing_VCPUs_live (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let add_to_VCPUs_params_live ~__context ~self ~key ~value =
        info "VM.add_to_VCPUs_params_live: VM = '%s'; params = ('%s','%s')"
          (vm_uuid ~__context self) key value ;
        let local_fn = Local.VM.add_to_VCPUs_params_live ~self ~key ~value in
        let remote_fn = Client.VM.add_to_VCPUs_params_live ~self ~key ~value in
        with_vm_operation ~__context ~self ~doc:"VM.add_to_VCPUs_params_live"
          ~op:`changing_VCPUs_live (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let set_NVRAM ~__context ~self ~value =
        info "VM.set_NVRAM: self='%s'" (vm_uuid ~__context self) ;
        with_vm_operation ~__context ~self ~doc:"VM.set_NVRAM"
          ~op:`changing_NVRAM (fun () ->
            Local.VM.set_NVRAM ~__context ~self ~value
        )

      let remove_from_NVRAM ~__context ~self ~key =
        info "VM.remove_from_NVRAM: self='%s', key='%s'"
          (vm_uuid ~__context self) key ;
        with_vm_operation ~__context ~self ~doc:"VM.remove_from_NVRAM"
          ~op:`changing_NVRAM (fun () ->
            Local.VM.remove_from_NVRAM ~__context ~self ~key
        )

      let add_to_NVRAM ~__context ~self ~key ~value =
        info "VM.add_to_NVRAM: self='%s', key='%s'" (vm_uuid ~__context self)
          key ;
        with_vm_operation ~__context ~self ~doc:"VM.add_to_NVRAM"
          ~op:`changing_NVRAM (fun () ->
            Local.VM.add_to_NVRAM ~__context ~self ~key ~value
        )

      let set_VCPUs_max ~__context ~self ~value =
        info "VM.set_VCPUs_max: self = %s; value = %Ld"
          (vm_uuid ~__context self) value ;
        with_vm_operation ~__context ~self ~doc:"VM.set_VCPUs_max"
          ~op:`changing_VCPUs (fun () ->
            Local.VM.set_VCPUs_max ~__context ~self ~value
        )

      let set_VCPUs_at_startup ~__context ~self ~value =
        info "VM.set_VCPUs_at_startup: self = %s; value = %Ld"
          (vm_uuid ~__context self) value ;
        Local.VM.set_VCPUs_at_startup ~__context ~self ~value

      let compute_memory_overhead ~__context ~vm =
        info "VM.compute_memory_overhead: vm = '%s'" (vm_uuid ~__context vm) ;
        Local.VM.compute_memory_overhead ~__context ~vm

      let set_memory_dynamic_range ~__context ~self ~min ~max =
        info "VM.set_memory_dynamic_range: VM = '%s'; min = %Ld; max = %Ld"
          (Ref.string_of self) min max ;
        let local_fn = Local.VM.set_memory_dynamic_range ~self ~min ~max in
        let remote_fn = Client.VM.set_memory_dynamic_range ~self ~min ~max in
        with_vm_operation ~__context ~self ~doc:"VM.set_memory_dynamic_range"
          ~op:`changing_dynamic_range (fun () ->
            (* XXX: Perform basic parameter validation, before forwarding *)
            (*      to the slave. Do this after sorting out the last boot *)
            (*      record via set_static_range.                          *)
            let power_state = Db.VM.get_power_state ~__context ~self in
            match power_state with
            | `Running ->
                (* If current dynamic_min is lower  *)
                (* then we will block the operation *)
                reserve_memory_for_dynamic_change ~__context ~vm:self min max
                  (fun () ->
                    forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
                )
            | `Halted ->
                local_fn ~__context
            | _ ->
                failwith
                  "assertion_failure: set_memory_dynamic_range: power_state \
                   should be Halted or Running"
        )

      let set_memory_dynamic_max ~__context ~self ~value =
        info "VM.set_memory_dynamic_max: VM = '%s'; value = %Ld"
          (vm_uuid ~__context self) value ;
        set_memory_dynamic_range ~__context ~self ~max:value
          ~min:(Db.VM.get_memory_dynamic_min ~__context ~self)

      let set_memory_dynamic_min ~__context ~self ~value =
        info "VM.set_memory_dynamic_min: VM = '%s'; value = %Ld"
          (vm_uuid ~__context self) value ;
        set_memory_dynamic_range ~__context ~self ~min:value
          ~max:(Db.VM.get_memory_dynamic_max ~__context ~self)

      let set_memory_static_range ~__context ~self ~min ~max =
        info "VM.set_memory_static_range: self = %s; min = %Ld; max = %Ld"
          (vm_uuid ~__context self) min max ;
        with_vm_operation ~__context ~self ~doc:"VM.set_memory_static_range"
          ~op:`changing_static_range (fun () ->
            Local.VM.set_memory_static_range ~__context ~self ~min ~max
        )

      let set_memory_static_max ~__context ~self ~value =
        info "VM.set_memory_static_max: VM = '%s'; value = %Ld"
          (vm_uuid ~__context self) value ;
        set_memory_static_range ~__context ~self ~max:value
          ~min:(Db.VM.get_memory_static_min ~__context ~self)

      let set_memory_static_min ~__context ~self ~value =
        info "VM.set_memory_static_min: VM = '%s'; value = %Ld"
          (vm_uuid ~__context self) value ;
        set_memory_static_range ~__context ~self ~min:value
          ~max:(Db.VM.get_memory_static_max ~__context ~self)

      let set_memory_limits ~__context ~self ~static_min ~static_max
          ~dynamic_min ~dynamic_max =
        info
          "VM.set_memory_limits: self = %s; static_min = %Ld; static_max = \
           %Ld; dynamic_min = %Ld; dynamic_max = %Ld"
          (vm_uuid ~__context self) static_min static_max dynamic_min
          dynamic_max ;
        let local_fn =
          Local.VM.set_memory_limits ~self ~static_min ~static_max ~dynamic_min
            ~dynamic_max
        in
        let remote_fn =
          Client.VM.set_memory_limits ~self ~static_min ~static_max ~dynamic_min
            ~dynamic_max
        in
        with_vm_operation ~__context ~self ~doc:"VM.set_memory_limits"
          ~op:`changing_memory_limits (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let set_memory ~__context ~self ~value =
        info "VM.set_memory: self = %s; value = %Ld" (vm_uuid ~__context self)
          value ;
        let local_fn = Local.VM.set_memory ~self ~value in
        let remote_fn = Client.VM.set_memory ~self ~value in
        with_vm_operation ~__context ~self ~doc:"VM.set_memory"
          ~op:`changing_memory_limits (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let set_memory_target_live ~__context ~self ~target =
        info "VM.set_memory_target_live: VM = '%s'; min = %Ld"
          (vm_uuid ~__context self) target ;
        let local_fn = Local.VM.set_memory_target_live ~self ~target in
        let remote_fn = Client.VM.set_memory_target_live ~self ~target in
        with_vm_operation ~__context ~self ~doc:"VM.set_memory_target_live"
          ~op:`changing_memory_live (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let wait_memory_target_live ~__context ~self =
        info "VM.wait_memory_target_live: VM = '%s'" (vm_uuid ~__context self) ;
        let local_fn = Local.VM.wait_memory_target_live ~self in
        let remote_fn = Client.VM.wait_memory_target_live ~self in
        with_vm_operation ~__context ~self ~doc:"VM.wait_memory_target_live"
          ~op:`awaiting_memory_live (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      (* Dummy implementation for a deprecated API method. *)
      let get_cooperative ~__context ~self =
        info "VM.get_cooperative: VM = '%s'" (vm_uuid ~__context self) ;
        Local.VM.get_cooperative ~__context ~self

      let set_HVM_shadow_multiplier ~__context ~self ~value =
        info "VM.set_HVM_shadow_multiplier: self = %s; multiplier = %f"
          (vm_uuid ~__context self) value ;
        with_vm_operation ~__context ~self ~doc:"VM.set_HVM_shadow_multiplier"
          ~op:`changing_shadow_memory (fun () ->
            Local.VM.set_HVM_shadow_multiplier ~__context ~self ~value
        )

      let set_shadow_multiplier_live ~__context ~self ~multiplier =
        info "VM.set_shadow_multiplier_live: VM = '%s'; min = %f"
          (vm_uuid ~__context self) multiplier ;
        (* No need to perform a memory calculation here: the real code
           will tell us if the new value is too big. *)
        let local_fn = Local.VM.set_shadow_multiplier_live ~self ~multiplier in
        let remote_fn =
          Client.VM.set_shadow_multiplier_live ~self ~multiplier
        in
        with_vm_operation ~__context ~self ~doc:"VM.set_shadow_multiplier_live"
          ~op:`changing_shadow_memory_live (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      (* this is in db *)
      let get_boot_record ~__context ~self =
        info "VM.get_boot_record: VM = '%s'" (vm_uuid ~__context self) ;
        with_vm_operation ~__context ~self ~doc:"VM.get_boot_record"
          ~op:`get_boot_record (fun () ->
            Local.VM.get_boot_record ~__context ~self
        )

      let get_data_sources ~__context ~self =
        info "VM.get_data_sources: VM = '%s'" (vm_uuid ~__context self) ;
        let local_fn = Local.VM.get_data_sources ~self in
        let remote_fn = Client.VM.get_data_sources ~self in
        with_vm_operation ~__context ~self ~doc:"VM.get_data_source"
          ~op:`data_source_op (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let record_data_source ~__context ~self ~data_source =
        info "VM.record_data_source: VM = '%s'; data source = '%s'"
          (vm_uuid ~__context self) data_source ;
        let local_fn = Local.VM.record_data_source ~self ~data_source in
        let remote_fn = Client.VM.record_data_source ~self ~data_source in
        with_vm_operation ~__context ~self ~doc:"VM.record_data_source"
          ~op:`data_source_op (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let query_data_source ~__context ~self ~data_source =
        info "VM.query_data_source: VM = '%s'; data source = '%s'"
          (vm_uuid ~__context self) data_source ;
        Xapi_vm_lifecycle.assert_initial_power_state_in ~__context ~self
          ~allowed:[`Running; `Paused] ;
        let local_fn = Local.VM.query_data_source ~self ~data_source in
        let remote_fn = Client.VM.query_data_source ~self ~data_source in
        forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn

      let forget_data_source_archives ~__context ~self ~data_source =
        info "VM.forget_data_source_archives: VM = '%s'; data source = '%s'"
          (vm_uuid ~__context self) data_source ;
        let local_fn =
          Local.VM.forget_data_source_archives ~self ~data_source
        in
        let remote_fn =
          Client.VM.forget_data_source_archives ~self ~data_source
        in
        with_vm_operation ~__context ~self ~doc:"VM.forget_data_source_archives"
          ~op:`data_source_op (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )

      let get_possible_hosts ~__context ~vm =
        info "VM.get_possible_hosts: VM = '%s'" (vm_uuid ~__context vm) ;
        Local.VM.get_possible_hosts ~__context ~vm

      let assert_operation_valid ~__context ~self ~op =
        info "VM.assert_operation_valid: VM = '%s'" (vm_uuid ~__context self) ;
        Local.VM.assert_operation_valid ~__context ~self ~op

      let update_allowed_operations ~__context ~self =
        info "VM.update_allowed_operations: VM = '%s'" (vm_uuid ~__context self) ;
        Local.VM.update_allowed_operations ~__context ~self

      let assert_can_boot_here ~__context ~self ~host =
        info "VM.assert_can_boot_here: VM = '%s'; host = '%s'"
          (vm_uuid ~__context self)
          (host_uuid ~__context host) ;
        if Db.VM.get_power_state ~__context ~self = `Halted then
          Pool_features.assert_enabled ~__context ~f:Features.VM_start ;
        Local.VM.assert_can_boot_here ~__context ~self ~host

      let retrieve_wlb_recommendations ~__context ~vm =
        info "VM.retrieve_wlb_recommendations: VM = '%s'" (vm_uuid ~__context vm) ;
        Local.VM.retrieve_wlb_recommendations ~__context ~vm

      let assert_agile ~__context ~self =
        info "VM.assert_agile: VM = '%s'" (vm_uuid ~__context self) ;
        Local.VM.assert_agile ~__context ~self

      let get_allowed_VBD_devices ~__context ~vm =
        info "VM.get_allowed_VBD_devices: VM = '%s'" (vm_uuid ~__context vm) ;
        Local.VM.get_allowed_VBD_devices ~__context ~vm

      let get_allowed_VIF_devices ~__context ~vm =
        info "VM.get_allowed_VIF_devices: VM = '%s'" (vm_uuid ~__context vm) ;
        Local.VM.get_allowed_VIF_devices ~__context ~vm

      let atomic_set_resident_on ~__context ~vm ~host =
        info "VM.atomic_set_resident_on: VM = '%s'" (vm_uuid ~__context vm) ;
        (* Need to prevent the host chooser being run while these fields are being modified *)
        Helpers.with_global_lock (fun () ->
            Db.VM.set_resident_on ~__context ~self:vm ~value:host ;
            Db.VM.set_scheduled_to_be_resident_on ~__context ~self:vm
              ~value:Ref.null
        )

      let create_new_blob ~__context ~vm ~name ~mime_type ~public =
        info
          "VM.create_new_blob: VM = '%s'; name = '%s'; MIME type = '%s' public \
           = %b"
          (vm_uuid ~__context vm) name mime_type public ;
        Local.VM.create_new_blob ~__context ~vm ~name ~mime_type ~public

      let s3_suspend ~__context ~vm =
        info "VM.s3_suspend: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.s3_suspend ~vm in
        let remote_fn = Client.VM.s3_suspend ~vm in
        forward_vm_op ~local_fn ~__context ~vm ~remote_fn

      let s3_resume ~__context ~vm =
        info "VM.s3_resume: VM = '%s'" (vm_uuid ~__context vm) ;
        let local_fn = Local.VM.s3_resume ~vm in
        let remote_fn = Client.VM.s3_resume ~vm in
        forward_vm_op ~local_fn ~__context ~vm ~remote_fn

      let set_bios_strings ~__context ~self ~value =
        info "VM.set_bios_strings: self = '%s'; value = '%s'"
          (vm_uuid ~__context self)
          (String.concat "; " (List.map (fun (k, v) -> k ^ "=" ^ v) value)) ;
        Local.VM.set_bios_strings ~__context ~self ~value

      let copy_bios_strings ~__context ~vm ~host =
        info "VM.copy_bios_strings: VM = '%s'; host = '%s'"
          (vm_uuid ~__context vm)
          (host_uuid ~__context host) ;
        Local.VM.copy_bios_strings ~__context ~vm ~host

      let set_protection_policy ~__context ~self:_ ~value:_ =
        raise
          Api_errors.(
            Server_error (not_implemented, ["VM.set_protection_policy"])
          )

      let set_snapshot_schedule ~__context ~self ~value =
        info "VM.set_snapshot_schedule: self = '%s'; " (vm_uuid ~__context self) ;
        Local.VM.set_snapshot_schedule ~__context ~self ~value

      let set_start_delay ~__context ~self ~value =
        info "VM.set_start_delay: self = '%s';" (vm_uuid ~__context self) ;
        Local.VM.set_start_delay ~__context ~self ~value

      let set_shutdown_delay ~__context ~self ~value =
        info "VM.set_shutdown_delay: self = '%s';" (vm_uuid ~__context self) ;
        Local.VM.set_shutdown_delay ~__context ~self ~value

      let set_order ~__context ~self ~value =
        info "VM.set_order: self = '%s';" (vm_uuid ~__context self) ;
        Local.VM.set_order ~__context ~self ~value

      let set_suspend_VDI ~__context ~self ~value =
        info "VM.set_suspend_VDI: self = '%s';" (vm_uuid ~__context self) ;
        Local.VM.set_suspend_VDI ~__context ~self ~value

      let assert_can_be_recovered ~__context ~self ~session_to =
        info "VM.assert_can_be_recovered: self = '%s';" (vm_uuid ~__context self) ;
        Local.VM.assert_can_be_recovered ~__context ~self ~session_to

      let get_SRs_required_for_recovery ~__context ~self ~session_to =
        info "VM.get_SRs_required_for_recovery: self = '%s';"
          (vm_uuid ~__context self) ;
        Local.VM.get_SRs_required_for_recovery ~__context ~self ~session_to

      let recover ~__context ~self ~session_to ~force =
        info "VM.recover: self = '%s'; force = %b;" (vm_uuid ~__context self)
          force ;
        (* If a VM is part of an appliance, the appliance *)
        (* should be recovered using VM_appliance.recover *)
        let appliance = Db.VM.get_appliance ~__context ~self in
        if Db.is_valid_ref __context appliance then
          raise
            (Api_errors.Server_error
               ( Api_errors.vm_is_part_of_an_appliance
               , [Ref.string_of self; Ref.string_of appliance]
               )
            ) ;
        Local.VM.recover ~__context ~self ~session_to ~force

      let set_appliance ~__context ~self ~value =
        info "VM.set_appliance: self = '%s'; value = '%s';"
          (vm_uuid ~__context self)
          (vm_appliance_uuid ~__context value) ;
        Local.VM.set_appliance ~__context ~self ~value

      let set_groups ~__context ~self ~value =
        info "VM.set_groups : self = '%s'; value = [ %s ]"
          (vm_uuid ~__context self)
          (String.concat "; " (List.map (vm_group_uuid ~__context) value)) ;
        let original_groups = Db.VM.get_groups ~__context ~self in
        Local.VM.set_groups ~__context ~self ~value ;
        Xapi_vm_group_helpers.update_vm_anti_affinity_alert ~__context
          ~groups:(original_groups @ value)

      let import_convert ~__context ~_type ~username ~password ~sr
          ~remote_config =
        info "VM.import_convert: type = '%s'; remote_config = '%s;'" _type
          (String.concat ","
             (List.map (fun (k, v) -> k ^ "=" ^ v) remote_config)
          ) ;
        Local.VM.import_convert ~__context ~_type ~username ~password ~sr
          ~remote_config

      let import ~__context ~url ~sr ~full_restore ~force =
        info "VM.import: url = '%s' sr='%s' force='%b'" "(url filtered)"
          (Ref.string_of sr) force ;
        let pbd =
          choose_pbd_for_sr ~consider_unplugged_pbds:false ~__context ~self:sr
            ()
        in
        let host = Db.PBD.get_host ~__context ~self:pbd in
        let local_fn = Local.VM.import ~url ~sr ~full_restore ~force in
        let remote_fn = Client.VM.import ~url ~sr ~full_restore ~force in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_domain_type ~__context ~self ~value =
        info "VM.set_domain_type: self = '%s'; value = '%s';"
          (vm_uuid ~__context self)
          (Record_util.domain_type_to_string value) ;
        Local.VM.set_domain_type ~__context ~self ~value

      let set_HVM_boot_policy ~__context ~self ~value =
        info "VM.set_HVM_boot_policy: self = '%s'; value = '%s';"
          (vm_uuid ~__context self) value ;
        Local.VM.set_HVM_boot_policy ~__context ~self ~value

      let set_NVRAM_EFI_variables ~__context ~self ~value =
        (* called by varstored, bypasses VM powerstate check *)
        info "VM.set_NVRAM_EFI_variables: self = '%s'" (vm_uuid ~__context self) ;
        Local.VM.set_NVRAM_EFI_variables ~__context ~self ~value

      let restart_device_models ~__context ~self =
        info "VM.restart_device_models: self = '%s'" (vm_uuid ~__context self) ;
        Local.VM.restart_device_models ~__context ~self

      let set_uefi_mode ~__context ~self ~mode =
        info "VM.set_uefi_mode: self = '%s'; mode = '%s'"
          (vm_uuid ~__context self)
          (Helpers.uefi_mode_to_string mode) ;
        (* The redirection to another host is done by the `varstored-sb-state`
           script which uses xmlrpc to make XAPI calls.
        *)
        Local.VM.set_uefi_mode ~__context ~self ~mode

      let get_secureboot_readiness ~__context ~self =
        info "VM.get_secureboot_readiness: self = '%s'" (vm_uuid ~__context self) ;
        Local.VM.get_secureboot_readiness ~__context ~self

      let set_blocked_operations ~__context ~self ~value =
        info "VM.set_blocked_operations: self = '%s'" (vm_uuid ~__context self) ;
        Local.VM.set_blocked_operations ~__context ~self ~value ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self

      let add_to_blocked_operations ~__context ~self ~key ~value =
        info "VM.add_to_blocked_operations: self = '%s'"
          (vm_uuid ~__context self) ;
        Local.VM.add_to_blocked_operations ~__context ~self ~key ~value ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self

      let remove_from_blocked_operations ~__context ~self ~key =
        info "VM.remove_from_blocked_operations: self = '%s'"
          (vm_uuid ~__context self) ;
        Local.VM.remove_from_blocked_operations ~__context ~self ~key ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self

      let sysprep ~__context ~self ~unattend ~timeout =
        info "VM.sysprep: self = '%s'" (vm_uuid ~__context self) ;
        let local_fn = Local.VM.sysprep ~self ~unattend ~timeout in
        let remote_fn = Client.VM.sysprep ~self ~unattend ~timeout in
        let policy = Helpers.Policy.fail_immediately in
        with_vm_operation ~__context ~self ~doc:"VM.sysprep" ~op:`sysprep
          ~policy (fun () ->
            forward_vm_op ~local_fn ~__context ~vm:self ~remote_fn
        )
    end

    module VM_metrics = struct end

    module VM_guest_metrics = struct end

    module Diagnostics = struct
      let gc_compact ~__context ~host =
        info "Diagnostics.gc_compact: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Diagnostics.gc_compact ~host in
        let remote_fn = Client.Diagnostics.gc_compact ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let gc_stats ~__context ~host =
        info "Diagnostics.gc_stats: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Diagnostics.gc_stats ~host in
        let remote_fn = Client.Diagnostics.gc_stats ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let db_stats ~__context =
        info "Diagnostics.db_stats" ;
        Local.Diagnostics.db_stats ~__context

      let network_stats ~__context ~host ~params =
        info "Diagnostics.network_stats: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Diagnostics.network_stats ~host ~params in
        let remote_fn = Client.Diagnostics.network_stats ~host ~params in
        do_op_on ~local_fn ~__context ~host ~remote_fn
    end

    module Host = struct
      let create ~__context ~uuid ~name_label ~name_description ~hostname
          ~address ~external_auth_type ~external_auth_service_name
          ~external_auth_configuration =
        info "Host.create: uuid='%s' name_label='%s' hostname='%s' address='%s'"
          uuid name_label hostname address ;
        Local.Host.create ~__context ~uuid ~name_label ~name_description
          ~hostname ~address ~external_auth_type ~external_auth_service_name
          ~external_auth_configuration

      let destroy ~__context ~self =
        info "Host.destroy: host = '%s'" (host_uuid ~__context self) ;
        Local.Host.destroy ~__context ~self

      let set_power_on_mode ~__context ~self ~power_on_mode ~power_on_config =
        info
          "Host.set_power_on_mode: host = '%s'; power_on_mode = '%s' ; \
           power_on_config = [ %s ]"
          (host_uuid ~__context self)
          power_on_mode
          (String.concat ", "
             (List.map (fun (k, v) -> k ^ "=" ^ v) power_on_config)
          ) ;
        Local.Host.set_power_on_mode ~__context ~self ~power_on_mode
          ~power_on_config

      let set_license_params ~__context ~self ~value =
        info "Host.set_license_params: host = '%s'; license_params = [ %s ]"
          (host_uuid ~__context self)
          (String.concat ", " (List.map (fun (k, v) -> k ^ "=" ^ v) value)) ;
        Local.Host.set_license_params ~__context ~self ~value

      let set_ssl_legacy ~__context ~self ~value =
        info "Host.set_ssl_legacy: host = '%s'; value = %b"
          (host_uuid ~__context self)
          value ;
        Local.Host.set_ssl_legacy ~__context ~self ~value

      let ha_disable_failover_decisions ~__context ~host =
        info "Host.ha_disable_failover_decisions: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.ha_disable_failover_decisions ~host in
        let remote_fn = Client.Host.ha_disable_failover_decisions ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let ha_disarm_fencing ~__context ~host =
        info "Host.ha_disarm_fencing: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.ha_disarm_fencing ~host in
        let remote_fn = Client.Host.ha_disarm_fencing ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let ha_stop_daemon ~__context ~host =
        info "Host.ha_stop_daemon: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.ha_stop_daemon ~host in
        let remote_fn = Client.Host.ha_stop_daemon ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let ha_release_resources ~__context ~host =
        info "Host.ha_release_resources: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.ha_release_resources ~host in
        let remote_fn = Client.Host.ha_release_resources ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let ha_wait_for_shutdown_via_statefile ~__context ~host =
        info "Host.ha_wait_for_shutdown_via_statefile: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.ha_wait_for_shutdown_via_statefile ~host in
        let remote_fn = Client.Host.ha_wait_for_shutdown_via_statefile ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let preconfigure_ha ~__context ~host ~statefiles ~metadata_vdi ~generation
          =
        info
          "Host.preconfigure_ha: host = '%s'; statefiles =[ %s ]; metadata_vdi \
           = '%s'; generation = '%s'"
          (host_uuid ~__context host)
          (String.concat "; " (List.map Ref.string_of statefiles))
          (vdi_uuid ~__context metadata_vdi)
          generation ;
        let local_fn =
          Local.Host.preconfigure_ha ~host ~statefiles ~metadata_vdi ~generation
        in
        let remote_fn =
          Client.Host.preconfigure_ha ~host ~statefiles ~metadata_vdi
            ~generation
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let ha_join_liveset ~__context ~host =
        info "Host.ha_join_liveset: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.ha_join_liveset ~host in
        let remote_fn = Client.Host.ha_join_liveset ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let request_backup ~__context ~host ~generation ~force =
        debug "Host.request_backup: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.request_backup ~host ~generation ~force in
        let remote_fn = Client.Host.request_backup ~host ~generation ~force in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let request_config_file_sync ~__context ~host ~hash =
        debug "Host.request_config_file_sync: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.request_config_file_sync ~host ~hash in
        let remote_fn = Client.Host.request_config_file_sync ~host ~hash in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      (* Call never forwarded *)
      let ha_xapi_healthcheck ~__context =
        Local.Host.ha_xapi_healthcheck ~__context

      (* Call never forwarded *)
      let local_assert_healthy ~__context =
        info "Host.local_assert_healthy" ;
        Local.Host.local_assert_healthy ~__context

      (* Call never forwarded *)
      let propose_new_master ~__context ~address ~manual =
        info "Host.propose_new_master: type = '%s'; host address = '%s'"
          (if manual then "manual" else "automatic")
          address ;
        Local.Host.propose_new_master ~__context ~address ~manual

      (* If someone aborts the transaction *)
      let abort_new_master ~__context ~address =
        info "Host.abort_new_master: host address = '%s'" address ;
        Local.Host.abort_new_master ~__context ~address

      (* Call never forwarded *)
      let commit_new_master ~__context ~address =
        info "Host.commit_new_master: host address = '%s'" address ;
        Local.Host.commit_new_master ~__context ~address

      (* Call never forwarded *)
      let is_in_emergency_mode ~__context =
        Local.Host.is_in_emergency_mode ~__context

      let local_management_reconfigure ~__context ~interface =
        info "Host.local_management_reconfigure: interface = '%s'" interface ;
        Local.Host.local_management_reconfigure ~__context ~interface

      let emergency_ha_disable ~__context ~soft =
        info "Host.emergency_ha_disable: soft = '%b'" soft ;
        Local.Host.emergency_ha_disable ~__context ~soft

      (* Dummy implementation for a deprecated API method. *)
      let get_uncooperative_resident_VMs ~__context ~self =
        info "Host.get_uncooperative_resident_VMs host=%s" (Ref.string_of self) ;
        Local.Host.get_uncooperative_resident_VMs ~__context ~self

      (* Dummy implementation for a deprecated API method. *)
      let get_uncooperative_domains ~__context ~self =
        info "Host.get_uncooperative_domains host=%s" (Ref.string_of self) ;
        Local.Host.get_uncooperative_domains ~__context ~self

      let management_reconfigure ~__context ~pif =
        info "Host.management_reconfigure: management PIF = '%s'"
          (pif_uuid ~__context pif) ;
        (* The management interface on the slave may change during this operation, so expect connection loss.
         * Consider the operation successful if management flag was set on the PIF we're working with. Since the slave
         * sets this flag after bringing up the management interface, this is a good indication of success. *)
        let success () =
          if Db.PIF.get_management ~__context ~self:pif then Some () else None
        in
        let local_fn = Local.Host.management_reconfigure ~pif in
        let remote_fn = Client.Host.management_reconfigure ~pif in
        let fn () =
          do_op_on ~local_fn ~__context
            ~host:(Db.PIF.get_host ~__context ~self:pif)
            ~remote_fn
        in
        tolerate_connection_loss fn success 30.

      let management_disable ~__context =
        info "Host.management_disable" ;
        Local.Host.management_disable ~__context

      let get_management_interface ~__context ~host =
        info "Host.get_management_interface: host = '%s'"
          (host_uuid ~__context host) ;
        Local.Host.get_management_interface ~__context ~host

      let disable ~__context ~host =
        info "Host.disable: host = '%s'" (host_uuid ~__context host) ;
        (* Block call if this would break our VM restart plan *)
        Xapi_ha_vm_failover.assert_host_disable_preserves_ha_plan ~__context
          host ;
        let local_fn = Local.Host.disable ~host in
        let remote_fn = Client.Host.disable ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn ;
        Xapi_host_helpers.update_allowed_operations ~__context ~self:host

      let declare_dead ~__context ~host =
        info "Host.declare_dead: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.declare_dead ~__context ~host ;
        Xapi_host_helpers.update_allowed_operations ~__context ~self:host

      let enable ~__context ~host =
        info "Host.enable: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.enable ~host in
        let remote_fn = Client.Host.enable ~host in
        Xapi_host_helpers.with_host_operation ~__context ~self:host
          ~doc:"Host.enable" ~op:`enable (fun () ->
            do_op_on ~local_fn ~__context ~host ~remote_fn
        ) ;
        Xapi_host_helpers.update_allowed_operations ~__context ~self:host

      let shutdown ~__context ~host =
        info "Host.shutdown: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.shutdown ~host in
        let remote_fn = Client.Host.shutdown ~host in
        Xapi_host_helpers.with_host_operation ~__context ~self:host
          ~doc:"Host.shutdown" ~op:`shutdown (fun () ->
            do_op_on ~local_fn ~__context ~host ~remote_fn
        )

      let reboot ~__context ~host =
        info "Host.reboot: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.reboot ~host in
        let remote_fn = Client.Host.reboot ~host in
        Xapi_host_helpers.with_host_operation ~__context ~self:host
          ~doc:"Host.reboot" ~op:`reboot (fun () ->
            do_op_on ~local_fn ~__context ~host ~remote_fn
        )

      (* This is only be called by systemd during shutdown when xapi-domains.service is stopped *)
      let prepare_for_poweroff ~__context ~host =
        info "Host.prepare_for_poweroff: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.prepare_for_poweroff ~host in
        let remote_fn = Client.Host.prepare_for_poweroff ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let power_on ~__context ~host =
        info "Host.power_on: host = '%s'" (host_uuid ~__context host) ;
        Xapi_host_helpers.with_host_operation ~__context ~self:host
          ~doc:"Host.power_on" ~op:`power_on (fun () ->
            (* Always executed on the master *)
            Local.Host.power_on ~__context ~host
        )

      let dmesg ~__context ~host =
        info "Host.dmesg: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.dmesg ~host in
        let remote_fn = Client.Host.dmesg ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let dmesg_clear ~__context ~host =
        info "Host.dmesg_clear: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.dmesg_clear ~host in
        let remote_fn = Client.Host.dmesg_clear ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let bugreport_upload ~__context ~host ~url ~options =
        let filtered_options =
          let filter' ((k, _) as orig) =
            match Astring.String.trim k with
            | "password" ->
                (k, "(password filtered)")
            | "http_proxy" ->
                (k, "(proxy filtered)")
            | _ ->
                orig
          in
          List.map filter' options
        in
        info "Host.bugreport_upload: host = '%s'; url = '%s'; options = [ %s ]"
          (host_uuid ~__context host)
          "(url filtered)"
          (String.concat "; "
             (List.map (fun (k, v) -> k ^ "=" ^ v) filtered_options)
          ) ;
        let local_fn = Local.Host.bugreport_upload ~host ~url ~options in
        let remote_fn = Client.Host.bugreport_upload ~host ~url ~options in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let list_methods ~__context =
        info "Host.list_methods" ;
        Local.Host.list_methods ~__context

      let send_debug_keys ~__context ~host ~keys =
        info "Host.send_debug_keys: host = '%s'; keys = '%s'"
          (host_uuid ~__context host)
          keys ;
        let local_fn = Local.Host.send_debug_keys ~host ~keys in
        let remote_fn = Client.Host.send_debug_keys ~host ~keys in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_log ~__context ~host =
        info "Host.get_log: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.get_log ~host in
        let remote_fn = Client.Host.get_log ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let license_add ~__context ~host ~contents =
        info "Host.license_add: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.license_add ~host ~contents in
        let remote_fn = Client.Host.license_add ~host ~contents in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let license_remove ~__context ~host =
        info "Host.license_remove: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.license_remove ~host in
        let remote_fn = Client.Host.license_remove ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let assert_can_evacuate ~__context ~host =
        info "Host.assert_can_evacuate: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.assert_can_evacuate ~__context ~host

      let get_vms_which_prevent_evacuation ~__context ~self =
        info "Host.get_vms_which_prevent_evacuation: host = '%s'"
          (host_uuid ~__context self) ;
        Local.Host.get_vms_which_prevent_evacuation ~__context ~self

      let evacuate ~__context ~host ~network ~evacuate_batch_size =
        info "Host.evacuate: host = '%s'" (host_uuid ~__context host) ;
        (* Block call if this would break our VM restart plan (because the body of this sets enabled to false) *)
        Xapi_ha_vm_failover.assert_host_disable_preserves_ha_plan ~__context
          host ;
        Xapi_host_helpers.with_host_operation ~__context ~self:host
          ~doc:"Host.evacuate" ~op:`evacuate (fun () ->
            Local.Host.evacuate ~__context ~host ~network ~evacuate_batch_size
        )

      let retrieve_wlb_evacuate_recommendations ~__context ~self =
        info "Host.retrieve_wlb_evacuate_recommendations: host = '%s'"
          (host_uuid ~__context self) ;
        Local.Host.retrieve_wlb_evacuate_recommendations ~__context ~self

      let update_pool_secret ~__context ~host ~pool_secret =
        info "Host.update_pool_secret: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.update_pool_secret ~host ~pool_secret in
        let remote_fn = Client.Host.update_pool_secret ~host ~pool_secret in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let update_master ~__context ~host ~master_address =
        info "Host.update_master: host = '%s'; master = '%s'"
          (host_uuid ~__context host)
          master_address ;
        let local_fn = Local.Pool.emergency_reset_master ~master_address in
        let remote_fn = Client.Host.update_master ~host ~master_address in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let restart_agent ~__context ~host =
        info "Host.restart_agent: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.restart_agent ~host in
        let remote_fn = Client.Host.restart_agent ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let shutdown_agent ~__context = Local.Host.shutdown_agent ~__context

      let signal_networking_change ~__context =
        info "Host.signal_networking_change" ;
        Local.Host.signal_networking_change ~__context

      let notify ~__context ~ty ~params =
        info "Host.notify" ;
        Local.Host.notify ~__context ~ty ~params

      let syslog_reconfigure ~__context ~host =
        info "Host.syslog_reconfigure: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.syslog_reconfigure ~host in
        let remote_fn = Client.Host.syslog_reconfigure ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_system_status_capabilities ~__context ~host =
        info "Host.get_system_status_capabilities: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.get_system_status_capabilities ~host in
        let remote_fn = Client.Host.get_system_status_capabilities ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_diagnostic_timing_stats ~__context ~host =
        info "Host.get_diagnostic_timing_stats: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.get_diagnostic_timing_stats ~host in
        let remote_fn = Client.Host.get_diagnostic_timing_stats ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_hostname_live ~__context ~host ~hostname =
        info "Host.set_hostname_live: host = '%s'; hostname = '%s'"
          (host_uuid ~__context host)
          hostname ;
        let local_fn = Local.Host.set_hostname_live ~host ~hostname in
        let remote_fn = Client.Host.set_hostname_live ~host ~hostname in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_data_sources ~__context ~host =
        info "Host.get_data_sources: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.get_data_sources ~host in
        let remote_fn = Client.Host.get_data_sources ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let record_data_source ~__context ~host ~data_source =
        info "Host.record_data_source: host = '%s';  data source = '%s'"
          (host_uuid ~__context host)
          data_source ;
        let local_fn = Local.Host.record_data_source ~host ~data_source in
        let remote_fn = Client.Host.record_data_source ~host ~data_source in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let query_data_source ~__context ~host ~data_source =
        info "Host.query_data_source: host = '%s'; data source = '%s'"
          (host_uuid ~__context host)
          data_source ;
        let local_fn = Local.Host.query_data_source ~host ~data_source in
        let remote_fn = Client.Host.query_data_source ~host ~data_source in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let forget_data_source_archives ~__context ~host ~data_source =
        info "Host.forget_data_source_archives: host = '%s'; data source = '%s'"
          (host_uuid ~__context host)
          data_source ;
        let local_fn =
          Local.Host.forget_data_source_archives ~host ~data_source
        in
        let remote_fn =
          Client.Host.forget_data_source_archives ~host ~data_source
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let tickle_heartbeat ~__context ~host ~stuff =
        (* info "Host.tickle_heartbeat: Incoming call from host '%s' with arguments [ %s ]" (Ref.string_of host) (String.concat "; " (List.map (fun (a, b) -> a ^ ": " ^ b) stuff)); *)
        Local.Host.tickle_heartbeat ~__context ~host ~stuff

      let create_new_blob ~__context ~host ~name ~mime_type ~public =
        info
          "Host.create_new_blob: host = '%s'; name = '%s' MIME type = '%s \
           public = %b"
          (host_uuid ~__context host)
          name mime_type public ;
        Local.Host.create_new_blob ~__context ~host ~name ~mime_type ~public

      let call_plugin ~__context ~host ~plugin ~fn ~args =
        info
          "Host.call_plugin host = '%s'; plugin = '%s'; fn = '%s' args = [ \
           'hidden' ]"
          (host_uuid ~__context host)
          plugin fn ;
        let local_fn = Local.Host.call_plugin ~host ~plugin ~fn ~args in
        let remote_fn = Client.Host.call_plugin ~host ~plugin ~fn ~args in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let call_extension ~__context ~host ~call =
        info "Host.call_extension host = '%s'; call = '%s'"
          (host_uuid ~__context host)
          call ;
        let local_fn = Local.Host.call_extension ~host ~call in
        let remote_fn = Client.Host.call_extension ~host ~call in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let has_extension ~__context ~host ~name =
        info "Host.has_extension: host = '%s'; name = '%s'"
          (host_uuid ~__context host)
          name ;
        let local_fn = Local.Host.has_extension ~host ~name in
        let remote_fn = Client.Host.has_extension ~host ~name in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let sync_data ~__context ~host =
        info "Host.sync_data: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.sync_data ~__context ~host

      let backup_rrds ~__context ~host ~delay =
        let local_fn = Local.Host.backup_rrds ~host ~delay in
        let remote_fn = Client.Host.backup_rrds ~host ~delay in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let compute_free_memory ~__context ~host =
        info "Host.compute_free_memory: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.compute_free_memory ~__context ~host

      let compute_memory_overhead ~__context ~host =
        info "Host.compute_memory_overhead: host = '%s'"
          (host_uuid ~__context host) ;
        Local.Host.compute_memory_overhead ~__context ~host

      let get_servertime ~__context ~host =
        (* info "Host.get_servertime"; *)
        (* suppressed because the GUI calls this frequently and it isn't interesting for debugging *)
        let local_fn = Local.Host.get_servertime ~host in
        let remote_fn = Client.Host.get_servertime ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_server_localtime ~__context ~host =
        (* info "Host.get_servertime"; *)
        (* suppressed because the GUI calls this frequently and it isn't interesting for debugging *)
        let local_fn = Local.Host.get_server_localtime ~host in
        let remote_fn = Client.Host.get_server_localtime ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let enable_binary_storage ~__context ~host =
        info "Host.enable_binary_storage: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.enable_binary_storage ~host in
        let remote_fn = Client.Host.enable_binary_storage ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let disable_binary_storage ~__context ~host =
        info "Host.disable_binary_storage: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.disable_binary_storage ~host in
        let remote_fn = Client.Host.disable_binary_storage ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let enable_external_auth ~__context ~host ~config ~service_name ~auth_type
          =
        info
          "Host.enable_external_auth: host = '%s'; service_name = '%s'; \
           auth_type = '%s'"
          (host_uuid ~__context host)
          service_name auth_type ;
        (* First assert that the AD feature is enabled if AD is requested *)
        if auth_type = Xapi_globs.auth_type_AD then
          Pool_features.assert_enabled ~__context ~f:Features.AD ;
        let local_fn =
          Local.Host.enable_external_auth ~host ~config ~service_name ~auth_type
        in
        let remote_fn =
          Client.Host.enable_external_auth ~host ~config ~service_name
            ~auth_type
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let disable_external_auth ~__context ~host ~config =
        info "Host.disable_external_auth: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.disable_external_auth ~host ~config in
        let remote_fn = Client.Host.disable_external_auth ~host ~config in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let install_ca_certificate ~__context ~host ~name ~cert =
        info "Host.install_ca_certificate: host = '%s'; name = '%s'"
          (host_uuid ~__context host)
          name ;
        let local_fn = Local.Host.install_ca_certificate ~host ~name ~cert in
        let remote_fn = Client.Host.install_ca_certificate ~host ~name ~cert in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let uninstall_ca_certificate ~__context ~host ~name ~force =
        info
          "Host.uninstall_ca_certificate: host = '%s'; name = '%s'; force = \
           '%b'"
          (host_uuid ~__context host)
          name force ;
        let local_fn = Local.Host.uninstall_ca_certificate ~host ~name ~force in
        let remote_fn =
          Client.Host.uninstall_ca_certificate ~host ~name ~force
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      (* legacy names *)
      let certificate_install = install_ca_certificate

      let certificate_uninstall = uninstall_ca_certificate ~force:false

      let certificate_list ~__context ~host =
        info "Host.certificate_list: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.certificate_list ~host in
        let remote_fn = Client.Host.certificate_list ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let crl_install ~__context ~host ~name ~crl =
        info "Host.crl_install: host = '%s'; name = '%s'"
          (host_uuid ~__context host)
          name ;
        let local_fn = Local.Host.crl_install ~host ~name ~crl in
        let remote_fn = Client.Host.crl_install ~host ~name ~crl in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let crl_uninstall ~__context ~host ~name =
        info "Host.crl_uninstall: host = '%s'; name = '%s'"
          (host_uuid ~__context host)
          name ;
        let local_fn = Local.Host.crl_uninstall ~host ~name in
        let remote_fn = Client.Host.crl_uninstall ~host ~name in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let crl_list ~__context ~host =
        info "Host.crl_list: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.crl_list ~host in
        let remote_fn = Client.Host.crl_list ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let certificate_sync ~__context ~host =
        info "Host.certificate_sync: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.certificate_sync ~host in
        let remote_fn = Client.Host.certificate_sync ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_server_certificate ~__context ~host =
        info "Host.get_server_certificate: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.get_server_certificate ~host in
        let remote_fn = Client.Host.get_server_certificate ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let refresh_server_certificate ~__context ~host =
        info "Host.refresh_server_certificate: host = '%s'"
          (host_uuid ~__context host) ;
        let pool = Helpers.get_pool ~__context in
        let local_fn = Local.Host.refresh_server_certificate ~host in
        let remote_fn = Client.Host.refresh_server_certificate ~host in
        let other =
          Db.Host.get_all ~__context |> List.filter (fun h -> h <> host)
        in
        Xapi_pool_helpers.with_pool_operation ~__context
          ~doc:"Host.refresh_server_certificate" ~self:pool ~op:`cert_refresh
        @@ fun () ->
        (* let host refresh its certificates first *)
        do_op_on ~local_fn ~__context ~host ~remote_fn ;
        (* update all other hosts in the pool *)
        other
        |> List.iter (fun h -> do_op_on ~local_fn ~__context ~host:h ~remote_fn)

      let _success ~__context () =
        let task = Context.get_task_id __context in
        let progress = Db.Task.get_progress ~__context ~self:task in
        if progress = 1. then Some () else None

      let install_server_certificate ~__context ~host ~certificate ~private_key
          ~certificate_chain =
        info "Host.install_server_certificate: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn =
          Local.Host.install_server_certificate ~host ~certificate ~private_key
            ~certificate_chain
        in
        let remote_fn =
          Client.Host.install_server_certificate ~host ~certificate ~private_key
            ~certificate_chain
        in
        let fn () = do_op_on ~local_fn ~__context ~host ~remote_fn in
        tolerate_connection_loss fn (_success ~__context) 30. ;
        try
          let _, _ =
            Forkhelpers.execute_command_get_output
              !Xapi_globs.alert_certificate_check
              []
          in
          ()
        with Forkhelpers.Spawn_internal_error (_, _, _) ->
          Helpers.internal_error
            "Generation of alerts for server certificate expiration failed."

      let reset_server_certificate ~__context ~host =
        info "Host.reset_server_certificate: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.reset_server_certificate ~host in
        let remote_fn = Client.Host.reset_server_certificate ~host in
        let fn () = do_op_on ~local_fn ~__context ~host ~remote_fn in
        tolerate_connection_loss fn (_success ~__context) 30.

      let emergency_reset_server_certificate ~__context =
        info "Host.emergency_reset_server_certificate" ;
        Local.Host.emergency_reset_server_certificate ~__context

      let cert_distrib_atom ~__context ~host ~command =
        info "Host.cert_distrib_atom" ;
        let local_fn = Local.Host.cert_distrib_atom ~host ~command in
        let remote_fn = Client.Host.cert_distrib_atom ~host ~command in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let copy_primary_host_certs ~__context ~host =
        info "Host.copy_primary_host_certs host = '%s'" (Ref.string_of host) ;
        Xapi_pool_helpers.with_pool_operation ~__context
          ~op:`copy_primary_host_certs ~doc:"Host.copy_primary_host_certs"
          ~self:(Helpers.get_pool ~__context)
        @@ fun () -> Local.Host.copy_primary_host_certs ~__context ~host

      let attach_static_vdis ~__context ~host ~vdi_reason_map =
        info "Host.attach_static_vdis: host = '%s'; vdi/reason pairs = [ %s ]"
          (host_uuid ~__context host)
          (String.concat "; "
             (List.map (fun (a, b) -> Ref.string_of a ^ "/" ^ b) vdi_reason_map)
          ) ;
        let local_fn = Local.Host.attach_static_vdis ~host ~vdi_reason_map in
        let remote_fn = Client.Host.attach_static_vdis ~host ~vdi_reason_map in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let detach_static_vdis ~__context ~host ~vdis =
        info "Host.detach_static_vdis: host = '%s'; vdis =[ %s ]"
          (host_uuid ~__context host)
          (String.concat "; " (List.map Ref.string_of vdis)) ;
        let local_fn = Local.Host.detach_static_vdis ~host ~vdis in
        let remote_fn = Client.Host.detach_static_vdis ~host ~vdis in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_localdb_key ~__context ~host ~key ~value =
        info "Host.set_localdb_key: host = '%s'; key = '%s'; value = '%s'"
          (host_uuid ~__context host)
          key value ;
        let local_fn = Local.Host.set_localdb_key ~host ~key ~value in
        let remote_fn = Client.Host.set_localdb_key ~host ~key ~value in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let apply_edition ~__context ~host ~edition ~force =
        info "Host.apply_edition: host = '%s'; edition = '%s'; force = '%s'"
          (host_uuid ~__context host)
          edition (string_of_bool force) ;
        let local_fn = Local.Host.apply_edition ~host ~edition ~force in
        let remote_fn = Client.Host.apply_edition ~host ~edition ~force in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let refresh_pack_info ~__context ~host =
        info "Host.refresh_pack_info: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.refresh_pack_info ~host in
        let remote_fn = Client.Host.refresh_pack_info ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let reset_networking ~__context ~host =
        info "Host.reset_networking: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.reset_networking ~__context ~host

      let enable_local_storage_caching ~__context ~host ~sr =
        let local_fn = Local.Host.enable_local_storage_caching ~host ~sr in
        let remote_fn = Client.Host.enable_local_storage_caching ~host ~sr in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let disable_local_storage_caching ~__context ~host =
        let local_fn = Local.Host.disable_local_storage_caching ~host in
        let remote_fn = Client.Host.disable_local_storage_caching ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_sm_diagnostics ~__context ~host =
        let local_fn = Local.Host.get_sm_diagnostics ~host in
        let remote_fn = Client.Host.get_sm_diagnostics ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let get_thread_diagnostics ~__context ~host =
        let local_fn = Local.Host.get_thread_diagnostics ~host in
        let remote_fn = Client.Host.get_thread_diagnostics ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let sm_dp_destroy ~__context ~host ~dp ~allow_leak =
        let local_fn = Local.Host.sm_dp_destroy ~host ~dp ~allow_leak in
        let remote_fn = Client.Host.sm_dp_destroy ~host ~dp ~allow_leak in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let sync_vlans ~__context ~host =
        info "Host.sync_vlans: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.sync_vlans ~__context ~host

      let sync_tunnels ~__context ~host =
        info "Host.sync_tunnels: host = '%s'" (host_uuid ~__context host) ;
        Local.Host.sync_tunnels ~__context ~host

      let sync_pif_currently_attached ~__context ~host ~bridges =
        info "Host.sync_pif_currently_attached: host = '%s'"
          (host_uuid ~__context host) ;
        Local.Host.sync_pif_currently_attached ~__context ~host ~bridges

      let migrate_receive ~__context ~host ~network ~options =
        info "Host.migrate_receive: host = '%s'; network = '%s'"
          (host_uuid ~__context host)
          (network_uuid ~__context network) ;
        Local.Host.migrate_receive ~__context ~host ~network ~options

      let enable_display ~__context ~host =
        info "Host.enable_display: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.enable_display ~host in
        let remote_fn = Client.Host.enable_display ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let disable_display ~__context ~host =
        info "Host.disable_display: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.disable_display ~host in
        let remote_fn = Client.Host.disable_display ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let apply_guest_agent_config ~__context ~host =
        info "Host.apply_guest_agent_config: host = '%s'"
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.apply_guest_agent_config ~host in
        let remote_fn = Client.Host.apply_guest_agent_config ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let mxgpu_vf_setup ~__context ~host =
        info "Host.mxgpu_vf_setup: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.mxgpu_vf_setup ~host in
        let remote_fn = Client.Host.mxgpu_vf_setup ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let nvidia_vf_setup ~__context ~host ~pf ~enable =
        info "Host.nvidia_vf_setup: host = '%s' pf = '%s' enable = %b"
          (host_uuid ~__context host)
          (pci_uuid ~__context pf) enable ;
        let local_fn = Local.Host.nvidia_vf_setup ~host ~pf ~enable in
        let remote_fn = Client.Host.nvidia_vf_setup ~host ~pf ~enable in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let allocate_resources_for_vm ~__context ~self ~vm ~live:_ =
        info "Host.host_allocate_resources_for_vm: host = %s; VM = %s"
          (host_uuid ~__context self)
          (vm_uuid ~__context vm) ;
        let snapshot = Db.VM.get_record ~__context ~self:vm in
        VM.allocate_vm_to_host ~__context ~vm ~host:self ~snapshot ()

      let set_iscsi_iqn ~__context ~host ~value =
        info "Host.set_iscsi_iqn: host='%s' iqn='%s'"
          (host_uuid ~__context host)
          value ;
        let local_fn = Local.Host.set_iscsi_iqn ~host ~value in
        let remote_fn = Client.Host.set_iscsi_iqn ~host ~value in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_multipathing ~__context ~host ~value =
        info "Host.set_multipathing: host='%s' value='%s'"
          (host_uuid ~__context host)
          (string_of_bool value) ;
        let local_fn = Local.Host.set_multipathing ~host ~value in
        let remote_fn = Client.Host.set_multipathing ~host ~value in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let write_uefi_certificates_to_disk ~__context ~host =
        info "Host.write_uefi_certificates_to_disk: host='%s' "
          (host_uuid ~__context host) ;
        let local_fn = Local.Host.write_uefi_certificates_to_disk ~host in
        let remote_fn = Client.Host.write_uefi_certificates_to_disk ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_uefi_certificates ~__context ~host ~value =
        info "Host.set_uefi_certificates: host='%s' value='%s'"
          (host_uuid ~__context host)
          value ;
        Local.Host.set_uefi_certificates ~__context ~host ~value

      let notify_accept_new_pool_secret ~__context ~host ~old_ps ~new_ps =
        (* we do not need to verify the old pool secret here, since it has
           already been verified (see xapi_http.assert_credentials_ok) *)
        info "Host.notify_accept_new_pool_secret: host='%s'"
          (host_uuid ~__context host) ;
        let local_fn =
          Local.Host.notify_accept_new_pool_secret ~host ~old_ps ~new_ps
        in
        let remote_fn =
          Client.Host.notify_accept_new_pool_secret ~host ~old_ps ~new_ps
        in
        do_op_on ~__context ~host ~local_fn ~remote_fn

      let notify_send_new_pool_secret ~__context ~host ~old_ps ~new_ps =
        info "Host.notify_send_new_pool_secret: host='%s'"
          (host_uuid ~__context host) ;
        let local_fn =
          Local.Host.notify_send_new_pool_secret ~host ~old_ps ~new_ps
        in
        let remote_fn =
          Client.Host.notify_send_new_pool_secret ~host ~old_ps ~new_ps
        in
        do_op_on ~__context ~host ~local_fn ~remote_fn

      let cleanup_pool_secret ~__context ~host ~old_ps ~new_ps =
        info "Host.cleanup_pool_secret: host='%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Host.cleanup_pool_secret ~host ~old_ps ~new_ps in
        let remote_fn = Client.Host.cleanup_pool_secret ~host ~old_ps ~new_ps in
        do_op_on ~__context ~host ~local_fn ~remote_fn

      let set_sched_gran ~__context ~self ~value =
        info "Host.set_sched_gran: host='%s' sched='%s'"
          (host_uuid ~__context self)
          (Record_util.host_sched_gran_to_string value) ;
        let local_fn = Local.Host.set_sched_gran ~self ~value in
        let remote_fn = Client.Host.set_sched_gran ~self ~value in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let get_sched_gran ~__context ~self =
        info "Host.get_sched_gran: host='%s'" (host_uuid ~__context self) ;
        let local_fn = Local.Host.get_sched_gran ~self in
        let remote_fn = Client.Host.get_sched_gran ~self in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let set_numa_affinity_policy ~__context ~self ~value =
        info "Host.set_numa_affinity_policy: host='%s' policy='%s'"
          (host_uuid ~__context self)
          (Record_util.host_numa_affinity_policy_to_string value) ;
        let local_fn = Local.Host.set_numa_affinity_policy ~self ~value in
        let remote_fn = Client.Host.set_numa_affinity_policy ~self ~value in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let emergency_disable_tls_verification ~__context =
        info "Host.emergency_disable_tls_verification" ;
        Local.Host.emergency_disable_tls_verification ~__context

      let emergency_reenable_tls_verification ~__context =
        info "Host.emergency_reenable_tls_verification" ;
        Local.Host.emergency_reenable_tls_verification ~__context

      let apply_updates ~__context ~self ~hash =
        let uuid = host_uuid ~__context self in
        info "Host.apply_updates: host = '%s'; hash = '%s'" uuid hash ;
        Local.Host.apply_updates ~__context ~self ~hash

      let rescan_drivers ~__context ~self =
        let uuid = host_uuid ~__context self in
        info "Host.rescan_drivers: host = '%s'" uuid ;
        let local_fn = Local.Host.rescan_drivers ~self in
        let remote_fn = Client.Host.rescan_drivers ~self in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let set_https_only ~__context ~self ~value =
        let uuid = host_uuid ~__context self in
        info "Host.set_https_only: self = %s ; value = %b" uuid value ;
        let local_fn = Local.Host.set_https_only ~self ~value in
        let remote_fn = Client.Host.set_https_only ~self ~value in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let emergency_clear_mandatory_guidance ~__context =
        info "Host.emergency_clear_mandatory_guidance" ;
        Local.Host.emergency_clear_mandatory_guidance ~__context

      let enable_ssh ~__context ~self =
        info "%s: host = '%s'" __FUNCTION__ (host_uuid ~__context self) ;
        let local_fn = Local.Host.enable_ssh ~self in
        let remote_fn = Client.Host.enable_ssh ~self in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let disable_ssh ~__context ~self =
        info "%s: host = '%s'" __FUNCTION__ (host_uuid ~__context self) ;
        let local_fn = Local.Host.disable_ssh ~self in
        let remote_fn = Client.Host.disable_ssh ~self in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let set_ssh_enabled_timeout ~__context ~self ~value =
        info "Host.set_ssh_enabled_timeout: host='%s' value='%Ld'"
          (host_uuid ~__context self)
          value ;
        let local_fn = Local.Host.set_ssh_enabled_timeout ~self ~value in
        let remote_fn = Client.Host.set_ssh_enabled_timeout ~self ~value in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let set_console_idle_timeout ~__context ~self ~value =
        info "Host.set_console_idle_timeout: host='%s' value='%Ld'"
          (host_uuid ~__context self)
          value ;
        let local_fn = Local.Host.set_console_idle_timeout ~self ~value in
        let remote_fn = Client.Host.set_console_idle_timeout ~self ~value in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn

      let set_ssh_auto_mode ~__context ~self ~value =
        info "Host.set_ssh_auto_mode: host='%s' value='%b'"
          (host_uuid ~__context self)
          value ;
        let local_fn = Local.Host.set_ssh_auto_mode ~self ~value in
        let remote_fn = Client.Host.set_ssh_auto_mode ~self ~value in
        do_op_on ~local_fn ~__context ~host:self ~remote_fn
    end

    module Host_crashdump = struct
      let destroy ~__context ~self =
        info "Host_crashdump.destroy: host crashdump = '%s'"
          (host_crashdump_uuid ~__context self) ;
        let local_fn = Local.Host_crashdump.destroy ~self in
        let remote_fn = Client.Host_crashdump.destroy ~self in
        do_op_on ~local_fn ~__context
          ~host:(Db.Host_crashdump.get_host ~__context ~self)
          ~remote_fn

      let upload ~__context ~self ~url ~options =
        info "Host_crashdump.upload: host crashdump = '%s'; url = '%s'"
          (host_crashdump_uuid ~__context self)
          "(url filtered)" ;
        let local_fn = Local.Host_crashdump.upload ~self ~url ~options in
        let remote_fn = Client.Host_crashdump.upload ~self ~url ~options in
        do_op_on ~local_fn ~__context
          ~host:(Db.Host_crashdump.get_host ~__context ~self)
          ~remote_fn
    end

    module Host_patch = struct
      let destroy ~__context ~self =
        info "Host_patch.destroy: host patch = '%s'"
          (host_patch_uuid ~__context self) ;
        Xapi_host_patch.destroy ~__context ~self

      let apply ~__context ~self =
        info "Host_patch.apply: host patch = '%s'"
          (host_patch_uuid ~__context self) ;
        let local_fn = Local.Host_patch.apply ~self in
        let remote_fn = Client.Host_patch.apply ~self in
        do_op_on ~local_fn ~__context
          ~host:(Db.Host_patch.get_host ~__context ~self)
          ~remote_fn
    end

    module Pool_patch = struct
      let apply ~__context ~self ~host =
        info "Pool_patch.apply: pool patch = '%s'; host = '%s'"
          (pool_patch_uuid ~__context self)
          (host_uuid ~__context host) ;
        let local_fn = Local.Pool_patch.apply ~self ~host in
        let remote_fn = Client.Pool_patch.apply ~self ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let precheck ~__context ~self ~host =
        info "Pool_patch.precheck: pool patch = '%s'; host = '%s'"
          (pool_patch_uuid ~__context self)
          (host_uuid ~__context host) ;
        let local_fn = Local.Pool_patch.precheck ~self ~host in
        let remote_fn = Client.Pool_patch.precheck ~self ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let pool_apply ~__context ~self =
        info "Pool_patch.pool_apply: pool patch = '%s'"
          (pool_patch_uuid ~__context self) ;
        Xapi_pool_patch.pool_apply ~__context ~self

      let clean ~__context ~self =
        info "Pool_patch.clean: pool patch = '%s'"
          (pool_patch_uuid ~__context self) ;
        Xapi_pool_patch.clean ~__context ~self

      let clean_on_host ~__context ~self ~host =
        info "Pool_patch.clean_on_host: pool patch = '%s'"
          (pool_patch_uuid ~__context self) ;
        let local_fn = Local.Pool_patch.clean ~self in
        let remote_fn = Client.Pool_patch.clean ~self in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let pool_clean ~__context ~self =
        info "Pool_patch.pool_clean: pool patch = '%s'"
          (pool_patch_uuid ~__context self) ;
        Xapi_pool_patch.pool_clean ~__context ~self

      let destroy ~__context ~self =
        info "Pool_patch.destroy: pool patch = '%s'"
          (pool_patch_uuid ~__context self) ;
        Xapi_pool_patch.destroy ~__context ~self
    end

    module Host_metrics = struct end

    module Host_cpu = struct end

    module Vdi_nbd_server_info = struct end

    module Probe_result = struct end

    module Sr_stat = struct end

    module Network = struct
      (* Don't forward. These are just db operations. Networks are "attached" when required by hosts that read db entries.
         Bridges corresponding to networks are removed by per-host GC threads that read from db. *)
      let create ~__context ~name_label ~name_description ~mTU ~other_config
          ~bridge ~managed ~tags =
        info "Network.create: name_label = '%s'; bridge = '%s'; managed = '%b'"
          name_label bridge managed ;
        Local.Network.create ~__context ~name_label ~name_description ~mTU
          ~other_config ~bridge ~managed ~tags

      let attach ~__context ~network ~host =
        info "Network.attach: network = '%s'; host = '%s'"
          (network_uuid ~__context network)
          (host_uuid ~__context host) ;
        let local_fn = Local.Network.attach ~network ~host in
        let remote_fn = Client.Network.attach ~network ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let pool_introduce ~__context ~name_label ~name_description ~mTU
          ~other_config ~bridge ~managed =
        Local.Network.pool_introduce ~__context ~name_label ~name_description
          ~mTU ~other_config ~bridge ~managed

      let destroy ~__context ~self =
        info "Network.destroy: network = '%s'" (network_uuid ~__context self) ;
        (* WARNING WARNING WARNING: directly call Network.destroy with the global lock since it does
           only database operations *)
        Helpers.with_global_lock (fun () ->
            Local.Network.destroy ~__context ~self
        )

      let create_new_blob ~__context ~network ~name ~mime_type ~public =
        info
          "Network.create_new_blob: network = '%s'; name = %s; MIME type = \
           '%s' public = %b"
          (network_uuid ~__context network)
          name mime_type public ;
        Local.Network.create_new_blob ~__context ~network ~name ~mime_type
          ~public

      let set_default_locking_mode ~__context ~network ~value =
        info "Network.set_default_locking_mode: network = '%s'; value = %s"
          (network_uuid ~__context network)
          (Record_util.network_default_locking_mode_to_string value) ;
        Local.Network.set_default_locking_mode ~__context ~network ~value

      let attach_for_vm ~__context ~host ~vm =
        info "Network.attach_for_vm: host = '%s'; VM = '%s'"
          (host_uuid ~__context host)
          (vm_uuid ~__context vm) ;
        let local_fn = Local.Network.attach_for_vm ~host ~vm in
        let remote_fn = Client.Network.attach_for_vm ~host ~vm in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let detach_for_vm ~__context ~host ~vm =
        info "Network.detach_for_vm: host = '%s'; VM = '%s'"
          (host_uuid ~__context host)
          (vm_uuid ~__context vm) ;
        let local_fn = Local.Network.detach_for_vm ~host ~vm in
        let remote_fn = Client.Network.detach_for_vm ~host ~vm in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let add_purpose ~__context ~self ~value =
        info "Network.add_purpose: self = '%s'; value = '%s'"
          (network_uuid ~__context self)
          (Record_util.network_purpose_to_string value) ;
        Local.Network.add_purpose ~__context ~self ~value

      let remove_purpose ~__context ~self ~value =
        info "Network.remove_purpose: self = '%s'; value = '%s'"
          (network_uuid ~__context self)
          (Record_util.network_purpose_to_string value) ;
        Local.Network.remove_purpose ~__context ~self ~value
    end

    module VIF = struct
      let unmark_vif ~__context ~vif ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn
          ~doc:("unmarking VIF after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.VIF.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vif_helpers.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vif, Ref.string_of self)
            )
          )
          vif

      let mark_vif ~__context ~vif ~doc ~op =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn ~doc:("marking VIF for " ^ doc)
          (fun self ->
            Xapi_vif_helpers.assert_operation_valid ~__context ~self ~op ;
            Db.VIF.add_to_current_operations ~__context ~self ~key:task_id
              ~value:op ;
            Xapi_vif_helpers.update_allowed_operations ~__context ~self
          )
          vif

      let with_vif_marked ~__context ~vif ~doc ~op f =
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            mark_vif ~__context ~vif ~doc ~op
        ) ;
        finally
          (fun () -> f ())
          (fun () ->
            Helpers.with_global_lock (fun () ->
                unmark_vif ~__context ~vif ~doc ~op
            )
          )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      let forward_vif_op ~local_fn ~__context ~self ~remote_fn =
        let vm = Db.VIF.get_VM ~__context ~self in
        let host_resident_on = Db.VM.get_resident_on ~__context ~self:vm in
        if host_resident_on = Ref.null then
          local_fn ~__context
        else
          do_op_on ~local_fn ~__context ~host:host_resident_on ~remote_fn

      (* -------------------------------------------------------------------------- *)

      let create ~__context ~device ~network ~vM ~mAC ~mTU ~other_config
          ~currently_attached ~qos_algorithm_type ~qos_algorithm_params =
        info "VIF.create: VM = '%s'; network = '%s'" (vm_uuid ~__context vM)
          (network_uuid ~__context network) ;
        Local.VIF.create ~__context ~device ~network ~vM ~mAC ~mTU ~other_config
          ~currently_attached ~qos_algorithm_type ~qos_algorithm_params

      let destroy ~__context ~self =
        info "VIF.destroy: VIF = '%s'" (vif_uuid ~__context self) ;
        Local.VIF.destroy ~__context ~self

      let plug ~__context ~self =
        info "VIF.plug: VIF = '%s'" (vif_uuid ~__context self) ;
        let local_fn = Local.VIF.plug ~self in
        let remote_fn = Client.VIF.plug ~self in
        with_vif_marked ~__context ~vif:self ~doc:"VIF.plug" ~op:`plug
          (fun () -> forward_vif_op ~local_fn ~__context ~self ~remote_fn
        )

      let unplug_common ~__context ~self ~force =
        let op = `unplug in
        let name = "VIF." ^ Record_util.vif_operations_to_string op in
        info "%s: VIF = '%s'" name (vif_uuid ~__context self) ;
        let local_fn, remote_fn =
          if force then
            (Local.VIF.unplug_force, Client.VIF.unplug_force)
          else
            (Local.VIF.unplug, Client.VIF.unplug)
        in
        let local_fn = local_fn ~self in
        let remote_fn = remote_fn ~self in
        with_vif_marked ~__context ~vif:self ~doc:name ~op (fun () ->
            forward_vif_op ~local_fn ~__context ~self ~remote_fn
        )

      let unplug ~__context ~self = unplug_common ~__context ~self ~force:false

      let unplug_force ~__context ~self =
        unplug_common ~__context ~self ~force:true

      let move ~__context ~self ~network =
        info "VIF.move: VIF = '%s' network = '%s'" (vif_uuid ~__context self)
          (network_uuid ~__context network) ;
        let local_fn = Local.VIF.move ~self ~network in
        let remote_fn = Client.VIF.move ~self ~network in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let set_locking_mode ~__context ~self ~value =
        info "VIF.set_locking_mode: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self)
          (Record_util.vif_locking_mode_to_string value) ;
        let local_fn = Local.VIF.set_locking_mode ~self ~value in
        let remote_fn = Client.VIF.set_locking_mode ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let set_ipv4_allowed ~__context ~self ~value =
        info "VIF.set_ipv4_allowed: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self) (String.concat "," value) ;
        let local_fn = Local.VIF.set_ipv4_allowed ~self ~value in
        let remote_fn = Client.VIF.set_ipv4_allowed ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let add_ipv4_allowed ~__context ~self ~value =
        info "VIF.add_ipv4_allowed: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self) value ;
        let local_fn = Local.VIF.add_ipv4_allowed ~self ~value in
        let remote_fn = Client.VIF.add_ipv4_allowed ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let remove_ipv4_allowed ~__context ~self ~value =
        info "VIF.remove_ipv4_allowed: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self) value ;
        let local_fn = Local.VIF.remove_ipv4_allowed ~self ~value in
        let remote_fn = Client.VIF.remove_ipv4_allowed ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let set_ipv6_allowed ~__context ~self ~value =
        info "VIF.set_ipv6_allowed: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self) (String.concat "," value) ;
        let local_fn = Local.VIF.set_ipv6_allowed ~self ~value in
        let remote_fn = Client.VIF.set_ipv6_allowed ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let add_ipv6_allowed ~__context ~self ~value =
        info "VIF.add_ipv6_allowed: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self) value ;
        let local_fn = Local.VIF.add_ipv6_allowed ~self ~value in
        let remote_fn = Client.VIF.add_ipv6_allowed ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let remove_ipv6_allowed ~__context ~self ~value =
        info "VIF.remove_ipv6_allowed: VIF = '%s'; value = '%s'"
          (vif_uuid ~__context self) value ;
        let local_fn = Local.VIF.remove_ipv6_allowed ~self ~value in
        let remote_fn = Client.VIF.remove_ipv6_allowed ~self ~value in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let configure_ipv4 ~__context ~self ~mode ~address ~gateway =
        info
          "VIF.configure_ipv4: VIF = '%s'; mode = '%s'; address = '%s'; \
           gateway = '%s'"
          (vif_uuid ~__context self)
          (Record_util.vif_ipv4_configuration_mode_to_string mode)
          address gateway ;
        let local_fn = Local.VIF.configure_ipv4 ~self ~mode ~address ~gateway in
        let remote_fn =
          Client.VIF.configure_ipv4 ~self ~mode ~address ~gateway
        in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn

      let configure_ipv6 ~__context ~self ~mode ~address ~gateway =
        info
          "VIF.configure_ipv6: VIF = '%s'; mode = '%s'; address = '%s'; \
           gateway = '%s'"
          (vif_uuid ~__context self)
          (Record_util.vif_ipv6_configuration_mode_to_string mode)
          address gateway ;
        let local_fn = Local.VIF.configure_ipv6 ~self ~mode ~address ~gateway in
        let remote_fn =
          Client.VIF.configure_ipv6 ~self ~mode ~address ~gateway
        in
        forward_vif_op ~local_fn ~__context ~self ~remote_fn
    end

    module VIF_metrics = struct end

    module VLAN = struct
      let pool_introduce ~__context ~tagged_PIF ~untagged_PIF ~tag ~other_config
          =
        info
          "VLAN.pool_introduce: tagged_PIF = '%s'; untagged_PIF = '%s'; VLAN \
           tag = %Ld"
          (pif_uuid ~__context tagged_PIF)
          (pif_uuid ~__context untagged_PIF)
          tag ;
        Local.VLAN.pool_introduce ~__context ~tagged_PIF ~untagged_PIF ~tag
          ~other_config

      let create ~__context ~tagged_PIF ~tag ~network =
        info "VLAN.create: network = '%s'; VLAN tag = %Ld"
          (network_uuid ~__context network)
          tag ;
        let local_fn = Local.VLAN.create ~tagged_PIF ~tag ~network in
        let remote_fn = Client.VLAN.create ~tagged_PIF ~tag ~network in
        do_op_on ~local_fn ~__context
          ~host:(Db.PIF.get_host ~__context ~self:tagged_PIF)
          ~remote_fn

      let destroy ~__context ~self =
        info "VLAN.destroy: VLAN = '%s'" (vlan_uuid ~__context self) ;
        let local_fn = Local.VLAN.destroy ~self in
        let remote_fn = Client.VLAN.destroy ~self in
        do_op_on ~local_fn ~__context
          ~host:
            (Db.PIF.get_host ~__context
               ~self:(Db.VLAN.get_tagged_PIF ~__context ~self)
            )
          ~remote_fn
    end

    module Tunnel = struct
      let create ~__context ~transport_PIF ~network ~protocol =
        info "Tunnel.create: network = '%s'" (network_uuid ~__context network) ;
        let local_fn = Local.Tunnel.create ~transport_PIF ~network ~protocol in
        let remote_fn =
          Client.Tunnel.create ~transport_PIF ~network ~protocol
        in
        do_op_on ~local_fn ~__context
          ~host:(Db.PIF.get_host ~__context ~self:transport_PIF)
          ~remote_fn

      let destroy ~__context ~self =
        info "Tunnel.destroy: tunnel = '%s'" (tunnel_uuid ~__context self) ;
        let local_fn = Local.Tunnel.destroy ~self in
        let remote_fn = Client.Tunnel.destroy ~self in
        do_op_on ~local_fn ~__context
          ~host:
            (Db.PIF.get_host ~__context
               ~self:(Db.Tunnel.get_transport_PIF ~__context ~self)
            )
          ~remote_fn
    end

    module Bond = struct
      let create ~__context ~network ~members ~mAC ~mode ~properties =
        info "Bond.create: network = '%s'; members = [ %s ]"
          (network_uuid ~__context network)
          (String.concat "; " (List.map (pif_uuid ~__context) members)) ;
        if members = [] then
          raise
            (Api_errors.Server_error (Api_errors.pif_bond_needs_more_members, [])
            ) ;
        let host = Db.PIF.get_host ~__context ~self:(List.hd members) in
        let local_fn =
          Local.Bond.create ~network ~members ~mAC ~mode ~properties
        in
        let remote_fn =
          Client.Bond.create ~network ~members ~mAC ~mode ~properties
        in
        (* The management interface on the slave may change during this operation, so expect connection loss.
         * Consider the operation successful if task progress is set to 1.0. *)
        let task = Context.get_task_id __context in
        let success () =
          let progress = Db.Task.get_progress ~__context ~self:task in
          debug "Task progress %.1f" progress ;
          if progress = 1.0 then
            Some (Db.PIF.get_bond_slave_of ~__context ~self:(List.hd members))
          else
            None
        in
        let fn () = do_op_on ~local_fn ~__context ~host ~remote_fn in
        tolerate_connection_loss fn success 30.

      let destroy ~__context ~self =
        info "Bond.destroy: bond = '%s'" (bond_uuid ~__context self) ;
        let host =
          Db.PIF.get_host ~__context ~self:(Db.Bond.get_master ~__context ~self)
        in
        (* The management interface on the slave may change during this operation, so expect connection loss.
         * Consider the operation successful if task progress is set to 1.0. *)
        let task = Context.get_task_id __context in
        let success () =
          let progress = Db.Task.get_progress ~__context ~self:task in
          debug "Task progress %.1f" progress ;
          if progress = 1.0 then
            Some ()
          else
            None
        in
        let local_fn = Local.Bond.destroy ~self in
        let remote_fn = Client.Bond.destroy ~self in
        let fn () = do_op_on ~local_fn ~__context ~host ~remote_fn in
        tolerate_connection_loss fn success 30.

      let set_mode ~__context ~self ~value =
        info "Bond.set_mode: bond = '%s'; value = '%s'"
          (bond_uuid ~__context self)
          (Record_util.bond_mode_to_string value) ;
        let host =
          Db.PIF.get_host ~__context ~self:(Db.Bond.get_master ~__context ~self)
        in
        let local_fn = Local.Bond.set_mode ~self ~value in
        let remote_fn = Client.Bond.set_mode ~self ~value in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_property ~__context ~self ~name ~value =
        info "Bond.set_property: bond = '%s'; name = '%s'; value = '%s'"
          (bond_uuid ~__context self)
          name value ;
        let host =
          Db.PIF.get_host ~__context ~self:(Db.Bond.get_master ~__context ~self)
        in
        let local_fn = Local.Bond.set_property ~self ~name ~value in
        let remote_fn = Client.Bond.set_property ~self ~name ~value in
        do_op_on ~local_fn ~__context ~host ~remote_fn
    end

    module PIF = struct
      let pool_introduce ~__context ~device ~network ~host ~mAC ~mTU ~vLAN
          ~physical ~ip_configuration_mode ~iP ~netmask ~gateway ~dNS
          ~bond_slave_of ~vLAN_master_of ~management ~other_config
          ~disallow_unplug =
        Local.PIF.pool_introduce ~__context ~device ~network ~host ~mAC ~mTU
          ~vLAN ~physical ~ip_configuration_mode ~iP ~netmask ~gateway ~dNS
          ~bond_slave_of ~vLAN_master_of ~management ~other_config
          ~disallow_unplug

      let db_introduce = Local.PIF.db_introduce

      let db_forget ~__context ~self =
        info "PIF.db_forget: PIF = '%s'" (pif_uuid ~__context self) ;
        Local.PIF.db_forget ~__context ~self

      let create_VLAN ~__context ~device ~network ~host ~vLAN =
        info "PIF.create_VLAN: network = '%s'; VLAN tag = %Ld"
          (network_uuid ~__context network)
          vLAN ;
        let local_fn = Local.PIF.create_VLAN ~device ~network ~host ~vLAN in
        let remote_fn = Client.PIF.create_VLAN ~device ~network ~host ~vLAN in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let destroy ~__context ~self =
        info "PIF.destroy: PIF = '%s'" (pif_uuid ~__context self) ;
        let local_fn = Local.PIF.destroy ~self in
        let remote_fn = Client.PIF.destroy ~self in
        let host = Db.PIF.get_host ~__context ~self in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let unplug ~__context ~self =
        info "PIF.unplug: PIF = '%s'" (pif_uuid ~__context self) ;
        let local_fn = Local.PIF.unplug ~self in
        let remote_fn = Client.PIF.unplug ~self in
        let host = Db.PIF.get_host ~__context ~self in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let plug ~__context ~self =
        info "PIF.plug: PIF = '%s'" (pif_uuid ~__context self) ;
        let local_fn = Local.PIF.plug ~self in
        let remote_fn = Client.PIF.plug ~self in
        let host = Db.PIF.get_host ~__context ~self in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let reconfigure_ip ~__context ~self ~mode ~iP ~netmask ~gateway ~dNS =
        info
          "PIF.reconfigure_ip: PIF = '%s'; mode = '%s'; IP = '%s'; netmask = \
           '%s'; gateway = '%s'; DNS = %s"
          (pif_uuid ~__context self)
          (Record_util.ip_configuration_mode_to_string mode)
          iP netmask gateway dNS ;
        let host = Db.PIF.get_host ~__context ~self in
        let local_fn =
          Local.PIF.reconfigure_ip ~self ~mode ~iP ~netmask ~gateway ~dNS
        in
        let remote_fn =
          Client.PIF.reconfigure_ip ~self ~mode ~iP ~netmask ~gateway ~dNS
        in
        let task = Context.get_task_id __context in
        let success () =
          let status = Db.Task.get_status ~__context ~self:task in
          if status <> `pending then
            Some ()
          else
            None
        in
        let fn () = do_op_on ~local_fn ~__context ~host ~remote_fn in
        tolerate_connection_loss fn success
          !Xapi_globs.pif_reconfigure_ip_timeout

      let reconfigure_ipv6 ~__context ~self ~mode ~iPv6 ~gateway ~dNS =
        info
          "PIF.reconfigure_ipv6: PIF = '%s'; mode = '%s'; IPv6 = '%s'; gateway \
           = '%s'; DNS = %s"
          (pif_uuid ~__context self)
          (Record_util.ipv6_configuration_mode_to_string mode)
          iPv6 gateway dNS ;
        let host = Db.PIF.get_host ~__context ~self in
        let local_fn =
          Local.PIF.reconfigure_ipv6 ~self ~mode ~iPv6 ~gateway ~dNS
        in
        let remote_fn =
          Client.PIF.reconfigure_ipv6 ~self ~mode ~iPv6 ~gateway ~dNS
        in
        let task = Context.get_task_id __context in
        let success () =
          let status = Db.Task.get_status ~__context ~self:task in
          if status <> `pending then
            Some ()
          else
            None
        in
        let fn () = do_op_on ~local_fn ~__context ~host ~remote_fn in
        tolerate_connection_loss fn success
          !Xapi_globs.pif_reconfigure_ip_timeout

      let set_primary_address_type ~__context ~self ~primary_address_type =
        info
          "PIF.set_primary_address_type: PIF = '%s'; primary_address_type = \
           '%s'"
          (pif_uuid ~__context self)
          (Record_util.primary_address_type_to_string primary_address_type) ;
        let local_fn =
          Local.PIF.set_primary_address_type ~self ~primary_address_type
        in
        let remote_fn =
          Client.PIF.set_primary_address_type ~self ~primary_address_type
        in
        let host = Db.PIF.get_host ~__context ~self in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_property ~__context ~self ~name ~value =
        info "PIF.set_property: PIF = '%s'; name = '%s'; value = '%s'"
          (pif_uuid ~__context self) name value ;
        let host = Db.PIF.get_host ~__context ~self in
        let local_fn = Local.PIF.set_property ~self ~name ~value in
        let remote_fn = Client.PIF.set_property ~self ~name ~value in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_disallow_unplug ~__context ~self ~value =
        info "PIF.set_disallow_unplug: PIF uuid = %s; value = %s"
          (pif_uuid ~__context self) (string_of_bool value) ;
        Local.PIF.set_disallow_unplug ~__context ~self ~value

      let scan ~__context ~host =
        info "PIF.scan: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.PIF.scan ~host in
        let remote_fn = Client.PIF.scan ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let introduce ~__context ~host ~mAC ~device ~managed =
        info
          "PIF.introduce: host = '%s'; MAC address = '%s'; device = '%s'; \
           managed = '%b'"
          (host_uuid ~__context host)
          mAC device managed ;
        let local_fn = Local.PIF.introduce ~host ~mAC ~device ~managed in
        let remote_fn = Client.PIF.introduce ~host ~mAC ~device ~managed in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let forget ~__context ~self =
        info "PIF.forget: PIF = '%s'" (pif_uuid ~__context self) ;
        let local_fn = Local.PIF.forget ~self in
        let remote_fn = Client.PIF.forget ~self in
        let host = Db.PIF.get_host ~__context ~self in
        do_op_on ~local_fn ~__context ~host ~remote_fn
    end

    module PIF_metrics = struct end

    module SM = struct end

    module SR = struct
      let unmark_sr ~__context ~sr ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        debug "Unmarking SR after %s (task=%s)" doc task_id ;
        log_exn_ignore
          ~doc:("unmarking SR after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.SR.remove_from_current_operations ~__context ~self ~key:task_id ;
              Xapi_sr_operations.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._sr, Ref.string_of self)
            )
          )
          sr

      let mark_sr ~__context ~sr ~doc ~op =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        debug "Marking SR for %s (task=%s)" doc task_id ;
        log_exn ~doc:("marking SR for " ^ doc)
          (fun self ->
            Xapi_sr_operations.assert_operation_valid ~__context ~self ~op ;
            Db.SR.add_to_current_operations ~__context ~self ~key:task_id
              ~value:op ;
            Xapi_sr_operations.update_allowed_operations ~__context ~self
          )
          sr

      let with_sr_marked ~__context ~sr ~doc ~op f =
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            mark_sr ~__context ~sr ~doc ~op
        ) ;
        finally
          (fun () -> f ())
          (fun () ->
            Helpers.with_global_lock (fun () ->
                unmark_sr ~__context ~sr ~doc ~op
            )
          )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      (* Forward SR operation to host that has a suitable plugged (or unplugged) PBD  *)
      let forward_sr_op ?(consider_unplugged_pbds = false) ~local_fn ~__context
          ~self ~remote_fn () =
        let pbd =
          choose_pbd_for_sr ~consider_unplugged_pbds ~__context ~self ()
        in
        let host = Db.PBD.get_host ~__context ~self:pbd in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      (** Do op on a host that can view multiple SRs. If none is found, the
        Not_found exception will be raised.
        WARNING: this may forward the call to a host that is NOT the SR master. *)
      let forward_sr_multiple_op ~local_fn ~__context ~srs
          ?(prefer_slaves = false) ~remote_fn =
        let choose_fn ~host =
          Xapi_vm_helpers.assert_can_see_specified_SRs ~__context ~reqd_srs:srs
            ~host
        in
        let host =
          try
            Xapi_vm_helpers.choose_host ~__context ~choose_fn ~prefer_slaves ()
          with _ -> raise Not_found
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      (* Forward SR operation to all hosts that have suitable, plugged or
         unplugged PBDs, best effort *)
      let forward_sr_all_op ?(consider_unplugged_pbds = false) ~local_fn
          ~__context ~self ~remote_fn () =
        match
          choose_pbds_for_sr ~consider_unplugged_pbds ~__context ~self ()
        with
        | Error `Sr_no_pbds ->
            D.info
              "forward_sr_all_op: doing nothing - there are no pbds attached \
               to SR (%s)"
              (Ref.string_of self)
        | Ok pbds ->
            pbds
            |> List.map (fun pbd -> Db.PBD.get_host ~__context ~self:pbd)
            |> List.iter (fun host ->
                   try do_op_on ~local_fn ~__context ~host ~remote_fn
                   with
                   | Api_errors.Server_error (reason, _)
                   when reason = Api_errors.host_offline
                   ->
                     ()
                   (* allow an offline host to continue the operation *)
               )

      let set_virtual_allocation ~__context ~self ~value =
        Sm.assert_session_has_internal_sr_access ~__context ~sr:self ;
        Local.SR.set_virtual_allocation ~__context ~self ~value

      let set_physical_size ~__context ~self ~value =
        Sm.assert_session_has_internal_sr_access ~__context ~sr:self ;
        Local.SR.set_physical_size ~__context ~self ~value

      let set_physical_utilisation ~__context ~self ~value =
        Sm.assert_session_has_internal_sr_access ~__context ~sr:self ;
        Local.SR.set_physical_utilisation ~__context ~self ~value

      let create ~__context ~host ~device_config ~physical_size ~name_label
          ~name_description ~_type ~content_type ~shared ~sm_config =
        let device_config =
          Xapi_secret.move_passwds_to_secrets ~__context device_config
        in
        info "SR.create: name label = '%s'" name_label ;
        let local_fn =
          Local.SR.create ~host ~device_config ~physical_size ~name_label
            ~name_description ~_type ~content_type ~shared ~sm_config
        in
        let remote_fn =
          Client.SR.create ~host ~device_config ~physical_size ~name_label
            ~name_description ~_type ~content_type ~shared ~sm_config
        in
        (* if shared, then ignore host parameter and do create on the master.. *)
        if shared then
          local_fn ~__context
        else (* otherwise forward to specified host *)
          do_op_on ~local_fn ~__context ~host ~remote_fn

      (* -------------------------------------------------------------------------- *)

      (* don't forward. this is just a db call *)
      let introduce ~__context ~uuid ~name_label ~name_description ~_type
          ~content_type =
        info "SR.introduce: uuid = '%s'; name label = '%s'" uuid name_label ;
        Local.SR.introduce ~__context ~uuid ~name_label ~name_description ~_type
          ~content_type

      let make ~__context ~host ~device_config ~physical_size ~name_label
          ~name_description ~_type ~content_type ~sm_config =
        info "SR.make: host = '%s'; name label = '%s'"
          (host_uuid ~__context host)
          name_label ;
        let device_config =
          Xapi_secret.move_passwds_to_secrets ~__context device_config
        in
        let local_fn =
          Local.SR.make ~host ~device_config ~physical_size ~name_label
            ~name_description ~_type ~content_type ~sm_config
        in
        let remote_fn =
          Client.SR.make ~host ~device_config ~physical_size ~name_label
            ~name_description ~_type ~content_type ~sm_config
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let destroy ~__context ~sr =
        info "SR.destroy: SR = '%s'" (sr_uuid ~__context sr) ;
        let local_destroy = Local.SR.destroy ~sr in
        let local_forget = Local.SR.forget ~sr in
        let remote_destroy = Client.SR.destroy ~sr in
        let remote_forget = Client.SR.forget ~sr in
        with_sr_marked ~__context ~sr ~doc:"SR.destroy" ~op:`destroy (fun () ->
            Xapi_sr.assert_all_pbds_unplugged ~__context ~sr ;
            Xapi_sr.assert_sr_not_indestructible ~__context ~sr ;
            Xapi_sr.assert_sr_not_local_cache ~__context ~sr ;
            forward_sr_op ~consider_unplugged_pbds:true ~local_fn:local_destroy
              ~__context ~self:sr ~remote_fn:remote_destroy () ;
            forward_sr_all_op ~consider_unplugged_pbds:true
              ~local_fn:local_forget ~__context ~self:sr
              ~remote_fn:remote_forget () ;
            (* don't forward - this is just a db call *)
            Xapi_sr.really_forget ~__context ~sr
        )

      let forget ~__context ~sr =
        info "SR.forget: SR = '%s'" (sr_uuid ~__context sr) ;
        let local_fn = Local.SR.forget ~sr in
        let remote_fn = Client.SR.forget ~sr in
        with_sr_marked ~__context ~sr ~doc:"SR.forget" ~op:`forget (fun () ->
            Xapi_sr.assert_all_pbds_unplugged ~__context ~sr ;
            forward_sr_all_op ~consider_unplugged_pbds:true ~local_fn ~__context
              ~self:sr ~remote_fn () ;
            (* don't forward - this is just a db call *)
            Xapi_sr.really_forget ~__context ~sr
        )

      let update ~__context ~sr =
        info "SR.update: SR = '%s'" (sr_uuid ~__context sr) ;
        let local_fn = Local.SR.update ~sr in
        let remote_fn = Client.SR.update ~sr in
        (* SR.update made lock free as of CA-27630 *)
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let get_supported_types ~__context =
        info "SR.get_supported_types" ;
        Local.SR.get_supported_types ~__context

      let scan ~__context ~sr =
        (* since we periodically sr_scan, only log those that aren't internal ones.. otherwise logs just get spammed *)
        let is_internal_scan =
          Db.Session.get_pool ~__context ~self:(Context.get_session_id __context)
        in
        (if is_internal_scan then debug else info)
          "SR.scan: SR = '%s'" (sr_uuid ~__context sr) ;
        let local_fn = Local.SR.scan ~sr in
        let remote_fn = Client.SR.scan ~sr in
        with_sr_marked ~__context ~sr ~doc:"SR.scan" ~op:`scan (fun () ->
            forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()
        )

      let probe ~__context ~host ~device_config ~_type ~sm_config =
        let device_config =
          Xapi_secret.move_passwds_to_secrets ~__context device_config
        in
        info "SR.probe: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.SR.probe ~host ~device_config ~_type ~sm_config in
        let remote_fn =
          Client.SR.probe ~host ~device_config ~_type ~sm_config
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let probe_ext ~__context ~host ~device_config ~_type ~sm_config =
        let device_config =
          Xapi_secret.move_passwds_to_secrets ~__context device_config
        in
        info "SR.probe_ext: host = '%s'" (host_uuid ~__context host) ;
        let local_fn =
          Local.SR.probe_ext ~host ~device_config ~_type ~sm_config
        in
        let remote_fn =
          Client.SR.probe_ext ~host ~device_config ~_type ~sm_config
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let set_shared ~__context ~sr ~value =
        Local.SR.set_shared ~__context ~sr ~value

      let set_name_label ~__context ~sr ~value =
        info "SR.set_name_label: SR = '%s' name-label = '%s'"
          (sr_uuid ~__context sr) value ;
        let local_fn = Local.SR.set_name_label ~sr ~value in
        let remote_fn = Client.SR.set_name_label ~sr ~value in
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let set_name_description ~__context ~sr ~value =
        info "SR.set_name_description: SR = '%s' name-description = '%s'"
          (sr_uuid ~__context sr) value ;
        let local_fn = Local.SR.set_name_description ~sr ~value in
        let remote_fn = Client.SR.set_name_description ~sr ~value in
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let assert_can_host_ha_statefile ~__context ~sr =
        info "SR.assert_can_host_ha_statefile: SR = '%s'" (sr_uuid ~__context sr) ;
        Local.SR.assert_can_host_ha_statefile ~__context ~sr

      let assert_supports_database_replication ~__context ~sr =
        info "SR.assert_supports_database_replication: SR '%s'"
          (sr_uuid ~__context sr) ;
        Local.SR.assert_supports_database_replication ~__context ~sr

      let enable_database_replication ~__context ~sr =
        info "SR.enable_database_replication: SR = '%s'" (sr_uuid ~__context sr) ;
        Local.SR.enable_database_replication ~__context ~sr

      let disable_database_replication ~__context ~sr =
        info "SR.disable_database_replication: SR = '%s'" (sr_uuid ~__context sr) ;
        Local.SR.disable_database_replication ~__context ~sr

      let create_new_blob ~__context ~sr ~name ~mime_type ~public =
        info "SR.create_new_blob: SR = '%s'" (sr_uuid ~__context sr) ;
        Local.SR.create_new_blob ~__context ~sr ~name ~mime_type ~public

      (* SR Level RRDs *)
      let get_data_sources ~__context ~sr =
        info "SR.get_data_sources: SR = '%s'" (sr_uuid ~__context sr) ;
        let local_fn = Local.SR.get_data_sources ~sr in
        let remote_fn = Client.SR.get_data_sources ~sr in
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let record_data_source ~__context ~sr ~data_source =
        info "SR.record_data_source: SR = '%s';  data source = '%s'"
          (sr_uuid ~__context sr) data_source ;
        let local_fn = Local.SR.record_data_source ~sr ~data_source in
        let remote_fn = Client.SR.record_data_source ~sr ~data_source in
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let query_data_source ~__context ~sr ~data_source =
        info "SR.query_data_source: SR = '%s'; data source = '%s'"
          (sr_uuid ~__context sr) data_source ;
        let local_fn = Local.SR.query_data_source ~sr ~data_source in
        let remote_fn = Client.SR.query_data_source ~sr ~data_source in
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let forget_data_source_archives ~__context ~sr ~data_source =
        info "SR.forget_data_source_archives: sr = '%s'; data source = '%s'"
          (sr_uuid ~__context sr) data_source ;
        let local_fn = Local.SR.forget_data_source_archives ~sr ~data_source in
        let remote_fn =
          Client.SR.forget_data_source_archives ~sr ~data_source
        in
        forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      let get_live_hosts ~__context ~sr =
        info "SR.get_live_hosts: SR = '%s'" (sr_uuid ~__context sr) ;
        Local.SR.get_live_hosts ~__context ~sr
    end

    module VDI = struct
      let unmark_vdi ~__context ~vdi ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn_ignore
          ~doc:("unmarking VDI after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.VDI.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vdi.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vdi, Ref.string_of self)
            )
          )
          vdi

      let mark_vdi ~__context ~vdi ~doc ~op =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn ~doc:("marking VDI for " ^ doc)
          (fun self ->
            Xapi_vdi.assert_operation_valid ~__context ~self ~op ;
            Db.VDI.add_to_current_operations ~__context ~self ~key:task_id
              ~value:op ;
            Xapi_vdi.update_allowed_operations ~__context ~self
          )
          vdi

      (** Use this function to mark the SR and/or the individual VDI *)
      let with_sr_andor_vdi ~__context ?sr ?vdi ~doc f =
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            Option.iter (fun (sr, op) -> SR.mark_sr ~__context ~sr ~doc ~op) sr ;
            (* If we fail to acquire the VDI lock, unlock the SR *)
            try
              Option.iter
                (fun (vdi, op) -> mark_vdi ~__context ~vdi ~doc ~op)
                vdi
            with e ->
              Option.iter
                (fun (sr, op) -> SR.unmark_sr ~__context ~sr ~doc ~op)
                sr ;
              raise e
        ) ;
        finally
          (fun () -> f ())
          (fun () ->
            Helpers.with_global_lock (fun () ->
                Option.iter
                  (fun (sr, op) -> SR.unmark_sr ~__context ~sr ~doc ~op)
                  sr ;
                Option.iter
                  (fun (vdi, op) -> unmark_vdi ~__context ~vdi ~doc ~op)
                  vdi
            )
          )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      (* Read SR from VDI and use same forwarding mechanism as SR *)
      let forward_vdi_op ~local_fn ~__context ~self ~remote_fn =
        let sr = Db.VDI.get_SR ~__context ~self in
        SR.forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()

      (* -------------------------------------------------------------------------- *)

      let set_sharable ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_sharable ~__context ~self ~value

      let set_managed ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_managed ~__context ~self ~value

      let set_read_only ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_read_only ~__context ~self ~value

      let set_missing ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_missing ~__context ~self ~value

      let set_virtual_size ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_virtual_size ~__context ~self ~value

      let set_physical_utilisation ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_physical_utilisation ~__context ~self ~value

      let set_is_a_snapshot ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_is_a_snapshot ~__context ~self ~value

      let set_snapshot_of ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_snapshot_of ~__context ~self ~value

      let set_snapshot_time ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_snapshot_time ~__context ~self ~value

      let set_metadata_of_pool ~__context ~self ~value =
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_metadata_of_pool ~__context ~self ~value

      let set_name_label ~__context ~self ~value =
        info "VDI.set_name_label: VDI = '%s' name-label = '%s'"
          (vdi_uuid ~__context self) value ;
        let local_fn = Local.VDI.set_name_label ~self ~value in
        let remote_fn = Client.VDI.set_name_label ~self ~value in
        forward_vdi_op ~local_fn ~__context ~self ~remote_fn

      let set_name_description ~__context ~self ~value =
        info "VDI.set_name_description: VDI = '%s' name-description = '%s'"
          (vdi_uuid ~__context self) value ;
        let local_fn = Local.VDI.set_name_description ~self ~value in
        let remote_fn = Client.VDI.set_name_description ~self ~value in
        forward_vdi_op ~local_fn ~__context ~self ~remote_fn

      let ensure_vdi_not_on_running_vm ~__context ~self =
        let vbds = Db.VDI.get_VBDs ~__context ~self in
        List.iter
          (fun vbd ->
            let vm = Db.VBD.get_VM ~__context ~self:vbd in
            Xapi_vm_lifecycle.assert_initial_power_state_is ~__context ~self:vm
              ~expected:`Halted
          )
          vbds

      let set_on_boot ~__context ~self ~value =
        ensure_vdi_not_on_running_vm ~__context ~self ;
        let local_fn = Local.VDI.set_on_boot ~self ~value in
        let remote_fn = Client.VDI.set_on_boot ~self ~value in
        let sr = Db.VDI.get_SR ~__context ~self in
        with_sr_andor_vdi ~__context ~sr:(sr, `vdi_set_on_boot)
          ~vdi:(self, `set_on_boot) ~doc:"VDI.set_on_boot" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self ~remote_fn
        )

      let set_allow_caching ~__context ~self ~value =
        ensure_vdi_not_on_running_vm ~__context ~self ;
        Local.VDI.set_allow_caching ~__context ~self ~value

      let open_database ~__context ~self =
        Local.VDI.open_database ~__context ~self

      let read_database_pool_uuid ~__context ~self =
        Local.VDI.read_database_pool_uuid ~__context ~self

      (* know sr so just use SR forwarding policy direct here *)
      let create ~__context ~name_label ~name_description ~sR ~virtual_size
          ~_type ~sharable ~read_only ~other_config ~xenstore_data ~sm_config
          ~tags =
        info "VDI.create: SR = '%s'; name label = '%s'" (sr_uuid ~__context sR)
          name_label ;
        let local_fn =
          Local.VDI.create ~name_label ~name_description ~sR ~virtual_size
            ~_type ~sharable ~read_only ~other_config ~xenstore_data ~sm_config
            ~tags
        in
        let remote_fn =
          Client.VDI.create ~name_label ~name_description ~sR ~virtual_size
            ~_type ~sharable ~read_only ~other_config ~xenstore_data ~sm_config
            ~tags
        in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_create) ~doc:"VDI.create"
          (fun () ->
            SR.forward_sr_op ~local_fn ~__context ~self:sR ~remote_fn ()
        )

      (* Hidden call used in pool join only *)
      let pool_introduce = Local.VDI.pool_introduce

      (* Called from the SM backend *)
      let db_introduce ~__context ~uuid ~name_label ~name_description ~sR ~_type
          ~sharable ~read_only ~other_config ~location ~xenstore_data ~sm_config
          ~managed ~virtual_size ~physical_utilisation ~metadata_of_pool
          ~is_a_snapshot ~snapshot_time ~snapshot_of ~cbt_enabled =
        Sm.assert_session_has_internal_sr_access ~__context ~sr:sR ;
        Local.VDI.db_introduce ~__context ~uuid ~name_label ~name_description
          ~sR ~_type ~sharable ~read_only ~other_config ~location ~xenstore_data
          ~sm_config ~managed ~virtual_size ~physical_utilisation
          ~metadata_of_pool ~is_a_snapshot ~snapshot_time ~snapshot_of
          ~cbt_enabled

      (* Called from the SM backend *)
      let db_forget ~__context ~vdi =
        let sr = Db.VDI.get_SR ~__context ~self:vdi in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.db_forget ~__context ~vdi

      let introduce ~__context ~uuid ~name_label ~name_description ~sR ~_type
          ~sharable ~read_only ~other_config ~location ~xenstore_data ~sm_config
          ~managed ~virtual_size ~physical_utilisation ~metadata_of_pool
          ~is_a_snapshot ~snapshot_time ~snapshot_of =
        info "VDI.introduce: SR = '%s'; name label = '%s'"
          (sr_uuid ~__context sR) name_label ;
        let local_fn =
          Local.VDI.introduce ~uuid ~name_label ~name_description ~sR ~_type
            ~sharable ~read_only ~other_config ~location ~xenstore_data
            ~sm_config ~managed ~virtual_size ~physical_utilisation
            ~metadata_of_pool ~is_a_snapshot ~snapshot_time ~snapshot_of
        in
        let remote_fn =
          Client.VDI.introduce ~uuid ~name_label ~name_description ~sR ~_type
            ~sharable ~read_only ~other_config ~location ~xenstore_data
            ~sm_config ~managed ~virtual_size ~physical_utilisation
            ~metadata_of_pool ~is_a_snapshot ~snapshot_time ~snapshot_of
        in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_introduce)
          ~doc:"VDI.introduce" (fun () ->
            SR.forward_sr_op ~local_fn ~__context ~self:sR ~remote_fn ()
        )

      let update ~__context ~vdi =
        let local_fn = Local.VDI.update ~vdi in
        let remote_fn = Client.VDI.update ~vdi in
        let sr = Db.VDI.get_SR ~__context ~self:vdi in
        with_sr_andor_vdi ~__context ~vdi:(vdi, `update) ~doc:"VDI.update"
          (fun () ->
            SR.forward_sr_op ~local_fn ~__context ~self:sr ~remote_fn ()
        )

      let forget ~__context ~vdi =
        info "VDI.forget: VDI = '%s'" (vdi_uuid ~__context vdi) ;
        with_sr_andor_vdi ~__context ~vdi:(vdi, `forget) ~doc:"VDI.forget"
          (fun () -> Local.VDI.forget ~__context ~vdi
        )

      let destroy ~__context ~self =
        info "VDI.destroy: VDI = '%s'" (vdi_uuid ~__context self) ;
        let local_fn = Local.VDI.destroy ~self in
        let remote_fn = Client.VDI.destroy ~self in
        let sR = Db.VDI.get_SR ~__context ~self in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_destroy)
          ~vdi:(self, `destroy) ~doc:"VDI.destroy" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self ~remote_fn
        )

      (* !! FIXME - Depends on what we're doing here... *)
      let snapshot ~__context ~vdi ~driver_params =
        info "VDI.snapshot: VDI = '%s'" (vdi_uuid ~__context vdi) ;
        let local_fn = Local.VDI.snapshot ~vdi ~driver_params in
        let remote_fn = Client.VDI.snapshot ~vdi ~driver_params in
        let sR = Db.VDI.get_SR ~__context ~self:vdi in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_snapshot)
          ~vdi:(vdi, `snapshot) ~doc:"VDI.snapshot" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self:vdi ~remote_fn
        )

      let clone ~__context ~vdi ~driver_params =
        info "VDI.clone: VDI = '%s'" (vdi_uuid ~__context vdi) ;
        let local_fn = Local.VDI.clone ~vdi ~driver_params in
        let remote_fn = Client.VDI.clone ~vdi ~driver_params in
        let sR = Db.VDI.get_SR ~__context ~self:vdi in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_clone) ~vdi:(vdi, `clone)
          ~doc:"VDI.clone" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self:vdi ~remote_fn
        )

      let copy ~__context ~vdi ~sr ~base_vdi ~into_vdi =
        info "VDI.copy: VDI = '%s'; SR = '%s'; base_vdi = '%s'; into_vdi = '%s'"
          (vdi_uuid ~__context vdi) (sr_uuid ~__context sr)
          (vdi_uuid ~__context base_vdi)
          (vdi_uuid ~__context into_vdi) ;
        let local_fn = Local.VDI.copy ~vdi ~sr ~base_vdi ~into_vdi in
        let src_sr = Db.VDI.get_SR ~__context ~self:vdi in
        (* No need to lock the VDI because the VBD.plug will do that for us *)
        (* Try forward the request to a host which can have access to both source
           and destination SR. *)
        let remote_fn ~rpc ~session_id =
          let sync_op () =
            Client.VDI.copy ~rpc ~session_id ~vdi ~sr ~base_vdi ~into_vdi
          in
          let async_op () =
            Client.InternalAsync.VDI.copy ~rpc ~session_id ~vdi ~sr ~base_vdi
              ~into_vdi
          in
          Helpers.try_internal_async ~__context API.ref_VDI_of_rpc async_op
            sync_op
        in
        with_sr_andor_vdi ~__context ~vdi:(vdi, `copy) ~doc:"VDI.copy"
          (fun () ->
            try
              SR.forward_sr_multiple_op ~local_fn ~__context ~srs:[src_sr; sr]
                ~prefer_slaves:true ~remote_fn
            with Not_found ->
              SR.forward_sr_multiple_op ~local_fn ~__context ~srs:[src_sr]
                ~prefer_slaves:true ~remote_fn
        )

      let pool_migrate ~__context ~vdi ~sr ~options =
        let vbds =
          let expr =
            Xapi_database.Db_filter_types.(
              Eq (Field "VDI", Literal (Ref.string_of vdi))
            )
          in
          Db.VBD.get_records_where ~__context ~expr
        in
        if vbds = [] then
          raise
            (Api_errors.Server_error
               (Api_errors.vdi_needs_vm_for_migrate, [Ref.string_of vdi])
            ) ;
        let vm = (snd (List.hd vbds)).API.vBD_VM in
        (* hackity hack *)
        let options =
          ("__internal__vm", Ref.string_of vm)
          :: List.remove_assoc "__internal__vm" options
        in
        let local_fn = Local.VDI.pool_migrate ~vdi ~sr ~options in
        let force =
          try bool_of_string (List.assoc "force" options) with _ -> false
        in
        info "VDI.pool_migrate: VDI = '%s'; SR = '%s'; VM = '%s'"
          (vdi_uuid ~__context vdi) (sr_uuid ~__context sr)
          (vm_uuid ~__context vm) ;
        VM.with_vm_operation ~__context ~self:vm ~doc:"VDI.pool_migrate"
          ~op:`migrate_send (fun () ->
            let snapshot, host =
              if Xapi_vm_lifecycle_helpers.is_live ~__context ~self:vm then
                ( Db.VM.get_record ~__context ~self:vm
                , Db.VM.get_resident_on ~__context ~self:vm
                )
              else
                let snapshot = Db.VM.get_record ~__context ~self:vm in
                let host =
                  Db.VM.get_scheduled_to_be_resident_on ~__context ~self:vm
                in
                let host =
                  if host <> Ref.null then
                    host
                  else
                    let choose_fn ~host =
                      Xapi_vm_helpers.assert_can_boot_here ~__context ~self:vm
                        ~snapshot ~host ~do_cpuid_check:(not force) () ;
                      Xapi_vm_helpers.assert_can_see_specified_SRs ~__context
                        ~reqd_srs:[sr] ~host
                    in
                    Xapi_vm_helpers.choose_host ~__context ~vm ~choose_fn ()
                in
                (snapshot, host)
            in
            let remote_fn ~rpc ~session_id =
              let sync_op () =
                Client.VDI.pool_migrate ~rpc ~session_id ~vdi ~sr ~options
              in
              let async_op () =
                Client.InternalAsync.VDI.pool_migrate ~rpc ~session_id ~vdi ~sr
                  ~options
              in
              Helpers.try_internal_async ~__context API.ref_VDI_of_rpc async_op
                sync_op
            in
            VM.reserve_memory_for_vm ~__context ~vm ~host ~snapshot
              ~host_op:`vm_migrate (fun () ->
                with_sr_andor_vdi ~__context ~vdi:(vdi, `mirror)
                  ~doc:"VDI.mirror" (fun () ->
                    do_op_on ~local_fn ~__context ~host ~remote_fn
                )
            )
        )

      let resize ~__context ~vdi ~size =
        info "VDI.resize: VDI = '%s'; size = %Ld" (vdi_uuid ~__context vdi) size ;
        let local_fn = Local.VDI.resize ~vdi ~size in
        let remote_fn = Client.VDI.resize ~vdi ~size in
        let sR = Db.VDI.get_SR ~__context ~self:vdi in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_resize) ~vdi:(vdi, `resize)
          ~doc:"VDI.resize" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self:vdi ~remote_fn
        )

      let generate_config ~__context ~host ~vdi =
        info "VDI.generate_config: VDI = '%s'; host = '%s'"
          (vdi_uuid ~__context vdi)
          (host_uuid ~__context host) ;
        let local_fn = Local.VDI.generate_config ~host ~vdi in
        let remote_fn = Client.VDI.generate_config ~host ~vdi in
        with_sr_andor_vdi ~__context ~vdi:(vdi, `generate_config)
          ~doc:"VDI.generate_config" (fun () ->
            do_op_on ~local_fn ~__context ~host ~remote_fn
        )

      let force_unlock ~__context ~vdi =
        info "VDI.force_unlock: VDI = '%s'" (vdi_uuid ~__context vdi) ;
        let local_fn = Local.VDI.force_unlock ~vdi in
        let remote_fn = Client.VDI.force_unlock ~vdi in
        with_sr_andor_vdi ~__context ~vdi:(vdi, `force_unlock)
          ~doc:"VDI.force_unlock" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self:vdi ~remote_fn
        )

      let checksum ~__context ~self =
        VM.forward_to_access_srs_and ~local_fn:(Local.VDI.checksum ~self)
          ~__context
          ~extra_sr:(Db.VDI.get_SR ~__context ~self)
          ~remote_fn:(Client.VDI.checksum ~self)
          ()

      let enable_cbt ~__context ~self =
        info "VDI.enable_cbt: VDI = '%s'" (vdi_uuid ~__context self) ;
        let local_fn = Local.VDI.enable_cbt ~self in
        let remote_fn = Client.VDI.enable_cbt ~self in
        let sR = Db.VDI.get_SR ~__context ~self in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_enable_cbt)
          ~vdi:(self, `enable_cbt) ~doc:"VDI.enable_cbt" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self ~remote_fn
        )

      let disable_cbt ~__context ~self =
        info "VDI.disable_cbt: VDI = '%s'" (vdi_uuid ~__context self) ;
        let local_fn = Local.VDI.disable_cbt ~self in
        let remote_fn = Client.VDI.disable_cbt ~self in
        let sR = Db.VDI.get_SR ~__context ~self in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_disable_cbt)
          ~vdi:(self, `disable_cbt) ~doc:"VDI.disable_cbt" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self ~remote_fn
        )

      let set_cbt_enabled ~__context ~self ~value =
        info "VDI.set_cbt_enabled: VDI = '%s'; value = '%b'"
          (vdi_uuid ~__context self) value ;
        let sr = Db.VDI.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        Local.VDI.set_cbt_enabled ~__context ~self ~value

      let data_destroy ~__context ~self =
        info "VDI.data_destroy: VDI = '%s'" (vdi_uuid ~__context self) ;
        let local_fn = Local.VDI.data_destroy ~self in
        let remote_fn = Client.VDI.data_destroy ~self in
        let sR = Db.VDI.get_SR ~__context ~self in
        with_sr_andor_vdi ~__context ~sr:(sR, `vdi_data_destroy)
          ~vdi:(self, `data_destroy) ~doc:"VDI.data_destroy" (fun () ->
            forward_vdi_op ~local_fn ~__context ~self ~remote_fn
        )

      let list_changed_blocks ~__context ~vdi_from ~vdi_to =
        info "VDI.list_changed_blocks: vdi_from  = '%s'; vdi_to = '%s'"
          (vdi_uuid ~__context vdi_from)
          (vdi_uuid ~__context vdi_to) ;
        let local_fn = Local.VDI.list_changed_blocks ~vdi_from ~vdi_to in
        let remote_fn = Client.VDI.list_changed_blocks ~vdi_from ~vdi_to in
        let vdi_to_sr = Db.VDI.get_SR ~__context ~self:vdi_to in
        with_sr_andor_vdi ~__context ~sr:(vdi_to_sr, `vdi_list_changed_blocks)
          ~vdi:(vdi_to, `list_changed_blocks) ~doc:"VDI.list_changed_blocks"
          (fun () -> forward_vdi_op ~local_fn ~__context ~self:vdi_to ~remote_fn
        )

      let get_nbd_info ~__context ~self =
        info "VDI.get_nbd_info: vdi  = '%s'" (vdi_uuid ~__context self) ;
        Local.VDI.get_nbd_info ~__context ~self
    end

    module VBD = struct
      let update_vbd_and_vdi_operations ~__context ~vbd =
        Helpers.with_global_lock (fun () ->
            try
              Xapi_vbd_helpers.update_allowed_operations ~__context ~self:vbd ;
              if not (Db.VBD.get_empty ~__context ~self:vbd) then
                let vdi = Db.VBD.get_VDI ~__context ~self:vbd in
                Xapi_vdi.update_allowed_operations ~__context ~self:vdi
            with _ -> ()
        )

      let unmark_vbd ~__context ~vbd ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn
          ~doc:("unmarking VBD after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.VBD.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vbd_helpers.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vbd, Ref.string_of vbd)
            )
          )
          vbd

      let mark_vbd ~__context ~vbd ~doc ~op =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn ~doc:("marking VBD for " ^ doc)
          (fun self ->
            Xapi_vbd_helpers.assert_operation_valid ~__context ~self ~op ;
            Db.VBD.add_to_current_operations ~__context ~self ~key:task_id
              ~value:op ;
            Xapi_vbd_helpers.update_allowed_operations ~__context ~self
          )
          vbd

      let with_vbd_marked ~__context ~vbd ~doc ~op f =
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            mark_vbd ~__context ~vbd ~doc ~op
        ) ;
        finally
          (fun () -> f ())
          (fun () ->
            Helpers.with_global_lock (fun () ->
                unmark_vbd ~__context ~vbd ~doc ~op
            )
          )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      (* Forward to host that has resident VM that this VBD references *)
      let forward_vbd_op ~local_fn ~__context ~self ~remote_fn =
        let vm = Db.VBD.get_VM ~__context ~self in
        let host_resident_on = Db.VM.get_resident_on ~__context ~self:vm in
        if host_resident_on = Ref.null then
          local_fn ~__context
        else
          do_op_on ~local_fn ~__context ~host:host_resident_on ~remote_fn

      (* -------------------------------------------------------------------------- *)

      (* these are db functions *)
      let create ~__context ~vM ~vDI ~device ~userdevice ~bootable ~mode ~_type
          ~unpluggable ~empty ~other_config ~currently_attached
          ~qos_algorithm_type ~qos_algorithm_params =
        info "VBD.create: VM = '%s'; VDI = '%s'" (vm_uuid ~__context vM)
          (vdi_uuid ~__context vDI) ;
        (* NB must always execute this on the master because of the autodetect_mutex *)
        Local.VBD.create ~__context ~vM ~vDI ~device ~userdevice ~bootable ~mode
          ~_type ~unpluggable ~empty ~other_config ~currently_attached
          ~qos_algorithm_type ~qos_algorithm_params

      let set_mode ~__context ~self ~value =
        info "VBD.set_mode: VBD = '%s'; value = %s" (vbd_uuid ~__context self)
          (Record_util.vbd_mode_to_string value) ;
        Local.VBD.set_mode ~__context ~self ~value

      let destroy ~__context ~self =
        info "VBD.destroy: VBD = '%s'" (vbd_uuid ~__context self) ;
        Local.VBD.destroy ~__context ~self

      let insert ~__context ~vbd ~vdi =
        info "VBD.insert: VBD = '%s'; VDI = '%s'" (vbd_uuid ~__context vbd)
          (vdi_uuid ~__context vdi) ;
        let local_fn = Local.VBD.insert ~vbd ~vdi in
        let remote_fn = Client.VBD.insert ~vbd ~vdi in
        with_vbd_marked ~__context ~vbd ~doc:"VBD.insert" ~op:`insert (fun () ->
            let vm = Db.VBD.get_VM ~__context ~self:vbd in
            if Db.VM.get_power_state ~__context ~self:vm = `Halted then (
              Xapi_vbd.assert_ok_to_insert ~__context ~vbd ~vdi ;
              Db.VBD.set_VDI ~__context ~self:vbd ~value:vdi ;
              Db.VBD.set_empty ~__context ~self:vbd ~value:false
            ) else
              forward_vbd_op ~local_fn ~__context ~self:vbd ~remote_fn
        ) ;
        update_vbd_and_vdi_operations ~__context ~vbd

      let eject ~__context ~vbd =
        info "VBD.eject: VBD = '%s'" (vbd_uuid ~__context vbd) ;
        let local_fn = Local.VBD.eject ~vbd in
        let remote_fn = Client.VBD.eject ~vbd in
        with_vbd_marked ~__context ~vbd ~doc:"VBD.eject" ~op:`eject (fun () ->
            let vm = Db.VBD.get_VM ~__context ~self:vbd in
            if Db.VM.get_power_state ~__context ~self:vm = `Halted then (
              Xapi_vbd.assert_ok_to_eject ~__context ~vbd ;
              Db.VBD.set_empty ~__context ~self:vbd ~value:true ;
              Db.VBD.set_VDI ~__context ~self:vbd ~value:Ref.null
            ) else
              forward_vbd_op ~local_fn ~__context ~self:vbd ~remote_fn
        ) ;
        update_vbd_and_vdi_operations ~__context ~vbd

      let plug ~__context ~self =
        info "VBD.plug: VBD = '%s'" (vbd_uuid ~__context self) ;
        let local_fn = Local.VBD.plug ~self in
        let remote_fn = Client.VBD.plug ~self in
        with_vbd_marked ~__context ~vbd:self ~doc:"VBD.plug" ~op:`plug
          (fun () -> forward_vbd_op ~local_fn ~__context ~self ~remote_fn
        ) ;
        update_vbd_and_vdi_operations ~__context ~vbd:self

      let unplug ~__context ~self =
        info "VBD.unplug: VBD = '%s'" (vbd_uuid ~__context self) ;
        let local_fn = Local.VBD.unplug ~self in
        let remote_fn = Client.VBD.unplug ~self in
        with_vbd_marked ~__context ~vbd:self ~doc:"VBD.unplug" ~op:`unplug
          (fun () -> forward_vbd_op ~local_fn ~__context ~self ~remote_fn
        ) ;
        update_vbd_and_vdi_operations ~__context ~vbd:self

      let unplug_force ~__context ~self =
        info "VBD.unplug_force: VBD = '%s'" (vbd_uuid ~__context self) ;
        let local_fn = Local.VBD.unplug_force ~self in
        let remote_fn = Client.VBD.unplug_force ~self in
        with_vbd_marked ~__context ~vbd:self ~doc:"VBD.unplug_force"
          ~op:`unplug_force (fun () ->
            forward_vbd_op ~local_fn ~__context ~self ~remote_fn
        ) ;
        update_vbd_and_vdi_operations ~__context ~vbd:self

      let unplug_force_no_safety_check ~__context ~self =
        warn "VBD.unplug_force_no_safety_check: VBD = '%s'"
          (vbd_uuid ~__context self) ;
        unplug_force ~__context ~self

      let pause ~__context ~self =
        info "VBD.pause: VBD = '%s'" (vbd_uuid ~__context self) ;
        let local_fn = Local.VBD.pause ~self in
        let remote_fn = Client.VBD.pause ~self in
        let result =
          with_vbd_marked ~__context ~vbd:self ~doc:"VBD.pause" ~op:`pause
            (fun () -> forward_vbd_op ~local_fn ~__context ~self ~remote_fn
          )
        in
        update_vbd_and_vdi_operations ~__context ~vbd:self ;
        result

      let unpause ~__context ~self ~token =
        info "VBD.unpause: VBD = '%s'; token = '%s'" (vbd_uuid ~__context self)
          token ;
        let local_fn = Local.VBD.unpause ~self ~token in
        let remote_fn = Client.VBD.unpause ~self ~token in
        with_vbd_marked ~__context ~vbd:self ~doc:"VBD.unpause" ~op:`unpause
          (fun () -> forward_vbd_op ~local_fn ~__context ~self ~remote_fn
        ) ;
        update_vbd_and_vdi_operations ~__context ~vbd:self

      let assert_attachable ~__context ~self =
        info "VBD.assert_attachable: VBD = '%s'" (vbd_uuid ~__context self) ;
        Local.VBD.assert_attachable ~__context ~self
    end

    module VBD_metrics = struct end

    module PBD = struct
      (* Create and destroy are just db operations, no need to forward; *)
      (* however, they can affect whether SR.destroy is allowed, so update SR.allowed_operations. *)
      let create ~__context ~host ~sR ~device_config ~other_config =
        let device_config =
          Xapi_secret.move_passwds_to_secrets ~__context device_config
        in
        info "PBD.create: SR = '%s'; host '%s'" (sr_uuid ~__context sR)
          (host_uuid ~__context host) ;
        SR.with_sr_marked ~__context ~sr:sR ~doc:"PBD.create" ~op:`pbd_create
          (fun () ->
            Local.PBD.create ~__context ~host ~sR ~device_config ~other_config
        )

      let destroy ~__context ~self =
        info "PBD.destroy: PBD '%s'" (pbd_uuid ~__context self) ;
        let sr = Db.PBD.get_SR ~__context ~self in
        SR.with_sr_marked ~__context ~sr ~doc:"PBD.destroy" ~op:`pbd_destroy
          (fun () -> Local.PBD.destroy ~__context ~self
        )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      let forward_pbd_op ~local_fn ~__context ~self ~remote_fn =
        do_op_on ~local_fn ~__context
          ~host:(Db.PBD.get_host ~__context ~self)
          ~remote_fn

      (* -------------------------------------------------------------------------- *)

      let sanitize (k, v) =
        if Astring.String.is_suffix ~affix:"transformed" k then
          k ^ "=undisclosed"
        else
          k ^ "=" ^ v

      let set_device_config ~__context ~self ~value =
        let value = Xapi_secret.move_passwds_to_secrets ~__context value in
        info "PBD.set_device_config: PBD = '%s'; device_config = [ %s ]"
          (pbd_uuid ~__context self)
          (String.concat "; " (List.map sanitize value)) ;
        let sr = Db.PBD.get_SR ~__context ~self in
        Sm.assert_session_has_internal_sr_access ~__context ~sr ;
        let local_fn = Local.PBD.set_device_config ~self ~value in
        let remote_fn = Client.PBD.set_device_config ~self ~value in
        forward_pbd_op ~local_fn ~__context ~self ~remote_fn

      (* Mark the SR and check, if we are the 'SRmaster' that no VDI
         current_operations are present (eg snapshot, clone) since these are all
         done on the SR master. *)
      let with_unplug_locks ~__context ~pbd:_ ~sr f =
        let doc = "PBD.unplug" and op = `unplug in
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            if Helpers.i_am_srmaster ~__context ~sr then
              List.iter
                (fun vdi ->
                  match Db.VDI.get_current_operations ~__context ~self:vdi with
                  | (op_ref, op_type) :: _ ->
                      raise
                        (Api_errors.Server_error
                           ( Api_errors.other_operation_in_progress
                           , [
                               Datamodel_common._vdi
                             ; Ref.string_of vdi
                             ; API.vdi_operations_to_string op_type
                             ; op_ref
                             ]
                           )
                        )
                  | [] ->
                      ()
                )
                (Db.SR.get_VDIs ~__context ~self:sr) ;
            SR.mark_sr ~__context ~sr ~doc ~op
        ) ;
        finally
          (fun () -> f ())
          (fun () ->
            Helpers.with_global_lock (fun () ->
                SR.unmark_sr ~__context ~sr ~doc ~op
            )
          )

      (* plug and unplug need to be executed on the host that the pbd is related to *)
      let plug ~__context ~self =
        info "PBD.plug: PBD = '%s'" (pbd_uuid ~__context self) ;
        let local_fn = Local.PBD.plug ~self in
        let remote_fn = Client.PBD.plug ~self in
        let sr = Db.PBD.get_SR ~__context ~self in
        let is_shared_sr = Db.SR.get_shared ~__context ~self:sr in
        let is_master_pbd =
          let pbd_host = Db.PBD.get_host ~__context ~self in
          let master_host = Helpers.get_localhost ~__context in
          pbd_host = master_host
        in
        SR.with_sr_marked ~__context ~sr ~doc:"PBD.plug" ~op:`plug (fun () ->
            forward_pbd_op ~local_fn ~__context ~self ~remote_fn
        ) ;
        (* We always plug the master PBD first and unplug it last. If this is the
         * first PBD plugged for this SR (proxy: the PBD being plugged is for the
         * master) then we should perform an initial SR scan. CA-379112
         * changed the scan from asynchronous to synchronous as
         * otherwise on return the xapi DB does not have the correct
         * information.
         * Note the current context contains a completed real task and we should
         * not reuse it for what is effectively another call. *)
        if is_master_pbd then
          Server_helpers.exec_with_new_task "PBD.plug initial SR scan"
            (fun __context ->
              let should_handle_metadata_vdis = is_shared_sr in
              if should_handle_metadata_vdis then
                Xapi_dr.signal_sr_is_processing ~__context ~sr ;
              let sr_scan_callback () =
                if is_shared_sr then (
                  Xapi_dr.handle_metadata_vdis ~__context ~sr ;
                  Xapi_dr.signal_sr_is_ready ~__context ~sr
                ) ;
                Xapi_sr.maybe_push_sr_rrds ~__context ~sr ;
                Xapi_sr.update ~__context ~sr
              in
              sr_scan_callback ()
          )

      let unplug ~__context ~self =
        info "PBD.unplug: PBD = '%s'" (pbd_uuid ~__context self) ;
        let local_fn = Local.PBD.unplug ~self in
        let remote_fn = Client.PBD.unplug ~self in
        let sr = Db.PBD.get_SR ~__context ~self in
        let is_master_pbd =
          let pbd_host = Db.PBD.get_host ~__context ~self in
          let master_host = Helpers.get_localhost ~__context in
          pbd_host = master_host
        in
        with_unplug_locks ~__context ~sr ~pbd:self (fun () ->
            if is_master_pbd then
              Xapi_sr.maybe_copy_sr_rrds ~__context ~sr ;
            forward_pbd_op ~local_fn ~__context ~self ~remote_fn
        )
    end

    module Crashdump = struct
      (* -------- Forwarding helper functions: ------------------------------------ *)

      (* Read VDI and then re-use VDI forwarding policy *)
      let forward_crashdump_op ~local_fn ~__context ~self ~remote_fn =
        let vdi = Db.Crashdump.get_VDI ~__context ~self in
        VDI.forward_vdi_op ~local_fn ~__context ~self:vdi ~remote_fn

      (* -------------------------------------------------------------------------- *)

      let destroy ~__context ~self =
        info "Crashdump.destroy: crashdump = '%s'"
          (crashdump_uuid ~__context self) ;
        let local_fn = Local.Crashdump.destroy ~self in
        let remote_fn = Client.Crashdump.destroy ~self in
        forward_crashdump_op ~local_fn ~__context ~self ~remote_fn
    end

    (* whatever *)
    module Console = Local.Console
    module User = Local.User
    module Blob = Local.Blob
    module Message = Local.Message

    module Data_source = struct end

    module Secret = Local.Secret

    module PCI = struct
      let disable_dom0_access ~__context ~self =
        info "PCI.disable_dom0_access: pci = '%s'" (pci_uuid ~__context self) ;
        let host = Db.PCI.get_host ~__context ~self in
        let local_fn = Local.PCI.disable_dom0_access ~self in
        let remote_fn = Client.PCI.disable_dom0_access ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let enable_dom0_access ~__context ~self =
        info "PCI.enable_dom0_access: pci = '%s'" (pci_uuid ~__context self) ;
        let host = Db.PCI.get_host ~__context ~self in
        let local_fn = Local.PCI.enable_dom0_access ~self in
        let remote_fn = Client.PCI.enable_dom0_access ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let get_dom0_access_status ~__context ~self =
        info "PCI.get_dom0_access_status: pci = '%s'" (pci_uuid ~__context self) ;
        let host = Db.PCI.get_host ~__context ~self in
        let local_fn = Local.PCI.get_dom0_access_status ~self in
        let remote_fn = Client.PCI.get_dom0_access_status ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module VTPM = struct
      let create ~__context ~vM ~is_unique =
        VM.with_vm_operation ~__context ~self:vM ~doc:"VTPM.create"
          ~op:`create_vtpm
        @@ fun () -> Local.VTPM.create ~__context ~vM ~is_unique

      let destroy ~__context ~self =
        let vm = Db.VTPM.get_VM ~__context ~self in
        Local.VTPM.destroy ~__context ~self ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self:vm

      let get_contents = Local.VTPM.get_contents

      let set_contents = Local.VTPM.set_contents
    end

    module PGPU = struct
      include Local.PGPU

      let enable_dom0_access ~__context ~self =
        info "PGPU.enable_dom0_access: pgpu = '%s'" (pgpu_uuid ~__context self) ;
        let host = Db.PGPU.get_host ~__context ~self in
        let local_fn = Local.PGPU.enable_dom0_access ~self in
        let remote_fn = Client.PGPU.enable_dom0_access ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let disable_dom0_access ~__context ~self =
        info "PGPU.disable_dom0_access: pgpu = '%s'" (pgpu_uuid ~__context self) ;
        let host = Db.PGPU.get_host ~__context ~self in
        let local_fn = Local.PGPU.disable_dom0_access ~self in
        let remote_fn = Client.PGPU.disable_dom0_access ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module GPU_group = struct
      (* Don't forward. These are just db operations. *)
      let create ~__context ~name_label ~name_description ~other_config =
        info "GPU_group.create: name_label = '%s'" name_label ;
        Local.GPU_group.create ~__context ~name_label ~name_description
          ~other_config

      let destroy ~__context ~self =
        info "GPU_group.destroy: gpu_group = '%s'"
          (gpu_group_uuid ~__context self) ;
        (* WARNING WARNING WARNING: directly call destroy with the global lock since it does only database operations *)
        Helpers.with_global_lock (fun () ->
            Local.GPU_group.destroy ~__context ~self
        )

      let update_enabled_VGPU_types ~__context ~self =
        info "GPU_group.update_enabled_VGPU_types: gpu_group = '%s'"
          (gpu_group_uuid ~__context self) ;
        Local.GPU_group.update_enabled_VGPU_types ~__context ~self

      let update_supported_VGPU_types ~__context ~self =
        info "GPU_group.update_supported_VGPU_types: gpu_group = '%s'"
          (gpu_group_uuid ~__context self) ;
        Local.GPU_group.update_supported_VGPU_types ~__context ~self

      let get_remaining_capacity ~__context ~self ~vgpu_type =
        info
          "GPU_group.get_remaining_capacity: gpu_group = '%s' vgpu_type = '%s'"
          (gpu_group_uuid ~__context self)
          (vgpu_type_uuid ~__context vgpu_type) ;
        Local.GPU_group.get_remaining_capacity ~__context ~self ~vgpu_type
    end

    module VGPU = struct
      let create ~__context ~vM ~gPU_group ~device ~other_config ~_type =
        info "VGPU.create: VM = '%s'; GPU_group = '%s'" (vm_uuid ~__context vM)
          (gpu_group_uuid ~__context gPU_group) ;
        let vgpu =
          Local.VGPU.create ~__context ~vM ~gPU_group ~device ~other_config
            ~_type
        in
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self:vM ;
        vgpu

      let destroy ~__context ~self =
        info "VGPU.destroy: VGPU = '%s'" (vgpu_uuid ~__context self) ;
        let vm = Db.VGPU.get_VM ~__context ~self in
        Local.VGPU.destroy ~__context ~self ;
        Xapi_vm_lifecycle.update_allowed_operations ~__context ~self:vm

      let atomic_set_resident_on ~__context ~self ~value =
        info "VGPU.atomic_set_resident_on: VGPU = '%s'; PGPU = '%s'"
          (vgpu_uuid ~__context self)
          (pgpu_uuid ~__context value) ;
        (* Need to prevent the host chooser being run while these fields are being modified *)
        Helpers.with_global_lock (fun () ->
            Db.VGPU.set_resident_on ~__context ~self ~value ;
            Db.VGPU.set_scheduled_to_be_resident_on ~__context ~self
              ~value:Ref.null
        )
    end

    module Pool_update = struct
      let introduce ~__context ~vdi =
        info "Pool_update.introduce: vdi = '%s'" (vdi_uuid ~__context vdi) ;
        let local_fn = Local.Pool_update.introduce ~vdi in
        let remote_fn = Client.Pool_update.introduce ~vdi in
        VDI.forward_vdi_op ~local_fn ~__context ~self:vdi ~remote_fn

      let pool_apply ~__context ~self =
        info "Pool_update.pool_apply: pool update = '%s'"
          (pool_update_uuid ~__context self) ;
        Local.Pool_update.pool_apply ~__context ~self

      let pool_clean ~__context ~self =
        info "Pool_update.pool_clean: pool update = '%s'"
          (pool_update_uuid ~__context self) ;
        let local_fn = Local.Pool_update.pool_clean ~self in
        let remote_fn = Client.Pool_update.pool_clean ~self in
        let update_vdi = Db.Pool_update.get_vdi ~__context ~self in
        if Db.is_valid_ref __context update_vdi then
          VDI.forward_vdi_op ~local_fn ~__context ~self:update_vdi ~remote_fn
        else
          info
            "Pool_update.pool_clean: pool update '%s' has already been cleaned."
            (pool_update_uuid ~__context self)

      let destroy ~__context ~self =
        info "Pool_update.destroy: pool update = '%s'"
          (pool_update_uuid ~__context self) ;
        Local.Pool_update.destroy ~__context ~self

      let attach ~__context ~self ~use_localhost_proxy =
        info "Pool_update.attach: pool update = '%s'"
          (pool_update_uuid ~__context self) ;
        let local_fn = Local.Pool_update.attach ~self ~use_localhost_proxy in
        let remote_fn = Client.Pool_update.attach ~self ~use_localhost_proxy in
        let update_vdi = Db.Pool_update.get_vdi ~__context ~self in
        if Db.is_valid_ref __context update_vdi then
          VDI.forward_vdi_op ~local_fn ~__context ~self:update_vdi ~remote_fn
        else
          raise
            (Api_errors.Server_error
               ( Api_errors.cannot_find_update
               , [pool_update_uuid ~__context self]
               )
            )

      let detach ~__context ~self =
        info "Pool_update.detach: pool update = '%s''"
          (pool_update_uuid ~__context self) ;
        let local_fn = Local.Pool_update.detach ~self in
        let remote_fn = Client.Pool_update.detach ~self in
        let update_vdi = Db.Pool_update.get_vdi ~__context ~self in
        if Db.is_valid_ref __context update_vdi then
          VDI.forward_vdi_op ~local_fn ~__context ~self:update_vdi ~remote_fn
        else
          raise
            (Api_errors.Server_error
               ( Api_errors.cannot_find_update
               , [pool_update_uuid ~__context self]
               )
            )

      let resync_host ~__context ~host =
        info "Pool_update.resync_host: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Pool_update.resync_host ~host in
        let remote_fn = Client.Pool_update.resync_host ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn
    end

    module VGPU_type = struct end

    module LVHD = struct end

    module PVS_site = struct
      let introduce ~__context ~name_label ~name_description ~pVS_uuid =
        info "PVS_site.introduce %s" name_label ;
        Local.PVS_site.introduce ~__context ~name_label ~name_description
          ~pVS_uuid

      let forget ~__context ~self =
        info "PVS_site.forget" ;
        Local.PVS_site.forget ~__context ~self

      let set_PVS_uuid ~__context ~self ~value =
        info "PVS_site.set_PVS_uuid %s" value ;
        Local.PVS_site.set_PVS_uuid ~__context ~self ~value
    end

    module PVS_server = struct
      let introduce ~__context ~addresses ~first_port ~last_port ~site =
        info "PVS_server.introduce" ;
        Local.PVS_server.introduce ~__context ~addresses ~first_port ~last_port
          ~site

      let forget ~__context ~self =
        info "PVS_server.forget" ;
        Local.PVS_server.forget ~__context ~self
    end

    module PVS_proxy = struct
      let choose_host ~__context ~vIF =
        let vm = Db.VIF.get_VM ~__context ~self:vIF in
        let host = Db.VM.get_resident_on ~__context ~self:vm in
        if Db.is_valid_ref __context host then
          host
        else
          Helpers.get_localhost ~__context

      let create ~__context ~site ~vIF =
        info "PVS_proxy.create" ;
        let host = choose_host ~__context ~vIF in
        let local_fn = Local.PVS_proxy.create ~site ~vIF in
        let remote_fn = Client.PVS_proxy.create ~site ~vIF in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let destroy ~__context ~self =
        info "PVS_proxy.destroy" ;
        let vIF = Db.PVS_proxy.get_VIF ~__context ~self in
        let host = choose_host ~__context ~vIF in
        let local_fn = Local.PVS_proxy.destroy ~self in
        let remote_fn = Client.PVS_proxy.destroy ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module PVS_cache_storage = struct
      let create ~__context ~host ~sR ~site ~size =
        info "PVS_cache_storage.create" ;
        Local.PVS_cache_storage.create ~__context ~host ~sR ~site ~size

      let destroy ~__context ~self =
        info "PVS_cache_storage.destroy" ;
        let local_fn = Local.PVS_cache_storage.destroy ~self in
        let remote_fn = Client.PVS_cache_storage.destroy ~self in
        let host = Db.PVS_cache_storage.get_host ~__context ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module Feature = struct end

    module SDN_controller = struct
      let introduce ~__context ~protocol ~address ~port =
        info "SDN_controller.introduce: protocol='%s', address='%s', port='%Ld'"
          (Record_util.sdn_controller_protocol_to_string protocol)
          address port ;
        Local.SDN_controller.introduce ~__context ~protocol ~address ~port

      let forget ~__context ~self =
        info "SDN_controller.forget: sdn_controller = '%s'"
          (sdn_controller_uuid ~__context self) ;
        Local.SDN_controller.forget ~__context ~self
    end

    module PUSB = struct
      include Local.PUSB

      let scan ~__context ~host =
        info "PUSB.scan: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.PUSB.scan ~host in
        let remote_fn = Client.PUSB.scan ~host in
        do_op_on ~local_fn ~__context ~host ~remote_fn
    end

    module USB_group = struct
      (* Don't forward. These are just db operations. *)
      let create ~__context ~name_label ~name_description ~other_config =
        info "USB_group.create: name_label = '%s'" name_label ;
        Local.USB_group.create ~__context ~name_label ~name_description
          ~other_config

      let destroy ~__context ~self =
        info "USB_group.destroy: usb_group = '%s'"
          (usb_group_uuid ~__context self) ;
        (* WARNING WARNING WARNING: directly call destroy with the global lock since it does only database operations *)
        Helpers.with_global_lock (fun () ->
            Local.USB_group.destroy ~__context ~self
        )
    end

    module VUSB = struct
      let update_vusb_operations ~__context ~vusb =
        Helpers.with_global_lock (fun () ->
            Xapi_vusb_helpers.update_allowed_operations ~__context ~self:vusb
        )

      let unmark_vusb ~__context ~vusb ~doc ~op:_ =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn
          ~doc:("unmarking VUSB after " ^ doc)
          (fun self ->
            if Db.is_valid_ref __context self then (
              Db.VUSB.remove_from_current_operations ~__context ~self
                ~key:task_id ;
              Xapi_vusb_helpers.update_allowed_operations ~__context ~self ;
              Helpers.Early_wakeup.broadcast
                (Datamodel_common._vusb, Ref.string_of vusb)
            )
          )
          vusb

      let mark_vusb ~__context ~vusb ~doc ~op =
        let task_id = Ref.string_of (Context.get_task_id __context) in
        log_exn
          ~doc:("marking VUSB for " ^ doc)
          (fun self ->
            Xapi_vusb_helpers.assert_operation_valid ~__context ~self ~op ;
            Db.VUSB.add_to_current_operations ~__context ~self ~key:task_id
              ~value:op ;
            Xapi_vusb_helpers.update_allowed_operations ~__context ~self
          )
          vusb

      let with_vusb_marked ~__context ~vusb ~doc ~op f =
        Helpers.retry_with_global_lock ~__context ~doc (fun () ->
            mark_vusb ~__context ~vusb ~doc ~op
        ) ;
        finally
          (fun () -> f ())
          (fun () ->
            Helpers.with_global_lock (fun () ->
                unmark_vusb ~__context ~vusb ~doc ~op
            )
          )

      (* -------- Forwarding helper functions: ------------------------------------ *)

      (* Forward to host that has resident VM that this VUSB references *)
      let forward_vusb_op ~local_fn ~__context ~self ~remote_fn =
        let vm = Db.VUSB.get_VM ~__context ~self in
        let host_resident_on = Db.VM.get_resident_on ~__context ~self:vm in
        if host_resident_on = Ref.null then
          local_fn ~__context
        else
          do_op_on ~local_fn ~__context ~host:host_resident_on ~remote_fn

      (* -------------------------------------------------------------------------- *)

      let create ~__context ~vM ~uSB_group ~other_config =
        info "VUSB.create: VM = '%s'; USB_group = '%s'" (vm_uuid ~__context vM)
          (usb_group_uuid ~__context uSB_group) ;
        Local.VUSB.create ~__context ~vM ~uSB_group ~other_config

      let unplug ~__context ~self =
        info "VUSB.unplug: VUSB = '%s'" (vusb_uuid ~__context self) ;
        let local_fn = Local.VUSB.unplug ~self in
        let remote_fn = Client.VUSB.unplug ~self in
        with_vusb_marked ~__context ~vusb:self ~doc:"VUSB.unplug" ~op:`unplug
          (fun () -> forward_vusb_op ~local_fn ~__context ~self ~remote_fn
        ) ;
        update_vusb_operations ~__context ~vusb:self

      let destroy ~__context ~self =
        info "VUSB.destroy: VUSB = '%s'" (vusb_uuid ~__context self) ;
        Local.VUSB.destroy ~__context ~self
    end

    module Network_sriov = struct
      let create ~__context ~pif ~network =
        info "Network_sriov.create : pif = '%s' , network = '%s' "
          (pif_uuid ~__context pif)
          (network_uuid ~__context network) ;
        let local_fn = Local.Network_sriov.create ~pif ~network in
        let remote_fn = Client.Network_sriov.create ~pif ~network in
        let host = Db.PIF.get_host ~__context ~self:pif in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let destroy ~__context ~self =
        info "Network_sriov.destroy : network_sriov = '%s'"
          (network_sriov_uuid ~__context self) ;
        let local_fn = Local.Network_sriov.destroy ~self in
        let remote_fn = Client.Network_sriov.destroy ~self in
        let physical_pif = Db.Network_sriov.get_physical_PIF ~__context ~self in
        let host = Db.PIF.get_host ~__context ~self:physical_pif in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let get_remaining_capacity ~__context ~self =
        info "Network_sriov.get_remaining_capacity : network_sriov = '%s'"
          (network_sriov_uuid ~__context self) ;
        Local.Network_sriov.get_remaining_capacity ~__context ~self
    end

    module Cluster = struct
      let forward_cluster_op ~local_fn ~__context ~remote_fn =
        let localhost = Helpers.get_localhost ~__context in
        let is_local_cluster_host self =
          Db.Cluster_host.get_host ~__context ~self = localhost
        in
        let host =
          match Db.Cluster_host.get_all ~__context with
          | [] ->
              Helpers.get_master ~__context
          | cluster_hosts when List.exists is_local_cluster_host cluster_hosts
            ->
              localhost
          | cluster_host :: _ ->
              Db.Cluster_host.get_host ~__context ~self:cluster_host
        in
        do_op_on ~local_fn ~__context ~host ~remote_fn

      let create ~__context ~pIF ~cluster_stack ~pool_auto_join ~token_timeout
          ~token_timeout_coefficient =
        info "Cluster.create" ;
        let pool = Helpers.get_pool ~__context in
        (* assumes 1 pool in DB *)
        Xapi_pool_helpers.with_pool_operation ~__context ~self:pool
          ~doc:"Cluster.create" ~op:`cluster_create (fun () ->
            let cluster =
              Local.Cluster.create ~__context ~pIF ~cluster_stack
                ~pool_auto_join ~token_timeout ~token_timeout_coefficient
            in
            Xapi_cluster_helpers.update_allowed_operations ~__context
              ~self:cluster ;
            cluster
        )

      let destroy ~__context ~self =
        info "Cluster.destroy cluster: %s" (Ref.string_of self) ;
        Xapi_cluster_helpers.with_cluster_operation ~__context ~self
          ~doc:"Cluster.destroy" ~op:`destroy (fun () ->
            let local_fn = Local.Cluster.destroy ~self in
            let remote_fn = Client.Cluster.destroy ~self in
            forward_cluster_op ~__context ~local_fn ~remote_fn
        )

      let get_network ~__context ~self =
        info "Cluster.get_network" ;
        Local.Cluster.get_network ~__context ~self

      (* Pool operations don't need a lock, they call other locked functions *)
      let pool_create ~__context ~network ~cluster_stack ~token_timeout
          ~token_timeout_coefficient =
        info "Cluster.pool_create" ;
        (* iterates over Cluster_host.create *)
        Local.Cluster.pool_create ~__context ~network ~cluster_stack
          ~token_timeout ~token_timeout_coefficient

      let pool_force_destroy ~__context ~self =
        (* iterates over Cluster_host.destroy *)
        info "Cluster.pool_force_destroy cluster: %s" (Ref.string_of self) ;
        Local.Cluster.pool_force_destroy ~__context ~self

      let pool_destroy ~__context ~self =
        (* iterates Cluster_host.destroy *)
        info "Cluster.pool_destroy cluster %s" (Ref.string_of self) ;
        Local.Cluster.pool_destroy ~__context ~self

      let pool_resync ~__context ~self =
        (* iterates Cluster_host.enable and Cluster_host where necessary*)
        info "Cluster.pool_resync cluster: %s" (Ref.string_of self) ;
        let hosts = Xapi_pool_helpers.get_master_slaves_list ~__context in
        let local_fn = Local.Cluster.pool_resync ~self in
        let remote_fn = Client.Cluster.pool_resync ~self in
        hosts
        |> List.iter (fun host ->
               do_op_on ~local_fn ~__context ~host ~remote_fn ;
               debug "Cluster.pool_resync for host %s" (Ref.string_of host)
           )

      let cstack_sync ~__context ~self =
        info "Cluster.cstack_sync cluster %s" (Ref.string_of self) ;
        let local_fn = Local.Cluster.cstack_sync ~self in
        let remote_fn = Client.Cluster.cstack_sync ~self in
        let coor = Helpers.get_master ~__context in
        do_op_on ~local_fn ~__context ~host:coor ~remote_fn
    end

    module Cluster_host = struct
      let create ~__context ~cluster ~host ~pif =
        info "Cluster_host.create with cluster:%s, host:%s, pif:%s"
          (Ref.string_of cluster) (Ref.string_of host) (Ref.string_of pif) ;
        let local_fn = Local.Cluster_host.create ~cluster ~host ~pif in
        let remote_fn = Client.Cluster_host.create ~cluster ~host ~pif in
        Xapi_cluster_helpers.with_cluster_operation ~__context ~self:cluster
          ~doc:"Cluster.add" ~op:`add (fun () ->
            let cluster_host = do_op_on ~__context ~local_fn ~host ~remote_fn in
            Xapi_cluster_host_helpers.update_allowed_operations ~__context
              ~self:cluster_host ;
            cluster_host
        )

      let destroy ~__context ~self =
        info "Cluster_host.destroy cluster_host: %s" (Ref.string_of self) ;
        let local_fn = Local.Cluster_host.destroy ~self in
        let remote_fn = Client.Cluster_host.destroy ~self in
        let host = Db.Cluster_host.get_host ~__context ~self in
        let cluster = Db.Cluster_host.get_cluster ~__context ~self in
        Xapi_cluster_helpers.with_cluster_operation ~__context ~self:cluster
          ~doc:"Cluster_host.destroy" ~op:`remove (fun () ->
            do_op_on ~__context ~local_fn ~host ~remote_fn
        )

      let force_destroy ~__context ~self =
        info "Cluster_host.force_destroy cluster_host: %s" (Ref.string_of self) ;
        let local_fn = Local.Cluster_host.force_destroy ~self in
        let remote_fn = Client.Cluster_host.force_destroy ~self in
        let host = Db.Cluster_host.get_host ~__context ~self in
        let cluster = Db.Cluster_host.get_cluster ~__context ~self in
        Xapi_cluster_helpers.with_cluster_operation ~__context ~self:cluster
          ~doc:"Cluster_host.force_destroy" ~op:`remove (fun () ->
            do_op_on ~__context ~local_fn ~host ~remote_fn
        )

      let enable ~__context ~self =
        info "Cluster_host.enable cluster_host %s" (Ref.string_of self) ;
        let cluster = Db.Cluster_host.get_cluster ~__context ~self in
        let local_fn = Local.Cluster_host.enable ~self in
        let remote_fn = Client.Cluster_host.enable ~self in
        let host = Db.Cluster_host.get_host ~__context ~self in
        Xapi_cluster_helpers.with_cluster_operation ~__context ~self:cluster
          ~doc:"Cluster.enable" ~op:`enable (fun () ->
            Xapi_cluster_host_helpers.with_cluster_host_operation ~__context
              ~self ~doc:"Cluster_host.enable" ~op:`enable (fun () ->
                do_op_on ~__context ~local_fn ~host ~remote_fn
            )
        )

      let disable ~__context ~self =
        info "Cluster_host.disable cluster_host: %s" (Ref.string_of self) ;
        let cluster = Db.Cluster_host.get_cluster ~__context ~self in
        let local_fn = Local.Cluster_host.disable ~self in
        let remote_fn = Client.Cluster_host.disable ~self in
        let host = Db.Cluster_host.get_host ~__context ~self in
        Xapi_cluster_helpers.with_cluster_operation ~__context ~self:cluster
          ~doc:"Cluster.disable" ~op:`disable (fun () ->
            Xapi_cluster_host_helpers.with_cluster_host_operation ~__context
              ~self ~doc:"Cluster_host.disable" ~op:`disable (fun () ->
                do_op_on ~__context ~local_fn ~host ~remote_fn
            )
        )

      let forget ~__context ~self =
        info "Cluster_host.forget cluster_host:%s" (Ref.string_of self) ;
        Db.Cluster_host.set_joined ~__context ~self ~value:false ;
        let cluster = Db.Cluster_host.get_cluster ~__context ~self in
        let local_fn = Local.Cluster_host.forget ~self in
        let remote_fn = Client.Cluster_host.forget ~self in
        (* We need to ask another host that has a cluster host to mark it as dead.
         * We might've run force destroy and this host would no longer have a cluster host
         * *)
        let other_hosts =
          Db.Cluster.get_cluster_hosts ~__context ~self:cluster
          |> List.filter (( <> ) self)
        in
        let rec find_first_live = function
          | [] ->
              info "No other cluster hosts, nothing to do"
              (* go ahead and finish Host.destroy *)
          | other_cluster_host :: rest -> (
            try
              let host =
                Db.Cluster_host.get_host ~__context ~self:other_cluster_host
              in
              Xapi_cluster_helpers.with_cluster_operation ~__context
                ~self:cluster ~doc:"Cluster.remove" ~op:`remove (fun () ->
                  do_op_on ~__context ~local_fn ~host ~remote_fn
              )
            with
            | Api_errors.Server_error (code, _) as e
            when code = Api_errors.host_offline
            -> (
              match rest with
              | [] ->
                  debug
                    "Ran out of hosts to try (and no cluster host on \
                     ourselves), reporting error" ;
                  raise e
              | _ ->
                  find_first_live rest
            )
          )
        in
        find_first_live other_hosts
    end

    module Certificate = struct end

    module Host_driver = struct
      (** select needs to be executed on the host of the driver *)
      let select ~__context ~self ~variant =
        info "Host_driver.select %s %s" (Ref.string_of self)
          (Ref.string_of variant) ;
        let host = Db.Host_driver.get_host ~__context ~self in
        let local_fn = Local.Host_driver.select ~self ~variant in
        let remote_fn = Client.Host_driver.select ~self ~variant in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      (** deselect needs to be executed on the host of the driver *)
      let deselect ~__context ~self =
        info "Host_driver.deselect %s" (Ref.string_of self) ;
        let host = Db.Host_driver.get_host ~__context ~self in
        let local_fn = Local.Host_driver.deselect ~self in
        let remote_fn = Client.Host_driver.deselect ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let rescan ~__context ~host =
        info "Host_driver.rescan %s" (Ref.string_of host) ;
        let local_fn = Local.Host_driver.rescan ~host in
        let remote_fn = Client.Host_driver.rescan ~host in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module Driver_variant = struct
      let select ~__context ~self =
        info "Driver_variant.select %s" (Ref.string_of self) ;
        let drv = Db.Driver_variant.get_driver ~__context ~self in
        let host = Db.Host_driver.get_host ~__context ~self:drv in
        let local_fn = Local.Driver_variant.select ~self in
        let remote_fn = Client.Driver_variant.select ~self in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module Repository = struct
      let introduce ~__context ~name_label ~name_description ~binary_url
          ~source_url ~update ~gpgkey_path =
        info
          "Repository.introduce: name = '%s'; name_description = '%s'; \
           binary_url = '%s'; source_url = '%s'; update = '%s'; gpgkey_path = \
           '%s'"
          name_label name_description binary_url source_url
          (string_of_bool update) gpgkey_path ;
        Local.Repository.introduce ~__context ~name_label ~name_description
          ~binary_url ~source_url ~update ~gpgkey_path

      let introduce_bundle ~__context ~name_label ~name_description =
        info "Repository.introduce_bundle: name = '%s'; name_description = '%s'"
          name_label name_description ;
        Local.Repository.introduce_bundle ~__context ~name_label
          ~name_description

      let introduce_remote_pool ~__context ~name_label ~name_description
          ~binary_url ~certificate =
        info
          "Repository.introduce_remote_pool: name = '%s'; name_description = \
           '%s'; binary_url = '%s'; certificate = '%s'"
          name_label name_description binary_url certificate ;
        Local.Repository.introduce_remote_pool ~__context ~name_label
          ~name_description ~binary_url ~certificate

      let forget ~__context ~self =
        info "Repository.forget: self = '%s'" (repository_uuid ~__context self) ;
        Local.Repository.forget ~__context ~self

      let apply ~__context ~host =
        info "Repository.apply: host = '%s'" (host_uuid ~__context host) ;
        let local_fn = Local.Repository.apply ~host in
        let remote_fn = Client.Repository.apply ~host in
        do_op_on ~__context ~local_fn ~host ~remote_fn

      let set_gpgkey_path ~__context ~self ~value =
        info "Repository.set_gpgkey_path : repository='%s' value='%s'"
          (repository_uuid ~__context self)
          value ;
        Local.Repository.set_gpgkey_path ~__context ~self ~value

      let apply_livepatch ~__context ~host ~component ~base_build_id
          ~base_version ~base_release ~to_version ~to_release =
        info
          "Repository.apply_livepatch: host='%s' component=%s \
           base_build_id='%s' base_version='%s' base_release='%s' \
           to_version='%s' to_release='%s'"
          (host_uuid ~__context host)
          component base_build_id base_version base_release to_version
          to_release ;
        let local_fn =
          Local.Repository.apply_livepatch ~host ~component ~base_build_id
            ~base_version ~base_release ~to_version ~to_release
        in
        let remote_fn =
          Client.Repository.apply_livepatch ~host ~component ~base_build_id
            ~base_version ~base_release ~to_version ~to_release
        in
        do_op_on ~__context ~local_fn ~host ~remote_fn
    end

    module VM_group = struct
      let create ~__context ~name_label ~name_description ~placement =
        info
          "VM_group.create: name_label = '%s'; name_description = '%s'; \
           placement = '%s'"
          name_label name_description
          (Record_util.vm_placement_policy_to_string placement) ;
        Local.VM_group.create ~__context ~name_label ~name_description
          ~placement

      let destroy ~__context ~self =
        info "VM_group.destroy: self = '%s'" (vm_group_uuid ~__context self) ;
        Xapi_vm_group_helpers.remove_vm_anti_affinity_alert ~__context
          ~groups:[self] ;
        Local.VM_group.destroy ~__context ~self
    end

    module Observer = struct
      module RefSet = Set.Make (struct
        type t = [`host] Ref.t

        let compare = Ref.compare
      end)

      let create ~__context ~name_label ~name_description ~hosts ~attributes
          ~endpoints ~components ~enabled =
        info "Observer.create: name_label=%s" name_label ;
        let self =
          Local.Observer.create ~__context ~name_label ~name_description ~hosts
            ~attributes ~endpoints ~components ~enabled
        in
        let local_fn =
          Local.Observer.register ~self ~host:(Helpers.get_localhost ~__context)
        in
        Xapi_observer.observed_hosts_of ~__context hosts
        |> List.iter (fun host ->
               let remote_fn = Client.Observer.register ~self ~host in
               do_op_on ~__context ~host ~local_fn ~remote_fn
           ) ;
        self

      let register ~__context ~self ~host =
        info "Observer.register: self=%s" (observer_uuid ~__context self) ;
        let local_fn = Local.Observer.register ~self ~host in
        let remote_fn = Client.Observer.register ~self ~host in
        do_op_on ~__context ~host ~local_fn ~remote_fn

      let unregister ~__context ~self ~host =
        info "Observer.unregister: self=%s" (observer_uuid ~__context self) ;
        let local_fn = Local.Observer.unregister ~self ~host in
        let remote_fn = Client.Observer.unregister ~self ~host in
        do_op_on ~__context ~host ~local_fn ~remote_fn

      let destroy ~__context ~self =
        info "Observer.destroy: self=%s" (observer_uuid ~__context self) ;
        let hosts = Db.Observer.get_hosts ~__context ~self in
        let local_fn =
          Local.Observer.unregister ~self
            ~host:(Helpers.get_localhost ~__context)
        in
        Xapi_observer.observed_hosts_of ~__context hosts
        |> List.iter (fun host ->
               let remote_fn = Client.Observer.unregister ~self ~host in
               do_op_on ~__context ~host ~local_fn ~remote_fn
           ) ;
        Local.Observer.destroy ~__context ~self

      let set_hosts ~__context ~self ~value =
        let uuid = observer_uuid ~__context self in
        info "Observer.set_hosts: self=%s value=%s" uuid
          (String.concat ";" (List.map (host_uuid ~__context) value)) ;
        Local.Observer.set_hosts ~__context ~self ~value ;
        let new_hosts =
          RefSet.of_list (Xapi_observer.observed_hosts_of ~__context value)
        in
        let old_hosts =
          RefSet.of_list
            (Xapi_observer.observed_hosts_of ~__context
               (Db.Observer.get_hosts ~__context ~self)
            )
        in
        let to_add = RefSet.diff new_hosts old_hosts in
        let to_remove = RefSet.diff old_hosts new_hosts in
        let localhost = Helpers.get_localhost ~__context in
        let local_fn = Local.Observer.unregister ~self ~host:localhost in
        RefSet.iter
          (fun host ->
            let remote_fn = Client.Observer.unregister ~self ~host in
            do_op_on ~__context ~host ~local_fn ~remote_fn
          )
          to_remove ;
        let local_fn = Local.Observer.register ~self ~host:localhost in
        RefSet.iter
          (fun host ->
            let remote_fn = Client.Observer.register ~self ~host in
            do_op_on ~__context ~host ~local_fn ~remote_fn
          )
          to_add

      let set_enabled ~__context ~self ~value =
        info "Observer.set_enabled: self=%s value=%B"
          (observer_uuid ~__context self)
          value ;
        let local_fn = Local.Observer.set_enabled ~self ~value in
        let remote_fn = Client.Observer.set_enabled ~self ~value in
        let fn ~rpc:_ ~session_id:_ ~host =
          do_op_on ~__context ~host ~local_fn ~remote_fn
        in
        Xapi_pool_helpers.call_fn_on_master_then_slaves ~__context fn

      let set_attributes ~__context ~self ~value =
        (* attributes will be kept out of the logs *)
        info "Observer.set_attributes: self=%s" (observer_uuid ~__context self) ;
        let local_fn = Local.Observer.set_attributes ~self ~value in
        let remote_fn = Client.Observer.set_attributes ~self ~value in
        let fn ~rpc:_ ~session_id:_ ~host =
          do_op_on ~__context ~host ~local_fn ~remote_fn
        in
        Xapi_pool_helpers.call_fn_on_master_then_slaves ~__context fn

      let set_endpoints ~__context ~self ~value =
        (* endpoints will be kept out of the logs *)
        info "Observer.set_endpoints: self=%s" (observer_uuid ~__context self) ;
        let local_fn = Local.Observer.set_endpoints ~self ~value in
        let remote_fn = Client.Observer.set_endpoints ~self ~value in
        let fn ~rpc:_ ~session_id:_ ~host =
          do_op_on ~__context ~host ~local_fn ~remote_fn
        in
        Xapi_pool_helpers.call_fn_on_master_then_slaves ~__context fn

      let set_components ~__context ~self ~value =
        info "Observer.set_components: self=%s value=%s"
          (observer_uuid ~__context self)
          (value |> String.concat ",") ;
        let local_fn = Local.Observer.set_components ~self ~value in
        let remote_fn = Client.Observer.set_components ~self ~value in
        let fn ~rpc:_ ~session_id:_ ~host =
          do_op_on ~__context ~host ~local_fn ~remote_fn
        in
        Xapi_pool_helpers.call_fn_on_slaves_then_master ~__context fn
    end
  end

(* for unit tests *)
let register_callback_fns () =
  let set_stunnelpid _task_opt pid =
    Locking_helpers.Thread_state.acquired
      (Locking_helpers.Process ("stunnel", pid))
  in
  let unset_stunnelpid _task_opt pid =
    Locking_helpers.Thread_state.released
      (Locking_helpers.Process ("stunnel", pid))
  in
  let stunnel_destination_is_ok addr =
    Server_helpers.exec_with_new_task "check_stunnel_destination"
      (fun __context ->
        let hosts =
          Db.Host.get_refs_where ~__context
            ~expr:(Eq (Field "address", Literal addr))
        in
        match hosts with
        | [host] -> (
          try check_live ~__context host ; true with _ -> false
        )
        | _ ->
            true
    )
  in
  Xmlrpc_client.Internal.set_stunnelpid_callback := Some set_stunnelpid ;
  Xmlrpc_client.Internal.unset_stunnelpid_callback := Some unset_stunnelpid ;
  Xmlrpc_client.Internal.destination_is_ok := Some stunnel_destination_is_ok ;
  TaskHelper.init ()
