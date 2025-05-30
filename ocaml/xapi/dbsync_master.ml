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
 * @group Main Loop and Start-up
*)

module D = Debug.Make (struct let name = "dbsync" end)

open D
open Client
open Recommendations

(* Synchronising code which is specific to the master *)

(* create pool record (if master and not one already there) *)
let create_pool_record ~__context =
  let pools = Db.Pool.get_all ~__context in
  if pools = [] then
    Db.Pool.create ~__context ~ref:(Ref.make ())
      ~uuid:(Uuidx.to_string (Uuidx.make ()))
      ~name_label:"" ~name_description:""
      ~master:(Helpers.get_localhost ~__context)
      ~default_SR:Ref.null ~suspend_image_SR:Ref.null ~crash_dump_SR:Ref.null
      ~ha_enabled:false ~ha_configuration:[] ~ha_statefiles:[]
      ~ha_host_failures_to_tolerate:0L ~ha_plan_exists_for:0L
      ~ha_allow_overcommit:false ~ha_overcommitted:false ~blobs:[] ~tags:[]
      ~gui_config:[] ~health_check_config:[] ~wlb_url:"" ~wlb_username:""
      ~wlb_password:Ref.null ~wlb_enabled:false ~wlb_verify_cert:false
      ~redo_log_enabled:false ~redo_log_vdi:Ref.null
      ~igmp_snooping_enabled:false ~vswitch_controller:"" ~restrictions:[]
      ~current_operations:[] ~allowed_operations:[]
      ~other_config:[Xapi_globs.memory_ratio_hvm; Xapi_globs.memory_ratio_pv]
      ~ha_cluster_stack:"xhad" ~guest_agent_config:[] ~cpu_info:[]
      ~policy_no_vendor_device:false ~live_patching_disabled:false
      ~uefi_certificates:"" ~custom_uefi_certificates:"" ~is_psr_pending:false
      ~tls_verification_enabled:false ~repositories:[]
      ~client_certificate_auth_enabled:false ~client_certificate_auth_name:""
      ~repository_proxy_url:"" ~repository_proxy_username:""
      ~repository_proxy_password:Ref.null ~migration_compression:false
      ~coordinator_bias:true ~telemetry_uuid:Ref.null
      ~telemetry_frequency:`weekly ~telemetry_next_collection:Clock.Date.epoch
      ~last_update_sync:Clock.Date.epoch ~update_sync_frequency:`weekly
      ~update_sync_day:0L ~update_sync_enabled:false ~local_auth_max_threads:8L
      ~ext_auth_max_threads:1L ~ext_auth_cache_enabled:false
      ~ext_auth_cache_size:50L ~ext_auth_cache_expiry:300L ~recommendations:[]
      ~license_server:[] ~ha_reboot_vm_on_internal_shutdown:true

let set_master_ip ~__context =
  let ip =
    match Helpers.get_management_ip_addr ~__context with
    | Some ip ->
        ip
    | None ->
        error
          "Cannot read master IP address. Check the control interface has an \
           IP address" ;
        ""
  in
  let host = Helpers.get_localhost ~__context in
  Db.Host.set_address ~__context ~self:host ~value:ip

(* NB the master doesn't use the heartbeat mechanism to track its own liveness so we
   must make sure that live starts out as true because it will never be updated. *)
let set_master_live ~__context =
  let host = Helpers.get_localhost ~__context in
  let metrics = Db.Host.get_metrics ~__context ~self:host in
  debug "Setting Host_metrics.live to true for localhost" ;
  Db.Host_metrics.set_live ~__context ~self:metrics ~value:true

let set_master_pool_reference ~__context =
  let pool = Helpers.get_pool ~__context in
  Db.Pool.set_master ~__context ~self:pool
    ~value:(Helpers.get_localhost ~__context)

let refresh_console_urls ~__context =
  List.iter
    (fun console ->
      Helpers.log_exn_continue
        (Printf.sprintf "Updating console: %s" (Ref.string_of console))
        (fun () ->
          let vm = Db.Console.get_VM ~__context ~self:console in
          let host = Db.VM.get_resident_on ~__context ~self:vm in
          let url_should_be =
            match Db.Host.get_address ~__context ~self:host with
            | "" ->
                ""
            | address ->
                Uri.(
                  make ~scheme:"https" ~host:address ~path:Constants.console_uri
                    ~query:[("ref", [Ref.string_of console])]
                    ()
                  |> to_string
                )
          in
          Db.Console.set_location ~__context ~self:console ~value:url_should_be
        )
        ()
    )
    (Db.Console.get_all ~__context)

(** CA-15449: after a pool restore database VMs which were running on slaves now have dangling resident_on fields.
    If these are control domains we destroy them, otherwise we reset them to Halted. *)
let reset_vms_running_on_missing_hosts ~__context =
  List.iter
    (fun vm ->
      let vm_r = Db.VM.get_record ~__context ~self:vm in
      let valid_resident_on =
        Db.is_valid_ref __context vm_r.API.vM_resident_on
      in
      if (not valid_resident_on) && vm_r.API.vM_power_state = `Running then (
        let msg =
          Printf.sprintf
            "Resetting VM uuid '%s' to Halted because VM.resident_on refers to \
             a Host which is no longer in the Pool"
            vm_r.API.vM_uuid
        in
        info "%s" msg ;
        Helpers.log_exn_continue msg
          (fun () ->
            Xapi_vm_lifecycle.force_state_reset ~__context ~self:vm
              ~value:`Halted
          )
          ()
      )
    )
    (Db.VM.get_all ~__context)

(** Release 'locks' on VMs in the Halted state: ie {VBD,VIF}.{currently_attached,reserved}
    Note that the {allowed,current}_operations fields are non-persistent so blanked on *master* startup (not slave)
    No allowed_operations are recomputed here: this work is performed later in a non-critical thread.
*)
let release_locks ~__context =
  (* non-running VMs should have their VBD.current_operations cleared: *)
  let vms =
    List.filter
      (fun self -> Db.VM.get_power_state ~__context ~self = `Halted)
      (Db.VM.get_all ~__context)
  in
  List.iter
    (fun vm ->
      List.iter
        (fun self -> Xapi_vbd_helpers.clear_current_operations ~__context ~self)
        (Db.VM.get_VBDs ~__context ~self:vm)
    )
    vms ;
  (* Resets the current operations of all Halted VMs *)
  List.iter
    (fun self ->
      Xapi_vm_lifecycle.force_state_reset ~__context ~self ~value:`Halted
    )
    vms ;
  (* Clear all assignments that are only scheduled *)
  let value = Ref.null in
  Db.VM.get_all ~__context
  |> List.iter (fun self ->
         Db.VM.set_scheduled_to_be_resident_on ~__context ~self ~value
     ) ;
  Db.PCI.get_all ~__context
  |> List.iter (fun self ->
         Db.PCI.set_scheduled_to_be_attached_to ~__context ~self ~value
     ) ;
  Db.VGPU.get_all ~__context
  |> List.iter (fun self ->
         Db.VGPU.set_scheduled_to_be_resident_on ~__context ~self ~value
     )

let create_tools_sr __context name_label name_description sr_introduce
    maybe_create_pbd =
  let create_magic_sr name_label name_description other_config =
    (* Create a new SR and PBD record *)
    (* N.b. dbsync_slave is called _before_ this, so we can't rely on the PBD creating code in there
       		   to make the PBD for the shared tools SR *)
    let sr =
      sr_introduce
        ~uuid:(Uuidx.to_string (Uuidx.make ()))
        ~name_label ~name_description ~_type:"iso" ~content_type:"iso"
        ~shared:true ~sm_config:[]
    in
    Db.SR.set_other_config ~__context ~self:sr ~value:other_config ;
    Db.SR.set_is_tools_sr ~__context ~self:sr ~value:true ;
    (* Master has created this shared SR, lets make PBDs for all of the slaves too. Nb. device-config is same for all hosts *)
    let hosts = Db.Host.get_all ~__context in
    List.iter
      (fun host ->
        ignore (maybe_create_pbd sr Xapi_globs.tools_sr_pbd_device_config host)
      )
      hosts ;
    sr
  in
  let other_config =
    [
      (Xapi_globs.xensource_internal, "true")
    ; (Xapi_globs.tools_sr_tag, "true")
    ; (Xapi_globs.i18n_key, "xenserver-tools")
    ; (Xapi_globs.i18n_original_value_prefix ^ "name_label", name_label)
    ; ( Xapi_globs.i18n_original_value_prefix ^ "name_description"
      , name_description
      )
    ]
  in
  let destroy self =
    try Db.SR.destroy ~__context ~self
    with e ->
      warn "failed to destroy redundant tools SR %s: %s" (Ref.string_of self)
        (Printexc.to_string e)
  in
  let sr =
    let srs = Db.SR.get_all ~__context in
    let tools_srs =
      List.filter (fun self -> Db.SR.get_is_tools_sr ~__context ~self) srs
    in
    let old_srs =
      List.filter
        (fun self ->
          let other_config = Db.SR.get_other_config ~__context ~self in
          Db.SR.get_is_tools_sr ~__context ~self = false
          && (List.mem_assoc Xapi_globs.tools_sr_tag other_config
             || List.mem_assoc Xapi_globs.xensource_internal other_config
             )
        )
        srs
    in
    match tools_srs with
    | sr :: others ->
        (* Let there be only one Tools SR *)
        List.iter destroy others ; List.iter destroy old_srs ; sr
    | [] -> (
      (* First check if there is an SR with the old tags on it, which needs upgrading (set is_tools_sr). *)
      (* We cannot do this in xapi_db_upgrade, because that runs later. *)
      match old_srs with
      | sr :: others ->
          Db.SR.set_is_tools_sr ~__context ~self:sr ~value:true ;
          List.iter destroy others ;
          (* destroy bogus Tool SRs CA-300103 *)
          sr
      | [] ->
          create_magic_sr name_label name_description other_config
    )
  in
  (* Ensure fields are up-to-date *)
  Db.SR.set_name_label ~__context ~self:sr ~value:name_label ;
  Db.SR.set_name_description ~__context ~self:sr ~value:name_description ;
  let other_config =
    (* Keep any existing keys/value pair besides the required ones *)
    let oc = Db.SR.get_other_config ~__context ~self:sr in
    let keys = List.map fst other_config in
    let extra = List.filter (fun (k, _) -> not (List.mem k keys)) oc in
    extra @ other_config
  in
  Db.SR.set_other_config ~__context ~self:sr ~value:other_config ;
  List.iter
    (fun self ->
      Db.PBD.set_device_config ~__context ~self
        ~value:Xapi_globs.tools_sr_pbd_device_config
    )
    (Db.SR.get_PBDs ~__context ~self:sr)

let create_tools_sr_noexn __context =
  let name_label = Xapi_globs.tools_sr_name () in
  let name_description = Xapi_globs.tools_sr_description () in
  Helpers.call_api_functions ~__context (fun rpc session_id ->
      let sr_introduce = Client.SR.introduce ~rpc ~session_id in
      let maybe_create_pbd = Create_storage.maybe_create_pbd rpc session_id in
      Helpers.log_exn_continue "creating tools SR"
        (fun () ->
          create_tools_sr __context name_label name_description sr_introduce
            maybe_create_pbd
        )
        ()
  )

let ensure_vm_metrics_records_exist __context =
  List.iter
    (fun vm ->
      let m = Db.VM.get_metrics ~__context ~self:vm in
      if not (Db.is_valid_ref __context m) then (
        info "Regenerating missing VM_metrics record for VM %s"
          (Ref.string_of vm) ;
        let m = Ref.make () in
        let uuid = Uuidx.to_string (Uuidx.make ()) in
        Db.VM_metrics.create ~__context ~ref:m ~uuid ~vCPUs_number:0L
          ~vCPUs_utilisation:[] ~memory_actual:0L ~vCPUs_CPU:[] ~vCPUs_params:[]
          ~vCPUs_flags:[] ~start_time:Clock.Date.epoch
          ~install_time:Clock.Date.epoch ~state:[]
          ~last_updated:Clock.Date.epoch ~other_config:[] ~hvm:false
          ~nested_virt:false ~nomigrate:false ~current_domain_type:`unspecified ;
        Db.VM.set_metrics ~__context ~self:vm ~value:m
      )
    )
    (Db.VM.get_all ~__context)

let ensure_vm_metrics_records_exist_noexn __context =
  Helpers.log_exn_continue "ensuring VM_metrics flags exist"
    ensure_vm_metrics_records_exist __context

let setup_telemetry ~__context =
  let pool = Helpers.get_pool ~__context in
  let ref = Db.Pool.get_telemetry_uuid ~__context ~self:pool in
  if ref = Ref.null then
    Helpers.log_exn_continue "Setting up telemetry"
      (fun () ->
        Helpers.call_api_functions ~__context (fun rpc session_id ->
            Client.Pool.reset_telemetry_uuid ~rpc ~session_id ~self:pool
        ) ;
        (* An exception will result in leaving the next collection as default *)
        let interval_hours =
          match Db.Pool.get_telemetry_frequency ~__context ~self:pool with
          | `daily ->
              1 * 24
          | `weekly ->
              7 * 24
          | `monthly ->
              30 * 24
        in
        let value =
          let open Ptime in
          (* A quiescent period (1 day) plus a random hour within a telemetry interval *)
          Span.of_int_s (3600 * 24)
          |> Span.add (Span.of_int_s (Random.int (interval_hours * 3600)))
          |> add_span (Ptime_clock.now ())
          |> Option.get
          |> Clock.Date.of_ptime
        in
        Helpers.call_api_functions ~__context (fun rpc session_id ->
            Client.Pool.set_telemetry_next_collection ~rpc ~session_id
              ~self:pool ~value
        )
      )
      ()

let update_pool_recommendations_noexn ~__context =
  Helpers.log_exn_continue "update pool recommendations"
    (fun () ->
      let pool = Helpers.get_pool ~__context in
      let recommendations =
        Recommendations.load ~path:!Xapi_globs.pool_recommendations_dir
        |> StringMap.bindings
      in
      Db.Pool.set_recommendations ~__context ~self:pool ~value:recommendations
    )
    ()

(* Update the database to reflect current state. Called for both start of day and after
   an agent restart. *)
let update_env __context =
  debug "creating root user" ;
  Create_misc.create_root_user ~__context ;
  debug "creating pool record" ;
  create_pool_record ~__context ;
  set_master_pool_reference ~__context ;
  set_master_ip ~__context ;
  set_master_live ~__context ;
  setup_telemetry ~__context ;
  (* CA-15449: when we restore from backup we end up with Hosts being forgotten and VMs
     marked as running with dangling resident_on references. We delete the control domains
     and reset the rest to Halted. *)
  reset_vms_running_on_missing_hosts ~__context ;
  (* Resets all Halted VMs to a known good state *)
  release_locks ~__context ;
  (* Cancel tasks that were running on the master - by setting host=None we consider all tasks
     in the db for cancelling *)
  Cancel_tasks.cancel_tasks_on_host ~__context ~host_opt:None ;
  (* Update the SM plugin table *)
  if !Xapi_globs.create_tools_sr then
    create_tools_sr_noexn __context ;
  ensure_vm_metrics_records_exist_noexn __context ;
  update_pool_recommendations_noexn ~__context
