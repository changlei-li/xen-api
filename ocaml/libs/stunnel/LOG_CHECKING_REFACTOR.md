# Stunnel Log Checking Refactor - Discussion

## Current Problems

### 1. Inconsistent Error Handling ⚠️ **Requires Backward Compatibility**

**Current State:**
```ocaml
(* Old API - exception-based *)
let diagnose_failure st_proc =
  match Stunnel_log.check_errors ~logfile:st_proc.logfile () with
  | Ok () -> ()
  | Error e -> raise (exception from e)

(* New API - Result-based *)
let wait_for ... = 
  | Error err -> Error err
```

**Problem:** Mixed paradigms force conversion layers and make error handling unpredictable.

**Proposed Solution:**
- Keep `diagnose_failure` with exceptions for **backward compatibility**
- Add new Result-based alternatives with different names
- Mark exception-based functions as deprecated

```ocaml
(* Old - keep for compatibility *)
val diagnose_failure : t -> unit
  [@@deprecated "Use diagnose_failure_result instead"]

(* New - Result-based *)
val diagnose_failure_result : t -> (unit, stunnel_error) result

(* Or provide both interfaces *)
val diagnose : t -> (unit, stunnel_error) result
val diagnose_exn : t -> unit  (* Raises exceptions *)
```

**Migration Path:**
1. Phase 1: Add Result-based alternatives alongside existing functions
2. Phase 2: Update internal code to use Result-based versions
3. Phase 3: (Optional) Remove deprecated exception-based functions in next major version

---

### 2. Inefficient Rescanning

**Current State:**
```ocaml
let wait_for_init_done unix_socket_path logfile =
  let rec check cnt =
    Thread.delay 1.0 ;
    (* Re-scans from beginning each time! *)
    match Stunnel_log.scan ~logfile patterns with
    ...
```

**Problem:** 
- Each iteration re-reads the entire log file
- No position tracking outside UnixSocketProxy
- Wasted I/O and CPU

**Discussion Points:**

**Option A: Stateful Watcher Object**
```ocaml
type log_watcher = {
  logfile: string;
  mutable position: int;
}

let create_watcher logfile = { logfile; position = 0 }

let check watcher patterns =
  (* Automatically tracks position *)
  let result, new_pos = scan ~start_pos:watcher.position ~logfile patterns in
  watcher.position <- new_pos;
  result
```
- ✅ Simple API
- ✅ Automatic position tracking
- ❌ Mutable state
- ❌ Not thread-safe

**Option B: Functional State Threading**
```ocaml
type log_state = {
  logfile: string;
  position: int;
}

let init logfile = { logfile; position = 0 }

let check state patterns =
  let result, new_pos = scan ~start_pos:state.position ~logfile patterns in
  let new_state = { state with position = new_pos } in
  (result, new_state)

(* Usage *)
let rec wait state patterns =
  let result, state' = check state patterns in
  match result with
  | Ok (`Success _) -> Ok ()
  | Ok `Not_found -> wait state' patterns
  | Error e -> Error e
```
- ✅ Pure functional
- ✅ Thread-safe
- ✅ Explicit state flow
- ❌ More verbose
- ❌ Caller must thread state

**Option C: Implicit Position in scan**
```ocaml
(* scan function maintains internal cache/state per logfile *)
val scan : ?logfile:string -> ... -> result

(* Internally maintains: *)
(* let position_cache : (string, int) Hashtbl.t = Hashtbl.create 10 *)
```
- ✅ Transparent to caller
- ❌ Hidden global state
- ❌ Memory leak potential
- ❌ Not composable

**Recommendation:** Start with **Option A** (stateful watcher) for `wait_for` functions since they're already imperative (Thread.delay). Add **Option B** (functional) for library functions that need to be pure.

**⚠️ CRITICAL: Incomplete Line Handling**

When tracking file position, there's a **serious bug risk** with line-based scanning:

```
Log file at scan time 1:
Position 0: "Configuration starting\n"
Position 28: "Connecting to server"    <- FILE ENDS HERE (no \n yet!)
             position = 48 saved

[stunnel continues writing...]

Log file at scan time 2:
Position 0: "Configuration starting\n"
Position 28: "Connecting to server...\n"
Position 52: "Configuration successful\n"

If we resume from position 48, we read: "r...\n"
First "line" is GARBAGE: "r...\n" - we started mid-line!
```

**The Problem:** If stunnel is actively writing logs, we might save a position that's **mid-line** (no newline yet). Next scan starts mid-line and produces corrupted data.

**Solution: Only Track Position After Complete Lines**

```ocaml
type log_watcher = {
  logfile: string;
  mutable position: int;  (* Always points AFTER last complete line *)
}

let scan watcher patterns =
  let ic = open_in watcher.logfile in
  seek_in ic watcher.position;
  
  let rec scan_lines () =
    let pos_before = pos_in ic in
    try
      (* input_line raises End_of_file if no \n found *)
      let line = input_line ic in
      let pos_after = pos_in ic in  (* Position AFTER the \n *)
      
      match check_patterns line patterns with
      | Some result -> 
          (* Update position only after complete line processed *)
          watcher.position <- pos_after;
          Some result
      | None ->
          (* No match - update position and continue *)
          watcher.position <- pos_after;
          scan_lines ()
    with End_of_file ->
      (* Hit EOF or incomplete line - DON'T update position *)
      (* Next scan will re-read from last complete line *)
      None
  in
  
  scan_lines ()
```

**Why This Works:**
- OCaml's `input_line` only succeeds for **complete lines** (ending with `\n`)
- If file ends mid-line, `End_of_file` is raised → position NOT updated
- Next scan starts from last known complete line
- When stunnel finishes writing the line (adds `\n`), we read it completely
- **Trade-off:** Might re-scan the last line if file ended exactly at `\n`, but this is rare and harmless

**Alternative Approaches Considered:**

1. **Buffer incomplete lines** - Complex state management, edge cases with very long lines
2. **Rewind to line boundary** - Requires backward scanning, inefficient
3. **Check for trailing newline** - Extra I/O operations

**Decision:** Track position after complete lines only (simplest and safest).

---

### 3. Arbitrary Timeouts

**Current State:**
```ocaml
wait_for ~delay:1.0 ~max_retries:3 ...
(* Actual timeout = 1.0 * 3 = ~3 seconds - implicit! *)
```

**Problem:**
- Total timeout is `delay * max_retries` - not obvious
- Can't distinguish "retry interval" from "total timeout"
- Hard to reason about timing

**Discussion Points:**

**Option A: Explicit Timeout Duration**
```ocaml
wait_for ~timeout:3.0 ~check_interval:1.0 ~logfile patterns

(* Implementation *)
let wait_for ~timeout ~check_interval ~logfile patterns =
  let deadline = Unix.gettimeofday () +. timeout in
  let rec check () =
    if Unix.gettimeofday () > deadline then
      Error (Stunnel "Timeout waiting for pattern")
    else
      match scan ~logfile patterns with
      | Ok (`Success x) -> Ok x
      | Ok `Not_found -> 
          Thread.delay check_interval;
          check ()
      | Error e -> Error e
  in check ()
```
- ✅ Clear semantics
- ✅ Actual wall-clock timeout
- ✅ Decouples timeout from check interval
- ❌ Breaking change to API

**Option B: Keep Both Parameters**
```ocaml
wait_for ~timeout:3.0 ~delay:1.0 ~logfile patterns
(* timeout is max duration, delay is between checks *)
```
- ✅ Most flexible
- ❌ More parameters
- ⚠️ Need to validate timeout >= delay

**Option C: Smart Defaults**
```ocaml
wait_for ?timeout ?delay ~logfile patterns

(* Default: timeout = 30s, delay = 0.5s *)
```
- ✅ Simpler common case
- ✅ Still configurable
- ❌ Magic numbers

**Recommendation:** **Option A** with reasonable defaults. Can add backward-compatible wrapper:

```ocaml
(* New preferred API *)
val wait_for : timeout:float -> check_interval:float -> ... -> result

(* Old API - backward compatible *)
val wait_for_retries : delay:float -> max_retries:int -> ... -> result
  [@@deprecated "Use wait_for with timeout instead"]
```

---

### 4. Pattern Duplication

**Current State:**
```ocaml
let wait_for_init_done unix_socket_path logfile =
  let patterns = [
    configuration_successful; configuration_failed;
    connection_refused; no_host_resolved; ...
  ] in ...

let wait_for_connection_done logfile =
  let patterns = [
    certificate_accepted; rejected_by_cert;
    connection_refused; no_host_resolved; ...  (* DUPLICATED *)
  ] in ...
```

**Problem:**
- Error patterns repeated everywhere
- Changes require updating multiple locations
- No single source of truth

**Discussion Points:**

**Option A: Named Pattern Groups**
```ocaml
module PatternGroups = struct
  (* Common error patterns *)
  let common_errors = [
    connection_refused
  ; no_host_resolved
  ; no_route_to_host
  ; invalid_argument
  ; address_in_use
  ]
  
  (* Certificate-related *)
  let cert_errors = [
    certificate_verify_failed
  ; rejected_by_cert
  ]
  
  (* Success patterns *)
  let init_success = [configuration_successful]
  let connection_success = [certificate_accepted; connected_remote_server]
  
  (* Combined *)
  let init_patterns = init_success @ common_errors
  let connection_patterns = connection_success @ cert_errors @ common_errors
end

let wait_for_init_done socket logfile =
  wait_for ~logfile PatternGroups.init_patterns
```
- ✅ Single source of truth
- ✅ Composable
- ✅ Self-documenting
- ❌ Need to maintain pattern groups

**Option B: Pattern Categories**
```ocaml
type pattern_category = 
  | InitSuccess
  | ConnectionSuccess
  | CommonError
  | CertError

let patterns_for_categories categories =
  List.concat_map (function
    | InitSuccess -> [configuration_successful]
    | ConnectionSuccess -> [certificate_accepted; connected_remote_server]
    | CommonError -> [connection_refused; no_host_resolved; ...]
    | CertError -> [certificate_verify_failed; rejected_by_cert]
  ) categories

let wait_for_init_done socket logfile =
  let patterns = patterns_for_categories [InitSuccess; CommonError] in
  wait_for ~logfile patterns
```
- ✅ Explicit categorization
- ✅ Type-safe
- ❌ More complex
- ❌ Extra indirection

**Recommendation:** **Option A** (named pattern groups) - simpler and sufficient.

---

### 5. Mixed Success/Error Patterns

**Current State:**
```ocaml
patterns = [
  configuration_successful  (* Success! *)
; configuration_failed      (* Error *)
; connection_refused        (* Error *)
]

(* How do we know which is which? Only by Result type *)
match scan patterns with
| Ok (`Success _) -> (* Was success pattern *)
| Error _ -> (* Was error pattern *)
```

**Problem:**
- Success and error patterns in same list
- Can't distinguish "waiting" from "success" from "error"
- Ambiguous when `Not_found`

**Discussion Points:**

**Option A: Separate Pattern Lists**
```ocaml
let wait_for_init_done socket logfile =
  let success_patterns = [configuration_successful] in
  let error_patterns = [
    configuration_failed; connection_refused; no_host_resolved
  ] in
  wait_for_either ~logfile ~success_patterns ~error_patterns

(* Returns *)
type wait_result =
  | Success of string  (* Which success pattern matched *)
  | Failed of stunnel_error  (* Which error pattern matched *)
  | Timeout  (* Neither matched in time *)
```
- ✅ Clear intent
- ✅ Explicit success vs error
- ✅ Better timeout handling
- ❌ More complex API
- ❌ Need to scan twice (or combine internally)

**Option B: Tagged Patterns**
```ocaml
type 'a pattern_type =
  | Success of 'a pattern
  | Error of 'a pattern

let wait_for_init_done socket logfile =
  let patterns = [
    Success configuration_successful;
    Error configuration_failed;
    Error connection_refused;
  ] in
  wait_for_tagged ~logfile patterns
```
- ✅ Single list with explicit tags
- ✅ Type-safe
- ❌ Changes pattern type
- ❌ More verbose

**Option C: Keep Current, Improve Documentation**
```ocaml
(* Just document the pattern's meaning in its definition *)
let configuration_successful = 
  { text = "Configuration successful"
  ; result = Success "ok"  (* Success marker *)
  ; match_type = Match
  }
```
- ✅ No API changes
- ✅ Simple
- ❌ Still ambiguous
- ❌ Relies on convention

**Recommendation:** **Option A** (separate lists) for wait functions - makes intent crystal clear and enables better timeout semantics.

---

### 6. No Cancellation

**Current State:**
```ocaml
let rec check cnt =
  Thread.delay 1.0 ;  (* BLOCKING - can't cancel *)
  match scan ~logfile patterns with
  ...
```

**Problem:**
- `Thread.delay` blocks completely
- No way to interrupt/cancel wait
- If conditions change, can't abort early

**Discussion Points:**

**Option A: Interruptible Sleep**
```ocaml
let rec check ~cancel deadline interval =
  if !cancel then Error (Stunnel "Cancelled")
  else if Unix.gettimeofday () > deadline then Error (Stunnel "Timeout")
  else (
    Thread.delay interval;
    if !cancel then Error (Stunnel "Cancelled")
    else match scan ~logfile patterns with ...
  )

(* Usage *)
let cancel_flag = ref false in
let result = wait_for ~cancel:cancel_flag ... in
(* In another thread: cancel_flag := true *)
```
- ✅ Simple cancellation
- ✅ Minimal changes
- ❌ Polling cancel flag
- ❌ Still blocks during Thread.delay

**Option B: Lwt/Async**
```ocaml
let rec check () =
  let%lwt () = Lwt_unix.sleep interval in
  match%lwt scan ~logfile patterns with
  | Ok (`Success x) -> Lwt.return (Ok x)
  | Ok `Not_found -> check ()
  | Error e -> Lwt.return (Error e)

(* Cancellable *)
Lwt.pick [
  wait_for ...;
  cancel_promise
]
```
- ✅ Proper async
- ✅ Composable cancellation
- ✅ Better concurrency
- ❌ **Major dependency** (Lwt/Async)
- ❌ Changes entire architecture

**Option C: Accept Current Limitation**
- Document that wait functions are blocking
- Suggest running in separate thread if needed
- Keep implementation simple

**Recommendation:** **Option C** for now - cancellation is rarely needed for stunnel startup. Can revisit if it becomes a problem. Document the blocking behavior clearly.

---

### 7. Stateless Scanning

**Current State:**
```ocaml
(* Most functions don't track position *)
Stunnel_log.scan ~logfile patterns

(* Only UnixSocketProxy.diagnose tracks it *)
type t = { ...; mutable last_checked_position: int }
```

**Problem:**
- Position tracking is opt-in
- Most callers don't use it
- Inefficient for repeated scans

**Discussion Points:**

This overlaps with **Issue #2** (Inefficient Rescanning). The solution depends on the state management approach chosen there.

If we go with **stateful watcher** (Issue #2, Option A):
```ocaml
(* All wait functions use watcher *)
let wait_for_init_done socket logfile =
  let watcher = Watcher.create logfile in
  wait_for watcher patterns
```

If we go with **functional state** (Issue #2, Option B):
```ocaml
(* State threaded explicitly *)
let wait_for_init_done socket logfile =
  let state = LogState.init logfile in
  wait_for state patterns
```

**Recommendation:** Align with Issue #2 decision.

---

## Implementation Strategy

### Phase 1: Non-Breaking Improvements
1. ✅ Add `PatternGroups` module (Issue #4)
2. ✅ Add position-tracking watcher for internal use (Issue #2)
3. ✅ Add explicit timeout API alongside existing (Issue #3)
4. ✅ Add Result-based alternatives to exception functions (Issue #1)
5. ✅ Improve documentation

### Phase 2: Internal Refactoring
1. Update `wait_for*` functions to use watcher internally
2. Update to use new timeout API internally
3. Update to use pattern groups
4. Add deprecation warnings to old APIs

### Phase 3: API Evolution (Optional - Next Major Version)
1. Remove deprecated exception-based functions
2. Change default APIs to new versions
3. Consider separate success/error patterns (Issue #5)

---

## Questions for Discussion

1. **State Management (Issue #2):** Stateful watcher vs functional state threading?
2. **Timeout API (Issue #3):** Explicit timeout duration vs retry count?
3. **Pattern Organization (Issue #4):** Named groups vs categories vs current?
4. **Success/Error Split (Issue #5):** Separate pattern lists worth the complexity?
5. **Cancellation (Issue #6):** Need it? If so, how important?
6. **Backward Compatibility:** How long to maintain old APIs?

---

## Next Steps

1. **Decide on approach** for each issue
2. **Prototype** key changes (state management, timeout API)
3. **Review** with team
4. **Implement** Phase 1 (non-breaking)
5. **Test** thoroughly
6. **Document** migration path
7. **Roll out** Phase 2 internally
8. **Plan** Phase 3 timeline

---

## Notes

- Priority: **Backward compatibility** - don't break existing callers
- Focus on **internal improvements** first
- New APIs can coexist with old ones
- Deprecation warnings help migration
- Documentation is critical
