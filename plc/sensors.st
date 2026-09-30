PROGRAM prog0
  VAR_EXTERNAL
    blinker  : BOOL;
    temp     : INT;
    press    : INT;
    flow     : INT;
    level    : INT;
    setpoint : INT;
  END_VAR
  VAR
    T1   : TON;
    T2   : TON;
    tick : INT := 0;
    err  : INT;
    init : BOOL := FALSE;
  END_VAR

  (* --- Blink coil: toggles Modbus coil 0 every 1s (link test) --- *)
  T1(IN := NOT T2.Q, PT := T#1s);
  T2(IN := T1.Q,     PT := T#1s);
  blinker := T1.Q;

  (* --- Free-running counter 0..999, +1 per 50ms scan => 50s cycle --- *)
  tick := tick + 1;
  IF tick >= 1000 THEN
    tick := 0;
  END_IF;

  (* --- Open-loop process signals (unchanged): temp/press/flow --- *)
  (* Temperature: 20.0-30.0 C (x10), triangle wave *)
  IF tick < 500 THEN
    temp := 200 + tick / 5;
  ELSE
    temp := 200 + (1000 - tick) / 5;
  END_IF;
  (* Pressure: 1000-1199 mbar, sawtooth *)
  press := 1000 + tick / 5;
  (* Flow: 0-499 L/min, faster sawtooth *)
  flow := (tick * 3) MOD 500;

  (* ======================================================================
     CLOSED-LOOP TANK LEVEL  (the process an insider can physically harm)
     ----------------------------------------------------------------------
     'setpoint' is holding register %QW10. The SCADA master WRITES it over
     Modbus; this program only READS it (after the one-shot init below), so a
     Modbus write persists and acts as the operator setpoint. 'level' (%QW3)
     tracks the setpoint through a first-order lag -- a simple stand-in for a
     level controller driving a pump.

     A legitimate operator moves the setpoint gently within [100,800] mm, so
     'level' stays well inside the safety band. An INSIDER can issue a valid
     Modbus write of ANY value (e.g. 1500): protocol-correct, but it drives the
     tank past its 900 mm high-level trip toward the 1200 mm brim. Nothing on
     the network distinguishes this from a normal setpoint change -- only the
     PHYSICAL consequence (level leaving its safe envelope) reveals it.
     ====================================================================== *)
  IF NOT init THEN
    setpoint := 400;     (* sane startup setpoint; written once *)
    level    := 400;
    init     := TRUE;
  END_IF;

  err   := setpoint - level;
  level := level + err / 20;   (* first-order approach: a big setpoint jump => a fast level rise *)

  (* physical clamp: tank cannot go below 0 or above the 1200 mm brim *)
  IF level < 0 THEN
    level := 0;
  END_IF;
  IF level > 1200 THEN
    level := 1200;
  END_IF;

END_PROGRAM

CONFIGURATION Config0

  VAR_GLOBAL
    blinker  AT %QX0.0 : BOOL;
    temp     AT %QW0   : INT;
    press    AT %QW1   : INT;
    flow     AT %QW2   : INT;
    level    AT %QW3   : INT;
    setpoint AT %QW10  : INT;
  END_VAR

  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
