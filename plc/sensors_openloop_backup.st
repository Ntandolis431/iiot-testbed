PROGRAM prog0
  VAR_EXTERNAL
    blinker : BOOL;
    temp    : INT;
    press   : INT;
    flow    : INT;
    level   : INT;
  END_VAR
  VAR
    T1   : TON;
    T2   : TON;
    tick : INT := 0;
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

  (* --- Temperature: 20.0-30.0 C (x10), triangle wave --- *)
  IF tick < 500 THEN
    temp := 200 + tick / 5;
  ELSE
    temp := 200 + (1000 - tick) / 5;
  END_IF;

  (* --- Pressure: 1000-1199 mbar, sawtooth --- *)
  press := 1000 + tick / 5;

  (* --- Flow: 0-499 L/min, faster sawtooth --- *)
  flow := (tick * 3) MOD 500;

  (* --- Level: 0-1000 mm, slow triangle --- *)
  IF tick < 500 THEN
    level := tick * 2;
  ELSE
    level := (1000 - tick) * 2;
  END_IF;

END_PROGRAM

CONFIGURATION Config0

  VAR_GLOBAL
    blinker AT %QX0.0 : BOOL;
    temp    AT %QW0   : INT;
    press   AT %QW1   : INT;
    flow    AT %QW2   : INT;
    level   AT %QW3   : INT;
  END_VAR

  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
