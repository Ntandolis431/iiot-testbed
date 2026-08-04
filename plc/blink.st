PROGRAM prog0
  VAR_EXTERNAL
    blinker : BOOL;
  END_VAR
  VAR
    T1 : TON;
    T2 : TON;
  END_VAR

  T1(IN := NOT T2.Q, PT := T#1s);
  T2(IN := T1.Q,     PT := T#1s);
  blinker := T1.Q;
END_PROGRAM

CONFIGURATION Config0

  VAR_GLOBAL
    blinker AT %QX0.0 : BOOL;
  END_VAR

  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
