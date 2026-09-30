##! modbus-memmap.zeek
##! Logs the register ADDRESS (and quantity) of every Modbus read/write request.
##! Zeek's default modbus.log records the function code but NOT the address, so
##! there is no way to tell an address-sweeping enumeration (unauthorized "read")
##! from ordinary polling. This script emits modbus_addr.log with one row per
##! request, which build_features.py aggregates into per-window address-coverage
##! features (mb_uniq_addr, mb_addr_span) -- the signal that separates a read
##! enumeration (many distinct addresses) from benign polling (a few fixed ones).
##!
##! Run offline on a saved capture:
##!   zeek -C -r capture.pcap modbus-memmap.zeek

@load base/protocols/modbus

module ModbusAddr;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:       time    &log;
        uid:      string  &log;
        orig_h:   addr    &log;
        func:     string  &log;
        address:  count   &log;
        quantity: count   &log;
    };
}

event zeek_init() {
    Log::create_stream(ModbusAddr::LOG, [$columns=Info, $path="modbus_addr"]);
}

function emit(c: connection, func: string, address: count, quantity: count) {
    Log::write(ModbusAddr::LOG, Info($ts = network_time(),
                                     $uid = c$uid,
                                     $orig_h = c$id$orig_h,
                                     $func = func,
                                     $address = address,
                                     $quantity = quantity));
}

# ---- read requests (the enumeration / scan signal) ------------------------
event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
                                start_address: count, quantity: count) {
    emit(c, "READ_COILS", start_address, quantity);
}
event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders,
                                          start_address: count, quantity: count) {
    emit(c, "READ_DISCRETE_INPUTS", start_address, quantity);
}
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders,
                                            start_address: count, quantity: count) {
    emit(c, "READ_HOLDING_REGISTERS", start_address, quantity);
}
event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders,
                                          start_address: count, quantity: count) {
    emit(c, "READ_INPUT_REGISTERS", start_address, quantity);
}

# ---- single-write requests (FC5/FC6) -- e.g. a setpoint write to one register.
#      Needed so an authenticated-insider setpoint write (FC6 to the actuator
#      register) is logged with its address and source, for attribution.
event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
                                       address: count, value: bool) {
    emit(c, "WRITE_SINGLE_COIL", address, 1);
}
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                           address: count, value: count) {
    emit(c, "WRITE_SINGLE_REGISTER", address, 1);
}

# ---- multi-write requests (write-coverage bonus) --------------------------
event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders,
                                          start_address: count, coils: ModbusCoils) {
    emit(c, "WRITE_MULTIPLE_COILS", start_address, |coils|);
}
event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                              start_address: count, registers: ModbusRegisters) {
    emit(c, "WRITE_MULTIPLE_REGISTERS", start_address, |registers|);
}
