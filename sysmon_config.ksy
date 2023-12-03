meta:
  id: sysmon_config
  title: Sysmon binary configuration file format
  endian: le
  tags:
    - sysmon
    - sysinternals
    - windows
seq:
  - id: header
    type: header
types:
  header:
    seq:
      - id: unknown_1
        type: u2
      - id: binary_version
        type: u2
      - id: rule_group_count
        type: u4
      - id: rule_group_first_ofs
        type: u4
      - id: config_schema_minor
        type: u2
      - id: config_schema_major
        type: u2
      - id: unknown_2
        type: u4
      - id: rule_first_ofs
        type: u4
    instances:
      rule_group_first:
        io: _root._io
        pos: rule_group_first_ofs
        type: rule_group
      rule_first:
        io: _root._io
        pos: rule_first_ofs
        type: rule
  rule_group:
    seq:
      - id: event_type
        type: u4
        enum: event_type
      - id: on_match
        type: u4
        enum: rule_on_match
      - id: relation
        type: u4
        enum: rule_relation
      - id: next_ofs
        type: u4
      - id: field_count
        type: u4
      - id: field_first_ofs
        type: u4
    instances:
      next:
        io: _root._io
        pos: next_ofs
        type: rule_group
        if: next_ofs != 0
      field_first:
        io: _root._io
        pos: field_first_ofs
        type: field
        if: field_first_ofs != 0
  rule:
    seq:
      - id: name
        type: str
        size: 264
        encoding: UTF-16
      - id: id
        type: u4
      - id: field_first_ofs
        type: u4
      - id: next_ofs
        type: u4
      - id: field_count
        type: u4
      - id: relation
        type: u4
        enum: rule_relation
      - id: unknown_1
        size: 12
    instances:
      next:
        io: _root._io
        pos: next_ofs
        type: rule
        if: next_ofs != 0
      field_first:
        io: _root._io
        pos: field_first_ofs
        type: field
  field:
    seq:
      - id: id
        type: u4
      - id: name
        type: str
        size: 256
        encoding: UTF-16
      - id: unknown_1
        size: 256
      - id: condition
        type: u4
        enum: condition
      - id: next_ofs
        type: u4
      - id: value_len
        type: u4
      - id: rule_id
        type: u4
      - id: rule_ofs
        type: u4
      - id: value
        type: str
        size: value_len
        encoding: UTF-16
    instances:
      next:
        io: _root._io
        pos: next_ofs
        type: field
        if: next_ofs != 0
      rule:
        io: _root._io
        pos: rule_ofs
        type: rule
        if: rule_ofs != 0
enums:
  rule_relation:
    0: r_or
    1: r_and
  rule_on_match:
    0: om_exclude
    1: om_include
  condition:
    0: c_is
    1: c_is_not
    2: c_contains
    3: c_contains_any
    4: c_is_any
    5: c_contains_all
    6: c_excludes
    7: c_excludes_any
    8: c_excludes_all
    9: c_begin_with
    10: c_end_with
    11: c_less_than
    12: c_more_than
    13: c_image
    14: c_not_begin_with
    15: c_not_end_with
  event_type:
    1: et_process_create
    2: et_file_create_time
    3: et_network_connect
    4: et_service_state_change
    5: et_process_terminate
    6: et_driver_load
    7: et_image_load
    8: et_create_remote_thread
    9: et_raw_access_read
    10: et_process_access
    11: et_file_create
    12: et_registry_event
    13: et_registry_event_set_value
    14: et_registry_event_name
    15: et_file_create_stream_hash
    16: et_sysmon_configuration_change
    17: et_pipe_event_create
    18: et_pipe_event_connect
    19: et_wmi_event_filter
    20: et_wmi_event_consumer
    21: et_wmi_event_consumer_to_filter
    22: et_dns_query
    23: et_file_delete
    24: et_clipboard_change
    25: et_process_tampering
    26: et_file_delete_detected
    27: et_file_block_executable
    28: et_file_block_shredding
	29: et_file_executable_detected
