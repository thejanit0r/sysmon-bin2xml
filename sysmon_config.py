# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class SysmonConfig(KaitaiStruct):

    class RuleRelation(Enum):
        r_or = 0
        r_and = 1

    class RuleOnMatch(Enum):
        om_exclude = 0
        om_include = 1

    class Condition(Enum):
        c_is = 0
        c_is_not = 1
        c_contains = 2
        c_contains_any = 3
        c_is_any = 4
        c_contains_all = 5
        c_excludes = 6
        c_excludes_any = 7
        c_excludes_all = 8
        c_begin_with = 9
        c_end_with = 10
        c_less_than = 11
        c_more_than = 12
        c_image = 13
        c_not_begin_with = 14
        c_not_end_with = 15

    class EventType(Enum):
        et_process_create = 1
        et_file_create_time = 2
        et_network_connect = 3
        et_service_state_change = 4
        et_process_terminate = 5
        et_driver_load = 6
        et_image_load = 7
        et_create_remote_thread = 8
        et_raw_access_read = 9
        et_process_access = 10
        et_file_create = 11
        et_registry_event = 12
        et_registry_event_set_value = 13
        et_registry_event_name = 14
        et_file_create_stream_hash = 15
        et_sysmon_configuration_change = 16
        et_pipe_event_create = 17
        et_pipe_event_connect = 18
        et_wmi_event_filter = 19
        et_wmi_event_consumer = 20
        et_wmi_event_consumer_to_filter = 21
        et_dns_query = 22
        et_file_delete = 23
        et_clipboard_change = 24
        et_process_tampering = 25
        et_file_delete_detected = 26
        et_file_block_executable = 27
        et_file_block_shredding = 28
        et_file_executable_detected = 29

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = SysmonConfig.Header(self._io, self, self._root)

    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.unknown_1 = self._io.read_u2le()
            self.binary_version = self._io.read_u2le()
            self.rule_group_count = self._io.read_u4le()
            self.rule_group_first_ofs = self._io.read_u4le()
            self.config_schema_minor = self._io.read_u2le()
            self.config_schema_major = self._io.read_u2le()
            self.unknown_2 = self._io.read_u4le()
            self.rule_first_ofs = self._io.read_u4le()

        @property
        def rule_group_first(self):
            if hasattr(self, '_m_rule_group_first'):
                return self._m_rule_group_first

            io = self._root._io
            _pos = io.pos()
            io.seek(self.rule_group_first_ofs)
            self._m_rule_group_first = SysmonConfig.RuleGroup(io, self, self._root)
            io.seek(_pos)
            return getattr(self, '_m_rule_group_first', None)

        @property
        def rule_first(self):
            if hasattr(self, '_m_rule_first'):
                return self._m_rule_first

            io = self._root._io
            _pos = io.pos()
            io.seek(self.rule_first_ofs)
            self._m_rule_first = SysmonConfig.Rule(io, self, self._root)
            io.seek(_pos)
            return getattr(self, '_m_rule_first', None)


    class RuleGroup(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.event_type = KaitaiStream.resolve_enum(SysmonConfig.EventType, self._io.read_u4le())
            self.on_match = KaitaiStream.resolve_enum(SysmonConfig.RuleOnMatch, self._io.read_u4le())
            self.relation = KaitaiStream.resolve_enum(SysmonConfig.RuleRelation, self._io.read_u4le())
            self.next_ofs = self._io.read_u4le()
            self.field_count = self._io.read_u4le()
            self.field_first_ofs = self._io.read_u4le()

        @property
        def next(self):
            if hasattr(self, '_m_next'):
                return self._m_next

            if self.next_ofs != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.next_ofs)
                self._m_next = SysmonConfig.RuleGroup(io, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_next', None)

        @property
        def field_first(self):
            if hasattr(self, '_m_field_first'):
                return self._m_field_first

            if self.field_first_ofs != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.field_first_ofs)
                self._m_field_first = SysmonConfig.Field(io, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_field_first', None)


    class Rule(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = (self._io.read_bytes(264)).decode(u"UTF-16")
            self.id = self._io.read_u4le()
            self.field_first_ofs = self._io.read_u4le()
            self.next_ofs = self._io.read_u4le()
            self.field_count = self._io.read_u4le()
            self.relation = KaitaiStream.resolve_enum(SysmonConfig.RuleRelation, self._io.read_u4le())
            self.unknown_1 = self._io.read_bytes(12)

        @property
        def next(self):
            if hasattr(self, '_m_next'):
                return self._m_next

            if self.next_ofs != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.next_ofs)
                self._m_next = SysmonConfig.Rule(io, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_next', None)

        @property
        def field_first(self):
            if hasattr(self, '_m_field_first'):
                return self._m_field_first

            io = self._root._io
            _pos = io.pos()
            io.seek(self.field_first_ofs)
            self._m_field_first = SysmonConfig.Field(io, self, self._root)
            io.seek(_pos)
            return getattr(self, '_m_field_first', None)


    class Field(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id = self._io.read_u4le()
            self.name = (self._io.read_bytes(256)).decode(u"UTF-16")
            self.unknown_1 = self._io.read_bytes(256)
            self.condition = KaitaiStream.resolve_enum(SysmonConfig.Condition, self._io.read_u4le())
            self.next_ofs = self._io.read_u4le()
            self.value_len = self._io.read_u4le()
            self.rule_id = self._io.read_u4le()
            self.rule_ofs = self._io.read_u4le()
            self.value = (self._io.read_bytes(self.value_len)).decode(u"UTF-16")

        @property
        def next(self):
            if hasattr(self, '_m_next'):
                return self._m_next

            if self.next_ofs != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.next_ofs)
                self._m_next = SysmonConfig.Field(io, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_next', None)

        @property
        def rule(self):
            if hasattr(self, '_m_rule'):
                return self._m_rule

            if self.rule_ofs != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.rule_ofs)
                self._m_rule = SysmonConfig.Rule(io, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_rule', None)



