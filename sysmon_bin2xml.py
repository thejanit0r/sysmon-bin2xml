#!/usr/bin/python3
"""
    Sysmon Bin2XML

    This utility converts SysInternals' Sysmon binary configuration blob to XML
        
    Default location for the configuration:

        - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\Rules

    Check revocation:

        - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\CheckRevocation

    Hashing algorithms:

        - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\HashingAlgorithm
            - 0x01 = SHA1
            - 0x02 = MD5
            - 0x03 = SHA256
            - 0x04 = IMPHASH

    Author: the_janitor
    
    License: Apache 2.0
"""

__version__ = "1.0"

import os
import io
import sys
import argparse
from sysmon_config import *

########################################################################################################################

Relations = [
    "or",
    "and"
]

OnMatch = [
    "exclude",
    "include"
]

Conditions = [
    "is",
    "is not", 
    "contains", 
    "contains any", 
    "is any", 
    "contains all", 
    "excludes", 
    "excludes any", 
    "excludes all",
    "begin with", 
    "end with", 
    "less than", 
    "more than", 
    "image", 
    "not begin with", 
    "not end with"
]

EventTypes = [
    "Error",
    "ProcessCreate",
    "FileCreateTime",
    "NetworkConnect",
    "ServiceStateChange",
    "ProcessTerminate",
    "DriverLoad",
    "ImageLoad",
    "CreateRemoteThread",
    "RawAccessRead",
    "ProcessAccess",
    "FileCreate",
    "RegistryEvent",
    "RegistryEvent",
    "RegistryEvent",
    "FileCreateStreamHash",
    "SysmonConfigurationChange",
    "PipeEvent",
    "PipeEvent",
    "WmiEvent",
    "WmiEvent",
    "WmiEvent",
    "DnsQuery",
    "FileDelete",
    "ClipboardChange",
    "ProcessTampering",
    "FileDeleteDetected",
    "FileBlockExecutable",
    "FileBlockShredding",
    "FileExecutableDetected"
]

Fields = [
    # Error
    [],
    # ProcessCreate
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "FileVersion",
        "Description",
        "Product",
        "Company",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "LogonGuid",
        "LogonId",
        "TerminalSessionId",
        "IntegrityLevel",
        "Hashes",
        "ParentProcessGuid",
        "ParentProcessId",
        "ParentImage",
        "ParentCommandLine",
        "ParentUser"
    ],
    # FileCreateTime
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetFilename",
        "CreationUtcTime",
        "PreviousCreationUtcTime",
        "User"
    ],
    # NetworkConnect
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "User",
        "Protocol",
        "Initiated",
        "SourceIsIpv6",
        "SourceIp",
        "SourceHostname",
        "SourcePort",
        "SourcePortName",
        "DestinationIsIpv6",
        "DestinationIp",
        "DestinationHostname",
        "DestinationPort",
        "DestinationPortName"
    ],
    # ServiceStateChange
    [
        "UtcTime",
        "State",
        "Version",
        "SchemaVersion"
    ],
    # ProcessTerminate
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "User"
    ],
    # DriverLoad
    [
        "RuleName",
        "UtcTime",
        "ImageLoaded",
        "Hashes",
        "Signed",
        "Signature",
        "SignatureStatus"
    ],
    # ImageLoad
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "ImageLoaded",
        "FileVersion",
        "Description",
        "Product",
        "Company",
        "OriginalFileName",
        "Hashes",
        "Signed",
        "Signature",
        "SignatureStatus",
        "User"
    ],
    # CreateRemoteThread
    [
        "RuleName",
        "UtcTime",
        "SourceProcessGuid",
        "SourceProcessId",
        "SourceImage",
        "TargetProcessGuid",
        "TargetProcessId",
        "TargetImage",
        "NewThreadId",
        "StartAddress",
        "StartModule",
        "StartFunction",
        "SourceUser",
        "TargetUser"
    ],
    # RawAccessRead
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "Device",
        "User"
    ],
    # ProcessAccess
    [
        "RuleName",
        "UtcTime",
        "SourceProcessGUID",
        "SourceProcessId",
        "SourceThreadId",
        "SourceImage",
        "TargetProcessGUID",
        "TargetProcessId",
        "TargetImage",
        "GrantedAccess",
        "CallTrace",
        "SourceUser",
        "TargetUser"
    ],
    # FileCreate
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetFilename",
        "CreationUtcTime",
        "User"
    ],
    # RegistryEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetObject",
        "User"
    ],
    # RegistryEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetObject",
        "Details",
        "User"
    ],
    # RegistryEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetObject",
        "NewName",
        "User"      
    ],
    # FileCreateStreamHash
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetFilename",
        "CreationUtcTime",
        "Hash",
        "Contents",
        "User"
    ],
    # SysmonConfigurationChange
    [
        "UtcTime",
        "Configuration",
        "ConfigurationFileHash"
    ],
    # PipeEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "PipeName",
        "Image",
        "User"
    ],
    # PipeEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "PipeName",
        "Image",
        "User"
    ],
    # WmiEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "Operation",
        "User",
        "EventNamespace",
        "Name",
        "Query"
    ],
    # WmiEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "Operation",
        "User",
        "Name",
        "Type",
        "Destination"
    ],
    # WmiEvent
    [
        "RuleName",
        "EventType",
        "UtcTime",
        "Operation",
        "User",
        "Consumer",
        "Filter"
    ],
    # DnsQuery
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "QueryName",
        "QueryStatus",
        "QueryResults",
        "Image",
        "User"
    ],
    # FileDelete
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "User",
        "Image",
        "TargetFilename",
        "Hashes",
        "IsExecutable",
        "Archived"
    ],
    # ClipboardChange
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "Session",
        "ClientInfo",
        "Hashes",
        "Archived",
        "User"
    ],
    # ProcessTampering
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "Type",
        "User"
    ],
    # FileDeleteDetected
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "User",
        "Image",
        "TargetFilename",
        "Hashes",
        "IsExecutable"
    ],
    # FileBlockExecutable
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "User",
        "Image",
        "TargetFilename",
        "Hashes"
    ],
    # FileBlockShredding
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "User",
        "Image",
        "TargetFilename",
        "Hashes",
        "IsExecutable"
    ],
    # FileExecutableDetected
    [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "User",
        "Image",
        "TargetFilename",
        "Hashes"
    ]
]

########################################################################################################################

def main():
    description = f"Sysmon Bin2XML {__version__} -- the_janitor"

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-i", "--input", type=str, required=True, help="Path to Sysmon's binary configuration file")
    parser.add_argument("-o", "--output", type=str, required=True, help="Path to the output XML configuration file")
    args = parser.parse_args()

    # Check if the file exists
    if not os.path.isfile(args.input):
        print(f"File '{args.input}' not found.")
        sys.exit()

    # Parse the binary
    config = SysmonConfig.from_file(args.input)

    schema_major = config.header.config_schema_major
    schema_minor = config.header.config_schema_minor

    print(description + "\n\n")
    print(f"Sysmon binary version: {config.header.binary_version}")
    print(f"Sysmon XML schema version: {schema_major}.{schema_minor}")

    with open(args.output, 'w') as fd:
        fd.write(f"<Sysmon schemaversion=\"{schema_major}.{schema_minor}\">\n")
        fd.write(f"<EventFiltering>\n")
        
        # Process rule groups
        rule_group = config.header.rule_group_first
        
        while rule_group is not None:
            rg_et_name = EventTypes[rule_group.event_type.value]
            rg_relation = Relations[rule_group.relation.value]
            rg_onmatch = OnMatch[rule_group.on_match.value]

            fd.write(f"\t<RuleGroup name=\"\" groupRelation=\"{rg_relation}\">\n")
            fd.write(f"\t\t<{rg_et_name} onmatch=\"{rg_onmatch}\">\n")
            
            # Process fields / rules
            field = rule_group.field_first
            field_curr_rule_id = 0
            
            while field is not None:
                field_et_name = Fields[rule_group.event_type.value][field.id]
                field_condition = Conditions[field.condition.value]
                field_name = field.name.rstrip('\x00')
                field_value = field.value.rstrip('\x00')
                
                # If the current field is part of a rule (begin)
                if field.rule_id != field_curr_rule_id:
                    field_curr_rule_id = field.rule_id
                    rule_relation = Relations[field.rule.relation.value]
                    rule_name = field.rule.name.rstrip('\x00')

                    fd.write(f"\t\t\t<Rule name=\"{rule_name}\" groupRelation=\"{rule_relation}\">\n")
                
                # If the current field is part of a rule
                if field.rule_id != 0:
                    # Rule names are propagated to field names on compilation
                    if field_name == field.rule.name.rstrip('\x00'):
                        field_name = ""

                    fd.write("\t")
                
                fd.write(f"\t\t\t<{field_et_name} name=\"{field_name}\" condition=\"{field_condition}\">" +
                    f"{field_value}" + 
                    f"</{field_et_name}>\n")
                
                # Terminate the rule block
                if (field.next is None and field_curr_rule_id != 0) or \
                    (field.next is not None and field.next.rule_id != field_curr_rule_id):
                    if field_curr_rule_id != 0:
                        field_curr_rule_id = 0

                        fd.write(f"\t\t\t</Rule>\n")
                
                # Get the next field
                field = field.next

            # Terminate the rule group block
            fd.write(f"\t\t</{rg_et_name}>\n")
            fd.write(f"\t</RuleGroup>\n")
            
            # Get the next rule group
            rule_group = rule_group.next

        fd.write(f"</EventFiltering>\n")
        fd.write(f"</Sysmon>\n")

if __name__ == "__main__":
    main()
