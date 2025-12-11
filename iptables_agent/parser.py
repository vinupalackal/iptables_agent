"""
IPTables Parser Module

This module parses iptables rules from command output and converts them
into structured Python objects for easier processing.
"""

import re
from typing import Dict, List, Optional


class IPTablesRule:
    """Represents a single iptables rule with all its properties"""
    
    def __init__(self):
        self.chain = ""
        self.target = ""
        self.protocol = ""
        self.source = ""
        self.destination = ""
        self.input_interface = ""
        self.output_interface = ""
        self.source_port = ""
        self.destination_port = ""
        self.state = ""
        self.extra_options = []
        self.raw_rule = ""
    
    def __repr__(self):
        return f"IPTablesRule(chain={self.chain}, target={self.target}, proto={self.protocol})"


class IPTablesParser:
    """Parser for iptables rules"""
    
    def __init__(self):
        self.rules = []
    
    def _is_size_value(self, part: str) -> bool:
        """Check if a part represents a numeric value with size suffixes"""
        return part.replace('K', '').replace('M', '').replace('G', '').isdigit()
    
    def parse_iptables_output(self, output: str) -> List[IPTablesRule]:
        """
        Parse the output from 'iptables -L -n -v' or 'iptables-save'
        
        Args:
            output: Raw iptables command output
            
        Returns:
            List of IPTablesRule objects
        """
        self.rules = []
        lines = output.strip().split('\n')
        current_chain = ""
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Detect chain headers
            if line.startswith('Chain'):
                match = re.match(r'Chain\s+(\S+)', line)
                if match:
                    current_chain = match.group(1)
                continue
            
            # Skip column headers
            if line.startswith('pkts') or line.startswith('target'):
                continue
            
            # Parse iptables-save format
            if line.startswith('-A'):
                rule = self._parse_save_format(line, current_chain)
                if rule:
                    self.rules.append(rule)
            # Parse iptables -L format
            elif current_chain and not line.startswith('*'):
                rule = self._parse_list_format(line, current_chain)
                if rule:
                    self.rules.append(rule)
        
        return self.rules
    
    def _parse_save_format(self, line: str, current_chain: str = "") -> Optional[IPTablesRule]:
        """Parse iptables-save format rules"""
        rule = IPTablesRule()
        rule.raw_rule = line
        
        parts = line.split()
        i = 0
        
        while i < len(parts):
            part = parts[i]
            
            if part == '-A' and i + 1 < len(parts):
                rule.chain = parts[i + 1]
                i += 2
            elif part == '-j' and i + 1 < len(parts):
                rule.target = parts[i + 1]
                i += 2
            elif part == '-p' and i + 1 < len(parts):
                rule.protocol = parts[i + 1]
                i += 2
            elif part == '-s' and i + 1 < len(parts):
                rule.source = parts[i + 1]
                i += 2
            elif part == '-d' and i + 1 < len(parts):
                rule.destination = parts[i + 1]
                i += 2
            elif part == '-i' and i + 1 < len(parts):
                rule.input_interface = parts[i + 1]
                i += 2
            elif part == '-o' and i + 1 < len(parts):
                rule.output_interface = parts[i + 1]
                i += 2
            elif part == '--sport' and i + 1 < len(parts):
                rule.source_port = parts[i + 1]
                i += 2
            elif part == '--dport' and i + 1 < len(parts):
                rule.destination_port = parts[i + 1]
                i += 2
            elif part == '-m' and i + 1 < len(parts):
                if i + 2 < len(parts) and parts[i + 1] == 'state':
                    if i + 3 < len(parts) and parts[i + 2] == '--state':
                        rule.state = parts[i + 3]
                        i += 4
                    else:
                        i += 2
                else:
                    rule.extra_options.append(f"{part} {parts[i + 1]}")
                    i += 2
            else:
                rule.extra_options.append(part)
                i += 1
        
        return rule if rule.chain else None
    
    def _parse_list_format(self, line: str, chain: str) -> Optional[IPTablesRule]:
        """Parse iptables -L -n -v format rules"""
        rule = IPTablesRule()
        rule.raw_rule = line
        rule.chain = chain
        
        # Split by whitespace
        parts = line.split()
        
        if len(parts) < 3:
            return None
        
        # Skip the packet/byte counters at the beginning
        # Format: pkts bytes target prot opt in out source destination
        try:
            # Find where target starts (first non-numeric field after initial counters)
            idx = 0
            # Skip packets
            if self._is_size_value(parts[idx]):
                idx += 1
            # Skip bytes
            if idx < len(parts) and self._is_size_value(parts[idx]):
                idx += 1
            
            if idx < len(parts):
                rule.target = parts[idx]
                idx += 1
            
            if idx < len(parts):
                rule.protocol = parts[idx] if parts[idx] != 'all' else ''
                idx += 1
            
            # Skip opt field
            if idx < len(parts):
                idx += 1
            
            if idx < len(parts):
                rule.input_interface = parts[idx] if parts[idx] not in ['*', 'any'] else ''
                idx += 1
            
            if idx < len(parts):
                rule.output_interface = parts[idx] if parts[idx] not in ['*', 'any'] else ''
                idx += 1
            
            if idx < len(parts):
                rule.source = parts[idx] if parts[idx] not in ['0.0.0.0/0', 'anywhere'] else ''
                idx += 1
            
            if idx < len(parts):
                rule.destination = parts[idx] if parts[idx] not in ['0.0.0.0/0', 'anywhere'] else ''
                idx += 1
            
            # Remaining parts are extra options
            if idx < len(parts):
                rule.extra_options = parts[idx:]
        
        except (IndexError, ValueError):
            return None
        
        return rule
