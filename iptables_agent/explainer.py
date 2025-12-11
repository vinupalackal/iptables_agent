"""
IPTables Rule Explainer Module

This module converts parsed iptables rules into human-readable explanations.
"""

import re
from typing import List
from .parser import IPTablesRule

# Constants for common address representations
ANY_ADDRESSES = ['0.0.0.0/0', 'anywhere', '']


class RuleExplainer:
    """Explains iptables rules in human-readable format"""
    
    def __init__(self):
        self.target_descriptions = {
            'ACCEPT': 'allow',
            'DROP': 'silently drop',
            'REJECT': 'reject and notify',
            'LOG': 'log',
            'MASQUERADE': 'masquerade (NAT)',
            'REDIRECT': 'redirect',
            'RETURN': 'return to calling chain',
            'SNAT': 'source NAT',
            'DNAT': 'destination NAT',
        }
        
        self.protocol_descriptions = {
            'tcp': 'TCP',
            'udp': 'UDP',
            'icmp': 'ICMP',
            'all': 'all protocols',
            '': 'any protocol',
        }
        
        self.chain_descriptions = {
            'INPUT': 'incoming traffic',
            'OUTPUT': 'outgoing traffic',
            'FORWARD': 'forwarded traffic',
            'PREROUTING': 'pre-routing traffic',
            'POSTROUTING': 'post-routing traffic',
        }
    
    def explain_rule(self, rule: IPTablesRule) -> str:
        """
        Generate a human-readable explanation for a single iptables rule
        
        Args:
            rule: IPTablesRule object to explain
            
        Returns:
            Human-readable explanation string
        """
        parts = []
        
        # Chain context
        chain_desc = self.chain_descriptions.get(rule.chain, f"chain {rule.chain}")
        parts.append(f"For {chain_desc}:")
        
        # Action
        action = self.target_descriptions.get(rule.target, rule.target.lower())
        
        # Build the condition description
        conditions = []
        
        # Protocol
        if rule.protocol:
            proto = self.protocol_descriptions.get(rule.protocol.lower(), rule.protocol.upper())
            conditions.append(f"{proto} traffic")
        else:
            conditions.append("all traffic")
        
        # Source
        if rule.source and rule.source not in ANY_ADDRESSES:
            conditions.append(f"from {rule.source}")
        
        # Source port
        if rule.source_port:
            conditions.append(f"from port {rule.source_port}")
        
        # Destination
        if rule.destination and rule.destination not in ANY_ADDRESSES:
            conditions.append(f"to {rule.destination}")
        
        # Destination port
        if rule.destination_port:
            conditions.append(f"to port {rule.destination_port}")
        
        # Input interface
        if rule.input_interface:
            conditions.append(f"on interface {rule.input_interface}")
        
        # Output interface
        if rule.output_interface:
            conditions.append(f"via interface {rule.output_interface}")
        
        # Connection state
        if rule.state:
            states = rule.state.replace(',', ', ')
            conditions.append(f"with state {states}")
        
        # Extra options
        if rule.extra_options:
            extra = ' '.join(rule.extra_options)
            if 'dpt:' in extra:
                # Extract destination port from extra options
                match = re.search(r'dpt:(\S+)', extra)
                if match and not rule.destination_port:
                    conditions.append(f"to port {match.group(1)}")
            elif 'spt:' in extra:
                # Extract source port from extra options
                match = re.search(r'spt:(\S+)', extra)
                if match and not rule.source_port:
                    conditions.append(f"from port {match.group(1)}")
        
        # Combine conditions
        if conditions:
            condition_str = " ".join(conditions)
            explanation = f"{parts[0]} {action} {condition_str}"
        else:
            explanation = f"{parts[0]} {action} all traffic"
        
        return explanation
    
    def explain_rules(self, rules: List[IPTablesRule]) -> List[str]:
        """
        Generate explanations for a list of iptables rules
        
        Args:
            rules: List of IPTablesRule objects
            
        Returns:
            List of human-readable explanation strings
        """
        return [self.explain_rule(rule) for rule in rules]
    
    def explain_rules_formatted(self, rules: List[IPTablesRule]) -> str:
        """
        Generate formatted explanations for a list of iptables rules
        
        Args:
            rules: List of IPTablesRule objects
            
        Returns:
            Formatted string with numbered explanations
        """
        explanations = []
        for i, rule in enumerate(rules, 1):
            explanation = self.explain_rule(rule)
            explanations.append(f"{i}. {explanation}")
        
        return "\n".join(explanations)
