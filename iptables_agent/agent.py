"""
IPTables Agent Module

Main interface for the iptables explanation agent.
"""

import subprocess
import sys
from typing import List, Optional
from .parser import IPTablesParser, IPTablesRule
from .explainer import RuleExplainer


class IPTablesAgent:
    """Main agent for fetching and explaining iptables rules"""
    
    def __init__(self):
        self.parser = IPTablesParser()
        self.explainer = RuleExplainer()
        self.rules = []
    
    def fetch_rules_from_system(self) -> bool:
        """
        Fetch iptables rules from the current system
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Try iptables-save first (more detailed)
            result = subprocess.run(
                ['iptables-save'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                self.rules = self.parser.parse_iptables_output(result.stdout)
                return True
            
            # Fallback to iptables -L
            result = subprocess.run(
                ['iptables', '-L', '-n', '-v'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.rules = self.parser.parse_iptables_output(result.stdout)
                return True
            
            return False
        
        except subprocess.TimeoutExpired:
            print("Error: Command timed out", file=sys.stderr)
            return False
        except FileNotFoundError:
            print("Error: iptables command not found. Are you on a Linux system with iptables installed?", file=sys.stderr)
            return False
        except PermissionError:
            print("Error: Permission denied. Try running with sudo.", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error fetching rules: {e}", file=sys.stderr)
            return False
    
    def load_rules_from_string(self, rules_text: str) -> List[IPTablesRule]:
        """
        Load and parse iptables rules from a string
        
        Args:
            rules_text: Raw iptables output as string
            
        Returns:
            List of parsed IPTablesRule objects
        """
        self.rules = self.parser.parse_iptables_output(rules_text)
        return self.rules
    
    def load_rules_from_file(self, filepath: str) -> List[IPTablesRule]:
        """
        Load and parse iptables rules from a file
        
        Args:
            filepath: Path to file containing iptables output
            
        Returns:
            List of parsed IPTablesRule objects
        """
        try:
            with open(filepath, 'r') as f:
                rules_text = f.read()
            return self.load_rules_from_string(rules_text)
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            return []
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return []
    
    def get_rules(self) -> List[IPTablesRule]:
        """Get the currently loaded rules"""
        return self.rules
    
    def explain_all_rules(self) -> List[str]:
        """
        Get explanations for all loaded rules
        
        Returns:
            List of explanation strings
        """
        return self.explainer.explain_rules(self.rules)
    
    def explain_all_rules_formatted(self) -> str:
        """
        Get formatted explanations for all loaded rules
        
        Returns:
            Formatted string with all explanations
        """
        return self.explainer.explain_rules_formatted(self.rules)
    
    def explain_rule(self, rule: IPTablesRule) -> str:
        """
        Get explanation for a single rule
        
        Args:
            rule: IPTablesRule object to explain
            
        Returns:
            Explanation string
        """
        return self.explainer.explain_rule(rule)
    
    def filter_rules_by_chain(self, chain: str) -> List[IPTablesRule]:
        """
        Filter rules by chain name
        
        Args:
            chain: Chain name (e.g., 'INPUT', 'OUTPUT', 'FORWARD')
            
        Returns:
            List of filtered rules
        """
        return [rule for rule in self.rules if rule.chain.upper() == chain.upper()]
    
    def filter_rules_by_target(self, target: str) -> List[IPTablesRule]:
        """
        Filter rules by target action
        
        Args:
            target: Target action (e.g., 'ACCEPT', 'DROP', 'REJECT')
            
        Returns:
            List of filtered rules
        """
        return [rule for rule in self.rules if rule.target.upper() == target.upper()]
