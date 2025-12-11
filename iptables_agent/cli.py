#!/usr/bin/env python3
"""
IPTables Agent CLI

Command-line interface for the iptables explanation agent.
"""

import argparse
import sys
import json
from .agent import IPTablesAgent


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='IPTables Agent - Explain iptables rules in human-readable format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch and explain rules from the system (requires sudo)
  sudo iptables-agent
  
  # Explain rules from a file
  iptables-agent --file /path/to/iptables-save.txt
  
  # Filter by chain
  iptables-agent --file rules.txt --chain INPUT
  
  # Output as JSON
  iptables-agent --file rules.txt --format json
"""
    )
    
    parser.add_argument(
        '--file', '-f',
        help='Read iptables rules from a file instead of the system',
        metavar='FILE'
    )
    
    parser.add_argument(
        '--chain', '-c',
        help='Filter rules by chain (INPUT, OUTPUT, FORWARD, etc.)',
        metavar='CHAIN'
    )
    
    parser.add_argument(
        '--target', '-t',
        help='Filter rules by target action (ACCEPT, DROP, REJECT, etc.)',
        metavar='TARGET'
    )
    
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='IPTables Agent 0.1.0'
    )
    
    args = parser.parse_args()
    
    # Create agent
    agent = IPTablesAgent()
    
    # Load rules
    if args.file:
        rules = agent.load_rules_from_file(args.file)
        if not rules:
            print("No rules found or error reading file", file=sys.stderr)
            return 1
    else:
        success = agent.fetch_rules_from_system()
        if not success:
            print("Failed to fetch rules from system. Try running with sudo or use --file option.", file=sys.stderr)
            return 1
        rules = agent.get_rules()
    
    # Apply filters
    if args.chain:
        rules = agent.filter_rules_by_chain(args.chain)
        if not rules:
            print(f"No rules found for chain: {args.chain}", file=sys.stderr)
            return 0
    
    if args.target:
        rules = agent.filter_rules_by_target(args.target)
        if not rules:
            print(f"No rules found for target: {args.target}", file=sys.stderr)
            return 0
    
    # Output results
    if args.format == 'json':
        output_json(agent, rules)
    else:
        output_text(agent, rules)
    
    return 0


def output_text(agent, rules):
    """Output explanations in text format"""
    if not rules:
        print("No iptables rules found.")
        return
    
    print(f"Found {len(rules)} iptables rule(s):\n")
    print("=" * 80)
    
    for i, rule in enumerate(rules, 1):
        explanation = agent.explain_rule(rule)
        print(f"\nRule {i}:")
        print(f"  {explanation}")
        print(f"  Raw: {rule.raw_rule}")
    
    print("\n" + "=" * 80)


def output_json(agent, rules):
    """Output explanations in JSON format"""
    output = []
    
    for rule in rules:
        rule_data = {
            'chain': rule.chain,
            'target': rule.target,
            'protocol': rule.protocol,
            'source': rule.source,
            'destination': rule.destination,
            'input_interface': rule.input_interface,
            'output_interface': rule.output_interface,
            'source_port': rule.source_port,
            'destination_port': rule.destination_port,
            'state': rule.state,
            'extra_options': rule.extra_options,
            'raw_rule': rule.raw_rule,
            'explanation': agent.explain_rule(rule)
        }
        output.append(rule_data)
    
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    sys.exit(main())
