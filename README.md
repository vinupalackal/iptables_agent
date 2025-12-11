# IPTables Agent

An automatic agent to explain iptables rules in human-readable format. This tool helps system administrators and developers understand their firewall rules by converting technical iptables syntax into clear, natural language explanations.

## Features

- 🔍 **Parse iptables rules** from system, files, or strings
- 📝 **Human-readable explanations** of complex firewall rules
- 🎯 **Filter rules** by chain (INPUT, OUTPUT, FORWARD) or target (ACCEPT, DROP, REJECT)
- 📊 **Multiple output formats**: text and JSON
- 🐍 **Pure Python**: No external dependencies
- 🔧 **CLI and library**: Use as a command-line tool or import into your Python code

## Installation

### From source

```bash
git clone https://github.com/vinupalackal/iptables_agent.git
cd iptables_agent
pip install -e .
```

### Using pip (when published)

```bash
pip install iptables-agent
```

## Quick Start

### Command Line Usage

Fetch and explain rules from your system (requires sudo):

```bash
sudo iptables-agent
```

Explain rules from a file:

```bash
iptables-agent --file /path/to/iptables-save.txt
```

Filter by chain:

```bash
iptables-agent --file rules.txt --chain INPUT
```

Output as JSON:

```bash
iptables-agent --file rules.txt --format json
```

### Library Usage

```python
from iptables_agent import IPTablesAgent

# Create an agent
agent = IPTablesAgent()

# Load rules from a file
agent.load_rules_from_file('iptables-rules.txt')

# Or load from string
rules_text = """
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
"""
agent.load_rules_from_string(rules_text)

# Get explanations
explanations = agent.explain_all_rules_formatted()
print(explanations)

# Filter rules
input_rules = agent.filter_rules_by_chain('INPUT')
for rule in input_rules:
    print(agent.explain_rule(rule))
```

## How It Works

The IPTables Agent consists of three main components:

1. **Parser** (`parser.py`): Parses iptables output from both `iptables -L` and `iptables-save` formats into structured Python objects.

2. **Explainer** (`explainer.py`): Converts parsed rules into human-readable explanations by interpreting:
   - Chain names (INPUT, OUTPUT, FORWARD, etc.)
   - Target actions (ACCEPT, DROP, REJECT, etc.)
   - Protocols (TCP, UDP, ICMP, etc.)
   - Source and destination IPs/ports
   - Network interfaces
   - Connection states

3. **Agent** (`agent.py`): Main interface that ties together parsing and explanation, with methods to:
   - Fetch rules from the system
   - Load rules from files or strings
   - Filter rules by various criteria
   - Generate explanations

## Example Output

Given this iptables rule:
```
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
```

The agent explains it as:
```
For incoming traffic: allow TCP traffic to port 22 with state NEW
```

## Supported Features

- ✅ All standard iptables chains (INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING)
- ✅ Common targets (ACCEPT, DROP, REJECT, LOG, MASQUERADE, REDIRECT, etc.)
- ✅ Protocol specifications (TCP, UDP, ICMP, etc.)
- ✅ Source/destination IPs and networks
- ✅ Port specifications (--sport, --dport)
- ✅ Network interfaces (-i, -o)
- ✅ Connection state matching
- ✅ Both iptables-save and iptables -L formats

## CLI Options

```
usage: iptables-agent [-h] [--file FILE] [--chain CHAIN] [--target TARGET]
                      [--format {text,json}] [--version]

Options:
  -h, --help            Show help message
  --file, -f FILE       Read rules from file instead of system
  --chain, -c CHAIN     Filter by chain (INPUT, OUTPUT, FORWARD, etc.)
  --target, -t TARGET   Filter by target (ACCEPT, DROP, REJECT, etc.)
  --format {text,json}  Output format (default: text)
  --version, -v         Show version
```

## Examples

See `example.py` for a comprehensive demonstration of the library's capabilities:

```bash
python example.py
```

## Requirements

- Python 3.7 or higher
- No external dependencies (uses only Python standard library)
- For fetching system rules: Linux system with iptables installed

## Development

### Running Tests

Tests can be added in a `tests/` directory following standard Python testing practices.

### Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - see LICENSE file for details

## Use Cases

- 📚 **Learning**: Understand how iptables rules work
- 🔍 **Auditing**: Review firewall configurations
- 📖 **Documentation**: Generate human-readable firewall documentation
- 🐛 **Debugging**: Troubleshoot connectivity issues
- 🤖 **Automation**: Integrate into monitoring and reporting tools

## Roadmap

Future enhancements may include:

- Support for more advanced iptables features
- Integration with other firewall systems (nftables, ufw)
- Web interface for visualization
- Rule optimization suggestions
- Security best practice recommendations

## Support

For issues, questions, or contributions, please visit:
https://github.com/vinupalackal/iptables_agent