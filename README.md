# GraphQL Hunter

> Firefox extension for GraphQL attack-surface discovery and security analysis.

GraphQL Hunter is an offensive-security focused Firefox extension designed to help security researchers discover and analyze GraphQL APIs while browsing web applications.

## Planned Features

- GraphQL traffic detection
- GraphQL operation parsing
- API surface discovery
- Schema reconstruction
- Security-sensitive operation detection
- Object-reference detection
- Query complexity analysis
- Authorization testing
- Response comparison
- Finding and evidence management

## Project Status

🚧 Work in progress

This project is currently under active development.

## Architecture

```text
Firefox
   ↓
Traffic Collector
   ↓
GraphQL Detector
   ↓
GraphQL Parser
   ↓
API / Schema Model
   ↓
Security Analysis
   ↓
Authorization Testing
   ↓
Findings Dashboard
