# Claude Code instructions

Follow [`AGENTS.md`](./AGENTS.md) as the authoritative repository development guide.

When changing public APIs, inspect real downstream usage before editing, keep the shared-library boundary free of service-specific models, and run the complete required check set. Do not claim compatibility from compilation of this repository alone: record which downstream commits were tested.
