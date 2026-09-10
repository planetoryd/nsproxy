# Repository agent guidance

This file is the stable IDE-facing entry point for the hierarchical agentic note system in `agentic/`. It is intentionally a compact router: read this file, then load only the topic note that owns the current task. See `agentic/README.md` for the loading and maintenance policy.

The `agentic/` tree is deliberately decomposed from this file into smaller,
topic-routing-aware notes. Keep this file concise so IDEs can load dense,
contextual guidance with minimal repeated tokens.

## Topic routing

- Runtime commands and `sp` CLI usage: `agentic/sp-commands.md`
- Persistent state, config, namespaces, sandboxing, mounts, or process spawning: `agentic/runtime-state.md`
- Rootfs backing, bind-mount I/O, and persistence concerns: `agentic/concerns-rootfs.md`
- Unix sockets, daemon/service lifecycle, routing, diagnostics, reconnection, or the supervisor actor: `agentic/ipc-diagnostics.md`
- egui views, editors, widgets, styling, or compact removal controls: `agentic/ui.md`
- PTYs, external terminal windows, titles, or terminal key mappings: `agentic/terminal.md`

Load more than one note only when the owning code path genuinely crosses those boundaries. Keep durable discoveries in the narrowest topic note, and add a routing entry here when introducing a new topic branch.

## Global facts

- This project is a namespace-based container/runtime system.
- Persistent profile state is rooted at `/nsp3` by default and can be overridden per process with `state_paths::set_persist_root` or `Cli.root`.
- Prefer the owning abstraction and searchable symbols named in the routed note over broad repository exploration.

## Maintenance and workflow

- When adding or changing a durable convention, update the narrowest relevant note under `agentic/` and add or adjust its route here when needed.
- Keep routed notes factual, searchable, and focused on ownership, symbols, invariants, and validation commands. Do not duplicate the whole repository map in this file.
- After code edits, use `./build-ui.sh` (or `./build-ui.sh --release` when release behavior is relevant) as the standard build/check path.
- Make a local commit after completing a coherent change, using a simple descriptive commit message. Branching is allowed for draft work; local commits may be squashed before pushing.
- Commits should describe the project change and contain no agent or tool identity.
- UI controls with the same semantic role must share a renderer and visual states. Compact removal controls are borderless, fixed-size, icon-based, and hover-responsive; validation indicators are a separate shared status renderer and must also provide clear hover feedback.

## Editing convention

- Preserve existing source formatting in focused changes.
- Do not run broad `cargo fmt` or reformat unrelated files unless explicitly requested.
- Keep formatting and documentation changes limited to the implementation touched by the task.
- Validate with the narrowest relevant executable check.
