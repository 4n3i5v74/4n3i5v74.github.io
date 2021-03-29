---
title: CheatSheet - TMUX
author: 4n3i5v74
date: 2021-01-05 00:00:00 +0530
categories: [CheatSheet, TMUX]
tags: [cheatsheet, tmux, pentest]
pin: true
---


Starting tmux
- `tmux`
  - bottom pane - left - `session name`
  - bottom pane - middle - `window name`
  - bottom pane - right - `hostname, time, date`

Prefix mode
- Enter prefix mode - `ctrl`+`b`
- Rename session - `enter-prefix-mode`+`shift`+`$`
- End tmux session - `enter-prefix-mode`+`d`

Prompt mode
- Enter prompt mode - `enter-prefix-mode`+`shift`+`:`
- Allows to enter commands without `tmux` prefix

Sessions
- Nested session - Start another `tmux` session
- List sessions - `tmux ls`
- Start new session detatched - `tmux new -s test1 -n window1 -d`
- Reattah detached session - `tmux a -t 0`
- Kill session - `tmux kill-session -t test1`
- Kill all sessions except `test1` - `tmux kill-session -t test1 -a`
- List sessions - `enter-prefix-mode`+`s`
- Move to next session - `enter-prefix-mode`+`)`
- Move to previous session - `enter-prefix-mode`+`(`

Windows
- New window - `enter-prefix-mode`+`c`
- Rename window - `enter-prefix-mode`+`,`
- Move pane to new window - `enter-prefix-mode`+`shift`+`!`
- Next window - `enter-prefix-mode`+`n`
- Previous window - `enter-prefix-mode`+`p`
- Select window - `enter-prefix-mode`+`w`
- Switch window - `enter-prefix-mode`+`[0-9]`
- Close window - `enter-prefix-mode`+`shift`+`&`
- Merge current window with horizontal pane - `enter-prompt-mode`+`join-pane -s <name_or_no> -h`
- Merge current window with horizontal pane - `enter-prefix-mode`+`join-pane -t <name_or_no> -v`

Panes
- Vertical split - `enter-prefix-mode`+`shift`+`"`
- Horizontal split - `enter-prefix-mode`+`shift`+`%`
- Move between panes - `enter-prefix-mode`+`arrow`
- Move between panes - `enter-prefix-mode`+`o`
- Move between recent panes - `enter-prefix-mode`+`;`
- Kill current pane - `enter-prefix-mode`+`x`
- Move pane clockwise - `enter-prefix-mode`+`shift`+`}`
- Move pane counter clockwise - `enter-prefix-mode`+`shift`+`{`
- Auto arrange panes - `enter-prefix-mode`+`esc`+`[1-5]`
- Cycle through arrangements - `enter-prefix-mode`+`space`
- Get current pane number - `enter-prefix-mode`+`q`
- Zoom pane - `enter-prefix-mode`+`z`
- Convert pane to window - `enter-prefix-mode`+`!`
- Resize pane height - `enter-prefix-mode`+`crtl`+`arrow`
- Swap panes - `enter-prompt-mode`+`swap-pane -s 0 -t 2`

Copy mode
- Enter copy mode - `enter-prefix-mode`+`[`
  - Move the cursor to position from where to copy
- Begin copy - `ctrl`+`space`
- Copy selected to clipboard - `alt`+`w`
- Go up - `g`
- Go down - `G`
- Start copying - `space`
- Copy selected to buffer - `enter`
- Preview copied content - `enter-prefix-mode`+`shift`+`#`
- Clear buffer - `q`
- Paste copied content - `enter-prefix-mode`+`]`

Search mode
- Search reverse - `enter-copy-mode`+`ctrl`+`r`
- Search forward - `enter-copy-mode`+`ctrl`+`s`
- Stop searching - `return`

Misc
- Config file - `.tmux.conf`
- Show current options - `tmux show -g`
- Reload config file - `enter-prompt-mode`+`source-file <file>`
- Start session with config - `tmux -f custom.tmux.conf`
- Enable command logging - `enter-prefix-mode`+`shift`+`P`
- Restore defaults - `tmux kill-server`
- Separate prefix key for remote server - `bind-key -n C-a send-prefix` in `.tmux.conf`

Plugins
- Tmux Resurrect
  - Default installation
    - `set -g @plugin 'tmux-plugins/tmux-resurrect'`
  - Manual installation
    - `git clone https://github.com/tmux-plugins/tmux-resurrect ~/clone/path`
    - `run-shell ~/clone/path/resurrect.tmux` in `.tmux.conf`
    - `tmux source-file ~/.tmux.conf`
  - Save - `enter-prefix-mode`+`ctrl`+`s`
  - Restore - `enter-prefix-mode`+`ctrl`+`r`
  - Save & Restore - `set -g @resurrect-capture-pane-contents 'on'` in `.tmux.conf`
  - Restore vim - `set -g @resurrect-strategy-vim 'session'` in `.tmux.conf`

