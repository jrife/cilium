<!-- This file was autogenerated via cilium-dbg cmdref, do not edit manually-->

## cilium-dbg completion

Output shell completion code

```
cilium-dbg completion [shell] [flags]
```

### Examples

```

# Installing bash completion
## Load the cilium completion code for bash into the current shell
	source <(cilium-dbg completion bash)
## Write bash completion code to a file and source if from .bash_profile
	cilium-dbg completion bash > ~/.cilium/completion.bash.inc
	printf "
	  # Cilium shell completion
	  source '$HOME/.cilium/completion.bash.inc'
	  " >> $HOME/.bash_profile
	source $HOME/.bash_profile


# Installing zsh completion
## Load the cilium completion code for zsh into the current shell
	source <(cilium-dbg completion zsh)
## Write zsh completion code to a file and source if from .zshrc
	cilium-dbg completion zsh > ~/.cilium/completion.zsh.inc
	printf "
	  # Cilium shell completion
	  source '$HOME/.cilium/completion.zsh.inc'
	  " >> $HOME/.zshrc
	source $HOME/.zshrc

# Installing fish completion
## Write fish completion code to fish specific location
	cilium-dbg completion fish > ~/.config/fish/completions/cilium.fish

```

### Options

```
  -h, --help   help for completion
```

### Options inherited from parent commands

```
      --config string   Config file (default is $HOME/.cilium.yaml)
  -D, --debug           Enable debug messages
  -H, --host string     URI to server-side API
```

### SEE ALSO

* [cilium-dbg](cilium-dbg.md)	 - CLI

