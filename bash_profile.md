# bash profile

Current version is for m1 macs.

https://gist.github.com/zachbrowne/8bc414c9f30192067831fafebd14255c

## pre req installs

```bash
# install brew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# upgrade bash
brew install bash

# change default shell
# may need to also change in system preferences: https://apple.stackexchange.com/a/400546
# also change bash binary path in vscode terminal settings
sudo chsh -s /opt/homebrew/bin/bash $(whoami) # m1

# bash and kubectl completion
# https://kubernetes.io/docs/tasks/tools/install-kubectl-macos/#optional-kubectl-configurations-and-plugins
brew install bash-completion@2

# upgrade git
brew install git
```

## .bash_profile

```bash
# brew
eval "$(/opt/homebrew/bin/brew shellenv)"

# load bash_source folder
if [ -d ~/.bash_source ]; then
    for file in ~/.bash_source/*; do
        . "$file"
    done
fi

# bash completion
[[ -r "/opt/homebrew/etc/profile.d/bash_completion.sh" ]] && . "/opt/homebrew/etc/profile.d/bash_completion.sh"

# git completion
[[ -r ~/.bash_scripts/git-completion.bash ]] && . ~/.bash_scripts/git-completion.bash
```

## scripts folder

Create/Add these to `~/.bash_scripts` folder

### git completion

```bash
curl https://raw.githubusercontent.com/git/git/master/contrib/completion/git-completion.bash -o ~/.bash_scripts/git-completion.bash
chmod u+x  ~/.bash_scripts/git-completion.bash
```

### .git-prompt.sh

https://anotheruiguy.gitbooks.io/gitforeveryone/content/auto/README.html

```bash
curl -o ~/.bash_scripts/.git-prompt.sh https://raw.githubusercontent.com/git/git/master/contrib/completion/git-prompt.sh
```

### tf-sort.sh

https://github.com/libre-devops/utils/blob/dev/scripts/terraform/tf-sort.sh

```bash
curl -o ~/.bash_scripts/tf-sort.sh https://raw.githubusercontent.com/libre-devops/utils/dev/scripts/terraform/tf-sort.sh

```

## source folder

Create/Add these files to `~/.bash_source` folder

### alias

```bash
# misc
alias bash_reload="exec bash -l"

# git
alias g_amend_commit="git commit --amend --no-edit"
alias g_amend_new="git add . $DEV_ENV_PATH; git commit --amend --no-edit; git push -f"
alias g_amend_staged="git commit --amend --no-edit; git push -f"
alias g_amend_updated="git add -u $DEV_ENV_PATH; git commit --amend --no-edit; git push -f"
alias g_commit_reuse="git commit --reuse-message=HEAD"
alias g_diff="git diff --name-only origin/master..."
alias g_log="git log --pretty=oneline --abbrev-commit"
alias g_rebase="git pull origin master --rebase"
alias g_stage_new="git add . $DEV_ENV_PATH"
alias g_stage_updated="git add -u $DEV_ENV_PATH"
alias g_new_dry="git add . $DEV_ENV_PATH -n"
alias g_stash="git stash save"

# vscode
alias code="/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code -r"

# rust
alias cargo_watch="cargo watch -c -x 'check --all-features --tests'"
alias clippy="cargo clippy -- --deny warnings --no-deps"
alias clippy_tests="cargo clippy --tests -- --deny warnings"

# terraform
alias terraform_fmt="terraform fmt -recursive"
alias terraform_sort_var="~/.bash_scripts/tf-sort.sh variables.tf variables.tf"
alias terraform_sort_var_new="~/.bash_scripts/tf-sort.sh variables.tf variables_sorted.tf"

# node
alias node16='export PATH="/usr/local/bin:/usr/local/opt/node@16/bin:$PATH"; node -v'
alias node14='export PATH="/usr/local/opt/node@14/bin:$PATH"; node -v'
```

### functions

```bash
#!/usr/bin/env bash

# git branch rename
g_rename_branch() {
  (
    set -e
    git branch -m $1 $2
    git push -u origin $2
    git push origin :$1
  )
}

# BK token
bk_read_token() {
  BUILDKITE_READ_API_TOKEN="$(
    CHAMBER_USE_PATHS=1 \
      CHAMBER_SECRET_BACKEND="S3-KMS" \
      CHAMBER_S3_BUCKET="stile-chamber-dev" \
      aws-vault exec dev -- chamber read -q deploy-stack buildkite_api_access_token_read_artifacts
  )"
  export BUILDKITE_READ_API_TOKEN
}

# BK find the commit for a given build number on BFP
bk_find_commit() {
bk_read_token
number="$1"
curl -Ss -H "Authorization: Bearer ${BUILDKITE_READ_API_TOKEN}" \
    "https://api.buildkite.com/v2/organizations/stile-education/pipelines/big-friendly-pipeline/builds/${number}" |
    jq -Mr .commit
}

# BK commit diff between two builds
bk_git_diff() {
build_number_1="$1"
build_number_2="$2"

commit_1=$(bk_find_commit "${build_number_1}")
commit_2=$(bk_find_commit "${build_number_2}")
open "https://github.com/StileEducation/dev-environment/compare/${commit_1}...${commit_2}"
}
```

### gitprompt

```bash
# load functions
source ~/.bash_scripts/.git-prompt.sh

# store colors
MAGENTA="\[\033[0;35m\]"
YELLOW="\[\033[01;33m\]"
BLUE="\[\033[00;34m\]"
LIGHT_GRAY="\[\033[0;37m\]"
CYAN="\[\033[0;36m\]"
GREEN="\[\033[00;32m\]"
RED="\[\033[0;31m\]"
VIOLET='\[\033[01;35m\]'
WHITE='\[\033[00;37m\]'
BLACK='\[\033[00;30m\]'

function color_my_prompt {
  local __user_and_host="$GREEN\u@\h"
  local __cur_location="$MAGENTA\W" # capital 'W': current directory, small 'w': full file path
  local __git_branch_color="$GREEN"
  local __prompt_tail="$VIOLET$"
  local __user_input_color="$WHITE"
  local __git_branch='$(__git_ps1)';

  # colour branch name depending on state
  if [[ "$(__git_ps1)" =~ "*" ]]; then     # if repository is dirty
      __git_branch_color="$RED"
  elif [[ "$(__git_ps1)" =~ "$" ]]; then   # if there is something stashed
      __git_branch_color="$YELLOW"
  elif [[ "$(__git_ps1)" =~ "%" ]]; then   # if there are only untracked files
      __git_branch_color="$LIGHT_GRAY"
  elif [[ "$(__git_ps1)" =~ "+" ]]; then   # if there are staged files
      __git_branch_color="$CYAN"
  fi

  # Build the PS1 (Prompt String)
  PS1="\D{%F %T} $__user_and_host $__cur_location$__git_branch_color$__git_branch $__prompt_tail$__user_input_color \n"
}

# configure PROMPT_COMMAND which is executed each time before PS1
export PROMPT_COMMAND=color_my_prompt

# if .git-prompt.sh exists, set options and execute it
if [ -f "/opt/homebrew/opt/bash-git-prompt/share/gitprompt.sh" ]; then
  __GIT_PROMPT_DIR="/opt/homebrew/opt/bash-git-prompt/share"
  GIT_PS1_SHOWDIRTYSTATE=true
  GIT_PS1_SHOWSTASHSTATE=true
  GIT_PS1_SHOWUNTRACKEDFILES=true
  GIT_PS1_SHOWUPSTREAM="auto"
  GIT_PS1_HIDE_IF_PWD_IGNORED=true
  GIT_PS1_SHOWCOLORHINTS=true
  source "/opt/homebrew/opt/bash-git-prompt/share/gitprompt.sh"
fi
```

### path_env

```bash
export PATH="$HOME/.local/bin:$PATH"

# psql
export PATH="/usr/local/opt/libpq/bin:$PATH"

# rust
export PATH="$HOME/.cargo:$PATH"

# openjdk
export PATH="/usr/local/opt/openjdk/bin:$PATH"

# mysql-client
export PATH="/usr/local/opt/mysql-client/bin:$PATH"
```

### shell_completion

```bash
# bash completion
export BASH_COMPLETION_COMPAT_DIR="/opt/homebrew/etc/bash_completion.d"
[[ -r "/opt/homebrew/etc/profile.d/bash_completion.sh" ]] && . "/opt/homebrew/etc/profile.d/bash_completion.sh"

# git completion
[[ -r ~/.bash_scripts/git-completion.bash ]] && . ~/.bash_scripts/git-completion.bash

# when pressing tab autocomplete, match regardless of case
set completion-ignore-case on

# use the text that has already been typed as the prefix for searching through
# commands (i.e. more intelligent Up/Down behaviour)
bind '"\e[B": history-search-forward'
bind '"\e[A": history-search-backward'

# list all matches in case multiple possible completions are possible
set show-all-if-ambiguous on
```

### vscode_prettier

```bash
function vscode_prettier (
cd ~/node_modules
npm uninstall prettier @prettier/plugin-ruby
npm install --save-dev prettier @prettier/plugin-ruby@2.1.0
)

function ruby_prettier (
  current_dir=$PWD
  cd ~ &&  ./node_modules/.bin/prettier --write "$current_dir/*.rb" "$current_dir/Rakefile"
)
```

# \_archive

This is the intel mac version.

## pre req installs

```bash
# upgrade bash
brew install bash

# bash and kubectl completion
# https://kubernetes.io/docs/tasks/tools/included/optional-kubectl-configs-bash-mac/
brew install bash-completion@2

# upgrade git
brew install git
```

## .bash_profile

```bash
# load bash_source folder
if [ -d ~/.bash_source ]; then
    for file in ~/.bash_source/*; do
        . "$file"
    done
fi

# rbenv
eval "$(rbenv init - bash)"

# bash completion
export BASH_COMPLETION_COMPAT_DIR="/usr/local/etc/bash_completion.d"
[[ -r "/usr/local/etc/profile.d/bash_completion.sh" ]] && . "/usr/local/etc/profile.d/bash_completion.sh"

# kubectl completion
source <(kubectl completion bash)

# nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
. "$HOME/.cargo/env"

# rust
. "$HOME/.cargo/env"

```

## scripts folder

Add these to `~/.bash_scripts` folder

### tf-sort.sh

https://github.com/libre-devops/utils/blob/dev/scripts/terraform/tf-sort.sh

## source folder

Add these to `~/.bash_source` folder

### alias

```bash
# misc
alias bash_reload="exec bash -l"

# git
alias g_amend_commit="git commit --amend --no-edit"
alias g_amend_new="git add . $DEV_ENV_PATH; git commit --amend --no-edit; git push -f"
alias g_amend_staged="git commit --amend --no-edit; git push -f"
alias g_amend_updated="git add -u $DEV_ENV_PATH; git commit --amend --no-edit; git push -f"
alias g_commit_reuse="git commit --reuse-message=HEAD"
alias g_diff="git diff --name-only origin/master..."
alias g_log="git log --pretty=oneline --abbrev-commit"
alias g_rebase="git pull origin master --rebase"
alias g_stage_new="git add . $DEV_ENV_PATH"
alias g_stage_updated="git add -u $DEV_ENV_PATH"
alias g_new_dry="git add . $DEV_ENV_PATH -n"
alias g_stash="git stash save"

# vscode
alias code="/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code -r"

# rust
alias cargo_watch="cargo watch -c -x 'check --all-features --tests'"
alias clippy="cargo clippy -- --deny warnings --no-deps"
alias clippy_tests="cargo clippy --tests -- --deny warnings"

# terraform
alias terraform_fmt="terraform fmt -recursive"
alias terraform_sort_var="~/.bash_scripts/tf-sort.sh variables.tf variables.tf"
alias terraform_sort_var_new="~/.bash_scripts/tf-sort.sh variables.tf variables_sorted.tf"

# node
alias node16='export PATH="/usr/local/bin:/usr/local/opt/node@16/bin:$PATH"; node -v'
alias node14='export PATH="/usr/local/opt/node@14/bin:$PATH"; node -v'
```

### functions

```bash
#!/bin/sh

# git branch rename
g_rename_branch() {
  (
    set -e
    git branch -m $1 $2
    git push -u origin $2
    git push origin :$1
  )
}

# BK token
bk_read_token() {
  BUILDKITE_READ_API_TOKEN="$(
    CHAMBER_USE_PATHS=1 \
      CHAMBER_SECRET_BACKEND="S3-KMS" \
      CHAMBER_S3_BUCKET="stile-chamber-dev" \
      aws-vault exec dev -- chamber read -q deploy-stack buildkite_api_access_token_read_artifacts
  )"
  export BUILDKITE_READ_API_TOKEN
}

# BK find the commit for a given build number on BFP
bk_find_commit() {
bk_read_token
number="$1"
curl -Ss -H "Authorization: Bearer ${BUILDKITE_READ_API_TOKEN}" \
    "https://api.buildkite.com/v2/organizations/stile-education/pipelines/big-friendly-pipeline/builds/${number}" |
    jq -Mr .commit
}

# BK commit diff between two builds
bk_git_diff() {
build_number_1="$1"
build_number_2="$2"

commit_1=$(bk_find_commit "${build_number_1}")
commit_2=$(bk_find_commit "${build_number_2}")
open "https://github.com/StileEducation/dev-environment/compare/${commit_1}...${commit_2}"
}
```

### gitprompt

```bash
# store colors
MAGENTA="\[\033[0;35m\]"
YELLOW="\[\033[01;33m\]"
BLUE="\[\033[00;34m\]"
LIGHT_GRAY="\[\033[0;37m\]"
CYAN="\[\033[0;36m\]"
GREEN="\[\033[00;32m\]"
RED="\[\033[0;31m\]"
VIOLET='\[\033[01;35m\]'
WHITE='\[\033[00;37m\]'
BLACK='\[\033[00;30m\]'

function color_my_prompt {
  local __user_and_host="$GREEN\u@\h"
  local __cur_location="$MAGENTA\W" # capital 'W': current directory, small 'w': full file path
  local __git_branch_color="$GREEN"
  local __prompt_tail="$VIOLET$"
  local __user_input_color="$WHITE"
  local __git_branch='$(__git_ps1)';

  # colour branch name depending on state
  if [[ "$(__git_ps1)" =~ "*" ]]; then     # if repository is dirty
      __git_branch_color="$RED"
  elif [[ "$(__git_ps1)" =~ "$" ]]; then   # if there is something stashed
      __git_branch_color="$YELLOW"
  elif [[ "$(__git_ps1)" =~ "%" ]]; then   # if there are only untracked files
      __git_branch_color="$LIGHT_GRAY"
  elif [[ "$(__git_ps1)" =~ "+" ]]; then   # if there are staged files
      __git_branch_color="$CYAN"
  fi

  # Build the PS1 (Prompt String)
  PS1="\D{%F %T} $__user_and_host $__cur_location$__git_branch_color$__git_branch $__prompt_tail$__user_input_color \n"
}

# configure PROMPT_COMMAND which is executed each time before PS1
export PROMPT_COMMAND=color_my_prompt

# if .git-prompt.sh exists, set options and execute it
if [ -f $(brew --prefix)/etc/bash_completion.d/git-prompt.sh ]; then
  GIT_PS1_SHOWDIRTYSTATE=true
  GIT_PS1_SHOWSTASHSTATE=true
  GIT_PS1_SHOWUNTRACKEDFILES=true
  GIT_PS1_SHOWUPSTREAM="auto"
  GIT_PS1_HIDE_IF_PWD_IGNORED=true
  GIT_PS1_SHOWCOLORHINTS=true
  . $(brew --prefix)/etc/bash_completion.d/git-prompt.sh
fi
```

### path_env

```bash
export PATH="$HOME/.local/bin:$PATH"

# psql
export PATH="/usr/local/opt/libpq/bin:$PATH"

# rust
export PATH="$HOME/.cargo:$PATH"

# openjdk
export PATH="/usr/local/opt/openjdk/bin:$PATH"

# mysql-client
export PATH="/usr/local/opt/mysql-client/bin:$PATH"
```

### vscode_prettier

```bash
function vscode_prettier (
cd ~/node_modules
npm uninstall prettier @prettier/plugin-ruby
npm install --save-dev prettier @prettier/plugin-ruby@2.1.0
)

function ruby_prettier (
  current_dir=$PWD
  cd ~ &&  ./node_modules/.bin/prettier --write "$current_dir/*.rb" "$current_dir/Rakefile"
)
```
