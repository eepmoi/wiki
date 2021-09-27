# \_todo

codebuild

# \_references

https://github.com/cloudposse/terraform-root-modules

# alpaca

https://github.com/samuong/alpaca

```bash
cat ~/Library/LaunchAgents/com.samuong.alpaca.plist
vi ~/Library/LaunchAgents/com.samuong.alpaca.plist
launchctl load ~/Library/LaunchAgents/com.samuong.alpaca.plist
launchctl unload ~/Library/LaunchAgents/com.samuong.alpaca.plist

ps -ef | grep alpaca
```

Setup Chrome icon - here are the steps:

- Open `Automator` - use spotlight search
- Choose `Application` type
- Go `Library` -> `Utilities` -> `Run Shell Script`
- Drag `Run Shell Script` to window on right hand side.
- Change Shell to `/bin/bash`
- Paste script

```bash
#!/bin/sh
open -a "Google Chrome" --args --proxy-server=localhost:3128
```

- Save, and it will now appear as an icon under `Applications` in Finder. Can create alias for desktop.

Derived from this: https://apple.stackexchange.com/questions/115114/how-to-put-a-custom-launcher-in-the-dock-mavericks

- To change icon, follow instructions here: https://discussions.apple.com/thread/5749045

## upgrade alpaca

```bash
cd ~/go/src/github.com/samuong/alpaca; git pull origin master; go build .; mv alpaca ../../../../bin cd ~/go/src/github.com/samuong/alpaca; git checkout master; go build ./...
```

# aws

## cloudwatch insights

```bash
fields @timestamp, @logStream, @message
| sort @timestamp
| filter @logStream like /(?i)(abcd-1234)/
#    and @message like /(?i)(xyzabc)/
# | limit 500
```

## ec2

```bash
# get ami id
curl http://169.254.169.254/latest/meta-data/ami-id; echo "";
```

## s3

```bash
# copy folder contents
aws s3 cp --recursive ~/source/ s3://bucket/
aws s3 cp --recursive s3://bucket/ ~/source/

```

## ssm

```bash
# jq to get ssm parameter value
aws ssm get-parameter --name "/core/v2/portfolio_facts" | jq -r '.Parameter.Value' | jq '.environment'
```

# bash

## \_my .bash_profile

```bash
# my bash_exec
export PATH="/Users/tanga/.bash_exec:$PATH"

# source bash_functions
if [ -d ~/.bash_functions ]; then
    for file in ~/.bash_functions/*; do
        . "$file"
    done
fi

# alpaca
export http_proxy=localhost:3128
export https_proxy=localhost:3128
export PATH="$HOME/go/bin:$PATH"
pgrep -q alpaca || nohup ~/go/bin/alpaca -d global -C http://proxy.com/gblproxy.pac &>/dev/null &

# aliases
alias alpaca_on="launchctl load ~/Library/LaunchAgents/com.samuong.alpaca.plist"
alias alpaca_off="launchctl unload ~/Library/LaunchAgents/com.samuong.alpaca.plist"

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
  local __cur_location="$MAGENTA\W"           # capital 'W': current directory, small 'w': full file path
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
#  PS1="$__user_and_host $__cur_location$__git_branch_color$__git_branch $__prompt_tail$__user_input_color "
  PS1="\D{%F %T} $__user_and_host $__cur_location$__git_branch_color$__git_branch $__prompt_tail$__user_input_color \n"
}

# configure PROMPT_COMMAND which is executed each time before PS1
export PROMPT_COMMAND=color_my_prompt

# if .git-prompt.sh exists, set options and execute it
if [ -f ~/.git-prompt.sh ]; then
  GIT_PS1_SHOWDIRTYSTATE=true
  GIT_PS1_SHOWSTASHSTATE=true
  GIT_PS1_SHOWUNTRACKEDFILES=true
  GIT_PS1_SHOWUPSTREAM="auto"
  GIT_PS1_HIDE_IF_PWD_IGNORED=true
  GIT_PS1_SHOWCOLORHINTS=true
  . ~/.git-prompt.sh
fi

test -e "${HOME}/.iterm2_shell_integration.bash" && source "${HOME}/.iterm2_shell_integration.bash"

# gcloud
source '/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/path.bash.inc'
source '/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/completion.bash.inc'

# kubectl completion support
source <(kubectl completion bash)
if [ -f $(brew --prefix)/etc/bash_completion ]; then
. $(brew --prefix)/etc/bash_completion
fi
```

## arrays and looping

https://www.shell-tips.com/bash/arrays/#array-operations

https://stackoverflow.com/questions/8880603/loop-through-an-array-of-strings-in-bash#comment110320649_8880633

```bash
myDemoArray=(1 2 3 4 5)
for value in "${myDemoArray[*]}"; do echo "$value"; done # double quotes are important, see output below.
for value in ${myDemoArray[*]}; do echo "$value"; done
for value in "${myDemoArray[@]}"; do echo "$value"; done
for value in ${myDemoArray[@]}; do echo "$value"; done

# different syntaxes with respective outputs on macos
for value in "${myDemoArray[*]}"; do echo "$value"; done
1 2 3 4 5

for value in ${myDemoArray[*]}; do echo "$value"; done
1
2
3
4
5

for value in ${myDemoArray[@]}; do echo "$value"; done
1
2
3
4
5

for value in "${myDemoArray[@]}"; do echo "$value"; done
1
2
3
4
5
```

## commands visible in ps

- shell builtin commands `don't` show up in ps (eg echo)
- handy for knowing which ones do show (eg sed with passwords)
- use type to find out

```bash
type echo
echo is a shell builtin

type cat
cat is /bin/cat

# use printf and sed while hiding variables from ps
SEDSCRIPT="$TF_BUILD_DIR/sedscript"
printf "%s\n" "s/_TFE_HOSTNAME/$TFE_HOSTNAME/g" "s/_TFE_TOKEN/$TFE_TOKEN/g" > "$SEDSCRIPT"
sed -f "$SEDSCRIPT" "$TF_CLI_CONFIG_FILE" > "$TF_BUILD_DIR/temp" && mv "$TF_BUILD_DIR/temp" "$TF_CLI_CONFIG_FILE"
```

## compare files in two folders

https://www.macworld.com/article/189460/termfoldercomp.html

```bash
# quick
diff -rq cluster/twistlock-defender/prod cluster/twistlock-defender/twistlock-defender_np

# line by line diff
diff -r cluster/twistlock-defender/prod cluster/twistlock-defender/twistlock-defender_np

# two files showing control chars
diff file1 file2 | cat -t
```

## copying hidden (dot) files

Issue is they are not matched by \*, and also behaviour is different with MacOS and Linux

https://jondavidjohn.com/linux-vs-osx-the-cp-command/

Solution is to turn on shell option dotglob and "/\*" to match

https://superuser.com/questions/61611/how-to-copy-with-cp-to-include-hidden-files-and-hidden-directories-and-their-con

```bash
echo "before:" environments/nonprod/*
shopt -s dotglob # include dot files for cp
shopt dotglob
shopt -s
echo "after:" environments/nonprod/*

cp -av environments/"$ENV"/* "$TF_BUILD_DIR"/
cp -av src/* "$TF_BUILD_DIR"/
shopt -u dotglob
```

## decode base64

```bash
echo "bnVsbA==" | base64 --decode
```

## envsubst

https://unix.stackexchange.com/questions/492772/replace-environment-variables-in-text-if-they-exist

Replaces variables in input. Not sure why you wouldn't just use echo, perhaps used for in files

Can be used in files: https://mywiki.wooledge.org/TemplateFiles

Also useful for cat for paths: cat ./kube-system/$CLUSTER_VERSION/cluster-autoscaler.yaml | envsubst | kubectl apply -f -

```bash
echo 'Hello $USER' | envsubst
Hello myusername
```

## find modified log files

```bash
cd /var/log
sudo find . -type f -exec stat --format '%Y :%y %n' "{}" \; | sort -nr | cut -d: -f2- | head
```

## macos get ip addresses

```bash
# get laptop internal ip
ifconfig | grep inet
ipconfig getifaddr en0 # wireless
ipconfig getifaddr en1 # ethernet

# get laptop external ip
curl ipecho.net/plain ; echo
```

## mv only files

https://unix.stackexchange.com/questions/323778/moving-only-files-not-directories

https://www.unix.com/shell-programming-and-scripting/162060-move-only-files-folder.html

https://unix.stackexchange.com/questions/147290/move-every-file-that-is-not-a-directory

```bash
find . -maxdepth 1 -type f -exec mv {} <folder> \;

find . -maxdepth 1 -type f -not -name 'exe_*' -exec mv {} <folder> \;
find . -type f -exec mv {} <folder> \;
```

## printf

https://www.computerhope.com/unix/uprintf.htm

use `"%s\n"` to:

- format output with trailing newline (eg EOF with newline)

- break up and span into multiple lines for readability

```bash
# all in one line
printf "%s\n" "s/_TFE_HOSTNAME/$TFE_HOSTNAME/g" "s/_TFE_TOKEN/$TFE_TOKEN/g" > "$SEDSCRIPT"

# spanning multiple lines
printf "%s\n" "s/_TFE_HOSTNAME/$TFE_HOSTNAME/g" \
  "s/_TFE_TOKEN/$TFE_TOKEN/g" \
  > "$SEDSCRIPT"
```

## reload bash

```bash
bash -l
```

## rename all _.txt to _.text

https://mywiki.wooledge.org/BashFAQ/030

```bash
for f in *.txt; do
    mv -- "$f" "${f%.txt}.text"
done
```

On macos can use finder for batch rename

https://tidbits.com/2018/06/28/macos-hidden-treasures-batch-rename-items-in-the-finder/

## rename dd-mm-yyyy to yyyy-mm-dd

https://unix.stackexchange.com/a/335588

```bash
#!/usr/bin/env perl

# -n for dry run

# string_DD-MM-YYYY_hhmm.pdf -> string_YYYY-MM-DD_hhmm.pdf
rename -n 's/(.*)_(.*)-(.*)-(.*)_(.*.pdf)/$1_$4-$3-$2_$5/' *.pdf

# dd-mm-yyyy.pdf to yyyy_mm_dd.pdf
rename -n 's/(.*)-(.*)-(.*).(pdf)/$3_$2_$1.$4/' *.pdf
```

On macos install via brew

https://newbedev.com/how-to-batch-rename-files-in-a-macos-terminal

```
brew install rename
rename -n -e 's/_.*_/_/'  *.png
```

## rsync

```bash
# rsync to synch two folders
# --delete removes extra files from destination; -q is quiet mode
rsync -aEv --delete /src/* /dest/
rsync --dry-run -aEv --delete /src/* /dest/
rsync --dry-run -aEvq --delete /src/* /dest/
```

## running shell scripts

```bash
# executes in own shell process (ie env variables are not exported)
./my_script.sh

# executes in terminal's shell process
. ./my_script.sh
```

## sample help text

```bash
#!/bin/bash

set -euo pipefail

exit_with_usage() {
    cat <<EOF

  Usage: $0 [-h] -g group_name -l api_username -t token_subject

    Generate an access token for a specified group
    Upstream doc: https://www.jfrog.com/confluence/display/JFROG/Artifactory+REST+API#ArtifactoryRESTAPI-create-tokenCreateToken

  Parameters:

    -g group_name       Name of a group creating an access token against. Comma separated for multiple groups.
    -l api_username     Name of the user invoking the API to create a token.
    -t token_subject    Subject of the token. Please refer to the naming convention:
                        https://confluence.com/display/xxx
    -h                  Print this message.

  Example:

    $ $0 -g GCP_CSP_CI_Users -l john.smith -t bx-csp-ci-bamboo

EOF
    exit 0
}

[[ $# -eq 0 ]] && exit_with_usage

while getopts "h?l:g:t:" opt; do
    case "$opt" in
        h)  exit_with_usage
            ;;
        l)  api_user=$OPTARG
            ;;
        g)  group_name=$OPTARG
            ;;
        t)  token_subject=$OPTARG
            ;;
    esac
done

shift $((OPTIND-1))

[[ "${1:-}" = "--" ]] && shift

curl -u"$api_user" -X POST https://artifactory.com/artifactory/api/security/token \
    -d "scope=member-of-groups:$group_name" \
    -d "expires_in=0" \
    -d "username=$token_subject"

echo ""
echo "*** Please add token information in the access token register ***."
```

## start process in background

```bash
pgrep -q alpaca || nohup ~/go/bin/alpaca &>/dev/null &
pgrep -q alpaca || nohup ~/go/bin/alpaca &>/dev/null 2>&1 &

# check if <command> running first, if not start <command>
pgrep -q <command> || nohup <command> &>/dev/null &

nohup <command> &>/dev/null &
```

## sudo login options

https://askubuntu.com/a/376386

```bash
sudo su
# Calls sudo with the command su. Bash is called as interactive non-login shell. So bash only executes .bashrc. You can see that after switching to root you are still in the same directory:

user@host:~$ sudo su
root@host:/home/user#
```

```bash
sudo su -
# This time it is a login shell, so /etc/profile, .profile and .bashrc are executed and you will find yourself in root's home directory with root's environment.
```

```bash
sudo -i
# It is nearly the same as sudo su - The -i (simulate initial login) option runs the shell specified by the password database entry of the target user as a login shell. This means that login-specific resource files such as .profile, .bashrc or .login will be read and executed by the shell.
```

```bash
sudo /bin/bash
# This means that you call sudo with the command /bin/bash. /bin/bash is started as non-login shell so all the dot-files are not executed, but bash itself reads .bashrc of the calling user. Your environment stays the same. Your home will not be root's home. So you are root, but in the environment of the calling user.
```

```bash
sudo -s
# reads the $SHELL variable and executes the content. If $SHELL contains /bin/bash it invokes sudo /bin/bash (see above).
```

```bash
# to check if you are in a login shell or not (works only in bash because shopt is a builtin command):
shopt -q login_shell && echo 'Login shell' || echo 'No login shell'
```

## tar

```bash
# by default it maintains folder structure
tar -czf plan_artifact.tar.gz build/nonprod

# remove destination folder structure by changing working folder "-C" and using working folder "."
# https://stackoverflow.com/questions/5695881/how-do-i-tar-a-directory-without-retaining-the-directory-structure
tar -czf plan_artifact.tar.gz -C build/nonprod .
```

## test and if

```bash
# double [[ is for enhanced globs (like *) and only supported in bash (ie not busybox or alpine)
# https://stackoverflow.com/a/61085370

# test return code is 0 for true, 1 for false
# https://stackoverflow.com/a/47876317

true; echo $?
> 0
false; echo $?
> 1

TF_VAR_environment=prod; echo $TF_VAR_environment
> prod

[[ $TF_VAR_environment == "prod" ]]; echo $?
> 0

[[ $TF_VAR_environment != "prod" ]]; echo $?
> 1
```

## variable expansion

https://stackoverflow.com/questions/8748831/when-do-we-need-curly-braces-around-shell-variables

# certificates

## CApath not working

https://github.com/openssl/openssl/issues/4708#issuecomment-343272673

https://www.openssl.org/docs/manmaster/man3/SSL_CTX_load_verify_locations.html

Only works if the folder has hash value.

So need to run openssl rehash $dir_keystore first

## generating cert chain

https://security.stackexchange.com/questions/190905/subject-alternative-name-in-certificate-signing-request-apparently-does-not-surv

https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line/91556#91556

```bash
# create root cert and private key
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -subj '/O=ANZ EKS Test EKS Ingress/CN=eks-example.anz.com' -keyout eks-example.key -out eks-example.crt

# verify
openssl x509 -text -noout -in eks-example.crt

*** server cert and key
# generate server cert with SAN
openssl req -out nginx.eks-example.csr -newkey rsa:2048 -nodes -keyout nginx.eks-example.key \
  -subj "/O=ANZ EKS Test Ingress/CN=nginx.eks-example.anz.com" \
  -reqexts san \
  -config \
  <(echo "[req]";
    echo distinguished_name=req;
    echo "[san]";
    echo subjectAltName=DNS:nginx.eks-example.anz.com
    )

# verify
openssl req -text -noout -in nginx.eks-example.csr

*** sign server cert with root

# sign server cert with root cert
openssl x509 -req -days 365 -CA eks-example.crt -CAkey eks-example.key -set_serial 0 -in nginx.eks-example.csr -out nginx.eks-example.crt \
  -extensions san \
  -extfile \
  <(echo "[req]";
    echo distinguished_name=req;
    echo "[san]";
    echo subjectAltName=DNS:nginx.eks-example.anz.com
    )

# verify
openssl x509 -text -noout -in nginx.eks-example.crt
```

## openssl

```bash
# get SAN
openssl x509 -noout -ext subjectAltName -in cert.crt

# self signed cert only
# https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line

# < v1.1
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout example.key -out example.crt -extensions san -config \
  <(echo "[req]";
    echo distinguished_name=req;
    echo "[san]";
    echo subjectAltName=DNS:example.com,DNS:www.example.net,IP:10.0.0.1
    ) \
  -subj "/CN=example.com"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout example.key -out example.crt -subj '/CN=example.com' \
  -extensions san \
  -config <(echo '[req]'; echo 'distinguished_name=req';
            echo '[san]'; echo 'subjectAltName=DNS:example.com,DNS:example.net')

# >= v1.1
openssl req -new -subj "/C=GB/CN=foo" \
                -addext "subjectAltName = DNS:foo.co.uk" \
                -addext "certificatePolicies = 1.2.3.4" \
                -newkey rsa:2048 -keyout key.pem -out req.pem

# view certificate details
openssl x509 -text -noout -in <cert>.pem

# view certificate chain
openssl pkcs7 -print_certs -in certnew.p7b

# get fingerprints
# SHA-256
openssl x509 -noout -fingerprint -sha256 -inform pem -in [certificate-file.crt]

# SHA-1
openssl x509 -noout -fingerprint -sha1 -inform pem -in [certificate-file.crt]

# MD5
openssl x509 -noout -fingerprint -md5 -inform pem -in [certificate-file.crt]
```

## show cert chain of bundle local file

```bash
# show issuers only
openssl crl2pkcs7 -nocrl -certfile artifactory-np-v2.gcpnp.anz.cer | openssl pkcs7 -print_certs -noout

# show all info
openssl crl2pkcs7 -nocrl -certfile artifactory-np-v2.gcpnp.anz.cer | openssl pkcs7 -print_certs -text -noout
```

## show certs presented by endpoint

```bash
openssl s_client -showcerts -connect spinnaker.com:443

# if sni is used need to add server name
# https://stackoverflow.com/a/29215480
openssl s_client -showcerts -connect nginx.eks-example.com:443 -servername nginx.eks-example.com

# with custom CA
openssl s_client -CApath /usr/local/etc/openssl/certs -showcerts -connect spinnaker.com:443
openssl s_client -CAfile ~/Documents/work/certs/root_certs.pem -showcerts -connect spinnaker.com:443
```

## macos

```bash
# extract cert from keychain
security find-certificate -p -c "Custom Global Root CA v2"

# import certificate to keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <certificate>
```

# curl

## general

```bash

# loop and test for timeout
for i in {1..9}; do curl --retry 0 --connect-timeout 3 -m 3 -kv --noproxy "*" https://sts.ap-southeast-2.amazonaws.com/&>/dev/null; echo $?; done

# resolve DNS to specific IP, preserves cert chain CN/SAN and SNI routing
curl -vvv --noproxy "*" --cacert eks-example.crt --resolve nginx.eks-example.com:443:10.xxx.xxx.xxx https://nginx.eks-example.com

# smtp
curl -v --ssl smtp://xx.xxx.xxx.xxx:587


```

## with response time

https://stackoverflow.com/a/47944496

```bash
curl_time -m 3 -kv --noproxy "*" https://sts.ap-southeast-2.amazonaws.com/

curl_time() {
  curl -so /dev/null -w "\n\
          local_ip:  %{local_ip}\n\
     url_effective:  %{url_effective}\n\
         remote_ip:  %{remote_ip}\n\
     response_code:  %{response_code}\n\
 ssl_verify_result:  %{ssl_verify_result}\n\
     num_redirects:  %{num_redirects}\n\
   time_namelookup:  %{time_namelookup}s\n\
      time_connect:  %{time_connect}s\n\
   time_appconnect:  %{time_appconnect}s\n\
  time_pretransfer:  %{time_pretransfer}s\n\
     time_redirect:  %{time_redirect}s\n\
time_starttransfer:  %{time_starttransfer}s\n\
        time_total:  %{time_total}s\n\
-----------------------------------------------\n" "$@"
}
```

# docker

## \_references

https://www.digitalocean.com/community/tutorials/how-to-remove-docker-images-containers-and-volumes#a-docker-cheat-sheet

Docker needs a service running to keep container up

https://stackoverflow.com/questions/25135897/how-to-automatically-start-a-service-when-running-a-docker-container

ARG and ENV not supported in COPY --chown

https://github.com/moby/moby/issues/35018

## build

build get logs

https://pythonspeed.com/articles/debugging-docker-build/

```bash
# build image with tag
docker build -t docker.com/jenkins:master-v14407 .
docker build -t docker.com/jenkins:latest-v14407 .
docker build -t docker.com/jenkins:774306 .
docker build -t docker.com/jenkins:v14407 .
docker build -t docker.com/nginx:e4fd463bb4206fde94c953a7ea0f0723557dbd8 .
```

## cpu/memory usage

```bash
docker stat
```

## docker build mac client with proxy

```bash
# with alpaca/cntlm port forwarding to localhost:3128
# this works
docker build \
  --build-arg HTTP_PROXY="http://host.docker.internal:3128" \
  --build-arg HTTPS_PROXY="http://host.docker.internal:3128" \
  .

# doesn't work
docker build \
  --build-arg http_proxy=http://localhost:3128 \
  --build-arg https_proxy=http://localhost:3128
  .
```

## docker run mac client with proxy

Docker internal VM and proxy, find out docker internal VM's IP

https://www.manthanhd.com/2017/01/19/setting-up-corporate-proxy-on-docker-for-mac/ https://docs.docker.com/docker-for-mac/networking/#use-cases-and-workarounds

Lower (http/s) vs uppercase (HTTP/S) variables

https://docs.docker.com/config/daemon/systemd/#httphttps-proxy https://unix.stackexchange.com/questions/212894/whats-the-right-format-for-the-http-proxy-environment-variable-caps-or-no-ca#:~:text=http_proxy%20and%20friends%20isn't,and%20no_proxy%20are%20commonly%20lowercase

```bash
# with alpaca/cntlm port forwarding to localhost:3128
# run aws cli in a container
docker run \
  --rm \
  -it \
  --env HTTP_PROXY="http://host.docker.internal:3128" \
  --env HTTPS_PROXY="http://host.docker.internal:3128" \
  -v ~/.aws:/root/.aws \
  amazon/aws-cli \
  s3 ls --region ap-southeast-2

docker run \
  --rm \
  -it \
  --env HTTP_PROXY="http://192.168.65.1:3128" \
  --env HTTPS_PROXY="http://192.168.65.1:3128" \
  -v ~/.aws:/root/.aws \
  amazon/aws-cli \
  codecommit list-repositories --region ap-southeast-2

# run with volume mount (eg for dev container)
docker run \
  --rm \
  -it \
  -u root \
  -v `pwd`:/home/working \
  docker.io/library/gradle:jdk8 \
  /bin/bash

# with proxy variables
  --env HTTP_PROXY="localhost:3128" \
  --env HTTPS_PROXY="localhost:3128" \

# using host network
docker run \
  --name tf-provider-github \
  -it \
  -u root \
  -v `pwd`:/home/working \
  -w /home/working \
  --network="host" \
  golang:1.11 \
  /bin/bash
```

## exec

```
docker ps
docker exec -it <name> /bin/bash
```

## images

```bash
# save image to tar
# https://docs.docker.com/engine/reference/commandline/save/
docker save -o test.tar <image_id>

# show docker image layers
docker history <image_id>
```

## image local locations

```bash
sudo cat /var/lib/docker/image/overlay2/repositories.json | python -mjson.tool
sudo ls -al /var/lib/docker/overlay2
sudo ls -al /var/lib/docker/image/overlay2
```

## list all repositories

```bash
# repo settings may limit pagination
curl -kX GET https://docker.registry.com/v2/_catalog?n=5000
curl -k -v --output docker_repos.log -X GET https://docker.com/v2/_catalog
curl -k -v -X GET https://docker.com/v2/_catalog

curl http://10.84.34.155:5000/v2/_catalog
curl http://10.84.34.155:5000/v2/_catalog
curl --output docker.log docker.com/v2/_catalog

# list tags for a repo
curl -k -X GET https://docker.com/v2/haproxy/tags/list
curl -k -X GET https://docker.com/v2/jenkins/tags/list
curl -k -v -X GET https://docker.com/v2/nginx/tags/list
curl -k -v -X GET https://docker.com/v2/oracle/tags/list
curl -k -v -X GET https://docker.com/v2/tags/list
curl -k -v -X GET https://docker.com/v2/kibana/tags/list

# list image details
curl -k -X GET https://docker.com/v2/clairscan/manifests/snapshot-01861d63c91bbfabffa163cda0f5e073de8e76d3
```

## logs

https://stackoverflow.com/questions/41144589/how-to-redirect-docker-logs-to-a-single-file

```bash
# view logs in stdout
docker ps -a # list all processes including previously running ones
docker logs <name>
docker logs -f <name>

# find and view actual log file
docker inspect --format='{{.LogPath}}' containername
/var/lib/docker/containers/f844a7b45ca5a9589ffaa1a5bd8dea0f4e79f0e2ff639c1d010d96afb4b53334/f844a7b45ca5a9589ffaa1a5bd8dea0f4e79f0e2ff639c1d010d96afb4b53334-json.log

# see live logs
tail -f `docker inspect --format='{{.LogPath}}' containername`
```

## output image to tar and import to create single layer image

```bash
docker save -o test.tar 55140bc5db4b
docker import test.tar test:1.1.0

docker save -o haproxy:git-8a23df32d7e49ab28736df12d48788c7a793c49c.tar 426267033468.dkr.ecr.ap-southeast-2.amazonaws.com/haproxy:git-8a23df32d7e49ab28736df12d48788c7a793c49c

docker import haproxy:git-8a23df32d7e49ab28736df12d48788c7a793c49c.tar esedocker-build.artifactory.dss.ext.national.com.au/haproxy:git-8a23df32d7e49ab28736df12d48788c7a793c49c
```

## pull / push

```bash
# pull
docker pull docker.com/haproxy:latest-v14407

# push
docker push docker.com/jenkins:master-v14407
docker push docker.com/jenkins:latest-v14407

# change tag, then delete old image tag (can use image id instead of name)
docker tag docker.com/jenkins:v14407 docker.com/jenkins:latest
docker rmi docker.com/jenkins:v14407
docker tag docker.com/jenkins:774306 docker.com/jenkins:v14407
docker rmi docker.com/jenkins:774306
```

## prune

```bash
# docker provides a single command that will clean up any resources — images, containers, volumes, and networks — that are dangling (not associated with a container):
docker system prune

# to additionally remove any stopped containers and all unused images (not just dangling images), add the -a flag to the command:
docker system prune -a
```

## restart stopped containers

https://www.unixtutorial.org/restart-stopped-containers-in-docker

```bash
# list stopped containers
docker ps -a -f status=exited

# list stopped container ids
docker ps -a -q -f status=exited

# start stopped containers
docker start $(docker ps -a -q -f status=exited)
```

## rm / rmi

```bash
# delete up local docker images
docker rmi docker.com/${IMAGE}:${COMMIT_ID}
docker rmi docker.com/${IMAGE}:latest

# list & delete dangling images (ie those with no tags or repos)
docker images -f 'dangling=true' -q
docker rmi $(docker images -f 'dangling=true' -q) -f || true
docker rmi $(docker images -f “dangling=true” -q)

# remove all stopped containers
docker rm $(docker ps -a -q)

# Delete all containers
docker rm $(docker ps -a -q)
# Delete all images
docker rmi $(docker images -q)
```

## rm prev containers

```bash
# The container name "<xxx>" is already in use by container "<xxx>". You have to remove (or rename) that container to be able to reuse that name.

docker ps -a # list all previously run containers
docker rm <container>
```

## run

```bash
# with shell
docker run -it --name jenkins2 docker.com/jenkins:latest-dcib-15856 /bin/bash

# detached mode
docker run -d --name jenkins2 docker.com/jenkins:latest-dcib-15856 /bin/bash

# run and view environment variables of image
docker run --rm <image> env
```

## run vs start

https://stackoverflow.com/questions/34782678/difference-between-running-and-starting-a-docker-container

Run: create a new container of image and execute the container, you can create N clones of the same image. Command is docker run IMAGE_ID and not docker run CONTAINER_ID

Start: Launch a container previously stopped, for example if you had stopped a database with the command docker stop CONTAINER_ID, you can relaunch the same container with the command docker start CONTAINER_ID and the data and settings are the same.

## view env vars of image

```bash
docker inspect <image> | grep env_name
docker inspect <image> | grep env_name
```

# eks

## kubeconfig scripts

```bash

# clear
cat <<EOF > ~/bin/eks_clear
rm ~/.kube/config
EOF

chmod u+x ~/bin/eks_clear

# kubeconfig
cat <<EOF > ~/bin/eks_np
# rm ~/.kube/config
aws eks update-kubeconfig --region ap-southeast-2 --name np-au1-ops --alias np-au1-ops --role arn:aws:iam::675218639914:role/np-au1-ops-clusteradmin
aws eks update-kubeconfig --region ap-southeast-2 --name mht-np-au1-workload --alias mht-np-au1-workload --role arn:aws:iam::675218639914:role/mht-np-au1-workload-clusteradmin
aws eks update-kubeconfig --region ap-southeast-2 --name mht-np-au1-services --alias mht-np-au1-services --role arn:aws:iam::675218639914:role/mht-np-au1-services-clusteradmin
aws eks update-kubeconfig --region ap-southeast-2 --name lt-np-au1-perimeter-payments --alias lt-np-au1-perimeter-payments --role arn:aws:iam::675218639914:role/lt-np-au1-perimeter-payments-clusteradmin
aws eks update-kubeconfig --region ap-southeast-2 --name lt-np-au1-perimeter-general --alias lt-np-au1-perimeter-general --role arn:aws:iam::675218639914:role/lt-np-au1-perimeter-general-clusteradmin
EOF

chmod u+x ~/bin/eks_np
```

## wait for nlb readiness

```bash
function wait_nlb {
  MAX_WAIT=180
  ATTEMPTS=0
  # hostname will be an empty string until the load balancer controller has begun to actually provision the load balancer
  while [[ $(kubectl get service -n $NAMESPACE $1 -o jsonpath='{.status.loadBalancer.ingress[0].hostname}') == "" ]]; do
    ATTEMPTS=$((ATTEMPTS+1))
    if [[ $ATTEMPTS -gt $MAX_WAIT ]]; then
      echo "Giving up waiting for nlb for service/$1"
      exit 1
    fi
    sleep 5
  done
}
```

# gcloud

## gcs download

https://cloud.google.com/storage/docs/downloading-objects

```bash
gsutil cp gs://[BUCKET_NAME]/[OBJECT_NAME] [SAVE_TO_LOCATION]
gsutil cp gs://anz-ex-services-dev-32c9ea-halyard-config/gcpnp.anz.crt.enc /Users/tanga/Documents/work/dev/
gsutil cp gs://anz-ex-services-dev-32c9ea-halyard-config/* /Users/tanga/Documents/work/dev/
```

## gcs versioning

https://cloud.google.com/storage/docs/using-object-versioning#list

```bash
# check if versioning is enabled
gsutil versioning get gs://[BUCKET_NAME]
gsutil versioning get gs://anz-ex-services-dev-32c9ea-halyard-config

# enable versioning
gsutil versioning set on gs://[BUCKET_NAME]

# list object versions
gsutil ls -a gs://[BUCKET_NAME]
gsutil ls -a gs://anz-ex-services-dev-32c9ea-halyard-config
```

## list of public gcr.io images

https://console.cloud.google.com/gcr/images/google-containers/GLOBAL

## setup

```bash
# set custom root cert
gcloud config configurations describe services-dev
gcloud config set core/custom_ca_certs_file ~/.ssl/custom_global_root_ca_v2.pem

# get cert from macos keychain
security find-certificate -p -c "Custom Global Root CA v2" > ~/.ssl/custom_global_root_ca_v2.pem
```

random script from CamH re certs, can't remember what for

````bash
#!/usr/bin/awk -f
BEGIN {
  print_cert = "openssl x509 -noout -text"
  begin_cert = "^-----BEGIN CERTIFICATE-----$"
  end_cert   = "^-----END CERTIFICATE-----$"
}
$0 ~ begin_cert, $0 ~ end_cert { print | print_cert }
$0 ~ end_cert { close(print_cert) }```
````

```bash
# authenticate
gcloud auth login

# list
gcloud config configurations list

# change active configuration
gcloud config configurations activate NAME
gcloud config configurations activate ex-services-dev
gcloud config configurations activate ex-services-stg
gcloud config configurations activate ex-services-prod

# set / unset project
gcloud config set project PROJECT_ID
gcloud config unset project

# setup project configuration
gcloud config configurations create ex-services-dev
gcloud config set project anz-ex-services-dev-32c9ea
gcloud auth login

gcloud config configurations create ex-services-stg
gcloud config set project anz-ex-services-stg-236d8f
gcloud auth login

gcloud config configurations create ex-services-prod
gcloud config set project anz-ex-services-prod-4525d2
gcloud auth login
```

# gke

## authenticate

```bash
# authenticate with GKE
gcloud container clusters get-credentials anz-ex-services-dev-gke --region australia-southeast1 --internal-ip --project anz-ex-services-dev-32c9ea
gcloud container clusters get-credentials anz-ex-services-stg-gke --region australia-southeast1 --internal-ip --project anz-ex-services-stg-236d8f
gcloud container clusters get-credentials anz-ex-services-prod-gke --region australia-southeast1 --project anz-ex-services-prod-4525d2

anz-ex-services-dev-32c9ea
anz-ex-services-stg-236d8f
anz-ex-services-prod-4525d2

# add custom root ca cert to allow SSL handshake via proxy
gcloud config set core/custom_ca_certs_file ~/.ssl/custom_global_root_ca_v2.pem

gcloud config configurations describe services-prod
gcloud config unset core/custom_ca_certs_file
```

## networking

Setting up a GKE cluster requires all 4 ranges defined below (GCP conventions for names). All visible in GKE console except Primary - defined in Terraform

- Master - Master address range (allocated by cloud services for GKE master)
- Primary - Nodes and LBs (not visible in GKE console)
- Secondary0 - Pod address range
- Secondary1 - Service address range

# helm

```bash
# install helm
brew install kubernetes-helm
helm init -c

# install
helm install \
  --namespace ns \
  --generate-name \
  /home/tanga/temp/abc-helm.tar.gz

# list installed packages
helm list -A
helm list -n ns --kube-context cluster

# uninstall
helm uninstall abc-helm --kube-context cluster -n ns
helm uninstall abc-helm --kube-context cluster -n ns --dry-run

# package
helm package ./abc

# template
helm template . \
  --namespace ns \
  --values values.yaml
```

# homebrew

https://apple.stackexchange.com/questions/101090/list-of-all-packages-installed-using-homebrew

```bash
brew list
brew list --cask
brew upgrade go

brew uninstall packageName
brew uninstall hashicorp/tap/terraform-ls
```

# istio

## disable / enable istio injection

```bash
# list status for namespaces
kubectl get namespace -L istio-injection

# disable injection
kubectl label namespace ns istio-injection-

# enable injection
kubectl label namespace ns istio-injection=enabled --overwrite
```

# git

## \_boiler plate

```bash
# misc
git checkout -b andy-deploy-helloweb
git push -u origin andy-deploy-helloweb
git push origin feature:andy -f

git add -u ; git commit --amend --no-edit; git push -f
git add . ; git commit --amend --no-edit; git push -f

git commit -m "Add andy-test namespace"

git commit
Add andy-test namespace

More information 1
More information 2

# tags
git tag -l "v0.1"
git tag "v0.2" -f
git push origin "v0.2" -f

# show oneline commits and tags
git log --pretty=oneline --abbrev-commit

# show staged files
git diff --name-only --cached
```

## add/remove executable permission

```bash
git add --chmod=+x file.txt
git add --chmod=-x file.txt
git add . --chmod=+x -n
```

## checkout PRs locally

https://gist.github.com/piscisaureus/3342247

```bash
# add 'fetch = +refs/pull/*/head:refs/remotes/origin/pr/*' to .git/config as per below
[remote "origin"]
	url = git@github.service.anz:ex/gitsync-config.git
	fetch = +refs/heads/*:refs/remotes/origin/*
	fetch = +refs/pull/*/head:refs/remotes/origin/pr/*

git pull
git checkout pr/999
```

## cherry-pick

```bash
# cherry pick sha to commit (does add/merge/commit for you like pull)
git cherry-pick 3cf974a33aa85e4b25278d02a3dd9452ec827e74
```

## clone add, commit, push

```bash
git clone git@github.com:eepmoi/k8s-debug-pod.git
git clone https://github.com/eepmoi/k8s-debug-pod.git

git checkout -b readme_update
git push -u origin readme_update

git commit -m "Add more dev tool installs."
git commit -m "Update onboarding steps"

git commit --amend --no-edit

git add -u ; git commit --amend --no-edit; git push -f
git add . ; git commit --amend --no-edit; git push -f
```

## delete branch

```bash
git branch -D andy
git push origin :andy
git push codecommit :andy

# restore deleted branch
git checkout -b <branch> <sha>
```

## diff

```bash
# show files only
git diff --name-only master

# show staged files
git diff --name-only --cached
```

## duplicate repository

https://help.github.com/en/enterprise/2.18/user/github/creating-cloning-and-archiving-repositories/duplicating-a-repository

- Create repo first via UI.
- Open Terminal. Create a bare clone of the repository.

```bash
git clone --bare https://hostname/exampleuser/old-repository.git
```

- Mirror-push to the new repository.

```bash
cd old-repository.git
git push --mirror https://hostname/exampleuser/new-repository.git
```

- Remove the temporary local repository you created earlier.

```bash
cd ..
rm -rf old-repository.git
```

## exclude local files without committing to .gitignore

https://hackernoon.com/exclude-files-from-git-without-committing-changes-to-gitignore-986fa712e78d

- add file or wildcard to this file: .git/info/exclude
- syntax is the same as .gitignore

```bash
echo *.log >> ~/git/terraform-aws-core-bootstrap/.git/info/exclude
echo .DS_Store >> ~/git/spin-config/.git/info/exclude
echo *.spin >> ~/git/spin-config/.git/info/exclude
echo dump_all_vars.yaml >> .git/info/exclude
echo "roles/dump_all_vars/*" >> .git/info/ex
```

## fetch

```bash
# pull in force pushed commits on branch
git fetch
git reset origin/master --hard
git pull
```

## log

https://stackoverflow.com/questions/4479225/how-to-output-git-log-with-the-first-line-only

```bash
# show one line commits with abbreviated commit sha and tags
git log --pretty=oneline --abbrev-commit
```

## prune local branches that are no longer in remote

git prune explained: https://stackoverflow.com/questions/20106712/what-are-the-differences-between-git-remote-prune-git-prune-git-fetch-prune/20107184

```bash
# branches with no upstream
# https://stackoverflow.com/questions/44477690/delete-local-git-branches-if-their-remote-tracking-references-dont-exist-anymor
git fetch --prune
git branch -lvv | cut -c3- | awk '/: gone]/ {print $1}' | xargs git branch -d

# branches that are merged
git branch --merged master | grep -v '^[ *]*master$' | xargs git branch -d
git branch --merged dev | grep -v '^[ *]*dev$' | xargs git branch -d
git branch --merged nonprod | grep -v '^[ *]*nonprod$' | xargs git branch -d
```

## rebase

```bash
git checkout master
git pull upstream master # or just `git pull` if `master` is set to track `upstream/master`
git checkout feature
git rebase master
git push -f
```

### rebase interactive to squash commits

https://www.internalpointers.com/post/squash-commits-into-one-git

https://stackoverflow.com/questions/47888343/how-to-squash-a-merge-commit-with-a-normal-commit

**NOTE** - this will not pickup merge commits (eg pull master). To do this cleanly, push merge commit upstream first, then do a normal rebase without -i. It should auto squash the merge commit.

```bash
git rebase -i <commit you want to amend>^
git rebase -i 43801824b475dfefdacbbd8b73546e0620032f43^
git push -f

# Commands:
# p, pick <commit> = use commit
# r, reword <commit> = use commit, but edit the commit message
# e, edit <commit> = use commit, but stop for amending
# s, squash <commit> = use commit, but meld into previous commit
# f, fixup <commit> = like "squash", but discard this commit's log message
# x, exec <command> = run command (the rest of the line) using shell
# b, break = stop here (continue rebase later with 'git rebase --continue')
# d, drop <commit> = remove commit
# l, label <label> = label current HEAD with a name
# t, reset <label> = reset HEAD to a label

# commits listed in reverse order to git log, newest commit last
# squash will amend with the prev commit in the list
# use "reword" command to reword commit message in editor (ie for multiline)

# to abort in vim exit with error code
:cq
```

**example**

https://stackoverflow.com/questions/8824971/how-to-amend-older-git-commit/18150592#18150592

- prepare your update to older commit, add it and commit

```bash
git rebase -i <commit you want to amend>^ # notice the ^ so you see the said commit in the text editor
  pick 8c83e24 use substitution instead of separate subsystems file to avoid jgroups.xml and jgroups-e2.xml going out of sync
  pick 799ce28 generate ec2 configuration out of subsystems-ha.xml and subsystems-full-ha.xml to avoid discrepancies
  pick e23d23a fix indentation of jgroups.xml
```

- now to combine e23d23a with 8c83e24 you can change line order and use squash like this:

```bash
  pick 8c83e24 use substitution instead of separate subsystems file to avoid jgroups.xml and jgroups-e2.xml going out of sync
  squash e23d23a fix indentation of jgroups.xml
  pick 799ce28 generate ec2 configuration out of subsystems-ha.xml and subsystems-full-ha.xml to avoid discrepancies
```

- write and exit the file, you will be present with an editor to merge the commit messages. Do so and save/exit the text document

- you are done, your commits are amended

## rename branch

```bash
# rename local branch
git branch -m old-branch-name new-branch-name

# remote push new branch and delete old one
git push -u origin new-branch-name
git push origin :old-branch-name

# to see the new branch name, each repository client will need to fetch and prune with:
git fetch origin
git remote prune origin
```

## remote repos

```bash
# add remote
git remote -v
git remote add codecommit codecommit://git-repo
git push -u origin andy-deploy-helloweb
git push codecommit andy-deploy-helloweb

git push codecommit add-features:master -f
git push origin add-features:andy -f

# checkout branch with >1 remotes
# https://stackoverflow.com/questions/1783405/how-do-i-check-out-a-remote-git-branch

git fetch origin
git branch -v -a
git checkout -b test origin/test

# update remote branch tracking
git branch branch_name -u your_new_remote/branch_name
```

## revert

https://stackoverflow.com/a/1470452 Revert a prev commit with a new commit that reverses the changes

```bash
# multiple commits
git revert --no-commit D
git revert --no-commit C
git revert --no-commit B
git commit -m "the commit message for all of them"

# multiple commits in one go
git revert --no-commit D C B

# alternative using reset
git reset --hard A
git reset --soft D # (or ORIG_HEAD or @{1} [previous location of HEAD]), all of which are D
git commit
```

## standards

### branch names

https://opensource.zalando.com/dress-code/docs.html

```bash
feat: A new feature
fix: A bug fix
docs: Documentation only changes
style: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
refactor: A code change that neither fixes a bug nor adds a feature
perf: A code change that improves performance
test: Adding missing tests
chore: Changes to the build process or auxiliary tools and libraries such as documentation generation
```

### commit messages

https://chris.beams.io/posts/git-commit/

Keep to 50 characters for single line, hard limit in github of 72

## set git config per repo

https://crunchify.com/how-to-set-github-user-name-and-user-email-per-repository-different-config-for-different-repository/

```bash
# cd into repo
git config user.email "andytang80@hotmail.com"
git config user.name "Andy Tang"

# change author of last commit
# https://www.git-tower.com/learn/git/faq/change-author-name-email/
git commit --amend --author="John Doe <john@doe.org>"
```

## tags

https://devconnected.com/how-to-list-git-tags/

https://git-scm.com/book/en/v2/Git-Basics-Tagging

https://blog.iqandreas.com/git/how-to-move-tags/

```bash
# move tags
git tag -f v0.2.0
git push origin --tags -f

# A lightweight tag is very much like a branch that doesn’t change — it’s just a pointer to a specific commit.
git tag v1.4-lw

# Annotated tags, however, are stored as full objects in the Git database. They’re checksummed; contain the tagger name, email, and date; have a tagging message; and can be signed and verified with GNU Privacy Guard (GPG). It’s generally recommended that you create annotated tags so you can have all this information; but if you want a temporary tag or for some reason don’t want to keep the other information, lightweight tags are available too.
git tag -a v1.4 -m "my version 1.4"

# list tags
git tag -l "v0.1.*"

# tag and push
git tag staging-spinnaker-v0.11.1
git push origin staging-spinnaker-v0.11.1

# show commit for tag
git show <tag>

# list tags with commits
# https://stackoverflow.com/a/8796647
#For annotated tags - the lines ending with ^{} start with the SHA1 hash of the actual commit that the tag points to. For lightweight tags there's not commit for the tag itself
git show-ref --tags -d

# delete tag
git tag -d v2.1.0
git push --delete origin v2.1.0
```

### show state of tags and branches

https://stackoverflow.com/q/47142799

```bash
git --no-pager log \
  --simplify-by-decoration \
  --tags --branches --remotes \
  --date-order \
  --decorate \
  --pretty=tformat:"%Cblue %h %Creset %<(25)%ci %C(auto)%d%Creset %s"
```

https://stackoverflow.com/a/25952970

```bash
# shorter version with tags only
git log --oneline --decorate --tags --no-walk
```

## transfer gist to repo

https://gist.github.com/ishu3101/830b556b487de5d69690

- clone the gist

```bash
git clone https://gist.github.com/ishu3101/6fb35afd237e42ef25f9
```

- rename the directory

```bash
mv 6fb35afd237e42ef25f9 ConvertTo-Markdown
```

- change the working directory to the newly renamed directory

```bash
cd ConvertTo-Markdown
```

- create a new repository on github
- add the github repository as a remote to your checked out gist repository

```bash
git remote add github https://github.com/ishu3101/ConvertTo-Markdown
```

- push to the new repository on github
- git push github master

- rename the remote of gist
- git remote rename origin gist

- Each time you make changes (or pull changes from github/gist), you can do

```bash
git push github master   # To github
git push gist master     # To gist
```

This will also push back your changes to the gist and not only the github repo.

```bash
# eg
git remote add github git@github.com:eepmoi/k8s-debug-pod.git
git remote add github https://github.com/eepmoi/k8s-debug-pod.git
git push https://github.com/eepmoi/k8s-debug-pod.git master
```

# k8s

## apply from stdin

```bash
kubectl apply --context cluster -n namespace -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: my-nginx
  labels:
    run: my-nginx
spec:
  ports:
    - port: 8080
      protocol: TCP
  selector:
    run: my-nginx
EOF
```

## clear credentials

```bash
rm ~/.kube/config
```

## cluster

```bash
# cluster info
kubectl cluster-info

# cluster name
kubectl config current-context

# cluster version
kubectl version
```

## debug pod for cloud build

https://github.com/eepmoi/k8s-debug-pod

```bash
kubectl create namespace andy-debug --dry-run=client -o yaml > namespace.yaml
kubectl apply -f namespace.yaml
kubectl delete namespaces andy-debug

kubectl apply -f ~/Documents/work/dev/utils_scripts/debug-pod.yaml -n andy-debug

kubectl get deployment -n andy-debug
kubectl delete deployments -n andy-debug debug-pod
kubectl delete namespaces andy-debug

kubectl get pods -n andy-debug
kubectl describe pods -n andy-debug debug-pod-5f568dd68c-kxr56
kubectl exec -it -n andy-debug debug-pod-5f568dd68c-kxr56 -- sh
kubectl exec --namespace=andy-debug -it $(kubectl get pod -l "app=debug-pod" --namespace=andy-debug -o jsonpath='{.items[0].metadata.name}') -- /bin/bash

kubectl cp /workspace andy-debug/debug-pod-697dff64b-r4cn9:/debug
kubectl cp andy-debug/debug-pod-7484488f7b-mb6fb:/debug/workspace/keystore.jks .
kill -9 1
```

```yaml
# cloudbuild spec
- name: gcr.io/cloud-builders/gcloud
  id: debug
  entrypoint: sh
  args:
    - "-c"
    - "kubectl cp /workspace andy-debug/debug-pod-697dff64b-r4cn9:/debug"
```

## deployments

```bash
# deployment info
kubectl describe deployments -n jenkins-pips-764

# create deployments
kubectl apply -f <deployment.yaml> --namespace <name_space>
kubectl apply -f ~/Documents/work/dev/utils_scripts/debug-pod.yaml --namespace andy-debug

# scale replica set (ie stop pod)
# get deployment name and current number of replicas
kubectl get deploy -n jenkins
  NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
  jenkins   1         1         1            1           8d

# scale to zero
kubectl scale --replicas=0 deployment jenkins -n jenkins
kubectl scale --replicas=1 deployment jenkins -n jenkins

# replicaset info
kubectl get rs -n jenkins-pips-764
kubectl describe rs -n jenkins jenkins-6b7b7fc666
```

## edit

```bash
# this is equivalent to first get the resource, edit it in text editor, and then apply the resource with the updated version:
kubectl edit deployment/my-nginx

# do some edit, and then save the file
kubectl get deployment my-nginx -o yaml > /tmp/nginx.yaml
vi /tmp/nginx.yaml

kubectl apply -f /tmp/nginx.yaml
deployment.apps/my-nginx configured

rm /tmp/nginx.yaml
```

## gatekeeper

### disable policy

```bash
# describe constraint, shows violations
kubectl describe enforcesecurepeerauthentication -n gatekeeper-system

# get constraint
kubectl get constraint | grep enforcesecurepeerauthentication

# edit constraint eg to add excluded namespace
kubectl edit enforcesecurepeerauthentication.constraints.gatekeeper.sh/enforcesecurepeerauthentication
```

### generate report of violations

```bash
#!/bin/bash

for c in $(kubectl get constraint -o name); do
  echo "Examine $c: kubectl get $c -o json"
  kubectl get $c -o json | jq ".status.auditTimestamp,.status.totalViolations,.status.violations" # only shows 20 violations by default
done
```

### wait for gatekeeper webhook readiness

https://github.com/open-policy-agent/gatekeeper/issues/1156

```bash
MAX_WAIT=180
ATTEMPTS=0
echo "Waiting for Gatekeeper webhook to be ready"
until kubectl label ns gatekeeper-system wait-for-gatekeeper=ready >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS+1))
  if [[ $ATTEMPTS -gt $MAX_WAIT ]]; then
    echo "Giving up waiting for Gatekeeper webhook"
    exit 1
  fi
  sleep 1
done
ATTEMPTS=0
echo "Remove temp gatekeeper-system namespace label"
until kubectl label ns gatekeeper-system wait-for-gatekeeper- >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS+1))
  if [[ $ATTEMPTS -gt $MAX_WAIT ]]; then
    echo "Giving up removing temp gatekeeper-system namespace label"
    exit 1
  fi
  sleep 1
done
```

## jsonpath

```json
# sample json
{
            "metadata": {
                "annotations": {
                    "csi.volume.kubernetes.io/nodeid": "{\"ebs.csi.aws.com\":\"i-013ff9b76814af22d\"}",
                    "node.alpha.kubernetes.io/ttl": "0",
                    "volumes.kubernetes.io/controller-managed-attach-detach": "true"
                },
                "creationTimestamp": "2020-11-22T17:30:59Z",
                "labels": {
                    "appname": "eks",
                    "beta.kubernetes.io/arch": "amd64",
                    "beta.kubernetes.io/instance-type": "m5d.large",
                    "beta.kubernetes.io/os": "linux",
                    "branch": "dev",
                    "bsbcc": "39970800",
                    "category": "undefined",
                    "dataclassif": "internal",
                    "domain": "institutional",
                    "eks.amazonaws.com/capacityType": "ON_DEMAND",
                    "eks.amazonaws.com/nodegroup": "andy-ops-type1-sn-02b0-grown-man",
                    "eks.amazonaws.com/nodegroup-image": "ami-0b41606664fe2824b",
                    "environment": "nonprod",
                    "failure-domain.beta.kubernetes.io/region": "ap-southeast-2",
                    "failure-domain.beta.kubernetes.io/zone": "ap-southeast-2b",
                    "kubernetes.io/arch": "amd64",
                    "kubernetes.io/hostname": "ip-10-191-124-112.corp.np.au1.aws.anz.com",
                    "kubernetes.io/os": "linux",
                    "materiality": "no",
                    "node.kubernetes.io/instance-type": "m5d.large",
                    "owneremail": "Christian-Ganal-at-anz-com",
                    "projectname": "ecpcs",
                    "techarea": "undefined",
                    "topology.ebs.csi.aws.com/zone": "ap-southeast-2b",
                    "topology.kubernetes.io/region": "ap-southeast-2",
                    "topology.kubernetes.io/zone": "ap-southeast-2b",
                    "type": "type1",
                    "uuid": "E388F9CE-CBC5-4901-83FF-F0EA24E5B65A"
                },
            }
}
```

```bash
# need to escape with \ if there is a `.` in the name of the key.
# custom columns
kubectl get nodes -o=custom-columns=NODE:.metadata.name,NODEGROUP:".metadata.labels['eks\.amazonaws\.com/nodegroup']",ZONE:".metadata.labels['topology\.kubernetes\.io/zone']" -n istio-system

# without custom columns
kubectl get nodes -o jsonpath="{.items[*].metadata.labels['topology\.kubernetes\.io/zone']}"
```

## kubectl

### exec into pod

```bash
# interactive mode using pod name
kubectl get pods -n artifactory
NAME                                   READY     STATUS    RESTARTS   AGE
artifactory-artifactory-ha-member-0    1/1       Running   0          12d
artifactory-artifactory-ha-member-1    1/1       Running   0          12d
artifactory-artifactory-ha-primary-0   1/1       Running   0          12d
artifactory-nginx-79cd548bbc-nrh48     1/1       Running   1          12d

kubectl exec -it -n artifactory artifactory-artifactory-ha-member-0 -- /bin/bash
kubectl exec -it -n artifactory artifactory-artifactory-ha-primary-0 -- /bin/bash

# using label for instance number 0 (1 for second replica, 2 for third replica etc)
kubectl get pods -n csp-spinnaker --show-labels
NAME                                         READY   STATUS    RESTARTS   AGE    LABELS
csp-spinnaker-redis-master-0                 1/1     Running   0          27h    app=redis,chart=redis-3.8.0,controller-revision-hash=csp-spinnaker-redis-master-78465dc547,release=csp-spinnaker,role=master,statefulset.kubernetes.io/pod-name=csp-spinnaker-redis-master-0
csp-spinnaker-redis-slave-69d9b768bf-czjvz   1/1     Running   2          27h    app=redis,chart=redis-3.8.0,pod-template-hash=69d9b768bf,release=csp-spinnaker,role=slave
csp-spinnaker-spinnaker-halyard-0            1/1     Running   0          22h    app=csp-spinnaker-spinnaker,chart=spinnaker-1.6.1,component=halyard,controller-revision-hash=csp-spinnaker-spinnaker-halyard-7bf96b5fd5,heritage=Tiller,release=csp-spinnaker,statefulset.kubernetes.io/pod-name=csp-spinnaker-spinnaker-halyard-0

kubectl exec --namespace=csp-spinnaker -it $(kubectl get pod -l "app=csp-spinnaker-spinnaker" --namespace=csp-spinnaker -o jsonpath='{.items[0].metadata.name}') -- /bin/bash
kubectl exec --namespace=csp-spinnaker -it $(kubectl get pod -l "app.kubernetes.io/name=clouddriver" --namespace=csp-spinnaker -o jsonpath='{.items[0].metadata.name}') -- /bin/bash

# exec into pod and run command
kubectl exec -n artifactory -it artifactory-artifactory-ha-primary-0 -- /bin/bash -c "curl --noproxy \"*\" -u \"andy.tang:xxx\" -X POST \"http://localhost:8081/artifactory/api/plugins/reload\""
kubectl exec -n artifactory -it artifactory-artifactory-ha-member-0 -- /bin/bash -c "curl --noproxy \"*\" -u \"andy.tang:xxx\" -X POST \"http://localhost:8081/artifactory/api/plugins/reload\""
kubectl exec -n artifactory -it artifactory-artifactory-ha-member-1 -- /bin/bash -c "curl --noproxy \"*\" -u \"andy.tang:xxx\" -X POST \"http://localhost:8081/artifactory/api/plugins/reload\""

# use label and run curl
kubectl exec --context lt-andy-au1-perimeter-general -n eks-tvt-d "$(kubectl get pod --context lt-andy-au1-perimeter-general -n eks-tvt-d -l run=my-nginx -o jsonpath={.items..metadata.name})" -c istio-proxy -- curl -sS -vvv -k http://localhost:8080
```

### ignore-not-found

```bash
# returns 0 error code if not found vs 1.
kubectl delete apiservice xxx --ignore-not-found
kubectl delete apiservice xxx
```

### get AZs

```bash
# node of pods
kubectl get pods -n istio-internal -o wide
NAME                                     READY   STATUS    RESTARTS   AGE   IP              NODE                                               NOMINATED NODE   READINESS GATES
aws-secret-replicator-7c7c5f7b58-d69dr   1/1     Running   0          81d   10.188.23.253   ip-10-188-22-231.ap-southeast-2.compute.internal   <none>           <none>
istio-ingressgateway-7658fbdbf7-v5b2b    1/1     Running   0          48d   10.188.22.179   ip-10-188-22-231.ap-southeast-2.compute.internal   <none>           <none>
istio-ingressgateway-7658fbdbf7-vncks    1/1     Running   0          81d   10.188.21.228   ip-10-188-20-144.ap-southeast-2.compute.internal   <none>           <none>
istio-ingressgateway-7658fbdbf7-z79w7    1/1     Running   0          61d   10.188.21.95    ip-10-188-20-113.ap-southeast-2.compute.internal   <none>           <none>
istiod-64cbbccbc6-76tt7                  1/1     Running   0          33d   10.188.23.62    ip-10-188-22-231.ap-southeast-2.compute.internal   <none>           <none>
istiod-64cbbccbc6-ccvwp                  1/1     Running   0          33d   10.188.18.106   ip-10-188-18-70.ap-southeast-2.compute.internal    <none>           <none>
istiod-64cbbccbc6-n5gt7                  1/1     Running   0          33d   10.188.20.126   ip-10-188-20-113.ap-southeast-2.compute.internal   <none>           <none>

# AZ of node
kubectl get nodes -o=custom-columns=NODE:.metadata.name,NODEGROUP:".metadata.labels['eks\.amazonaws\.com/nodegroup']",ZONE:".metadata.labels['topology\.kubernetes\.io/zone']"
NODE                                                NODEGROUP                             ZONE
ip-10-191-123-179.ap-southeast-2.compute.internal   andy-ops-type1-sn-06b0-easy-terrier   ap-southeast-2a
ip-10-191-124-112.ap-southeast-2.compute.internal   andy-ops-type1-sn-02b0-grown-man      ap-southeast-2b
ip-10-191-127-16.ap-southeast-2.compute.internal    andy-ops-type1-sn-0d9c-curious-fawn   ap-southeast-2c
```

## list apiversion

https://akomljen.com/kubernetes-api-resources-which-group-and-version-to-use/

https://matthewpalmer.net/kubernetes-app-developer/articles/kubernetes-apiversion-definition-guide.html

```bash
# shows kubectl commands with short names (eg get pods = get po)
# Note can't find online but assume entries with empty APIGROUP use "apiVersion: v1"
list api-resources
NAME                              SHORTNAMES   APIGROUP                       NAMESPACED   KIND
pods                              po                                          true         Pod

kubectl api-resources -o wide
NAME                              SHORTNAMES   APIGROUP                       NAMESPACED   KIND
bindings                                                                      true         Binding
componentstatuses                 cs                                          false        ComponentStatus
configmaps                        cm                                          true         ConfigMap
endpoints                         ep                                          true         Endpoints
events                            ev                                          true         Event
limitranges                       limits                                      true         LimitRange
<snip>
controllerrevisions                            apps                           true         ControllerRevision
daemonsets                        ds           apps                           true         DaemonSet
deployments                       deploy       apps                           true         Deployment
replicasets                       rs           apps                           true         ReplicaSet
statefulsets                      sts          apps                           true         StatefulSet

# list api-resources for group apps - referenced in "apiVersion: apps/v1"
# eg for "kind: Deployment", use apigroup = apps
kubectl api-resources --api-group apps -o wide
NAME                  SHORTNAMES   APIGROUP   NAMESPACED   KIND                 VERBS
controllerrevisions                apps       true         ControllerRevision   [create delete deletecollection get list patch update watch]
daemonsets            ds           apps       true         DaemonSet            [create delete deletecollection get list patch update watch]
deployments           deploy       apps       true         Deployment           [create delete deletecollection get list patch update watch]
replicasets           rs           apps       true         ReplicaSet           [create delete deletecollection get list patch update watch]
statefulsets          sts          apps       true         StatefulSet          [create delete deletecollection get list patch update watch]

# get api-versions
kubectl api-versions
admissionregistration.k8s.io/v1beta1
apiextensions.k8s.io/v1beta1
apiregistration.k8s.io/v1
apiregistration.k8s.io/v1beta1
apps/v1
apps/v1beta1
apps/v1beta2
authentication.k8s.io/v1
authentication.k8s.io/v1beta1
authorization.k8s.io/v1
authorization.k8s.io/v1beta1
autoscaling/v1
autoscaling/v2beta1
batch/v1
batch/v1beta1
certificates.k8s.io/v1beta1
crd.projectcalico.org/v1
extensions/v1beta1
internal.autoscaling.k8s.io/v1alpha1
metrics.k8s.io/v1beta1
networking.gke.io/v1beta1
networking.k8s.io/v1
policy/v1beta1
rbac.authorization.k8s.io/v1
rbac.authorization.k8s.io/v1beta1
scalingpolicy.kope.io/v1alpha1
scheduling.k8s.io/v1beta1
storage.k8s.io/v1
storage.k8s.io/v1beta1
v1
```

### list apiservice

```bash
# api services
kubectl get apiservice

# api resources - used to get api group of resource type
kubectl api-resources
kubectl api-resources | grep node

# api resources for namespace
kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get -o name -n ns
```

### multiple labels / selector syntax

```bash
kubectl logs --selector=app=artifactory-ha,component=nginx,release=artifactory -n artifactory
kubectl logs --selector app=artifactory-ha,component=nginx,release=artifactory -n artifactory
kubectl logs -l app=artifactory-ha,component=nginx,release=artifactory -n artifactory
```

### pv / pvc

```bash
# get all pv and pvc
kubectl get pv

# get pvc for pod
kubectl get pod -n artifactory artifactory-artifactory-ha-primary-0 -o yaml
kubectl get pod -n artifactory artifactory-artifactory-ha-primary-0 -o yaml | grep claim

# get pvc for namespace
kubectl get pvc -n <namespace> <pvc_name> -o yaml

# edit pvc for namespace
kubectl edit pvc jenkins -n jenkins
```

```bash
# delete pv
# https://stackoverflow.com/questions/54629660/kubernetes-how-do-i-delete-pv-in-the-correct-manner

kubectl delete pvc -n namespace <pvc_name>
kubectl delete pvc -n cluster-operation grafana --dry-run=server

# If pv Reclaim Policy = "Delete", then deleting pvc will delete pv (and underlyng EBS volume)
kubectl get pv
NAME                                                                        CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS      CLAIM                                         STORAGECLASS                                                                REASON   AGE
aws-efs-csi-pv-provisioner-root                                             1Mi        RWX            Retain           Bound       kube-system/aws-efs-csi-pv-provisioner-root   efs-sc                                                                               99d
efs-ee-workplace-jceap-confluence-dev-fs-e51053dd-fsap-037965ec556462de0    1Mi        RWX            Retain           Available                                                 efs-ee-workplace-jceap-confluence-dev-fs-e51053dd-fsap-037965ec556462de0             23d
efs-ee-workplace-jceap-confluence-evo-fs-e51053dd-fsap-043f67e9d09259e30    1Mi        RWX            Retain           Available                                                 efs-ee-workplace-jceap-confluence-evo-fs-e51053dd-fsap-043f67e9d09259e30             23d
efs-ee-workplace-jceap-confluence-test-fs-e51053dd-fsap-04058d8dd96d6ba5e   1Mi        RWX            Retain           Available                                                 efs-ee-workplace-jceap-confluence-test-fs-e51053dd-fsap-04058d8dd96d6ba5e            23d
efs-ee-workplace-jceap-jira-dev-fs-e31053db-fsap-00475db7a5fbff359          1Mi        RWX            Retain           Available                                                 efs-ee-workplace-jceap-jira-dev-fs-e31053db-fsap-00475db7a5fbff359                   23d
efs-ee-workplace-jceap-jira-evo-fs-e31053db-fsap-036b3fe9c2328e989          1Mi        RWX            Retain           Available                                                 efs-ee-workplace-jceap-jira-evo-fs-e31053db-fsap-036b3fe9c2328e989                   23d
efs-ee-workplace-jceap-jira-test-fs-e31053db-fsap-0c65190507bd6ecb1         1Mi        RWX            Retain           Available                                                 efs-ee-workplace-jceap-jira-test-fs-e31053db-fsap-0c65190507bd6ecb1                  23d
efs-it-mfo-gmp-dev1-fs-6e1e3356-fsap-0552a254a6b89d062                      1Mi        RWX            Retain           Available                                                 efs-it-mfo-gmp-dev1-fs-6e1e3356-fsap-0552a254a6b89d062                               49d
pvc-1a55abcc-dc8f-4d3c-8322-d48ac3d318da                                    20Gi       RWO            Delete           Bound       cluster-operation/grafana                     ebs-sc                                                                               203d
pvc-4a6fb3db-394e-4065-b860-37bb9875ac5b                                    10Gi       RWO            Delete           Bound       cluster-operation/kubecost-cost-analyzer      ebs-sc                                                                               203d
pvc-f3a9e602-99bf-4862-9598-4147f308f182                                    80Gi       RWO            Delete           Bound       cluster-operation/prometheus                  ebs-sc                                                                               203d

# find out if a pvc is mounted by a pod
#https://github.com/kubernetes/kubernetes/issues/65233
#https://github.com/kubernetes/kubernetes/pull/65837

# Mounted By = <none> if no pod
[GLOBALTEST\tanga@aab18dd45157c32 ~] $ kubectl describe pvc -n cluster-operation grafana
Name:          grafana
Namespace:     cluster-operation
StorageClass:  ebs-sc
Status:        Bound
Volume:        pvc-1a55abcc-dc8f-4d3c-8322-d48ac3d318da
Labels:        <none>
Annotations:   pv.kubernetes.io/bind-completed: yes
               pv.kubernetes.io/bound-by-controller: yes
               volume.beta.kubernetes.io/storage-provisioner: ebs.csi.aws.com
               volume.kubernetes.io/selected-node: ip-10-188-19-110.ap-southeast-2.compute.internal
Finalizers:    [kubernetes.io/pvc-protection]
Capacity:      20Gi
Access Modes:  RWO
VolumeMode:    Filesystem
Mounted By:    <none>
Events:        <none>

[GLOBALTEST\tanga@aab18dd45157c32 ~] $ kubectl describe pvc -n cluster-operation prometheus
Name:          prometheus
Namespace:     cluster-operation
StorageClass:  ebs-sc
Status:        Bound
Volume:        pvc-f3a9e602-99bf-4862-9598-4147f308f182
Labels:        <none>
Annotations:   pv.kubernetes.io/bind-completed: yes
               pv.kubernetes.io/bound-by-controller: yes
               volume.beta.kubernetes.io/storage-provisioner: ebs.csi.aws.com
               volume.kubernetes.io/selected-node: ip-10-188-20-174.ap-southeast-2.compute.internal
Finalizers:    [kubernetes.io/pvc-protection]
Capacity:      80Gi
Access Modes:  RWO
VolumeMode:    Filesystem
Mounted By:    prometheus-694c5884cc-ng979
Events:        <none>
```

### remove finalizer

https://stackoverflow.com/a/59667608

```bash
kubectl get namespace stuck-namespace -o json \
  | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
  | kubectl replace --raw /api/v1/namespaces/stuck-namespace/finalize -f -
```

### replace config map / secret

```bash
kubectl create configmap -n tenant-a nginx-configmap --from-file=nginx.conf=./nginx.conf -o yaml --dry-run=client | kubectl replace -f -

kubectl create secret -n tenant-a tls nginx-server-certs --key nginx.eks-example.key --cert nginx.eks-example.crt -o yaml --dry-run=client | kubectl replace -f -
```

### secrets

**move secret across namespaces**

https://computingforgeeks.com/copy-kubernetes-secrets-between-namespaces/

```bash
kubectl delete secret ingress-wildcard-tls -n ns
kubectl get secret ingress-wildcard-tls -n ns -o yaml

# seems to add annotation to new secret, need to debug why
kubectl get secret ingress-wildcard-tls -n istio-internal -o json | jq '{apiVersion,data,kind,metadata,type} | .metadata |= {"annotations", "name"}' | kubectl apply -n ns -f -
```

**decode base64 secret**

```bash
kubectl get secret ingress-wildcard-tls -n ns --context cluster -o json | jq '.data | map_values(@base64d)'
```

## namespace

```bash
kubectl get namespace
kubectl create namespace andy-debug --dry-run -o yaml > namespace.yaml
kubectl apply -f namespace.yaml
kubectl delete namespaces andy-debug
```

## pods

```bash
kubectl get namespaces
kubectl get pods -n artifactory
kubectl get pod -n artifactory artifactory-artifactory-ha-member-0
kubectl get pods -n jenkins --watch # similar to tail
kubectl describe pods -n artifactory artifactory-artifactory-ha-member-0
kubectl get pods --show-labels -n csp-spinnaker csp-spinnaker-spinnaker-halyard-0 #show labels

# with ip
kubectl get pods -n codefresh -l app=codefresh-helloweb -o wide

# get pod noes
kubectl get pod -o=custom-columns=NODE:.spec.nodeName,NAME:.metadata.name -n istio-system
kubectl get pod -o=custom-columns=NODE:.spec.nodeName,NAME:.metadata.name --all-namespaces

# logs
kubectl logs -n <namespace> <pod> -c <container>

# copy from / to pod
kubectl cp {{namespace}}/{{podname}}:path/to/directory /local/path
kubectl cp /local/path namespace/podname:path/to/directory
kubectl cp workspace andy-debug/debug-pod-697dff64b-r4cn9:/debug
kubectl cp artifactory/artifactory-artifactory-ha-primary-0:/var/opt/jfrog/artifactory/backup/backup-daily/current/ ~/Documents/work/dev
```

## port forwarding

https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/

Used to forward requests from local host to pod, very useful for testing. Eg curl post to pod when pod doesn't have curl installed

```bash
# get service ports
kubectl get svc -n artifactory
NAME                                  TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
artifactory-artifactory-ha            ClusterIP      10.149.23.122   <none>        8081/TCP                     21h
artifactory-artifactory-ha-nodeport   NodePort       10.149.23.78    <none>        8081:30333/TCP               21h
artifactory-artifactory-ha-primary    ClusterIP      10.149.23.170   <none>        8081/TCP                     21h
artifactory-nginx                     LoadBalancer   10.149.23.236   10.149.17.4   80:31464/TCP,443:30665/TCP   21h
artifactory-nginx-nodeport            NodePort       10.149.23.209   <none>        30334:30334/TCP              21h

kubectl get pods -n artifactory
NAME                                   READY   STATUS    RESTARTS   AGE
artifactory-artifactory-ha-member-0    1/1     Running   0          21h
artifactory-artifactory-ha-member-1    1/1     Running   0          21h
artifactory-artifactory-ha-primary-0   1/1     Running   0          20h
artifactory-nginx-7df79574f5-vjrdn     1/1     Running   0          21h

# verify which port pod is listening on
kubectl get pods -n artifactory artifactory-artifactory-ha-member-0 --template='{{(index (index .spec.containers 0).ports 0).containerPort}}{{"\n"}}'
kubectl get pods -n artifactory artifactory-artifactory-ha-member-1 --template='{{(index (index .spec.containers 0).ports 0).containerPort}}{{"\n"}}'
kubectl get pods -n artifactory artifactory-artifactory-ha-primary-0 --template='{{(index (index .spec.containers 0).ports 0).containerPort}}{{"\n"}}'

# port forward
kubectl port-forward -n artifactory artifactory-artifactory-ha-member-0 7000:8081
curl -v --noproxy "*" -u "andy.tang:xxx" -X POST "http://localhost:7000/artifactory/api/plugins/reload"

# run in background and pkill
kubectl port-forward -n artifactory artifactory-artifactory-ha-member-0 7000:8081 &
pkill kubectl
```

## secrets

```bash
kubectl get secret mysecret -o yaml
```

## service account and generate token

https://www.spinnaker.io/setup/install/providers/kubernetes-v2/#optional-create-a-kubernetes-service-account

```bash
CONTEXT=$(kubectl config current-context)

# this service account uses the ClusterAdmin role -- this is not necessary more restrictive roles can be applied
kubectl apply --context $CONTEXT \
    -f https://spinnaker.io/downloads/kubernetes/service-account.yml

TOKEN=$(kubectl get secret --context $CONTEXT \
   $(kubectl get serviceaccount spinnaker-service-account \
       --context $CONTEXT \
       -n spinnaker \
       -o jsonpath='{.secrets[0].name}') \
   -n spinnaker \
   -o jsonpath='{.data.token}' | base64 --decode)

kubectl config set-credentials ${CONTEXT}-token-user --token $TOKEN
kubectl config set-context $CONTEXT --user ${CONTEXT}-token-user
```

```yaml
# https://www.spinnaker.io/downloads/kubernetes/service-account.yml

apiVersion: v1
kind: Namespace
metadata:
  name: spinnaker
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spinnaker-service-account
  namespace: spinnaker
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spinnaker-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: spinnaker-service-account
    namespace: spinnaker
---
# copy info in ~/.kube/config to craft kubeconfig file - pretty much delete parts not needed.  Example:
apiVersion: v1
kind: Config
clusters:
  - cluster:
      certificate-authority-data: xxxxxx
      server: https://10.149.16.34
    name: gke_anz-ex-services-dev-32c9ea_australia-southeast1_anz-ex-services-dev-gke
contexts:
  - context:
      cluster: gke_anz-ex-services-dev-32c9ea_australia-southeast1_anz-ex-services-dev-gke
      user: gke_anz-ex-services-dev-32c9ea_australia-southeast1_anz-ex-services-dev-gke-token-user
    name: main-demoapp
  - context:
      cluster: gke_anz-ex-services-dev-32c9ea_australia-southeast1_anz-ex-services-dev-gke
      user: gke_anz-ex-services-dev-32c9ea_australia-southeast1_anz-ex-services-dev-gke-token-user
    name: spinnaker
users:
  - name: gke_anz-ex-services-dev-32c9ea_australia-southeast1_anz-ex-services-dev-gke-token-user
    user:
      token: xxxxxx
```

## wait for pod readiness

can also look to use `kubectl wait`

```bash
MAX_WAIT=180
ATTEMPTS=0
# jq expression below looks at the "Ready" condition of each pod, filters for pods where it is equal to "True", and finally confirms the list has length>0 i.e. at least one pod is ready
while [[ $(kubectl -n gatekeeper-system get pods -l control-plane=audit-controller -o json | jq '.items|map(select(.status.conditions|map(select(.type=="Ready"))[].status=="True"))|length>0') != "true" ]]; do
  ATTEMPTS=$((ATTEMPTS+1))
  if [[ $ATTEMPTS -gt $MAX_WAIT ]]; then
    echo "Giving up waiting for audit-controller deployment"
    exit 1
  fi
  sleep 1
done
```

# kubectx

https://github.com/ahmetb/kubectx

```bash
# completion
Need to install bash-completion first

git clone https://github.com/ahmetb/kubectx.git ~/.kubectx
COMPDIR=$(pkg-config --variable=completionsdir bash-completion)
ln -sf ~/.kubectx/completion/kubens.bash $COMPDIR/kubens
ln -sf ~/.kubectx/completion/kubectx.bash $COMPDIR/kubectx
cat << FOE >> ~/.bash_profile

#kubectx and kubens
export PATH=~/.kubectx:\$PATH
FOE
```

# java keystore

```bash
# decrypt and list keystore
keytool -list -v -keystore keystore.jks -storepass <password>
```

# jsonnet

```bash
## print number of elements
jsonnet -e 'std.length((import "launchpad.jsonnet").sync)'
```

# macos

## rotate log files

https://www.richard-purves.com/2017/11/08/log-rotation-mac-admin-cheats-guide/

```bash
# logfilename                           [owner:group]           mode    count   size    when    flags   [/pid_file]     [sig_num]
/Users/<USERNAME>/Library/Logs/alpaca.log <username>:<group>       666     5       5124    *       J


cat > /etc/newsyslog.d/alpaca.conf
# logfilename                           [owner:group]           mode    count   size    when    flags   [/pid_file]     [sig_num]
/Users/tanga/Library/Logs/alpaca.log tanga:staff       666     5       5124    *       J
```

# make

## \_references

https://3musketeers.io/docs/make.html#make-and-target-all

## self documenting help, multi line support, folding long lines

Doesn't support new lines within comments for formatting

https://gist.github.com/klmr/575726c7e05d8780505a

```bash
.PHONY: show-help
# See <https://gist.github.com/klmr/575726c7e05d8780505a> for explanation.
show-help:
	@echo "$$(tput bold)Available rules:$$(tput sgr0)";echo;sed -ne"/^## /{h;s/.*//;:d" -e"H;n;s/^## //;td" -e"s/:.*//;G;s/\\n## /---/;s/\\n/ /g;p;}" ${MAKEFILE_LIST}|LC_ALL='C' sort -f|awk -F --- -v n=$$(tput cols) -v i=29 -v a="$$(tput setaf 6)" -v z="$$(tput sgr0)" '{printf"%s%*s%s ",a,-i,$$1,z;m=split($$2,w," ");l=n-i;for(j=1;j<=m;j++){l-=length(w[j])+1;if(l<= 0){l=n-i-length(w[j])-1;printf"\n%*s ",-i," ";}printf"%s ",w[j];}printf"\n";}'
```

## tfe example

```bash
SHELL := /bin/bash -euo pipefail

# exported variables
export TF_BUILD_DIR = build/$(ENV)
export TF_BACKEND_FILE = $(TF_BUILD_DIR)/_backend.tf

# tf reserved variables
export TF_CLI_CONFIG_FILE = $(TF_BUILD_DIR)/.terraformrc
export TF_DATA_DIR = $(TF_BUILD_DIR)/.terraform
export TF_INPUT = false
export TF_IN_AUTOMATION = true

# map non env specific bamboo variables - env specfic ones passed in via bamboo job
export TFE_HOSTNAME=$(bamboo_TFE_HOSTNAME)
export TFE_ORG=$(bamboo_TFE_ORG)
export TFE_PLAN_ARTIFACT_FILE=$(bamboo_TFE_PLAN_ARTIFACT_FILE)

# initialise work dir, backend and credentials
.PHONY: init
init: _check-env-init _clean
	scripts/init_tfe.sh
	terraform $@ $(TF_BUILD_DIR)

# plan and save build artifact for apply
.PHONY: plan
plan: _check-env init
	terraform $@ $(TF_BUILD_DIR)
	tar -czf $(TFE_PLAN_ARTIFACT_FILE) -C $(TF_BUILD_DIR) .

# apply with build artifact from plan
.PHONY: apply
apply: _check-env
	mkdir -p $(TF_BUILD_DIR) && tar -xf $(TFE_PLAN_ARTIFACT_FILE) -C $(TF_BUILD_DIR)
	terraform $@ -auto-approve $(TF_BUILD_DIR)

##@ helpers

.PHONY: _clean
_clean:
	@rm -rf $(TF_BUILD_DIR)

.PHONY: _check-env-init
_check-env-init:
	@[ -n "$(ENV)" ] || (echo 'You must export ENV (eg nonprod, prod)'; exit 1)
	@[ -n "$(TFE_HOSTNAME)" ] || (echo 'You must export TFE_HOSTNAME'; exit 1)
	@[ -n "$(TFE_ORG)" ] || (echo 'You must export TFE_ORG'; exit 1)
	@[ -n "$(TFE_WORKSPACE)" ] || (echo 'You must export TFE_WORKSPACE'; exit 1)
	@[ -n "$(TFE_TOKEN)" ] || (echo 'You must export TFE_TOKEN'; exit 1)

.PHONY: _check-env
_check-env:
	@[ -n "$(ENV)" ] || (echo 'You must export ENV (eg nonprod, prod)'; exit 1)
	@[ -n "$(TFE_PLAN_ARTIFACT_FILE)" ] || (echo 'You must export TFE_PLAN_ARTIFACT_FILE'; exit 1)
```

# markdown

## sort by headings - perl

https://groups.google.com/g/pandoc-discuss/c/WRJJQEgksu0/m/Pnmc89gvAgAJ

```bash
#!/usr/bin/env perl

local $/;
my $text = <>;
my ($start, @chapters) = split/^#(?=[^#])/m, $text;
print $start;
for (sort @chapters) {
    my ($level1, @subchapters) = split/^##(?=[^#])/m;
    print "#$level1";
        for (sort @subchapters) {
        my ($level2, @subsubchapters) = split/^###(?=[^#])/m;
        print "##$level2";
        print map {"###$_"} sort @subsubchapters;
        }
}
```

## sort by headings - python

https://github.com/Logan-Lin/SortMarkdown

# spinnaker

## get halyard config

```bash
kubectl get pods -n csp-spinnaker
kubectl cp csp-spinnaker/csp-spinnaker-spinnaker-halyard-0:/home/spinnaker/.hal/config ~/Documents/work/dev/
kubectl exec -it -n csp-spinnaker csp-spinnaker-spinnaker-halyard-0 -- /bin/bash
```

# splunk

## add time stamp to search

https://docs.splunk.com/Documentation/Splunk/8.0.2/Search/Specifytimemodifiersinyoursearch

https://answers.splunk.com/answers/437887/how-to-search-for-events-with-latest-time-down-to.html

Only up to the second - can't do millisecond

```
earliest=03/25/2020:9:17:00 latest=03/25/2020:9:17:30

index=_internal [| gentimes start=-1 | eval earliest=strptime("08/01/2016 10:53:54.987","%m/%d/%Y %H:%M:%S.%N") | table earliest] [| gentimes start=-1 | eval latest=strptime("08/01/2016 10:53:54.997","%m/%d/%Y %H:%M:%S.%N") | table latest ]| head 100
index=_internal [| gentimes start=-1 | eval earliest=strptime("3/25/20 9:17:00.000","%m/%d/%Y %H:%M:%S.%N") | table earliest] [| gentimes start=-1 | eval latest=strptime("3/25/20 9:17:50.000","%m/%d/%Y %H:%M:%S.%N") | table latest ]| head 100
```

## how to search for events before and after entry

- Click on time stamp

- Apply time filter - this will add filter to the "Date time range" in top right corner

- Remove search strings to expand results.

## sample queries

```
AWS vpc flow logs:
index=au_aws_common_platform sourcetype="au_aws_networklogs" log_group="/core/network/ingress-flow-logs-vpc2" | eval _raw = replace(message, "\"", "")
| rex "^\d [0-9]+ .* (?<srcaddr>.*) (?<destaddr>.*) (?<srcport>.*) (?<destport>.*) (?<protocol>.*) .* .* (?<startTime>.*) (?<endTime>.*) (?<action>.*) (?<status>.*)$"
| where (cidrmatch("10.188.200.0/21", srcaddr) OR cidrmatch("10.188.208.0/21", srcaddr) OR cidrmatch("10.188.216.0/21", srcaddr))
AND destaddr = "10.188.211.83"

Inbound Range:
index=au_aws_common_platform sourcetype="au_aws_networklogs" log_group="/core/network/sscontainer-flow-logs-*" | eval _raw = replace(message, "\"", "")
| rex "^\d [0-9]+ .* (?<srcaddr>.*) (?<destaddr>.*) (?<srcport>.*) (?<destport>.*) (?<protocol>.*) .* .* (?<startTime>.*) (?<endTime>.*) (?<action>.*) (?<status>.*)$"
| where (cidrmatch("10.188.16.0/25", srcaddr) OR cidrmatch("10.188.16.128/25", srcaddr) OR cidrmatch("10.188.17.0/25", srcaddr))
  AND (cidrmatch("10.188.18.0/23", destaddr) OR cidrmatch("10.188.20.0/23", destaddr) OR cidrmatch("10.188.22.0/23", destaddr))
| dedup srcport
| table srcport

Outbound Range:
index=au_aws_common_platform sourcetype="au_aws_networklogs" log_group="/core/network/sscontainer-flow-logs-*" | eval _raw = replace(message, "\"", "")
| rex "^\d [0-9]+ .* (?<srcaddr>.*) (?<destaddr>.*) (?<srcport>.*) (?<destport>.*) (?<protocol>.*) .* .* (?<startTime>.*) (?<endTime>.*) (?<action>.*) (?<status>.*)$"
| where (cidrmatch("10.188.16.0/25", srcaddr) OR cidrmatch("10.188.16.128/25", srcaddr) OR cidrmatch("10.188.17.0/25", srcaddr))
  AND (cidrmatch("10.188.18.0/23", destaddr) OR cidrmatch("10.188.20.0/23", destaddr) OR cidrmatch("10.188.22.0/23", destaddr))
| dedup destport
| table destport

# tfe
index=au_tfe_common_app sourcetype=anz_tfe_all_syslog earliest=03/25/2020:9:17:08 latest=03/25/2020:9:17:10 "Gateway Timeout" NOT "Server error: http: TLS handshake error from" NOT "Connecting to LaunchDarkly stream using URL"
```

# stern

https://kubernetes.io/blog/2016/10/tail-kubernetes-with-stern/

```bash
stern "artifactory-artifactory-ha-.*" --namespace artifactory --tail 50
stern "^(spin-orca.*|spin-echo.*|spin-clouddriver.*)$" -n csp-spinnaker --tail 50

stern --context cluster "istio-ingressgateway-.*" --namespace istio-perimeter-general --color=always
stern "istio-ingressgateway-.*" --namespace istio-internal --tail 30 --color=always | grep myapp.ns.svc.cluster.local

# can start stern logging before pod comes up, useful for capturing full log when cycling pods to debug
stern --context cluster "istio-ingressgateway-.*" --namespace istio-internal --color=always > at_workload_istio-ingressgateway.log
```

# terraform

## \_init plan apply

```bash
# init
terraform init -no-color \
  -input=false \
  -backend-config "bucket=$TF_STATE_BUCKET" \
  -backend-config "dynamodb_table=$TF_STATE_TABLE" \
  -backend-config "key=state/clusters/${TF_VAR_xxx}/default.tfstate"
TF_INIT_STATUS=$?
if [[ $TF_INIT_STATUS -ne 0 ]]; then echo "error during terraform init for $TF_VAR_xxx"; exit $TF_INIT_STATUS; fi

# plan
terraform plan -no-color \
  -input=false \
  -out="${TF_VAR_xxx}_infra.tfplan" \
  -var-file $CODEBUILD_SRC_DIR/$TF_VAR_environment/$TF_VAR_xxx.tfvars \
TF_PLAN_STATUS=$?
if [[ $TF_PLAN_STATUS -ne 0 ]]; then echo "error during plan for $TF_VAR_xxx"; exit $TF_PLAN_STATUS; fi
mkdir -p $CODEBUILD_SRC_DIR/plans
mv -v "${TF_VAR_xxx}_infra.tfplan" $CODEBUILD_SRC_DIR/plans/

# apply
cp -v "$CODEBUILD_SRC_DIR_plans/${TF_VAR_xxx}_infra.tfplan" .
terraform apply -no-color \
  -input=false \
  "${TF_VAR_xxx}_infra.tfplan"
TF_APPLY_STATUS=$?
if [[ $TF_APPLY_STATUS -ne 0 ]]; then echo "error during apply for $TF_VAR_xxx"; exit $TF_APPLY_STATUS; fi

# destroy plan
terraform plan -no-color \
  -input=false \
  -out="${TF_VAR_xxx}_infra_destroy.tfplan" \
  -var-file $CODEBUILD_SRC_DIR/$TF_VAR_org_entity/$TF_VAR_environment/$TF_VAR_xxx.tfvars \
  -var-file $CODEBUILD_SRC_DIR/$TF_VAR_org_entity/$TF_VAR_environment/istio-meshes.tfvars \
  -destroy
TF_DESTROY_PLAN_STATUS=$?
if [[ $TF_DESTROY_PLAN_STATUS -ne 0 ]]; then echo "error during destroy plan destroy for $TF_VAR_xxx"; exit $TF_DESTROY_PLAN_STATUS; fi
echo "Apply destroy plan"

# destroy apply
terraform apply -no-color \
  -input=false \
  "${TF_VAR_xxx}_infra_destroy.tfplan"
TF_DESTROY_APPLY_STATUS=$?
```

## list vs map vs set

https://www.reddit.com/r/Terraform/comments/bwo2w1/how_are_we_now_supposed_to_iterate_over_a_list_to/eq8mbb8?utm_source=share&utm_medium=web2x&context=3

list = array of values, ordered

maps = key value pairs, un-ordered

sets = values only, no key or index

What lists, maps, and sets have in common is that they are all collections of values where all the values have the same type.

Lists are collections where those values are defined in a particular order and assigned numeric indices starting at zero, so we can say that each value is identified by a number.

Maps are collections where those values are not in a particular order but are each assigned a key string. We can therefore say that each value is identified by a string.

Sets are, similar to maps, collections where the values are in no particular order, but unlike maps the values are not assigned a key string. Instead, the values identify themselves.

## backend cannot use variables

https://github.com/hashicorp/terraform/issues/13022

https://github.com/hashicorp/terraform/issues/17288

Potential workaround using TF_CLI_ARGS

https://www.terraform.io/docs/commands/environment-variables.html#tf_cli_args-and-tf_cli_args_name

https://archive.sweetops.com/terraform/2019/03/

# vim

## select all and delete

https://unix.stackexchange.com/questions/161821/how-can-i-delete-all-lines-in-a-file-using-vi

```
I always use ggVG
gg jumps to the start of the current editing file
V (capitalized v) will select the current line. In this case the first line of the current editing file
G (capitalized g) will jump to the end of the file. In this case, since I selected the first line, G will select the whole text in this file.
Then you can simply press d or x to delete all the lines.
```

# yamllint

```bash
# yamllint config
https://yamllint.readthedocs.io/en/stable/configuration.html

.yamllint

mkdir ~/.config/yamllint
cat > ~/.config/yamllint/config <<EOF
extends: default

rules:
  line-length:
    level: warning
  indentation:
    indent-sequences: consistent
    level: warning
    spaces: consistent

EOF

*** default
cat > ~/.config/yamllint/config <<EOF
yaml-files:
  - '*.yaml'
  - '*.yml'
  - '.yamllint'

rules:
  braces: enable
  brackets: enable
  colons: enable
  commas: enable
  comments:
    level: warning
  comments-indentation:
    level: warning
  document-end: disable
  document-start:
    level: warning
  empty-lines: enable
  empty-values: disable
  hyphens: enable
  indentation: enable
  key-duplicates: enable
  key-ordering: disable
  line-length: enable
  new-line-at-end-of-file: enable
  new-lines: enable
  octal-values: disable
  quoted-strings: disable
  trailing-spaces: enable
  truthy:
    level: warning
EOF
```
