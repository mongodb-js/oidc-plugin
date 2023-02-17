#!/bin/bash
# adapted from the Node.js driver's script for installing Node.js
set -e
set -x

export BASEDIR="$PWD"
mkdir -p .deps
cd .deps

NVM_WINDOWS_URL="https://github.com/coreybutler/nvm-windows/releases/download/1.1.9/nvm-noinstall.zip"
NVM_URL="https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh"

# this needs to be explicitly exported for the nvm install below
export NVM_DIR="$PWD/nvm"
export XDG_CONFIG_HOME=$PWD

# install Node.js on Windows
if [[ "$OS" == "Windows_NT" ]]; then
  # Delete pre-existing node to avoid version conflicts
  rm -rf "/cygdrive/c/Program Files/nodejs"

  mkdir -p node/bin
  export NVM_HOME=$(cygpath -w "$NVM_DIR")
  export NVM_SYMLINK=$(cygpath -w "$PWD/node/bin")
  export NVM_ARTIFACTS_PATH=$(cygpath -w "$PWD/node/bin")
  export PATH=$(cygpath $NVM_SYMLINK):$(cygpath $NVM_HOME):$PATH

  curl -L $NVM_WINDOWS_URL -o nvm.zip
  unzip -d "$NVM_DIR" nvm.zip
  rm nvm.zip

  chmod 777 "$NVM_DIR"
  chmod -R a+rx "$NVM_DIR"

  cat <<EOT > "$NVM_DIR/settings.txt"
root: $NVM_HOME
path: $NVM_SYMLINK
EOT
  nvm install "$NODE_VERSION"
  nvm use "$NODE_VERSION"

# install Node.js on Linux/MacOS
else
  curl -o- $NVM_URL | bash
  set +x
  [ -s "${NVM_DIR}/nvm.sh" ] && source "${NVM_DIR}/nvm.sh"
  nvm install --no-progress "$NODE_VERSION"
fi

which node || echo "node not found, PATH=$PATH"
which npm || echo "npm not found, PATH=$PATH"
