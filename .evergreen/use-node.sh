export NVM_DIR="$PWD/.deps/nvm"

if [[ "$OS" == "Windows_NT" ]]; then
    export NVM_HOME=$(cygpath -w "$NVM_DIR")
    export NVM_SYMLINK=$(cygpath -w "$PWD/.deps/node/bin")
    export NVM_ARTIFACTS_PATH=$(cygpath -w "$PWD/.deps/node/bin")
    export PATH=$(cygpath $NVM_SYMLINK):$(cygpath $NVM_HOME):$PATH
    echo "updated path on windows PATH=$PATH"
else
    [ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
fi
