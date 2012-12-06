# Source this to set the necessary env vars.

# Kudu is our high-level wrapper for the Antelope API.
export PYTHONPATH=$PYTHONPATH:$HOME/kudu

# StreamProx is a reverse proxy for Twisted which, among other things, lets our
# web services and websockets services appear on the same port.
export PYTHONPATH=$PYTHONPATH:$HOME/StreamProx

# Config PF location
export PFPATH=$PFPATH:`pwd`/etc

