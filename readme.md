## Pebble installing
 First, in order to get the project running for testing, please install pebble. You can follow the steps at <https://github.com/letsencrypt/pebble>.
However, some students (including me) had issues running all the commands on Ubuntu, so here is the list of commands I recommend in order to properly install pebble. 

```export GOPATH=$HOME/work```

```export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin```

```source ~/.profile ```

```go version``` (to check that everything is okay)

```go get -u github.com/letsencrypt/pebble/...```

```cd $GOPATH/src/github.com/letsencrypt/pebble && go install ./...```

```pebble -h```

## Pebble Running

To get pebble running, don't forget to pass as argument the DNS server's port once your DNS is up and running: 

```pebble -config ./test/config/pebble-config.json -dnsserver :10053```

## Running the code locally
You can run the code for debugging by running the command :

```project/run dns01 --dir https://127.0.0.1:14000/dir --record 127.0.0.1 --domain www.example.com```

To get the code up and running correctly, you MUST have the pebble server up and running as well, otherwise the program will crash.

## MISC 

We leave all comments that might either be useful for debugging purposes, and explaining of methods in this version. Submited version is the same, with comments removed and code linted. The code obtained 63/63 points. I also leave the project description of my year (Fall 2020), in case the projects has subtle changes next year. 



