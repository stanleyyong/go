'use strict';

var shell = require('shelljs');

const exec = require('child_process').execSync;

function scprobe(){
  var reO = "";
  try{
    var outcome = exec("stellar-core --conf=/home/geekdom/node01/stellar-core.cfg http-command 'info' | grep \"state\"");
    reO = outcome.toString();
    return reO;
  }
  catch{
    return "error";
  }
}

const http = require('http')
const port = 3000

const requestHandler = (request, response) => {
  console.log(request.url)
  var scret = scprobe();
  if(scret == "error"){
    response.writeHead(404);
    response.end();
  }else{
    response.writeHead(200);
    response.end(scprobe());
  }
}

const server = http.createServer(requestHandler)

server.listen(port, (err) => {
  if (err) {
    return console.log('something bad happened', err)
  }

  console.log(`server is listening on ${port}`)
})
