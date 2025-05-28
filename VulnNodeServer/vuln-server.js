// vuln-server.js
const http = require('http')
http.createServer((req, res) => {
  res.writeHead(200)
  res.end('Olá, sou uma vulnerabilidade!')
}).listen(8080)
