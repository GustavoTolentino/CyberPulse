import { parseStringPromise } from 'xml2js'
import { promisify } from 'util'
import { execFile } from 'child_process'

const NMAP_CMD = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
const execFileAsync = promisify(execFile)
const COMMON_PORTS = [21, 22, 23, 25, 53, 67, 3000, 8080]
const PORT_LIST = COMMON_PORTS.join(',')

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const ip = searchParams.get('range')
  if (!ip) {
    return new Response(JSON.stringify({ error: 'Parâmetro "range" ausente' }), { status: 400 })
  }

  try {
    const { stdout } = await execFileAsync(
      NMAP_CMD,
      ['-Pn', '-T4', '-p', PORT_LIST, '--script', 'vuln', '-oX', '-', ip]
    )
    const parsed = await parseStringPromise(stdout, { explicitArray: false })
    const hosts = parsed.nmaprun.host
      ? (Array.isArray(parsed.nmaprun.host) ? parsed.nmaprun.host : [parsed.nmaprun.host])
      : []

    if (hosts.length === 0) {
      return new Response(
        JSON.stringify({ ip, status: 'down', openPorts: [], vulnerabilities: [] }),
        { headers: { 'Content-Type': 'application/json' } }
      )
    }

    const host = hosts[0]
    const status = host.status?.$.state || 'unknown'
    const portsArr = host.ports?.port
      ? (Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port])
      : []

    const openPorts = portsArr
      .filter(p => p.state?.$?.state === 'open')
      .map(p => ({
        port: Number(p.$.portid),
        service: p.service?.$.name || 'unknown'
      }))

    const vulnerabilities = []
    for (const port of portsArr) {
      const script = port.script
      if (script) {
        const scripts = Array.isArray(script) ? script : [script]
        scripts.forEach(s => {
          vulnerabilities.push({
            port: Number(port.$.portid),
            id: s.$.id || 'unknown',
            output: s.$.output || ''
          })
        })
      }
    }

    return new Response(
      JSON.stringify({ ip, status, openPorts, vulnerabilities }),
      { headers: { 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    return new Response(
      JSON.stringify({ ip, status: 'error', error: err.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    )
  }
}
