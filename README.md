# revshell
A multiplatform reverse shell generator cli. Built to be easy to use, simple, lightweight, and get you hacking CTFs/Labs/Targets/Nations quicker. Currently the scope is limited to only support a linux attack box, have reverse shell parity with revshells.com, and include automatic reverse shell generation listening and handling. 

I might later add some additional logic and handling for caught listeners, but I don't want to start making my own C2, this will be lightweight and limited to CTFs and what not.

## Architecture and Setup
The CLI tool is developed in Golang 1.27.1, and built of the Cobra library and Cobra-CLI tool for initial set up and monitoring

## Selecting a payload
Run `go run .` from the project directory. Select your callback interface, target
platform, a matching payload from the JSON catalog, and an encoding. The callback
IP and port are substituted before encoding, and the result is printed before the
TCP listener starts on the displayed port.

The catalog is read from `payloadsList.json` in the current directory, falling
back to a file beside the executable. To use a custom catalog, pass
`--payloads /path/to/payloadsList.json`.

- No encoding prints the substituted payload directly.
- Base64 prints UTF-8 Base64 data; the receiving context must decode it before
  execution.
- URL encoding prints percent-encoded data for a URL query context that decodes
  it before execution.
- PowerShell Base64 is available for the PowerShell script and prints a
  `powershell -EncodedCommand` command using UTF-16LE Base64.

PowerShell Base64 is offered only to catalog entries marked with
`"powershell": true`. Payloads still require the corresponding runtime or shell
on the target; for example, the Node.js entry is JavaScript for a Node.js context.

## Security and Contributing
You are welcome to contribute with/without AI, with the guidelines being lightweight, with these being:
- Ensure you provide sufficient detail and keep contributions small
- If you see or find a vuln, email me at hi@maxfrancis.me until I set up a formal security policy through GH
